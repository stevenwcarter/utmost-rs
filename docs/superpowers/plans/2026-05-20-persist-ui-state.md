# Per-case UI-state persistence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist each case's GUI filter/sort/toggle state, selection, and scroll-position to its `<slug>-index.sqlite` and restore it the next time the user opens the case.

**Architecture:** One JSON blob at `meta.ui_state` per case sqlite. Versioned `UiStateSnapshot` struct (serde) in `view_model.rs` plus an `into_runtime` conversion that validates against the live `RunSummary`/sources. Hydration is **synchronous in `open_case`** — the DB is already open there; the snapshot rides on `CaseHandle.ui_state_on_open` into `UiState::new`, which applies it before posting the first Requery (guarded by a `hydrating: bool` so the apply doesn't trigger an immediate re-save). Save is **debounced ~500ms** in `slint_adapter::UiState` via a Slint timer + dirty flag; the timer body sends `IndexerCommand::PersistUiState(snapshot)` on the per-case command channel. A final flush runs in the picker's back-button / window-close paths before `shutdown_query_loop` drains the indexer. Selection-scroll-into-view fires on the first `MatchIds` response after hydration.

**Tech Stack:** Rust, serde / serde_json (already in `utmost-gui`'s deps), Diesel + SQLite, crossbeam-channel, Slint timer.

**Spec:** `docs/superpowers/specs/2026-05-20-persist-ui-state-design.md`

---

## File structure

**Modify:**
- `crates/utmost-gui/src/view_model.rs` — add `UiStateSnapshot`, `FilterStateSnapshot`, `file_type_to_pub_str` (companion to the existing `parse_file_type_pub`), the `from_view_model` constructor, and `into_runtime` conversion. Unit tests in the same file's `#[cfg(test)] mod tests`.
- `crates/utmost-gui/src/index_db/writer.rs` — add `write_ui_state` and `read_ui_state` helpers + their tests. Reuses the existing `upsert_meta` and `read_meta_str` patterns.
- `crates/utmost-gui/src/case.rs` — add `ui_state_on_open: Option<UiStateSnapshot>` to `CaseHandle`; `open_case` calls `read_ui_state` and populates it. Unit tests in the same file.
- `crates/utmost-gui/src/indexer_thread.rs` — add `IndexerCommand::PersistUiState(UiStateSnapshot)` variant and its handler arm in `run_query_loop`.
- `crates/utmost-gui/src/slint_adapter.rs` — `UiState::new` gains a `ui_state_on_open: Option<UiStateSnapshot>` parameter, plus three new fields (`hydrating: Cell<bool>`, `ui_state_dirty: Cell<bool>`, `ui_state_save_timer: slint::Timer`, `pending_scroll_to_selection: Cell<Option<FileId>>`); add `mark_ui_state_dirty(&self)`, `flush_pending_ui_state(&self)`, and `scroll_to_row(&self, idx)` methods; wire `mark_ui_state_dirty()` into every mutation handler; apply scroll target after `MatchIds` arrives.
- `crates/utmost-gui/src/lib.rs` — pass `handle.ui_state_on_open.take()` into `UiState::new`; call `ui.flush_pending_ui_state()` in `on_back_to_picker` and the post-`window.run()` cleanup, before dropping the UiState.

**Create:**
- `crates/utmost-gui/tests/ui_state_persistence.rs` — integration tests that drive `open_case` → mutate VM → `close_case` → `open_case` again → assert restoration.

**Documentation:**
- `CLAUDE.md` — add a "Per-case UI-state" subsection under "GUI: case model."

---

## Task 1: Snapshot types + conversion + `file_type_to_pub_str`

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs`

Adds the pure-data layer that the rest of the plan builds on. No I/O.

- [ ] **Step 1: Add the `file_type_to_pub_str` helper paired with the existing `parse_file_type_pub`**

In `crates/utmost-gui/src/view_model.rs`, find the existing `pub fn parse_file_type_pub` (around line 1020) and add immediately above it:

```rust
/// Canonical lowercase string for a [`FileType`]. Inverse of
/// [`parse_file_type_pub`]. Each new `FileType` variant must add a
/// match arm here; the `view_model::tests::file_type_string_round_trip`
/// test guards the inverse property.
pub fn file_type_to_pub_str(ft: FileType) -> &'static str {
    match ft {
        FileType::Jpeg => "jpeg",
        FileType::Gif => "gif",
        FileType::Bmp => "bmp",
        FileType::Mpg => "mpg",
        FileType::Pdf => "pdf",
        FileType::Doc => "doc",
        FileType::Avi => "avi",
        FileType::Wmv => "wmv",
        FileType::Htm => "htm",
        FileType::Zip => "zip",
        FileType::Mov => "mov",
        FileType::Xls => "xls",
        FileType::Ppt => "ppt",
        FileType::Wpd => "wpd",
        FileType::Cpp => "cpp",
        FileType::Ole => "ole",
        FileType::Gzip => "gzip",
        FileType::Riff => "riff",
        FileType::Wav => "wav",
        FileType::VJpeg => "vjpeg",
        // Match the rest of the variants by mirroring `parse_file_type`'s arms.
        // The implementer must list every FileType variant; the round-trip test
        // below will fail loudly if any are missed.
        _ => "unknown",
    }
}
```

> **Implementing-agent note:** Replace the `_ => "unknown"` arm with explicit arms for every remaining `FileType` variant. Mirror `parse_file_type` (which appears immediately below in the same file) — every string it accepts must come back from `file_type_to_pub_str`. The duplicate-of-`file_type_to_db_string` (which is private in `queries.rs`) is intentional — both are needed for different layers; the round-trip test below catches drift.

- [ ] **Step 2: Add a round-trip test for the new helper**

In the `#[cfg(test)] mod tests` block of `view_model.rs`, add:

```rust
#[test]
fn file_type_string_round_trip() {
    // Walk every variant via the iterator used by chips/groups; if any
    // variant is missing from file_type_to_pub_str, this fails.
    for ft in all_known_file_types() {
        let s = file_type_to_pub_str(ft);
        assert_ne!(s, "unknown", "file_type_to_pub_str missing arm for {:?}", ft);
        let back = parse_file_type_pub(s);
        assert_eq!(back, Some(ft), "round-trip failed for {:?} via {:?}", ft, s);
    }
}

fn all_known_file_types() -> Vec<FileType> {
    // Source from the existing parse_file_type matches by feeding it every
    // string the codebase recognises. If parse_file_type recognises a string
    // not present in file_type_to_pub_str, the assertion above catches it.
    let candidates = [
        "jpeg", "gif", "bmp", "mpg", "pdf", "doc", "avi", "wmv", "htm", "zip",
        "mov", "xls", "ppt", "wpd", "cpp", "ole", "gzip", "riff", "wav",
        "vjpeg",
        // Add the remaining strings the implementer mirrored above.
    ];
    candidates.iter().filter_map(|s| parse_file_type_pub(s)).collect()
}
```

> **Implementing-agent note:** Expand the `candidates` array to match the full set of strings `parse_file_type` accepts (find the function body right below `parse_file_type_pub`; copy each `"xxx" =>` arm's literal). The test's reliability depends on this list being complete.

- [ ] **Step 3: Add `UiStateSnapshot` and `FilterStateSnapshot` types with serde derives**

Near the top of `view_model.rs` — after the existing `pub struct FilterState` definition (~line 91) — add:

```rust
/// On-disk shape of [`FilterState`] + UI chrome + selection. Stored as a
/// versioned JSON blob in `meta.ui_state` per case sqlite. Use the
/// snapshot type (not `FilterState` directly) so the on-disk layout stays
/// stable independent of internal `FilterState` churn, and so
/// `into_runtime` is the only place that validates against a live case.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct UiStateSnapshot {
    /// Schema version. `v = 1` today; future incompatible changes bump
    /// this and add a migration arm in `into_runtime`.
    pub v: u32,
    pub filter: FilterStateSnapshot,
    pub filters_visible: bool,
    /// `Group::as_key_str` value; `None` means "All".
    pub selected_group: Option<String>,
    pub selection_file_id: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FilterStateSnapshot {
    pub enabled_types: Vec<String>,
    pub enabled_partial_types: Vec<String>,
    pub bookmarked_only: bool,
    pub source_filter: Option<u32>,
    pub sort_key: String,
    pub sort_dir: String,
    pub bookmarked_first: bool,
    pub hide_no_preview: bool,
    pub size_range: Option<(u64, u64)>,
}

impl UiStateSnapshot {
    pub const CURRENT_VERSION: u32 = 1;
}
```

- [ ] **Step 4: Add `UiStateSnapshot::from_view_model` constructor**

Append in the same module-level location:

```rust
impl UiStateSnapshot {
    /// Capture the current UI-relevant subset of `vm` into a snapshot.
    /// Pure: no I/O, no locks held.
    pub fn from_view_model(vm: &ViewModel) -> Self {
        let sort_key = match vm.filter.sort_key {
            SortKey::Filename => "Filename",
            SortKey::Size => "Size",
            SortKey::FileType => "FileType",
            SortKey::SourceOffset => "SourceOffset",
        };
        let sort_dir = match vm.filter.sort_dir {
            SortDir::Asc => "Asc",
            SortDir::Desc => "Desc",
        };
        Self {
            v: Self::CURRENT_VERSION,
            filter: FilterStateSnapshot {
                enabled_types: vm
                    .filter
                    .enabled_types
                    .iter()
                    .map(|ft| file_type_to_pub_str(*ft).to_string())
                    .collect(),
                enabled_partial_types: vm
                    .filter
                    .enabled_partial_types
                    .iter()
                    .map(|ft| file_type_to_pub_str(*ft).to_string())
                    .collect(),
                bookmarked_only: vm.filter.bookmarked_only,
                source_filter: vm.filter.source_filter,
                sort_key: sort_key.into(),
                sort_dir: sort_dir.into(),
                bookmarked_first: vm.filter.bookmarked_first,
                hide_no_preview: vm.filter.hide_no_preview,
                size_range: vm.filter.size_range,
            },
            filters_visible: vm.filters_visible,
            selected_group: vm.selected_group.map(|g| g.as_key_str().to_string()),
            selection_file_id: vm.selection,
        }
    }
}
```

> **Implementing-agent note:** The `selection_file_id: vm.selection` line assumes `ViewModel.selection: Option<FileId>` where `FileId = u64`. Verify by reading the `selection` field declaration around line 282 of `view_model.rs`. If `FileId` is a different integer type, cast appropriately.

- [ ] **Step 5: Add `UiStateSnapshot::into_runtime` — the only validation point**

Append in the same module:

```rust
impl UiStateSnapshot {
    /// Convert this snapshot into runtime ViewModel-bound values, validating
    /// against the current case's run and sources. Best-effort: anything
    /// that can't be mapped (unknown file types, off-configuration entries,
    /// missing sources, invalid size ranges, unknown sort strings) is
    /// dropped silently or replaced with the default. Never errors.
    ///
    /// Returns: (filter, filters_visible, selected_group, selection_file_id).
    /// The caller (`UiState::new`) assigns these into the live ViewModel.
    pub fn into_runtime(
        self,
        run: &RunSummary,
        sources: &[SourceRow],
    ) -> (FilterState, bool, Option<Group>, Option<FileId>) {
        // Handle schema-version drift.
        if self.v != Self::CURRENT_VERSION {
            tracing::warn!(
                "UiStateSnapshot: unknown schema v={}, expected {}; using defaults",
                self.v,
                Self::CURRENT_VERSION,
            );
            return (FilterState::default(), true, None, None);
        }

        let configured: std::collections::BTreeSet<FileType> =
            run.configured_types.iter().copied().collect();

        let map_types = |strings: &[String]| -> std::collections::BTreeSet<FileType> {
            strings
                .iter()
                .filter_map(|s| parse_file_type_pub(s))
                .filter(|ft| configured.is_empty() || configured.contains(ft))
                .collect()
        };

        let sort_key = match self.filter.sort_key.as_str() {
            "Filename" => SortKey::Filename,
            "Size" => SortKey::Size,
            "FileType" => SortKey::FileType,
            "SourceOffset" => SortKey::SourceOffset,
            other => {
                tracing::debug!("UiStateSnapshot: unknown sort_key {other:?}, defaulting");
                SortKey::default()
            }
        };
        let sort_dir = match self.filter.sort_dir.as_str() {
            "Asc" => SortDir::Asc,
            "Desc" => SortDir::Desc,
            other => {
                tracing::debug!("UiStateSnapshot: unknown sort_dir {other:?}, defaulting");
                SortDir::default()
            }
        };

        let source_filter = self
            .filter
            .source_filter
            .filter(|sid| sources.iter().any(|s| s.source_id == *sid));

        let size_range = match self.filter.size_range {
            Some((lo, hi)) if lo > hi => None,
            Some((0, 0)) => None,
            other => other,
        };

        let filter = FilterState {
            enabled_types: map_types(&self.filter.enabled_types),
            enabled_partial_types: map_types(&self.filter.enabled_partial_types),
            bookmarked_only: self.filter.bookmarked_only,
            source_filter,
            sort_key,
            sort_dir,
            bookmarked_first: self.filter.bookmarked_first,
            hide_no_preview: self.filter.hide_no_preview,
            size_range,
        };

        let selected_group = self
            .selected_group
            .as_deref()
            .and_then(Group::from_key_str);

        (filter, self.filters_visible, selected_group, self.selection_file_id)
    }
}
```

> **Implementing-agent note:** This function takes ownership of `self` so the snapshot is consumed exactly once at apply time. `FileId` is defined elsewhere in `view_model.rs` (search `pub type FileId`); if the import for it isn't already in scope at the impl block, add a `use` line.

- [ ] **Step 6: Add unit tests for the conversion**

In the `#[cfg(test)] mod tests` block of `view_model.rs`, add:

```rust
#[test]
fn snapshot_from_default_view_model_round_trips() {
    let vm = ViewModel::new();
    let snap = UiStateSnapshot::from_view_model(&vm);
    assert_eq!(snap.v, UiStateSnapshot::CURRENT_VERSION);

    let mut run = RunSummary::default();
    run.configured_types = vec![FileType::Jpeg, FileType::Pdf];
    let sources = vec![];
    let (filter, vis, group, sel) = snap.into_runtime(&run, &sources);

    assert_eq!(filter, FilterState::default());
    assert!(vis);
    assert_eq!(group, None);
    assert_eq!(sel, None);
}

#[test]
fn into_runtime_drops_unknown_file_types() {
    let snap = UiStateSnapshot {
        v: 1,
        filter: FilterStateSnapshot {
            enabled_types: vec!["jpeg".into(), "totally-bogus".into(), "pdf".into()],
            enabled_partial_types: vec![],
            bookmarked_only: false,
            source_filter: None,
            sort_key: "Filename".into(),
            sort_dir: "Asc".into(),
            bookmarked_first: false,
            hide_no_preview: false,
            size_range: None,
        },
        filters_visible: true,
        selected_group: None,
        selection_file_id: None,
    };
    let mut run = RunSummary::default();
    run.configured_types = vec![FileType::Jpeg, FileType::Pdf];
    let (filter, _, _, _) = snap.into_runtime(&run, &[]);
    assert!(filter.enabled_types.contains(&FileType::Jpeg));
    assert!(filter.enabled_types.contains(&FileType::Pdf));
    assert_eq!(filter.enabled_types.len(), 2, "bogus type must be dropped");
}

#[test]
fn into_runtime_intersects_with_configured_types() {
    let snap = UiStateSnapshot {
        v: 1,
        filter: FilterStateSnapshot {
            enabled_types: vec!["jpeg".into(), "pdf".into()],
            enabled_partial_types: vec![],
            bookmarked_only: false,
            source_filter: None,
            sort_key: "Filename".into(),
            sort_dir: "Asc".into(),
            bookmarked_first: false,
            hide_no_preview: false,
            size_range: None,
        },
        filters_visible: true,
        selected_group: None,
        selection_file_id: None,
    };
    let mut run = RunSummary::default();
    run.configured_types = vec![FileType::Jpeg]; // PDF NOT configured
    let (filter, _, _, _) = snap.into_runtime(&run, &[]);
    assert!(filter.enabled_types.contains(&FileType::Jpeg));
    assert!(!filter.enabled_types.contains(&FileType::Pdf),
        "PDF must be dropped because it's not in configured_types");
}

#[test]
fn into_runtime_clears_source_filter_for_missing_source() {
    let snap = UiStateSnapshot {
        v: 1,
        filter: FilterStateSnapshot {
            enabled_types: vec![],
            enabled_partial_types: vec![],
            bookmarked_only: false,
            source_filter: Some(99),
            sort_key: "Filename".into(),
            sort_dir: "Asc".into(),
            bookmarked_first: false,
            hide_no_preview: false,
            size_range: None,
        },
        filters_visible: true,
        selected_group: None,
        selection_file_id: None,
    };
    let run = RunSummary::default();
    let sources = vec![SourceRow {
        source_id: 0,
        filename: "a.img".into(),
        output_subdir: "a".into(),
        total_bytes: 0,
        bytes_read: 0,
        files_found: 0,
        status: SourceStatus::Finished,
        duration_ms: None,
    }];
    let (filter, _, _, _) = snap.into_runtime(&run, &sources);
    assert_eq!(filter.source_filter, None, "missing source must clear filter");
}

#[test]
fn into_runtime_clamps_invalid_size_range() {
    let mk = |range: Option<(u64, u64)>| UiStateSnapshot {
        v: 1,
        filter: FilterStateSnapshot {
            enabled_types: vec![],
            enabled_partial_types: vec![],
            bookmarked_only: false,
            source_filter: None,
            sort_key: "Filename".into(),
            sort_dir: "Asc".into(),
            bookmarked_first: false,
            hide_no_preview: false,
            size_range: range,
        },
        filters_visible: true,
        selected_group: None,
        selection_file_id: None,
    };
    let run = RunSummary::default();

    let (f, _, _, _) = mk(Some((100, 50))).into_runtime(&run, &[]);
    assert_eq!(f.size_range, None, "lo>hi must clamp to None");

    let (f, _, _, _) = mk(Some((0, 0))).into_runtime(&run, &[]);
    assert_eq!(f.size_range, None, "(0,0) must clamp to None");

    let (f, _, _, _) = mk(Some((10, 100))).into_runtime(&run, &[]);
    assert_eq!(f.size_range, Some((10, 100)), "valid range preserved");
}

#[test]
fn into_runtime_drops_bogus_sort_strings_to_default() {
    let snap = UiStateSnapshot {
        v: 1,
        filter: FilterStateSnapshot {
            enabled_types: vec![],
            enabled_partial_types: vec![],
            bookmarked_only: false,
            source_filter: None,
            sort_key: "BogusKey".into(),
            sort_dir: "BogusDir".into(),
            bookmarked_first: false,
            hide_no_preview: false,
            size_range: None,
        },
        filters_visible: true,
        selected_group: None,
        selection_file_id: None,
    };
    let run = RunSummary::default();
    let (filter, _, _, _) = snap.into_runtime(&run, &[]);
    assert_eq!(filter.sort_key, SortKey::default());
    assert_eq!(filter.sort_dir, SortDir::default());
}

#[test]
fn into_runtime_unknown_schema_version_returns_defaults() {
    let snap = UiStateSnapshot {
        v: 9999,
        filter: FilterStateSnapshot {
            enabled_types: vec!["jpeg".into()],
            enabled_partial_types: vec![],
            bookmarked_only: true,
            source_filter: Some(0),
            sort_key: "Size".into(),
            sort_dir: "Desc".into(),
            bookmarked_first: true,
            hide_no_preview: true,
            size_range: Some((10, 100)),
        },
        filters_visible: false,
        selected_group: Some("image".into()),
        selection_file_id: Some(42),
    };
    let mut run = RunSummary::default();
    run.configured_types = vec![FileType::Jpeg];
    let (filter, vis, group, sel) = snap.into_runtime(&run, &[]);
    assert_eq!(filter, FilterState::default());
    assert!(vis);
    assert_eq!(group, None);
    assert_eq!(sel, None);
}

#[test]
fn from_view_model_round_trips_all_fields() {
    let mut vm = ViewModel::new();
    vm.filter.enabled_types.insert(FileType::Jpeg);
    vm.filter.enabled_partial_types.insert(FileType::Pdf);
    vm.filter.bookmarked_only = true;
    vm.filter.source_filter = Some(0);
    vm.filter.sort_key = SortKey::Size;
    vm.filter.sort_dir = SortDir::Desc;
    vm.filter.bookmarked_first = true;
    vm.filter.hide_no_preview = true;
    vm.filter.size_range = Some((10, 100));
    vm.filters_visible = false;
    vm.selected_group = Some(Group::Image);
    vm.selection = Some(7);

    let snap = UiStateSnapshot::from_view_model(&vm);

    // Round-trip through into_runtime with a permissive case.
    let mut run = RunSummary::default();
    run.configured_types = vec![FileType::Jpeg, FileType::Pdf];
    let sources = vec![SourceRow {
        source_id: 0,
        filename: "a.img".into(),
        output_subdir: "a".into(),
        total_bytes: 0,
        bytes_read: 0,
        files_found: 0,
        status: SourceStatus::Finished,
        duration_ms: None,
    }];
    let (f, vis, g, sel) = snap.into_runtime(&run, &sources);

    assert_eq!(f.enabled_types, vm.filter.enabled_types);
    assert_eq!(f.enabled_partial_types, vm.filter.enabled_partial_types);
    assert_eq!(f.bookmarked_only, true);
    assert_eq!(f.source_filter, Some(0));
    assert_eq!(f.sort_key, SortKey::Size);
    assert_eq!(f.sort_dir, SortDir::Desc);
    assert_eq!(f.bookmarked_first, true);
    assert_eq!(f.hide_no_preview, true);
    assert_eq!(f.size_range, Some((10, 100)));
    assert_eq!(vis, false);
    assert_eq!(g, Some(Group::Image));
    assert_eq!(sel, Some(7));
}
```

- [ ] **Step 7: Run the tests**

```bash
cargo test -p utmost-gui --lib view_model::tests -- --nocapture 2>&1 | tail -30
```

Expected: all new tests pass alongside the existing ones.

- [ ] **Step 8: fmt + clippy**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -20
```

- [ ] **Step 9: Commit**

```bash
git add crates/utmost-gui/src/view_model.rs
git commit -m "$(cat <<'EOF'
feat(gui): UiStateSnapshot + into_runtime conversion

Pure data + validation layer for per-case UI-state persistence:
- UiStateSnapshot (versioned v=1) and FilterStateSnapshot with
  serde derives ready for JSON.
- file_type_to_pub_str pairs with parse_file_type_pub for the
  string-based on-disk encoding.
- into_runtime is the only place that validates against a live
  RunSummary/sources: drops unknown types, intersects with
  configured_types, clears missing source filters, clamps invalid
  size ranges, falls back on unknown sort strings, returns
  defaults on schema-version drift.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: `write_ui_state` / `read_ui_state` helpers

**Files:**
- Modify: `crates/utmost-gui/src/index_db/writer.rs`

Adds the on-disk I/O. Mirrors the existing `upsert_meta` / `read_meta_str` patterns.

- [ ] **Step 1: Add the writer and reader functions**

Open `crates/utmost-gui/src/index_db/writer.rs`. After the existing `fn upsert_meta` (search for `fn upsert_meta`), add:

```rust
/// Persist the [`UiStateSnapshot`] under `meta.ui_state` as a JSON blob.
/// Atomic upsert via the existing [`upsert_meta`] helper. Errors propagate
/// to the caller; the query-loop thread that owns this connection treats
/// them as `tracing::warn!` (a UI-state save failure must not break the
/// session).
pub fn write_ui_state(
    conn: &mut diesel::sqlite::SqliteConnection,
    snapshot: &crate::view_model::UiStateSnapshot,
) -> anyhow::Result<()> {
    let json = serde_json::to_string(snapshot).context("serialising UiStateSnapshot")?;
    conn.transaction::<_, anyhow::Error, _>(|tx| {
        upsert_meta(tx, "ui_state", &json)
            .map_err(|e| anyhow::anyhow!("upsert meta.ui_state: {e}"))?;
        Ok(())
    })
}

/// Read the persisted [`UiStateSnapshot`] from `meta.ui_state` if present.
/// Returns `Ok(None)` when the key is absent OR when the stored JSON
/// fails to deserialise (corrupt blob, future schema). The next debounced
/// save overwrites the bad blob automatically.
pub fn read_ui_state(
    conn: &mut diesel::sqlite::SqliteConnection,
) -> anyhow::Result<Option<crate::view_model::UiStateSnapshot>> {
    let raw = match read_meta_str(conn, "ui_state")? {
        Some(s) => s,
        None => return Ok(None),
    };
    match serde_json::from_str::<crate::view_model::UiStateSnapshot>(&raw) {
        Ok(snap) => Ok(Some(snap)),
        Err(e) => {
            tracing::warn!(
                "read_ui_state: failed to deserialise ui_state blob ({e}); returning None"
            );
            Ok(None)
        }
    }
}
```

> **Implementing-agent note:** `Context` is already imported at the top of writer.rs (it's used by other functions). If not, add `use anyhow::Context;`. The existing private helper `read_meta_str` lives in this same file — verify the function name + signature by searching for `fn read_meta_str` before relying on it.

- [ ] **Step 2: Add tests for write/read roundtrip and corrupt-blob fallback**

In the `#[cfg(test)] mod tests` block at the bottom of `writer.rs`, add:

```rust
#[test]
fn write_read_ui_state_round_trips() {
    use crate::index_db::IndexDb;
    use crate::view_model::{FilterStateSnapshot, UiStateSnapshot};

    let mut db = IndexDb::open_in_memory().expect("open in-memory db");
    let snap = UiStateSnapshot {
        v: 1,
        filter: FilterStateSnapshot {
            enabled_types: vec!["jpeg".into(), "pdf".into()],
            enabled_partial_types: vec![],
            bookmarked_only: true,
            source_filter: Some(2),
            sort_key: "Size".into(),
            sort_dir: "Desc".into(),
            bookmarked_first: false,
            hide_no_preview: true,
            size_range: Some((10, 1000)),
        },
        filters_visible: false,
        selected_group: Some("image".into()),
        selection_file_id: Some(42),
    };

    db.with_conn::<_, anyhow::Error, _>(|c| write_ui_state(c, &snap))
        .expect("write_ui_state");

    let got = db
        .with_conn::<_, anyhow::Error, _>(read_ui_state)
        .expect("read_ui_state")
        .expect("ui_state row present");
    assert_eq!(got, snap);
}

#[test]
fn read_ui_state_returns_none_when_missing() {
    use crate::index_db::IndexDb;
    let mut db = IndexDb::open_in_memory().expect("open in-memory db");
    let got = db
        .with_conn::<_, anyhow::Error, _>(read_ui_state)
        .expect("read_ui_state");
    assert!(got.is_none());
}

#[test]
fn read_ui_state_returns_none_for_corrupt_blob() {
    use crate::index_db::IndexDb;
    use diesel::prelude::*;

    let mut db = IndexDb::open_in_memory().expect("open in-memory db");
    diesel::sql_query("INSERT INTO meta(key, value) VALUES ('ui_state', '{not json')")
        .execute(db.conn())
        .unwrap();
    let got = db
        .with_conn::<_, anyhow::Error, _>(read_ui_state)
        .expect("read_ui_state must not error on corrupt blob");
    assert!(got.is_none());
}
```

- [ ] **Step 3: Run the tests**

```bash
cargo test -p utmost-gui --lib index_db::writer::tests -- --nocapture 2>&1 | tail -20
```

Expected: all three new tests pass.

- [ ] **Step 4: fmt + clippy**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -20
```

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-gui/src/index_db/writer.rs
git commit -m "$(cat <<'EOF'
feat(gui): write_ui_state / read_ui_state on meta.ui_state

JSON blob in the existing meta table; atomic upsert via the
existing upsert_meta helper. Corrupt blobs return Ok(None) and
let the next save overwrite them.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: `CaseHandle.ui_state_on_open` + `open_case` reads sqlite

**Files:**
- Modify: `crates/utmost-gui/src/case.rs`

`open_case` already has an open `IndexDb` connection for the duration of the journal-recovery step. Reuse it to read `ui_state` before the function returns.

- [ ] **Step 1: Add the field to `CaseHandle`**

Open `crates/utmost-gui/src/case.rs`. Find the `pub struct CaseHandle` definition (search `pub struct CaseHandle`). Add the new field at the end of the struct:

```rust
pub struct CaseHandle {
    // … existing fields, unchanged …
    /// Snapshot of the case's UI state as it was when the case was last
    /// closed (or `None` for first-ever open / corrupt blob / missing key).
    /// Taken by `run_picker` and handed to `UiState::new` for hydration.
    pub ui_state_on_open: Option<crate::view_model::UiStateSnapshot>,
}
```

- [ ] **Step 2: Read `ui_state` inside `open_case` and populate the field**

Find the body of `open_case`. After `IndexDb::open` succeeds (the line that produces the open connection used for journal recovery) and BEFORE the indexer-writer thread is spawned, add:

```rust
// Read the persisted UI state, if any. Reuses the IndexDb connection
// that journal recovery already needed; no extra open. Done synchronously
// here because the picker hands ui_state_on_open into UiState::new before
// it posts the first Requery — there's no race between hydration and the
// first match-ids response.
let ui_state_on_open: Option<crate::view_model::UiStateSnapshot> = {
    // The relevant `IndexDb` instance in open_case is local. Adapt the
    // following to the actual variable name used by the surrounding code.
    let mut tmp_db = crate::index_db::IndexDb::open(&sqlite_path)
        .context("opening IndexDb to read ui_state during open_case")?;
    crate::index_db::writer::read_ui_state(tmp_db.conn())
        .unwrap_or_else(|e| {
            tracing::warn!("read_ui_state in open_case failed: {e:#}");
            None
        })
};
```

> **Implementing-agent note:** `open_case` may have already opened an `IndexDb` for journal recovery. If so, reuse that connection rather than opening a second one — the `OPEN_GUARD` serialisation makes the second open safe but pointless. If the existing `IndexDb` is already dropped by the time we want to read ui_state, the snippet above (its own short-lived `IndexDb::open`) is fine. Choose whichever fits the existing code path; the goal is "read ui_state once during open_case, before returning."

Add `ui_state_on_open` to the `CaseHandle { … }` constructor expression at the end of `open_case`:

```rust
Ok(CaseHandle {
    // … existing fields …
    ui_state_on_open,
})
```

- [ ] **Step 3: Add a unit test**

In the `#[cfg(test)] mod tests` block at the bottom of `case.rs`, add (mirroring the existing minimal-events.bin fixture):

```rust
#[test]
fn open_case_returns_persisted_ui_state_when_present() {
    use crate::view_model::{FilterStateSnapshot, UiStateSnapshot};
    let tmp = tempfile::TempDir::new().unwrap();
    let log = tmp.path().join("t-events.bin");
    write_minimal_events_bin(&log);

    // First open: nothing persisted yet → ui_state_on_open is None.
    let h1 = open_case(CaseSource::Historical(log.clone()), &[]).expect("first open");
    assert!(h1.ui_state_on_open.is_none(), "first open has no prior state");
    let sqlite_path = h1.sqlite_path.clone();
    close_case(h1).expect("first close");

    // Seed a snapshot directly into sqlite to simulate "the user did things
    // last time, debounced save fired, close_case landed the final flush."
    {
        let mut db = crate::index_db::IndexDb::open(&sqlite_path).expect("reopen sqlite");
        let snap = UiStateSnapshot {
            v: 1,
            filter: FilterStateSnapshot {
                enabled_types: vec!["jpeg".into()],
                enabled_partial_types: vec![],
                bookmarked_only: true,
                source_filter: None,
                sort_key: "Filename".into(),
                sort_dir: "Asc".into(),
                bookmarked_first: false,
                hide_no_preview: false,
                size_range: None,
            },
            filters_visible: false,
            selected_group: Some("image".into()),
            selection_file_id: Some(7),
        };
        crate::index_db::writer::write_ui_state(db.conn(), &snap).unwrap();
    }

    // Second open: ui_state_on_open populated with what we wrote.
    let h2 = open_case(CaseSource::Historical(log.clone()), &[]).expect("second open");
    let got = h2.ui_state_on_open.as_ref().expect("persisted snapshot present");
    assert_eq!(got.selection_file_id, Some(7));
    assert!(got.filter.bookmarked_only);
    assert_eq!(got.selected_group.as_deref(), Some("image"));
    close_case(h2).expect("second close");
}
```

> **Implementing-agent note:** `write_minimal_events_bin` is the helper already present in `case.rs`'s test module (added in Plan 1 Task 10). Reuse it as-is; do not reimplement.

- [ ] **Step 4: Run the tests**

```bash
cargo test -p utmost-gui --lib case::tests -- --nocapture 2>&1 | tail -20
```

Expected: the existing tests still pass plus the new one.

- [ ] **Step 5: fmt + clippy**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -20
```

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-gui/src/case.rs
git commit -m "$(cat <<'EOF'
feat(gui): open_case reads ui_state from sqlite

Adds CaseHandle.ui_state_on_open: Option<UiStateSnapshot>. Read
synchronously during open_case (the DB is already open there);
the picker hands the snapshot to UiState::new for application
before the first Requery. None on first-ever open, corrupt blob,
or missing key.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: `IndexerCommand::PersistUiState` variant + query-loop handler

**Files:**
- Modify: `crates/utmost-gui/src/indexer_thread.rs`

- [ ] **Step 1: Add the variant**

Open `crates/utmost-gui/src/indexer_thread.rs`. Find `pub enum IndexerCommand` (around line 398). Add a new variant before `Shutdown`:

```rust
pub enum IndexerCommand {
    // … existing variants …
    /// Write the supplied [`UiStateSnapshot`] to `meta.ui_state` on this
    /// case's sqlite. Fire-and-forget — the UI thread does not wait for
    /// acknowledgement. Errors are logged on the query-loop thread.
    PersistUiState(crate::view_model::UiStateSnapshot),
    Shutdown,
}
```

- [ ] **Step 2: Add the handler arm in `run_query_loop`**

In the same file, find the existing match arm that handles `IndexerCommand::Shutdown => break;` (around line 676). Add the `PersistUiState` arm immediately above it:

```rust
IndexerCommand::PersistUiState(snap) => {
    if let Err(e) = crate::index_db::writer::write_ui_state(&mut conn, &snap) {
        tracing::warn!("write_ui_state on PersistUiState failed: {e:#}");
    }
}
IndexerCommand::Shutdown => break,
```

> **Implementing-agent note:** The local variable that holds the open `SqliteConnection` inside `run_query_loop` may be called `conn`, `db.conn()`, or accessed via some accessor — check the surrounding match-arm bodies (`Requery`, `FetchWindow`) and use the same idiom they already use.

- [ ] **Step 3: Add a test that PersistUiState writes through the query loop**

In the `#[cfg(test)] mod tests` block of `indexer_thread.rs`, add:

```rust
#[test]
fn query_loop_handles_persist_ui_state() {
    use crate::index_db::IndexDb;
    use crate::view_model::{FilterStateSnapshot, UiStateSnapshot};
    let tmp = tempfile::TempDir::new().unwrap();
    let bin = tmp.path().join("t-events.bin");
    // Minimal log: just enough for run_query_loop to open IndexDb.
    {
        use utmost_lib::events::{BincodeFileSink, EventSink};
        let sink = BincodeFileSink::create(&bin).unwrap();
        // Mirror the existing tests' RunStarted construction:
        sink.emit(&make_run_started_for_tests());
    }
    let (cmd_tx, cmd_rx) = crossbeam_channel::unbounded::<IndexerCommand>();
    let (event_tx, _event_rx) = crossbeam_channel::unbounded::<IndexerEvent>();
    let bin_clone = bin.clone();
    let join = std::thread::spawn(move || {
        let _ = run_query_loop(bin_clone, cmd_rx, event_tx);
    });

    let snap = UiStateSnapshot {
        v: 1,
        filter: FilterStateSnapshot {
            enabled_types: vec!["jpeg".into()],
            enabled_partial_types: vec![],
            bookmarked_only: true,
            source_filter: None,
            sort_key: "Filename".into(),
            sort_dir: "Asc".into(),
            bookmarked_first: false,
            hide_no_preview: false,
            size_range: None,
        },
        filters_visible: false,
        selected_group: None,
        selection_file_id: Some(99),
    };
    cmd_tx
        .send(IndexerCommand::PersistUiState(snap.clone()))
        .expect("send PersistUiState");
    cmd_tx.send(IndexerCommand::Shutdown).expect("send shutdown");
    join.join().expect("query loop thread join");

    // Re-open and read back.
    let sqlite_path = crate::picker::sqlite_path_for(&bin);
    let mut db = IndexDb::open(&sqlite_path).expect("reopen");
    let got = crate::index_db::writer::read_ui_state(db.conn())
        .expect("read")
        .expect("snapshot present");
    assert_eq!(got, snap);
}
```

> **Implementing-agent note:** `make_run_started_for_tests` is a stand-in for the existing test helper that builds a minimal `CarveEvent::RunStarted`. Re-use whatever the surrounding tests use (e.g., the `make_run_started` helper from `picker.rs::tests`, lifted into a shared `mod common` if it's not already accessible). The fixture itself is auxiliary — the assertion is what matters.

- [ ] **Step 4: Run the test**

```bash
cargo test -p utmost-gui --lib indexer_thread::tests::query_loop_handles_persist_ui_state -- --nocapture 2>&1 | tail -20
```

Expected: pass.

- [ ] **Step 5: fmt + clippy**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -20
```

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-gui/src/indexer_thread.rs
git commit -m "$(cat <<'EOF'
feat(gui): IndexerCommand::PersistUiState

The query-loop thread already owns the per-case sqlite connection
so it's the natural place to handle UI-state writes. Fire-and-forget;
the UI thread queues the command from a 500ms debounce timer and
doesn't wait for acknowledgement.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: `UiState::new` accepts and applies the snapshot

**Files:**
- Modify: `crates/utmost-gui/src/slint_adapter.rs`
- Modify: `crates/utmost-gui/src/lib.rs`

- [ ] **Step 1: Add fields to `UiState`**

Open `crates/utmost-gui/src/slint_adapter.rs`. Find the `pub struct UiState` definition. Add four new fields:

```rust
pub struct UiState {
    // … existing fields …

    /// True while UiState::new is applying a hydration snapshot. Prevents
    /// mark_ui_state_dirty from re-saving the state we just restored.
    pub(crate) hydrating: std::cell::Cell<bool>,
    /// True when there's a pending change waiting for the debounced save.
    pub(crate) ui_state_dirty: std::cell::Cell<bool>,
    /// Single-shot timer restarted to ~500ms on each mutation; fires
    /// once when the user pauses input.
    pub(crate) ui_state_save_timer: slint::Timer,
    /// File id to scroll into view once the first MatchIds after
    /// hydration arrives. Consumed on use.
    pub(crate) pending_scroll_to_selection:
        std::cell::Cell<Option<crate::view_model::FileId>>,
}
```

> **Implementing-agent note:** `std::cell::Cell` requires the inner type to be `Copy`. `Option<FileId>` is `Copy` (FileId is u64). The Slint `Timer` is owned by value, not `Cell`. `pub(crate)` lets the lib.rs caller read these for the final-flush path.

- [ ] **Step 2: Extend `UiState::new` signature and apply the snapshot**

In `crates/utmost-gui/src/slint_adapter.rs`, find `pub fn new`. Add a new parameter `ui_state_on_open: Option<crate::view_model::UiStateSnapshot>` AT THE END of the parameter list:

```rust
pub fn new(
    window: MainWindow,
    vm: Arc<Mutex<ViewModel>>,
    source_search_locations: Vec<std::path::PathBuf>,
    event_log_path: Option<std::path::PathBuf>,
    indexer_rx: Option<crossbeam_channel::Receiver<crate::indexer_thread::IndexProgress>>,
    perf: Arc<crate::telemetry::PerfRecorder>,
    preview_outcomes_tx: Option<crossbeam_channel::Sender<PreviewOutcome>>,
    indexer_cmd_tx: Option<crossbeam_channel::Sender<IndexerCommand>>,
    indexer_event_rx: Option<crossbeam_channel::Receiver<IndexerEvent>>,
    ui_state_on_open: Option<crate::view_model::UiStateSnapshot>,
) -> Result<Self, slint::PlatformError> {
    // … existing body up through the construction of `self` …
}
```

Inside the body, before the existing `chips`/`tiles`/etc. initial population and BEFORE any initial Requery happens, apply the snapshot:

```rust
// Hydrate UI-relevant VM fields from the persisted snapshot. Guarded by
// `hydrating` so the chip-toggle / sort handlers' mark_ui_state_dirty
// calls (if any indirectly fire during apply) are no-ops.
let pending_scroll: std::cell::Cell<Option<crate::view_model::FileId>> =
    std::cell::Cell::new(None);
if let Some(snap) = ui_state_on_open {
    let (filter, filters_visible, selected_group, selection) = {
        let v = vm.lock().unwrap();
        snap.into_runtime(&v.run, &v.sources)
    };
    let mut v = vm.lock().unwrap();
    v.filter = filter;
    v.filters_visible = filters_visible;
    v.selected_group = selected_group;
    v.selection = selection;
    pending_scroll.set(selection);
}
```

In the same `new` function, when constructing the `UiState { … }` value at the end, add the four new fields:

```rust
Ok(UiState {
    // … existing fields …
    hydrating: std::cell::Cell::new(false),
    ui_state_dirty: std::cell::Cell::new(false),
    ui_state_save_timer: slint::Timer::default(),
    pending_scroll_to_selection: pending_scroll,
})
```

> **Implementing-agent note:** If `UiState::new` already mutates `vm` in other places before the apply (e.g., initial sync), make sure the apply happens BEFORE that work so the first computed UI render reflects the hydrated state. Match the pattern used by Plan 1's Task 8 for the "post-hydration Requery" — the apply must precede the Requery.

- [ ] **Step 3: Update the call site in `lib.rs`**

Open `crates/utmost-gui/src/lib.rs`. Find the call to `UiState::new` inside the `on_case_clicked` closure of `run_picker`. Pass `handle.ui_state_on_open.take()` as the new last argument:

```rust
match slint_adapter::UiState::new(
    window.clone_strong(),
    vm.clone(),
    search_locs.clone(),
    event_log_path,
    progress_rx,
    perf.clone(),
    preview_outcomes_tx,
    indexer_cmd_tx.clone(),
    indexer_event_rx,
    handle.ui_state_on_open.take(),    // ← new last argument
)
```

Also update the call site in `launch_ui_with_journal` — that path is used by `run_live` and has no per-case persistence yet, so pass `None`:

```rust
let ui = slint_adapter::UiState::new(
    window,
    vm.clone(),
    source_search_locations,
    event_log_path,
    indexer_rx,
    perf,
    preview_outcomes_tx,
    query_cmd_tx.clone(),
    query_event_rx,
    None,        // ← run_live has no ui_state hydration in plan 1
)?;
```

- [ ] **Step 4: Add a sanity test**

In the `#[cfg(test)] mod tests` block of `slint_adapter.rs` (or wherever the existing UiState unit tests live), add:

```rust
#[test]
fn hydration_does_not_mark_dirty() {
    // Construct a minimal UiState with a snapshot. After construction,
    // ui_state_dirty must be false: the apply happens inside `new` and
    // mark_ui_state_dirty (added in the next task) must not fire during it.
    //
    // NOTE: This test can be expanded once mark_ui_state_dirty is in place
    // (Task 6). For Task 5 it just asserts that the dirty flag is initialised
    // to false and that the snapshot was applied to the VM.
    use crate::view_model::{FilterStateSnapshot, UiStateSnapshot};
    let vm = Arc::new(Mutex::new(crate::view_model::ViewModel::new()));
    // Configure the VM so the snapshot's enabled_types stay accepted.
    {
        let mut v = vm.lock().unwrap();
        v.run.configured_types = vec![utmost_lib::types::FileType::Jpeg];
    }
    let snap = UiStateSnapshot {
        v: 1,
        filter: FilterStateSnapshot {
            enabled_types: vec!["jpeg".into()],
            enabled_partial_types: vec![],
            bookmarked_only: true,
            source_filter: None,
            sort_key: "Filename".into(),
            sort_dir: "Asc".into(),
            bookmarked_first: false,
            hide_no_preview: false,
            size_range: None,
        },
        filters_visible: false,
        selected_group: None,
        selection_file_id: Some(3),
    };

    // UiState::new needs a window; if there's an existing helper that
    // constructs a UiState for tests, reuse it. Otherwise call
    // MainWindow::new()? inside a slint::PlatformError-tolerant block.
    let window = MainWindow::new().expect("window");
    let perf = Arc::new(crate::telemetry::PerfRecorder::new_disabled());
    let ui = UiState::new(
        window, vm.clone(),
        vec![], None, None, perf, None, None, None,
        Some(snap),
    ).expect("ui state");

    // Assertions: ui_state_dirty must be false; pending_scroll_to_selection
    // must hold the file id from the snapshot; VM filter must have JPEG enabled.
    assert!(!ui.ui_state_dirty.get());
    assert_eq!(ui.pending_scroll_to_selection.get(), Some(3));
    let v = vm.lock().unwrap();
    assert!(v.filter.bookmarked_only);
    assert!(!v.filters_visible);
}
```

> **Implementing-agent note:** This test constructs a real `MainWindow`. Slint requires a backend; if the test runner doesn't have one (e.g. headless CI), gate the test with `#[cfg(target_os = "macos")]` or whichever scope the existing slint_adapter tests use — match the pattern. If the existing slint_adapter tests work around this by avoiding `MainWindow::new`, follow that pattern instead. `PerfRecorder::new_disabled` is a placeholder for whatever no-op constructor PerfRecorder offers — check `telemetry.rs` and substitute the real one.

- [ ] **Step 5: Run tests**

```bash
cargo test -p utmost-gui --lib 2>&1 | tail -20
```

Expected: existing tests + new tests pass.

- [ ] **Step 6: fmt + clippy**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -20
```

- [ ] **Step 7: Commit**

```bash
git add crates/utmost-gui/src/slint_adapter.rs crates/utmost-gui/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(gui): UiState::new applies ui_state_on_open before first Requery

Hydration is synchronous: the snapshot was already read in open_case.
UiState::new now takes ui_state_on_open: Option<UiStateSnapshot> as
its last param, calls into_runtime against the live VM's run + sources,
and assigns the result into vm.filter, vm.filters_visible,
vm.selected_group, vm.selection. selection_file_id is also stashed
on the new pending_scroll_to_selection field for the post-Requery
scroll-into-view step. New fields hydrating / ui_state_dirty /
ui_state_save_timer are wired in by the next task.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: `mark_ui_state_dirty` + debounced timer wired into mutation handlers

**Files:**
- Modify: `crates/utmost-gui/src/slint_adapter.rs`

- [ ] **Step 1: Add the `mark_ui_state_dirty` method on `UiState`**

In `crates/utmost-gui/src/slint_adapter.rs`, find the `impl UiState { … }` block where the existing pub methods live (e.g., `pub fn set_journal`, `pub fn sync`). Add:

```rust
impl UiState {
    /// Mark the UI state dirty and (re)start the 500ms debounce timer.
    /// When the timer fires, the closure built in `start_ui_state_timer`
    /// builds a snapshot and sends `IndexerCommand::PersistUiState` on the
    /// per-case command channel. No-op when `hydrating` is set.
    pub(crate) fn mark_ui_state_dirty(&self) {
        if self.hydrating.get() {
            return;
        }
        self.ui_state_dirty.set(true);
        // Slint's `Timer::start` replaces a previously-running single-shot
        // timer in place; this is the natural "restart" semantics.
        let vm = self.vm.clone();
        let cmd_tx = self.indexer_cmd_tx.clone();
        let dirty = self.ui_state_dirty.clone();  // Cell<bool> is Copy-ish; clone the handle
        self.ui_state_save_timer.start(
            slint::TimerMode::SingleShot,
            std::time::Duration::from_millis(500),
            move || {
                let Some(tx) = &cmd_tx else { return; };
                let snap = {
                    let v = vm.lock().unwrap();
                    crate::view_model::UiStateSnapshot::from_view_model(&v)
                };
                let _ = tx.send(crate::indexer_thread::IndexerCommand::PersistUiState(snap));
                dirty.set(false);
            },
        );
    }
}
```

> **Implementing-agent note:** `Cell<bool>` is not `Clone` — you can't move a `Cell` into a closure and also keep using it from elsewhere. Two options that compile: (a) make `ui_state_dirty: Rc<Cell<bool>>` and clone the `Rc`; (b) capture `self.ui_state_dirty` by reference, which forces the closure to be `Fn` — but the timer closure has 'static bounds. The cleanest fix is to wrap `ui_state_dirty: Rc<Cell<bool>>` (and same for `pending_scroll_to_selection` if needed). Update Task 5's field declarations accordingly. Same goes for capturing `self.vm` and `self.indexer_cmd_tx` — they're already `Arc`/`Option<Sender>` and clone cheaply.

- [ ] **Step 2: Add `flush_pending_ui_state` for the final-flush path**

In the same `impl UiState` block:

```rust
impl UiState {
    /// If dirty, build a snapshot from the current VM and send it on the
    /// indexer command channel. Used by `run_picker`'s back / close paths
    /// to land the most-recent unsynced changes before the query-loop
    /// thread is shut down. FIFO command processing guarantees the
    /// persist runs before Shutdown drains the loop.
    pub fn flush_pending_ui_state(&self) {
        if !self.ui_state_dirty.get() {
            return;
        }
        let Some(tx) = &self.indexer_cmd_tx else { return; };
        let snap = {
            let v = self.vm.lock().unwrap();
            crate::view_model::UiStateSnapshot::from_view_model(&v)
        };
        let _ = tx.send(crate::indexer_thread::IndexerCommand::PersistUiState(snap));
        self.ui_state_dirty.set(false);
    }
}
```

- [ ] **Step 3: Wire `mark_ui_state_dirty()` into every mutation handler**

In `crates/utmost-gui/src/slint_adapter.rs`, find each of these handlers (search for the strings in column 1) and add a `mark_ui_state_dirty(&self)` call AFTER the existing mutation. Use the existing pattern by which the handler obtains `&UiState` (typically via a captured `weak.upgrade()` — match what the existing handlers do; if a handler currently captures only `vm_cb` and `tx_cb`, also capture a clone of the `Rc<UiState>` or equivalent and call `ui.mark_ui_state_dirty()` after the requery).

| Handler | File:line (approx) | Change |
|---|---|---|
| `on_chip_toggled` | slint_adapter.rs:257 | After `requery(...)` |
| `on_group_tab_clicked` | slint_adapter.rs:280 | After the mutation |
| `on_filters_toggle` | slint_adapter.rs:287 | After `vm.filters_visible = …` |
| `on_bookmarked_filter_toggle` | slint_adapter.rs:295 | After `requery(...)` |
| `on_hide_no_preview_toggle` | slint_adapter.rs:304 | After `requery(...)` |
| `on_sort_key_changed` | slint_adapter.rs:313 | After `requery(...)` |
| `on_sort_dir_toggle` | slint_adapter.rs:328 | After `requery(...)` |
| `on_bookmarked_first_toggle` | slint_adapter.rs:340 | After `requery(...)` |
| `on_size_range_changed` | slint_adapter.rs:349 | After the mutation |
| `on_tile_clicked` | slint_adapter.rs:249 | After `vm.selection = …` |
| `on_gallery_nav` | slint_adapter.rs:370 | After selection update |

> **Implementing-agent note:** The simplest pattern is to capture `Rc<UiState>` (the same one created in `run_picker`) inside each handler closure and call `ui.mark_ui_state_dirty()`. If the closures currently don't have access to `Rc<UiState>`, they can be refactored to take a `Weak<UiState>` like the periodic-sync timer does. Match whatever pattern is least invasive. The end goal: every user-driven mutation visible in the spec's "save cadence" section triggers a `mark_ui_state_dirty` call.

For `on_row_clicked` (source filter), if it actually mutates state, wire it too. If `on_row_clicked` is now dead-callback territory (it was for the old source-list landing — confirm by looking at it), leave it alone.

- [ ] **Step 4: Add a guard test that hydration doesn't mark dirty**

Extend the test added in Task 5 (or add a new one in the same file):

```rust
#[test]
fn hydration_under_guard_does_not_set_dirty() {
    // Reuse the setup from hydration_does_not_mark_dirty: construct a
    // UiState with a snapshot. After construction, ui_state_dirty must
    // remain false even if a mutation handler would have been called
    // during the apply (it shouldn't be — but the guard belt-and-suspenders
    // protects against future refactors).
    //
    // Specifically, this test sets `hydrating = true`, then calls
    // mark_ui_state_dirty, and asserts ui_state_dirty is still false.
    let vm = Arc::new(Mutex::new(crate::view_model::ViewModel::new()));
    let window = MainWindow::new().expect("window");
    let perf = Arc::new(crate::telemetry::PerfRecorder::new_disabled());
    let ui = UiState::new(
        window, vm, vec![], None, None, perf, None, None, None, None,
    ).expect("ui state");

    ui.hydrating.set(true);
    ui.mark_ui_state_dirty();
    assert!(!ui.ui_state_dirty.get(), "mark_ui_state_dirty must no-op while hydrating");

    ui.hydrating.set(false);
    ui.mark_ui_state_dirty();
    assert!(ui.ui_state_dirty.get(), "mark_ui_state_dirty must set dirty when not hydrating");
}
```

- [ ] **Step 5: Run tests**

```bash
cargo test -p utmost-gui --lib 2>&1 | tail -20
```

Expected: all green.

- [ ] **Step 6: fmt + clippy**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -20
```

- [ ] **Step 7: Commit**

```bash
git add crates/utmost-gui/src/slint_adapter.rs
git commit -m "$(cat <<'EOF'
feat(gui): debounced UI-state save via mark_ui_state_dirty

Wires every mutation handler (chip toggle, sort changes, panel
toggle, size range, selection moves) to call mark_ui_state_dirty
after applying. The Slint single-shot timer is restarted on each
call to coalesce bursts into one write 500ms after the user pauses.
Hydration is guarded by `hydrating` so the apply step doesn't
trigger an immediate re-save.

flush_pending_ui_state synchronously builds a snapshot and queues
PersistUiState on the per-case channel — used by the close paths
in the next task.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Final flush in `run_picker` close paths

**Files:**
- Modify: `crates/utmost-gui/src/lib.rs`

- [ ] **Step 1: Flush in `on_back_to_picker`**

In `crates/utmost-gui/src/lib.rs`, find the `on_back_to_picker` closure inside `run_picker`. The current shape is:

```rust
window.on_back_to_picker(move || {
    if let Some((ui, timer)) = current_ui.borrow_mut().take() {
        drop(timer);
        drop(ui);
    }
    if let Some(h) = current_handle.borrow_mut().take()
        && let Err(e) = case::close_case(h)
    { … }
    if let Some(window) = window_weak.upgrade() {
        window.set_show_detail(false);
    }
});
```

Modify so the flush call happens between stopping the timer and dropping the UI:

```rust
window.on_back_to_picker(move || {
    if let Some((ui, timer)) = current_ui.borrow_mut().take() {
        drop(timer);                       // stop periodic sync first
        ui.flush_pending_ui_state();       // queue final write before shutdown
        drop(ui);
    }
    if let Some(h) = current_handle.borrow_mut().take()
        && let Err(e) = case::close_case(h)
    {
        tracing::warn!("close_case on back failed: {e}");
    }
    if let Some(window) = window_weak.upgrade() {
        window.set_show_detail(false);
    }
});
```

- [ ] **Step 2: Same flush in the `on_case_clicked` reopen path**

Earlier in the same handler closure (`on_case_clicked`), the "tear down any existing open case" block currently looks like:

```rust
if let Some((ui, timer)) = current_ui.borrow_mut().take() {
    drop(timer);
    drop(ui);
}
if let Some(h) = current_handle.borrow_mut().take()
    && let Err(e) = case::close_case(h)
{ … }
```

Apply the same flush call:

```rust
if let Some((ui, timer)) = current_ui.borrow_mut().take() {
    drop(timer);
    ui.flush_pending_ui_state();
    drop(ui);
}
if let Some(h) = current_handle.borrow_mut().take()
    && let Err(e) = case::close_case(h)
{
    tracing::warn!("close_case on reopen failed: {e}");
}
```

- [ ] **Step 3: Same flush in the post-`window.run()` cleanup**

At the bottom of `run_picker`, after `window.run()?`:

```rust
// 8) Final cleanup on window close.
if let Some((ui, timer)) = current_ui.borrow_mut().take() {
    drop(timer);
    ui.flush_pending_ui_state();
    drop(ui);
}
if let Some(h) = current_handle.borrow_mut().take() {
    let _ = case::close_case(h);
}
```

- [ ] **Step 4: Build**

```bash
cargo build -p utmost-gui 2>&1 | tail -10
```

Expected: clean.

- [ ] **Step 5: fmt + clippy**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -20
```

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-gui/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(gui): final UI-state flush on back / reopen / window close

The picker's three teardown paths (on_back_to_picker, the
"tear down before reopen" branch of on_case_clicked, and the
post-window.run() cleanup) all call ui.flush_pending_ui_state()
between stopping the periodic-sync timer and dropping the UiState.
FIFO command processing in the query loop guarantees the write
lands before Shutdown drains the loop.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Selection-scroll-into-view after first MatchIds

**Files:**
- Modify: `crates/utmost-gui/src/slint_adapter.rs`

- [ ] **Step 1: Add a `scroll_to_row` helper on `UiState`**

In `crates/utmost-gui/src/slint_adapter.rs`'s `impl UiState`, add:

```rust
impl UiState {
    /// Position the windowed grid so row `idx` (0-based, within the
    /// current `match_ids` order) is centered in the viewport — or
    /// top-aligned if centering would push past the end of the list.
    ///
    /// Sets `grid_viewport_y` directly; the Slint windowed-grid bridge
    /// re-renders accordingly. A no-op if `match_ids` is empty.
    pub(crate) fn scroll_to_row(&self, vm: &ViewModel, idx: usize) {
        if vm.match_ids.is_empty() {
            return;
        }
        const ROW_HEIGHT_PX: f32 = 192.0;   // matches the tile grid row height
        let cols = self.window.get_grid_cols().max(1) as usize;
        let target_row = idx / cols;            // row index in the grid
        let total_rows = vm.match_ids.len().div_ceil(cols);
        let viewport_h_px =
            self.window.get_height() as f32 - self.window.get_grid_chrome_offset() as f32;
        // Center target_row in the viewport.
        let center_y = (target_row as f32) * ROW_HEIGHT_PX
            - (viewport_h_px / 2.0)
            + (ROW_HEIGHT_PX / 2.0);
        let max_y = ((total_rows as f32) * ROW_HEIGHT_PX - viewport_h_px).max(0.0);
        let y = center_y.clamp(0.0, max_y);
        self.window.set_grid_viewport_y(slint::LogicalPosition::new(0.0, y).y.into());
    }
}
```

> **Implementing-agent note:** This is the highest-uncertainty step. The exact mechanism for setting the grid's scroll position is whatever the existing windowed-grid code uses — look at `slint_adapter.rs` (search for `grid_viewport_y` and `set_grid_viewport_y`) and at `main.slint` / `detail.slint` to see how the bridge currently works. The actual `ROW_HEIGHT_PX` is a constant somewhere in the Slint markup; mirror it. If the windowed-grid setup makes "scroll to row N" trivial via an existing Slint property, prefer that and skip the manual pixel arithmetic. The CONTRACT this method must satisfy: after calling it, the viewport contains row `idx`, preferring centered placement.

- [ ] **Step 2: Apply the pending scroll in the `MatchIds`-handling path**

In `crates/utmost-gui/src/slint_adapter.rs`, find the code that processes `IndexerEvent::MatchIds` (search for `MatchIds` or `apply_match_ids`). After the existing `vm.apply_match_ids(...)` (or equivalent) call, add:

```rust
// Consume the pending scroll target if hydration set one. We do this
// AFTER apply_match_ids so the selection has been re-validated against
// the new id list (if the selection isn't present, vm.selection is
// already None and the scroll is skipped).
if let Some(target) = self.pending_scroll_to_selection.get() {
    self.pending_scroll_to_selection.set(None);
    if let Some(idx) = vm.match_ids.iter().position(|s| s.file_id == target) {
        self.scroll_to_row(vm, idx);
    }
}
```

> **Implementing-agent note:** `vm.match_ids` is the existing `Vec<FileStub>` populated by `apply_match_ids`. The `.iter().position(|s| s.file_id == target)` shape assumes `FileStub` has a `file_id: u64` field — verify in `index_db/queries.rs` (search `pub struct FileStub`). If the field has a different name, adjust.

- [ ] **Step 3: Add a unit test for the position-finding logic**

In the same file's `#[cfg(test)] mod tests` block:

```rust
#[test]
fn scroll_to_row_no_ops_when_match_ids_empty() {
    // The current windowed grid uses set_grid_viewport_y; if match_ids is
    // empty there's nothing to scroll to, so we shouldn't touch the property.
    // The cleanest assertion is "it doesn't panic" + "grid_viewport_y stays
    // at its initial value (0)".
    // … construct a minimal UiState with empty match_ids …
    // ui.scroll_to_row(&vm, 0);
    // assert_eq!(ui.window.get_grid_viewport_y(), 0.0);
}
```

> **Implementing-agent note:** Writing a robust Slint-property assertion without a real backend may not be straightforward. If the existing test scaffold doesn't make this easy, omit this unit test and instead rely on the integration test from Task 9 (`selection_restored_when_present_in_match_ids`) to exercise the path end-to-end. The point of Task 8 is the production code — not the unit test for it.

- [ ] **Step 4: Run tests**

```bash
cargo test -p utmost-gui 2>&1 | tail -20
```

Expected: build clean, existing tests pass.

- [ ] **Step 5: fmt + clippy**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -20
```

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-gui/src/slint_adapter.rs
git commit -m "$(cat <<'EOF'
feat(gui): scroll restored selection into view after first MatchIds

After hydration sets vm.selection from the persisted snapshot, the
first MatchIds response back from the query loop is also the first
moment we know the selected file's row index. Walks match_ids to
find the file_id and centers it in the viewport (or top-aligns if
that would scroll past the end). One-shot — consumed once and
cleared. If the selection isn't in the new match list, the scroll
is skipped.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Integration tests

**Files:**
- Create: `crates/utmost-gui/tests/ui_state_persistence.rs`

End-to-end tests that exercise the open → mutate → close → reopen cycle without driving the Slint event loop.

- [ ] **Step 1: Create the file with the round-trip test**

Create `crates/utmost-gui/tests/ui_state_persistence.rs`:

```rust
//! Integration tests for per-case UI-state persistence. Drive the
//! open_case / write_ui_state / close_case path without standing up
//! a Slint event loop (which is hard to test headlessly).

use std::sync::Arc;
use tempfile::TempDir;
use utmost_gui::case::{close_case, open_case, CaseSource};
use utmost_gui::indexer_thread::IndexerCommand;
use utmost_gui::view_model::{FilterStateSnapshot, UiStateSnapshot};
use utmost_lib::events::{BincodeFileSink, CarveEvent, CliConfigSnapshot, EventSink, SourceDescriptor};

fn write_minimal_events_bin(path: &std::path::Path, source_image_path: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let sink = BincodeFileSink::create(path).expect("create sink");
    sink.emit(&CarveEvent::RunStarted {
        utmost_version: "test".into(),
        format_version: 1,
        started_at: "2026-05-20T00:00:00Z".into(),
        command_line: vec![],
        working_directory: "/".into(),
        execution_environment: Default::default(),
        cli_config: CliConfigSnapshot::default(),
        case: None,
        configured_types: vec![utmost_lib::types::FileType::Jpeg],
        sources: vec![SourceDescriptor {
            source_id: 0,
            filename: source_image_path.into(),
            total_bytes: 0,
            output_subdir: "s".into(),
        }],
        output_root: "/out".into(),
    });
}

#[test]
fn open_then_persist_then_reopen_restores_state() {
    let tmp = TempDir::new().unwrap();
    let log = tmp.path().join("t-events.bin");
    write_minimal_events_bin(&log, "/in/t.img");

    // 1) First open — no prior state.
    let h1 = open_case(CaseSource::Historical(log.clone()), &[]).expect("open 1");
    assert!(h1.ui_state_on_open.is_none());

    // 2) Send a PersistUiState command directly on the command channel,
    //    simulating what the debounced timer in UiState would do.
    let snap = UiStateSnapshot {
        v: 1,
        filter: FilterStateSnapshot {
            enabled_types: vec!["jpeg".into()],
            enabled_partial_types: vec![],
            bookmarked_only: true,
            source_filter: None,
            sort_key: "Size".into(),
            sort_dir: "Desc".into(),
            bookmarked_first: false,
            hide_no_preview: true,
            size_range: Some((100, 10_000)),
        },
        filters_visible: false,
        selected_group: Some("image".into()),
        selection_file_id: Some(42),
    };
    h1.indexer_cmd_tx
        .send(IndexerCommand::PersistUiState(snap.clone()))
        .expect("send PersistUiState");

    // 3) close_case drains commands FIFO before shutting down the query
    //    loop, so the persist lands before close returns.
    close_case(h1).expect("close 1");

    // 4) Second open — restored.
    let h2 = open_case(CaseSource::Historical(log.clone()), &[]).expect("open 2");
    let got = h2.ui_state_on_open.as_ref().expect("snapshot present on second open");
    assert_eq!(got, &snap);
    close_case(h2).expect("close 2");
}

#[test]
fn snapshot_lost_changes_bounded_by_last_persisted() {
    // If two PersistUiState commands are queued, the LAST one wins (the
    // upsert overwrites). This proves that successive debounced saves
    // converge to the most recent state.
    let tmp = TempDir::new().unwrap();
    let log = tmp.path().join("t-events.bin");
    write_minimal_events_bin(&log, "/in/t.img");

    let h1 = open_case(CaseSource::Historical(log.clone()), &[]).expect("open");
    let make = |sort_key: &str| UiStateSnapshot {
        v: 1,
        filter: FilterStateSnapshot {
            enabled_types: vec![],
            enabled_partial_types: vec![],
            bookmarked_only: false,
            source_filter: None,
            sort_key: sort_key.into(),
            sort_dir: "Asc".into(),
            bookmarked_first: false,
            hide_no_preview: false,
            size_range: None,
        },
        filters_visible: true,
        selected_group: None,
        selection_file_id: None,
    };
    h1.indexer_cmd_tx
        .send(IndexerCommand::PersistUiState(make("Filename")))
        .unwrap();
    h1.indexer_cmd_tx
        .send(IndexerCommand::PersistUiState(make("Size")))
        .unwrap();
    h1.indexer_cmd_tx
        .send(IndexerCommand::PersistUiState(make("FileType")))
        .unwrap();
    close_case(h1).expect("close");

    let h2 = open_case(CaseSource::Historical(log.clone()), &[]).expect("reopen");
    let got = h2.ui_state_on_open.as_ref().expect("snapshot");
    assert_eq!(got.filter.sort_key, "FileType", "last writer wins");
    close_case(h2).expect("close");
}

#[test]
fn missing_meta_returns_none_on_first_open() {
    let tmp = TempDir::new().unwrap();
    let log = tmp.path().join("t-events.bin");
    write_minimal_events_bin(&log, "/in/t.img");

    let h = open_case(CaseSource::Historical(log.clone()), &[]).expect("open");
    assert!(h.ui_state_on_open.is_none());
    close_case(h).expect("close");
}
```

- [ ] **Step 2: Run the tests**

```bash
cargo test -p utmost-gui --test ui_state_persistence -- --nocapture 2>&1 | tail -20
```

Expected: all three tests pass.

> **Implementing-agent note:** These tests depend on the query-loop thread draining the `PersistUiState` command FIFO before responding to `Shutdown` — which is the contract Task 4 established. If a test flakes, the underlying ordering bug is in `close_case` / `shutdown_query_loop`, not the test. Do NOT add sleeps; debug the ordering.

- [ ] **Step 3: fmt + clippy**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -20
```

- [ ] **Step 4: Commit**

```bash
git add crates/utmost-gui/tests/ui_state_persistence.rs
git commit -m "$(cat <<'EOF'
test(gui): integration tests for per-case UI-state persistence

End-to-end open → persist → close → reopen round-trip without
driving Slint. Plus a "last writer wins" test for queued saves
and a "missing meta returns None" guard for fresh cases.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: CLAUDE.md update

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Append a "Per-case UI-state" subsection under "GUI: case model"**

Open `CLAUDE.md`. Find the existing "GUI: case model" section. Add a new subsection at the end of it (right before the "Specs and plans:" subsection):

```markdown
**Per-case UI-state persistence** (`crates/utmost-gui/src/view_model.rs`, `index_db/writer.rs`):

- The user's filter chips, sort key/dir, layout toggles, selected group tab, and current selection are saved per case as a versioned JSON blob in `meta.ui_state` on that case's `<slug>-index.sqlite`.
- Hydration is synchronous in `open_case`: `read_ui_state` populates `CaseHandle.ui_state_on_open`. `UiState::new` calls `into_runtime` against the live `RunSummary`/sources, applies the result to the VM (guarded by `hydrating: bool` so the apply doesn't trigger a re-save), and stashes `selection` on `pending_scroll_to_selection` for the post-Requery scroll step.
- Save is debounced ~500ms via a single-shot Slint timer + `ui_state_dirty: Cell<bool>`. Every mutation handler calls `mark_ui_state_dirty()` after applying; the timer body builds a fresh `UiStateSnapshot` and sends `IndexerCommand::PersistUiState(snap)` on the per-case command channel. The query-loop thread does the actual `write_ui_state`.
- On case-close (back button, reopen, window close), `flush_pending_ui_state()` queues one final write before `shutdown_query_loop` drains the indexer thread. FIFO command processing guarantees the final save lands before `Shutdown` breaks the loop.
- Validation lives only in `UiStateSnapshot::into_runtime`: unknown file-type strings, off-configuration filter entries, missing source-filter source ids, invalid size ranges, and unknown sort strings are all silently dropped to safe defaults. Corrupt blobs in `meta.ui_state` return `Ok(None)` from `read_ui_state` and let the next debounced save overwrite them.
```

- [ ] **Step 2: Update the "Specs and plans:" list at the bottom of the same section**

```markdown
**Specs and plans:**

- Design (case picker): `docs/superpowers/specs/2026-05-20-case-selection-screen-design.md`
- Plan 1 (viewer-mode case picker): `docs/superpowers/plans/2026-05-20-case-selection-screen-viewer-mode.md`
- Design (per-case UI-state): `docs/superpowers/specs/2026-05-20-persist-ui-state-design.md`
- Plan (per-case UI-state): `docs/superpowers/plans/2026-05-20-persist-ui-state.md`
- Plan 2 (live-carve CLI refactor): not yet written; will follow.
```

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "$(cat <<'EOF'
docs(claude): document per-case UI-state persistence

Future sessions need to know: state lives in meta.ui_state on the
case sqlite as a versioned JSON blob; hydration is sync in open_case;
saves are 500ms-debounced via UiState's Slint timer; close paths
call flush_pending_ui_state before shutdown_query_loop. All validation
lives in into_runtime.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Self-review checklist (for the implementing agent)

After all tasks, verify:

1. **Open a case, change filters, click "← Cases", click the same case again.** Filters/sort/toggles restored.
2. **Open case A, change filters, click back, open case B.** Case B starts from defaults (or its own saved state).
3. **Open case A, navigate to a specific file (Enter or click).** Click back. Click case A. The same file is selected AND scrolled into view.
4. **Quit the app entirely.** Re-launch `utmost-viewer`. Click the same case. Filters restored.
5. **Corrupt the `ui_state` row by hand (`UPDATE meta SET value = 'garbage' WHERE key = 'ui_state'`).** Re-open the case. App shows defaults; no crash. Change one filter; new state overwrites the bad blob.
6. **All tests green:** `cargo test --workspace`.
7. **Lints clean:** `cargo clippy --all-targets --workspace -- -D warnings`.
8. **CLAUDE.md** has the new subsection.

If any of these fails, fix the failing task before declaring the plan complete.
