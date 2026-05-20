# Case-selection screen (viewer-mode) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `utmost-viewer <dir>` open to a clickable case-selection screen that lists every `<slug>-events.bin` found under `<dir>` (recursively), let the user click into a case for the existing detail view, and return to the picker via a back button — with the same case openable/closeable multiple times in one process.

**Architecture:** Replace the single-case landing in `crates/utmost-gui/ui/main.slint` with a picker (`ListView` of `CaseRowData`). In Rust, extract the per-case runtime state from `run_from_file`'s body into a `CaseHandle` plus `open_case` / `close_case` functions, and introduce a new `run_picker` top-level entry that owns the Slint window, the case list, and the open/close lifecycle. Live-carve / `utmost --gui` multi-source support is **out of scope** for this plan and will follow as Plan 2.

**Tech Stack:** Rust, Slint 1.x, Diesel + rusqlite, crossbeam-channel, anyhow, tracing. `cargo`, `just`, pre-commit hook enforces `cargo fmt` + `cargo clippy --all-targets` clean.

**Spec:** `docs/superpowers/specs/2026-05-20-case-selection-screen-design.md`

---

## File structure

This plan touches the GUI crate, the viewer binary, and the project CLAUDE.md.

**Create:**
- `crates/utmost-gui/src/discover.rs` — `discover_cases` and `walk_for_events_bin` (recursive scan helper). Keeps lib.rs from growing further.
- `crates/utmost-gui/src/case.rs` — `CaseSource`, `CaseHandle`, `open_case`, `close_case`. Per-case lifecycle.
- `crates/utmost-gui/src/picker.rs` — `CaseRowDescriptor` (plain-Rust descriptor used by tests), `build_case_rows`, `read_picker_metadata`, `head_read_events_bin`. Picker-only logic, sqlite-and-events-bin reads.
- `crates/utmost-gui/tests/picker.rs` — integration tests that drive the picker against fixture event-log dirs.

**Modify:**
- `crates/utmost-gui/src/lib.rs` — remove `resolve_sources`/`find_events_bin_in`; add module declarations; add `run_picker` entry; reduce `run_from_file` to a thin shim that builds one `CaseSource::Historical` and calls `run_picker`. `run_live` and its CLI caller are left **untouched** in this plan (they continue to work as today; Plan 2 will rebuild them on top of `run_picker`).
- `crates/utmost-gui/ui/main.slint` — add `CaseRowData` struct, `cases`/`picker-selected-index` properties, `case-clicked`/`back-to-picker` callbacks, and a picker layout that's visible when `show-detail == false`.
- `crates/utmost-gui/src/slint_adapter.rs` — `UiState::new` becomes constructible against an empty / not-yet-opened case (delayed binding when the user hasn't clicked into a case yet); add picker-model binding and the click → open_case → bind detail UI flow.
- `crates/utmost-gui/src/index_db/queries.rs` — add `picker_metadata_row` helper.
- `crates/utmost-viewer/src/main.rs` — call `discover_cases` + `run_picker` instead of `run_from_file`.
- `CLAUDE.md` — add a "GUI: case model" section describing case/source/picker terms and the open/close lifecycle.

**Out of scope for this plan (Plan 2):**
- `crates/utmost-cli/src/main.rs` `--gui` branch (still uses `run_live` from today).
- Per-source channel split / `CaseSource::Live` end-to-end.
- Removing `run_live`.

---

## Task 1: Resolver — `discover_cases`

**Files:**
- Create: `crates/utmost-gui/src/discover.rs`
- Modify: `crates/utmost-gui/src/lib.rs:1-15` (add `mod discover;`)
- Modify: `crates/utmost-gui/src/lib.rs:408-450` (remove `resolve_sources`, `find_events_bin_in`, `resolve_sources_for_test`; replace with `pub use discover::*` re-export only of what's needed by tests)
- Test: in-module `#[cfg(test)] mod tests` inside `discover.rs`

- [ ] **Step 1: Add the module file with a failing test for a basic nested layout**

Create `crates/utmost-gui/src/discover.rs` with:

```rust
//! Case discovery for `utmost-viewer <dir>`. Recursive walk for any
//! `*-events.bin` file under the target. Hidden dirs are skipped;
//! symlinks to directories are not followed. Bounded by MAX_DEPTH.

use anyhow::Result;
use std::path::{Path, PathBuf};

const MAX_DEPTH: usize = 8;

pub fn discover_cases(target: &Path) -> Result<Vec<PathBuf>> {
    if target.is_file() {
        return Ok(vec![target.to_path_buf()]);
    }
    if !target.is_dir() {
        anyhow::bail!("target is neither a file nor a directory: {}", target.display());
    }
    let mut found = Vec::new();
    walk_for_events_bin(target, 0, &mut found);
    found.sort();
    found.dedup();
    if found.is_empty() {
        anyhow::bail!("no <stem>-events.bin found under {}", target.display());
    }
    Ok(found)
}

fn walk_for_events_bin(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > MAX_DEPTH {
        return;
    }
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("discover_cases: skipping unreadable dir {}: {e}", dir.display());
            return;
        }
    };
    for entry in read {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("discover_cases: skipping bad dirent in {}: {e}", dir.display());
                continue;
            }
        };
        let p = entry.path();
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_file() {
            if let Some(name) = p.file_name().and_then(|n| n.to_str())
                && name.ends_with("-events.bin")
            {
                out.push(p.canonicalize().unwrap_or(p));
            }
        } else if ft.is_dir() {
            let basename = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !basename.starts_with('.') {
                walk_for_events_bin(&p, depth + 1, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn touch(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"").unwrap();
    }

    #[test]
    fn finds_nested_events_bins() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        touch(&root.join("run1/run1-events.bin"));
        touch(&root.join("run2/run2-events.bin"));
        touch(&root.join("readme.txt"));
        let found = discover_cases(root).unwrap();
        assert_eq!(found.len(), 2);
        let names: Vec<_> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"run1-events.bin".to_string()));
        assert!(names.contains(&"run2-events.bin".to_string()));
    }
}
```

In `crates/utmost-gui/src/lib.rs`, near the existing `mod` declarations (around line 1-15), add:

```rust
mod discover;
pub use discover::discover_cases;
```

Add `tempfile = "3"` to `crates/utmost-gui/Cargo.toml`'s `[dev-dependencies]` if not already present (check first; do not duplicate).

- [ ] **Step 2: Run the new test; expect FAIL with linker / module not yet wired**

Run: `cargo test -p utmost-gui --lib discover::tests::finds_nested_events_bins`

Expected: PASS (the implementation above is complete). If it fails, fix imports / `mod` ordering before continuing.

- [ ] **Step 3: Add the remaining unit tests inside `discover.rs`'s test module**

Append to the `mod tests` block in `crates/utmost-gui/src/discover.rs`:

```rust
    #[test]
    fn returns_single_when_passed_file() {
        let tmp = TempDir::new().unwrap();
        let f = tmp.path().join("solo-events.bin");
        touch(&f);
        let found = discover_cases(&f).unwrap();
        assert_eq!(found, vec![f]);
    }

    #[test]
    fn errors_on_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let err = discover_cases(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("no <stem>-events.bin found"));
    }

    #[test]
    fn skips_hidden_dirs() {
        let tmp = TempDir::new().unwrap();
        touch(&tmp.path().join(".hidden/run-events.bin"));
        touch(&tmp.path().join("visible/run-events.bin"));
        let found = discover_cases(tmp.path()).unwrap();
        assert_eq!(found.len(), 1);
        assert!(found[0].to_string_lossy().contains("visible"));
    }

    #[test]
    fn respects_max_depth() {
        let tmp = TempDir::new().unwrap();
        // Create depth = MAX_DEPTH + 2 nesting; the deepest one must NOT be found.
        let mut p = tmp.path().to_path_buf();
        for i in 0..(MAX_DEPTH + 2) {
            p = p.join(format!("d{i}"));
        }
        touch(&p.join("deep-events.bin"));
        // Also place one within depth so we get a non-empty success rather than an error.
        touch(&tmp.path().join("d0/d1/shallow-events.bin"));
        let found = discover_cases(tmp.path()).unwrap();
        let names: Vec<_> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"shallow-events.bin".to_string()));
        assert!(!names.contains(&"deep-events.bin".to_string()));
    }

    #[test]
    fn dedups_canonicalised_paths() {
        let tmp = TempDir::new().unwrap();
        let real = tmp.path().join("real/run-events.bin");
        touch(&real);
        // Symlink the dir to itself by another name; only on Unix.
        #[cfg(unix)]
        std::os::unix::fs::symlink(tmp.path().join("real"), tmp.path().join("link")).unwrap();
        let found = discover_cases(tmp.path()).unwrap();
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn continues_past_unreadable_subdir() {
        // Best-effort: skipping unreadable dirs must not abort the walk. We can't
        // easily produce a guaranteed-unreadable dir cross-platform, so this test
        // verifies the function still returns Ok when one subdir errors at
        // read_dir time. We simulate by creating a path that's "looks like a
        // dir to is_dir() but read_dir will fail" — a regular file passed as
        // the target is already handled by the file-branch; we use a fifo on
        // Unix instead. Skip on non-Unix.
        #[cfg(unix)]
        {
            use std::os::unix::net::UnixListener;
            let tmp = TempDir::new().unwrap();
            touch(&tmp.path().join("good/run-events.bin"));
            // Create a unix socket inside the target dir; read_dir on the dir
            // succeeds but file_type on the socket is neither file nor dir, so
            // it's harmlessly skipped. This exercises the "ft.is_file/is_dir
            // both false" branch.
            let sock_path = tmp.path().join("weird.sock");
            let _l = UnixListener::bind(&sock_path).unwrap();
            let found = discover_cases(tmp.path()).unwrap();
            assert_eq!(found.len(), 1);
        }
    }
```

- [ ] **Step 4: Remove the old resolver**

In `crates/utmost-gui/src/lib.rs`, delete `fn resolve_sources`, `fn find_events_bin_in`, and `pub fn resolve_sources_for_test` (lines around 408-450). Update the call site in `run_from_file` (around `let files = resolve_sources(target)?;`) to:

```rust
let files = discover_cases(target)?;
```

Search the whole crate for `resolve_sources_for_test` and replace any callers with `discover_cases` (there should be none outside lib.rs; verify with `rg resolve_sources_for_test crates/`).

- [ ] **Step 5: Build + run the full test suite for the GUI crate**

Run:
```bash
cargo build -p utmost-gui 2>&1 | tail -20
cargo test -p utmost-gui 2>&1 | tail -20
```

Expected: build clean, all existing tests still pass, new discover tests pass.

- [ ] **Step 6: `cargo fmt` and `cargo clippy --all-targets`**

Run:
```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -20
```

Expected: no diff after fmt, zero warnings.

- [ ] **Step 7: Commit**

```bash
git add crates/utmost-gui/src/discover.rs crates/utmost-gui/src/lib.rs crates/utmost-gui/Cargo.toml
git commit -m "$(cat <<'EOF'
feat(gui): recursive case discovery via discover_cases

Replaces the short-circuiting resolve_sources, which returned only one
events.bin when the target dir contained any matching file directly.
Walks subdirs (bounded depth, skips hidden + symlinks), canonicalises
and dedups results. Used only by the viewer entry point; the live-carve
path is untouched until plan 2.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Picker metadata reader — sqlite-first

**Files:**
- Modify: `crates/utmost-gui/src/index_db/queries.rs` (add `picker_metadata_row` and its model)
- Modify: `crates/utmost-gui/src/index_db/queries.rs` `#[cfg(test)]` block (add test)

- [ ] **Step 1: Add the metadata struct and reader function**

Open `crates/utmost-gui/src/index_db/queries.rs`. Find the existing query helpers (search for `pub fn query_match_ids` to locate the section style). Append at the end of the impl-free helpers section (above the `#[cfg(test)]` block):

```rust
/// Compact row used by the picker to render a case without opening the
/// full ViewModel. Reads only from the `run` and `meta` tables of an
/// already-open `IndexDb`. No fold, no migration.
#[derive(Debug, Clone)]
pub struct PickerMetadataRow {
    pub source_image_path: String,
    pub status: String,         // "Running" | "Finished" | "Interrupted"
    pub started_at: String,     // RFC3339 from the `run` table
    pub elapsed_ms: i64,
    pub total_files: i64,
    /// True when meta.last_event_offset is < the on-disk events.bin size,
    /// or when last_event_offset is absent. Caller computes this; the
    /// helper only reports last_event_offset back.
    pub last_event_offset: i64,
}

pub fn picker_metadata_row(
    conn: &mut diesel::sqlite::SqliteConnection,
) -> diesel::QueryResult<PickerMetadataRow> {
    use crate::index_db::schema::{meta, run};
    use diesel::prelude::*;

    let (source_image_path, status, started_at, elapsed_ms, total_files): (
        String, String, String, i64, i64,
    ) = run::table
        .filter(run::id.eq(1))
        .select((
            run::source_image_path,
            run::status,
            run::started_at,
            run::elapsed_ms,
            run::total_files,
        ))
        .first(conn)?;

    let last_event_offset: i64 = meta::table
        .filter(meta::key.eq("last_event_offset"))
        .select(meta::value)
        .first::<String>(conn)
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0);

    Ok(PickerMetadataRow {
        source_image_path,
        status,
        started_at,
        elapsed_ms,
        total_files,
        last_event_offset,
    })
}
```

- [ ] **Step 2: Add a failing test**

In the `#[cfg(test)] mod tests` block of `queries.rs` (search for `fn test_` patterns), add:

```rust
#[test]
fn picker_metadata_row_reads_run_and_last_event_offset() {
    use crate::index_db::IndexDb;
    let mut db = IndexDb::open_in_memory().expect("open in-memory db");

    // Seed minimal run + meta rows.
    diesel::sql_query(
        "INSERT INTO run (id, started_at, output_root, source_image_path, configured_types_json, status, elapsed_ms, total_files) \
         VALUES (1, '2026-05-20T00:00:00Z', '/out', '/sources/l2.img', '[]', 'Finished', 1234, 2036)",
    )
    .execute(&mut db.conn)
    .unwrap();
    diesel::sql_query("INSERT INTO meta(key, value) VALUES ('last_event_offset', '99999')")
        .execute(&mut db.conn)
        .unwrap();

    let row = picker_metadata_row(&mut db.conn).unwrap();
    assert_eq!(row.source_image_path, "/sources/l2.img");
    assert_eq!(row.status, "Finished");
    assert_eq!(row.elapsed_ms, 1234);
    assert_eq!(row.total_files, 2036);
    assert_eq!(row.last_event_offset, 99999);
}

#[test]
fn picker_metadata_row_missing_meta_returns_zero_offset() {
    use crate::index_db::IndexDb;
    let mut db = IndexDb::open_in_memory().expect("open in-memory db");
    diesel::sql_query(
        "INSERT INTO run (id, started_at, output_root, source_image_path, configured_types_json, status, elapsed_ms, total_files) \
         VALUES (1, '2026-05-20T00:00:00Z', '/out', '/sources/l2.img', '[]', 'Running', 0, 0)",
    )
    .execute(&mut db.conn)
    .unwrap();
    let row = picker_metadata_row(&mut db.conn).unwrap();
    assert_eq!(row.last_event_offset, 0);
}
```

Note: `IndexDb::conn` may be private. If it is, add a `pub(crate) fn conn_mut(&mut self) -> &mut SqliteConnection { &mut self.conn }` accessor in `crates/utmost-gui/src/index_db/mod.rs` (search for `pub struct IndexDb` to find the right spot), and use `db.conn_mut()` in the tests instead of `db.conn`. Match the existing pattern used by other tests in `queries.rs`.

- [ ] **Step 3: Run the tests**

Run: `cargo test -p utmost-gui --lib index_db::queries::tests::picker_metadata_row -- --nocapture`

Expected: PASS on both tests.

- [ ] **Step 4: `cargo fmt` and `cargo clippy --all-targets`**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -20
```

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-gui/src/index_db/queries.rs crates/utmost-gui/src/index_db/mod.rs
git commit -m "$(cat <<'EOF'
feat(gui): picker_metadata_row helper for case picker

Reads source_image_path, status, started_at, elapsed_ms, total_files
from the run table and last_event_offset from meta — enough to render
a case row without opening the full ViewModel.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Picker metadata fallback — `head_read_events_bin`

**Files:**
- Create: `crates/utmost-gui/src/picker.rs`
- Modify: `crates/utmost-gui/src/lib.rs` (add `mod picker;`)

- [ ] **Step 1: Create the module with the fallback reader and a failing test**

Create `crates/utmost-gui/src/picker.rs`:

```rust
//! Case-picker helpers: read enough metadata from an on-disk events.bin
//! (without opening the full IndexDb) to render a row on the picker.

use anyhow::Result;
use std::path::Path;
use utmost_lib::events::{BincodeFileReader, CarveEvent};

/// What the picker shows on a row, independent of UI framework. Returned
/// by `build_case_row`. Field meanings match the spec.
#[derive(Debug, Clone)]
pub struct CaseRowDescriptor {
    pub events_bin_path: std::path::PathBuf,
    pub source_basename: String,
    pub source_path: String,
    pub status: PickerStatus,
    pub files_found: u64,
    pub elapsed_ms: u64,
    pub started_at: String,
    pub progress: f32,
    pub clickable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickerStatus {
    Running,
    Finished,
    Interrupted,
    Indexing,
    Unindexed,
    Corrupt,
}

impl PickerStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Running => "Running",
            Self::Finished => "Finished",
            Self::Interrupted => "Interrupted",
            Self::Indexing => "Indexing\u{2026}",
            Self::Unindexed => "Unindexed",
            Self::Corrupt => "Corrupt",
        }
    }
}

/// Read the head and tail of an events.bin to derive picker metadata
/// when no `<stem>-index.sqlite` is available. Returns the RunStarted
/// info and whether the tail looks like a clean RunFinished.
#[derive(Debug, Clone)]
pub struct HeadReadResult {
    pub source_image_path: String,
    pub started_at: String,
    pub finished: bool,
}

pub fn head_read_events_bin(path: &Path) -> Result<HeadReadResult> {
    let mut reader = BincodeFileReader::open(path)
        .map_err(|e| anyhow::anyhow!("opening events.bin {}: {e}", path.display()))?;

    let first = reader
        .read_next()
        .map_err(|e| anyhow::anyhow!("reading head of {}: {e}", path.display()))?
        .ok_or_else(|| anyhow::anyhow!("empty events.bin: {}", path.display()))?;

    let (source_image_path, started_at) = match first {
        CarveEvent::RunStarted {
            ref source_image_path,
            ref started_at,
            ..
        } => (source_image_path.clone(), started_at.clone()),
        other => {
            anyhow::bail!(
                "events.bin {} did not start with RunStarted (got {:?})",
                path.display(),
                std::mem::discriminant(&other)
            );
        }
    };

    // Cheap tail check: read until we either exhaust the log or see a
    // RunFinished. Caller decides what counts as "finished" if the loop
    // returns without seeing one — we just report what we saw.
    let mut finished = false;
    while let Some(ev) = reader.read_next().ok().flatten() {
        if matches!(ev, CarveEvent::RunFinished { .. }) {
            finished = true;
            break;
        }
    }

    Ok(HeadReadResult {
        source_image_path,
        started_at,
        finished,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::TempDir;
    use utmost_lib::events::{BincodeFileSink, EventSink};

    fn write_log(path: &Path, events: &[CarveEvent]) {
        let sink = BincodeFileSink::create(path).expect("create sink");
        for ev in events {
            sink.emit(ev);
        }
        // Sink Drop flushes; Arc<dyn EventSink> not needed here.
    }

    #[test]
    fn head_read_returns_source_and_unfinished_when_no_runfinished() {
        let tmp = TempDir::new().unwrap();
        let log = tmp.path().join("a-events.bin");
        write_log(
            &log,
            &[CarveEvent::RunStarted {
                output_root: "/out".into(),
                source_image_path: "/in/a.img".into(),
                started_at: "2026-05-20T00:00:00Z".into(),
                configured_types: vec![],
                case: None,
            }],
        );
        let r = head_read_events_bin(&log).unwrap();
        assert_eq!(r.source_image_path, "/in/a.img");
        assert!(!r.finished);
    }

    #[test]
    fn head_read_detects_runfinished_in_tail() {
        let tmp = TempDir::new().unwrap();
        let log = tmp.path().join("b-events.bin");
        write_log(
            &log,
            &[
                CarveEvent::RunStarted {
                    output_root: "/out".into(),
                    source_image_path: "/in/b.img".into(),
                    started_at: "2026-05-20T00:00:00Z".into(),
                    configured_types: vec![],
                    case: None,
                },
                CarveEvent::RunFinished {
                    finished_at: "2026-05-20T00:00:01Z".into(),
                    elapsed_ms: 1000,
                    total_files: 5,
                },
            ],
        );
        let r = head_read_events_bin(&log).unwrap();
        assert!(r.finished);
    }

    #[test]
    fn head_read_errors_on_missing_run_started() {
        let tmp = TempDir::new().unwrap();
        let log = tmp.path().join("c-events.bin");
        write_log(
            &log,
            &[CarveEvent::SourceStarted { source_id: 0 }],
        );
        let err = head_read_events_bin(&log).unwrap_err().to_string();
        assert!(err.contains("did not start with RunStarted"));
    }
}
```

> **Note for the implementing agent:** The exact constructor / fields of `CarveEvent::RunStarted`, `BincodeFileReader`, and `BincodeFileSink` may differ slightly from what's shown above. Search `crates/utmost-lib/src/events.rs` for the actual definitions and match them when writing the code. The test helpers are illustrative — the *behavior* (head-read returns RunStarted info; tail-read flips `finished`) is the contract.

In `crates/utmost-gui/src/lib.rs`, add near other `mod` declarations:

```rust
pub mod picker;
```

- [ ] **Step 2: Run the tests**

Run: `cargo test -p utmost-gui --lib picker::tests -- --nocapture`

Expected: PASS on all three. If the `RunStarted` / `RunFinished` field shape differs, fix the test fixtures to match `crates/utmost-lib/src/events.rs`.

- [ ] **Step 3: `cargo fmt` and `cargo clippy --all-targets`**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -20
```

- [ ] **Step 4: Commit**

```bash
git add crates/utmost-gui/src/picker.rs crates/utmost-gui/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(gui): head_read_events_bin fallback for picker metadata

Used when a case has no <stem>-index.sqlite yet (the picker doesn't
trigger indexing). Returns source_image_path + started_at from the
RunStarted head and a `finished` flag from a tail scan.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Orchestrator — `build_case_row`

**Files:**
- Modify: `crates/utmost-gui/src/picker.rs` (add `build_case_row`)
- Modify: `crates/utmost-gui/src/picker.rs` (`#[cfg(test)] mod tests`)

- [ ] **Step 1: Add the orchestrator and helpers**

Append to `crates/utmost-gui/src/picker.rs`:

```rust
/// Build a CaseRowDescriptor for one events.bin path. Tries sqlite first
/// (cheap; one short SELECT); on miss, falls back to head_read_events_bin.
/// On any non-recoverable failure (e.g. RunStarted absent), returns a
/// Corrupt-status descriptor rather than propagating the error — the
/// picker must not abort on a single bad case.
pub fn build_case_row(events_bin: &Path) -> CaseRowDescriptor {
    let sqlite_path = sqlite_path_for(events_bin);

    // Source basename from the filename (fallback if we can't read the recorded path).
    let fallback_basename = events_bin
        .file_stem()
        .and_then(|s| s.to_str())
        .map(|s| s.trim_end_matches("-events").to_string())
        .unwrap_or_default();

    // 1) Try sqlite.
    if sqlite_path.exists() {
        if let Ok(mut db) = crate::index_db::IndexDb::open(&sqlite_path) {
            if let Ok(row) = crate::index_db::queries::picker_metadata_row(db.conn_mut()) {
                let events_size = std::fs::metadata(events_bin).map(|m| m.len()).unwrap_or(0);
                let needs_indexing = (row.last_event_offset as u64) < events_size;
                let status = match row.status.as_str() {
                    "Running" => PickerStatus::Running,
                    "Finished" if needs_indexing => PickerStatus::Indexing,
                    "Finished" => PickerStatus::Finished,
                    "Interrupted" if needs_indexing => PickerStatus::Indexing,
                    "Interrupted" => PickerStatus::Interrupted,
                    _ => PickerStatus::Interrupted,
                };
                let basename = std::path::Path::new(&row.source_image_path)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(&fallback_basename)
                    .to_string();
                let progress = if matches!(status, PickerStatus::Running) {
                    0.0
                } else {
                    1.0
                };
                return CaseRowDescriptor {
                    events_bin_path: events_bin.to_path_buf(),
                    source_basename: basename,
                    source_path: row.source_image_path,
                    status,
                    files_found: row.total_files as u64,
                    elapsed_ms: row.elapsed_ms as u64,
                    started_at: row.started_at,
                    progress,
                    clickable: true,
                };
            }
        }
    }

    // 2) Sqlite absent or unreadable; head-read the events.bin.
    match head_read_events_bin(events_bin) {
        Ok(hr) => {
            let basename = std::path::Path::new(&hr.source_image_path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(&fallback_basename)
                .to_string();
            CaseRowDescriptor {
                events_bin_path: events_bin.to_path_buf(),
                source_basename: basename,
                source_path: hr.source_image_path,
                status: if hr.finished {
                    PickerStatus::Unindexed   // no sqlite, finished log → catch-up index on click
                } else {
                    PickerStatus::Unindexed
                },
                files_found: 0,
                elapsed_ms: 0,
                started_at: hr.started_at,
                progress: 0.0,
                clickable: true,
            }
        }
        Err(e) => {
            tracing::warn!(
                "build_case_row: corrupt events.bin {}: {e}",
                events_bin.display()
            );
            CaseRowDescriptor {
                events_bin_path: events_bin.to_path_buf(),
                source_basename: fallback_basename,
                source_path: events_bin.display().to_string(),
                status: PickerStatus::Corrupt,
                files_found: 0,
                elapsed_ms: 0,
                started_at: String::new(),
                progress: 0.0,
                clickable: false,
            }
        }
    }
}

/// Derive the sibling sqlite index path: `<stem>-events.bin` → `<stem>-index.sqlite`.
/// Lives next to `events_bin`.
pub fn sqlite_path_for(events_bin: &Path) -> std::path::PathBuf {
    // Same convention as indexer_thread.rs's existing helper:
    // <stem>-events.bin → <stem>-index.sqlite.
    let mut p = events_bin.to_path_buf();
    let new_name = events_bin
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.replace("-events.bin", "-index.sqlite"))
        .unwrap_or_else(|| "index.sqlite".to_string());
    p.set_file_name(new_name);
    p
}

/// Wrap [`build_case_row`] across many events.bin paths.
pub fn build_case_rows(events_bins: &[std::path::PathBuf]) -> Vec<CaseRowDescriptor> {
    events_bins.iter().map(|p| build_case_row(p)).collect()
}
```

> **Implementing agent:** If `IndexDb::open` requires a different signature or if `conn_mut` doesn't exist yet, add it in Task 2's Step 1 (it was conditionally mentioned there). Verify `crate::index_db::IndexDb::open` takes `&Path` and returns `Result`.

- [ ] **Step 2: Add tests**

Append to the `#[cfg(test)] mod tests` block in `picker.rs`:

```rust
    #[test]
    fn build_case_row_sqlite_path_alongside_events_bin() {
        let p = std::path::Path::new("/foo/bar/run1-events.bin");
        let sqlite = sqlite_path_for(p);
        assert_eq!(sqlite, std::path::Path::new("/foo/bar/run1-index.sqlite"));
    }

    #[test]
    fn build_case_row_unindexed_when_no_sqlite_present() {
        let tmp = TempDir::new().unwrap();
        let log = tmp.path().join("solo-events.bin");
        write_log(
            &log,
            &[CarveEvent::RunStarted {
                output_root: "/out".into(),
                source_image_path: "/in/solo.img".into(),
                started_at: "2026-05-20T00:00:00Z".into(),
                configured_types: vec![],
                case: None,
            }],
        );
        let row = build_case_row(&log);
        assert_eq!(row.status, PickerStatus::Unindexed);
        assert_eq!(row.source_basename, "solo.img");
        assert!(row.clickable);
    }

    #[test]
    fn build_case_row_corrupt_for_unreadable_log() {
        let tmp = TempDir::new().unwrap();
        let log = tmp.path().join("bad-events.bin");
        std::fs::write(&log, b"not a bincode file").unwrap();
        let row = build_case_row(&log);
        assert_eq!(row.status, PickerStatus::Corrupt);
        assert!(!row.clickable);
    }
```

- [ ] **Step 3: Run tests**

`cargo test -p utmost-gui --lib picker::tests`

Expected: all pass.

- [ ] **Step 4: fmt + clippy**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -20
```

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-gui/src/picker.rs
git commit -m "$(cat <<'EOF'
feat(gui): build_case_row orchestrator for picker rows

Prefers picker_metadata_row from <stem>-index.sqlite when present;
otherwise head-reads the events.bin. Returns a Corrupt-status row
(not an error) on any unrecoverable failure so the picker never
aborts on a single bad case.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Slint UI — `CaseRowData` and picker layout

**Files:**
- Modify: `crates/utmost-gui/ui/main.slint`

- [ ] **Step 1: Add the `CaseRowData` struct and properties**

Open `crates/utmost-gui/ui/main.slint`. Near the existing `SourceRowData` struct definition (~line 8), add a new struct:

```slint
export struct CaseRowData {
    case_id: int,
    source_basename: string,
    source_path: string,
    status: string,
    files_found: int,
    elapsed: string,
    progress: float,
    clickable: bool,
}
```

Inside the `MainWindow` component (search for `export component MainWindow inherits Window`), in the `in property` block (after the existing `sources` / `chips` properties), add:

```slint
in property <[CaseRowData]> cases;
in-out property <int> picker-selected-index: -1;
callback case-clicked(int);
callback back-to-picker();
```

- [ ] **Step 2: Add the picker layout (conditional on `!show-detail`)**

Inside `MainWindow`'s top-level layout, find the existing root layout (a `VerticalBox` or similar that holds the source-row list / DetailPage). Wrap the existing content so that:

- When `show-detail == false`, render the **picker** (ListView of `CaseRowData`).
- When `show-detail == true`, render the existing DetailPage as today.

Replace the existing root content with:

```slint
if !root.show-detail : VerticalBox {
    spacing: 0px;
    Rectangle {
        height: 32px;
        background: #1f2937;
        Text {
            text: "utmost — select a case";
            color: white;
            vertical-alignment: center;
            x: 12px;
        }
    }
    ListView {
        for case[i] in root.cases : Rectangle {
            height: 56px;
            background: case.clickable ? (root.picker-selected-index == i ? #2a3441 : transparent) : #14181f;
            Rectangle {
                // Per-row layout: basename + source-path (left), status + counts (right), progress bar (Running only).
                x: 12px;
                y: 0px;
                width: parent.width - 24px;
                height: parent.height;
                HorizontalBox {
                    alignment: stretch;
                    spacing: 12px;
                    VerticalLayout {
                        alignment: center;
                        Text {
                            text: case.source-basename;
                            color: case.clickable ? white : #6b7280;
                            font-size: 14px;
                        }
                        Text {
                            text: case.source-path;
                            color: #6b7280;
                            font-size: 11px;
                        }
                    }
                    Rectangle { horizontal-stretch: 1; }
                    Text {
                        text: case.files-found + " files";
                        color: case.clickable ? #9ca3af : #4b5563;
                        font-size: 12px;
                        vertical-alignment: center;
                    }
                    Text {
                        text: case.elapsed;
                        color: #9ca3af;
                        font-size: 12px;
                        vertical-alignment: center;
                    }
                    Text {
                        text: case.status;
                        color: case.status == "Running" ? #10b981 : (case.status == "Corrupt" ? #ef4444 : #9ca3af);
                        font-size: 12px;
                        vertical-alignment: center;
                    }
                }
                if case.progress > 0 && case.progress < 1 : Rectangle {
                    y: parent.height - 2px;
                    height: 2px;
                    width: parent.width * case.progress;
                    background: #10b981;
                }
            }
            TouchArea {
                enabled: case.clickable;
                clicked => {
                    root.picker-selected-index = i;
                    root.case-clicked(case.case-id);
                }
            }
        }
    }
}
if root.show-detail : DetailPage {
    // ── unchanged: existing DetailPage instantiation goes here ──
}
```

> **Implementing agent:** The exact existing DetailPage instantiation (its props, callbacks, two-way bindings) is in `main.slint` between the `if root.show-detail` line and the close of the layout. Move that block intact into the `if root.show-detail :` branch. Do not change DetailPage's existing wiring.

- [ ] **Step 3: Build to check Slint compiles**

```bash
cargo build -p utmost-gui 2>&1 | tail -20
```

Expected: clean build. Slint will emit detailed errors with file:line if the markup is malformed; address them by referring to existing Slint patterns in `main.slint` and `detail.slint`.

- [ ] **Step 4: fmt + clippy**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -20
```

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-gui/ui/main.slint
git commit -m "$(cat <<'EOF'
feat(gui): add CaseRowData and picker layout to main.slint

Picker is rendered when show-detail == false: ListView of clickable
case rows showing basename + path + files + elapsed + status, plus
inline progress for Running cases. Hooks up case-clicked and
back-to-picker callbacks. DetailPage placement is unchanged; just
gated on show-detail == true.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: `CaseSource`, `CaseHandle` types

**Files:**
- Create: `crates/utmost-gui/src/case.rs`
- Modify: `crates/utmost-gui/src/lib.rs` (add `pub mod case;`)

- [ ] **Step 1: Define the types**

Create `crates/utmost-gui/src/case.rs`:

```rust
//! Per-case runtime state. One CaseHandle for the case currently open
//! in the picker; created by [`open_case`], destroyed by [`close_case`].

use anyhow::Result;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crossbeam_channel::{Receiver, Sender};
use utmost_lib::events::CarveEvent;

use crate::indexer_thread::{IndexerCommand, IndexerEvent};
use crate::journal::Journal;
use crate::thumb_worker::PreviewOutcome;
use crate::view_model::ViewModel;

/// Where a case's events come from. Today only `Historical` is built;
/// `Live` is here for Plan 2 (live-carve multi-source) and intentionally
/// unused in Plan 1.
pub enum CaseSource {
    Historical(PathBuf),
    #[allow(dead_code)]
    Live {
        events_bin: PathBuf,
        event_rx: Receiver<CarveEvent>,
    },
}

impl CaseSource {
    pub fn events_bin(&self) -> &PathBuf {
        match self {
            Self::Historical(p) => p,
            Self::Live { events_bin, .. } => events_bin,
        }
    }
}

/// Per-case lifetime bundle. Created by [`open_case`]; on [`close_case`]
/// all threads are joined and channels dropped in order.
pub struct CaseHandle {
    pub events_bin: PathBuf,
    pub sqlite_path: PathBuf,
    pub vm: Arc<Mutex<ViewModel>>,
    pub indexer_cmd_tx: Sender<IndexerCommand>,
    pub indexer_event_rx: Receiver<IndexerEvent>,
    pub indexer_thread: Option<JoinHandle<()>>,
    pub preview_writer_thread: Option<JoinHandle<()>>,
    pub preview_outcomes_tx: Option<Sender<PreviewOutcome>>,
    pub journal: Option<Arc<Journal>>,
    pub vm_event_tx: Option<Sender<CarveEvent>>,
    pub shutdown_signal: Arc<AtomicBool>,
}

/// Stub: real implementation lands in Task 7. Defined here so callers
/// can compile against the signature.
pub fn open_case(_source: CaseSource, _source_search_locations: &[PathBuf]) -> Result<CaseHandle> {
    anyhow::bail!("open_case is not implemented yet (see Task 7)");
}

/// Stub: real implementation lands in Task 7.
pub fn close_case(_handle: CaseHandle) -> Result<()> {
    Ok(())
}
```

In `crates/utmost-gui/src/lib.rs`, add near the other `mod` declarations:

```rust
pub mod case;
```

- [ ] **Step 2: Build to verify compilation**

```bash
cargo build -p utmost-gui 2>&1 | tail -20
```

Expected: clean build. If `Journal`, `ViewModel`, `IndexerCommand`, etc. are not at the assumed paths, adjust the `use` lines to match the actual module layout.

- [ ] **Step 3: fmt + clippy**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -20
```

- [ ] **Step 4: Commit**

```bash
git add crates/utmost-gui/src/case.rs crates/utmost-gui/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(gui): introduce CaseSource and CaseHandle scaffolding

Types only — open_case / close_case are stubs that the next task
fills in by extracting the per-case wiring out of run_from_file.
CaseSource::Live is allowed-dead for now; plan 2 will use it.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Implement `open_case` / `close_case` (extract from `run_from_file`)

**Files:**
- Modify: `crates/utmost-gui/src/case.rs` (replace stubs)
- Modify: `crates/utmost-gui/src/lib.rs` (refactor `run_from_file` to delegate)

This task is the single biggest refactor in the plan. Read `crates/utmost-gui/src/lib.rs:33-150` carefully first — `run_from_file` is the source of truth for what setup a case needs.

- [ ] **Step 1: Build the new `open_case` body by lifting from `run_from_file`**

Replace the stub `pub fn open_case` in `crates/utmost-gui/src/case.rs` with the per-case setup currently embedded in `run_from_file`. The structure is:

```rust
pub fn open_case(source: CaseSource, source_search_locations: &[PathBuf]) -> Result<CaseHandle> {
    use crate::indexer_thread;
    use crate::journal;
    use crate::picker;
    use std::sync::atomic::Ordering;

    let events_bin = source.events_bin().clone();
    let sqlite_path = picker::sqlite_path_for(&events_bin);

    let vm = Arc::new(Mutex::new(ViewModel::new()));

    // 1) Journal recovery — replay any annotations crashed before fold.
    let journal = Arc::new(journal::Journal::for_main_log(&events_bin));
    let recovered = journal.recover_on_open().unwrap_or_else(|e| {
        tracing::warn!("journal recover_on_open failed: {e}");
        Vec::new()
    });
    for ev in &recovered {
        vm.lock().unwrap().apply(ev);
    }

    // 2) Query loop (indexer thread) + preview-outcomes writer.
    let (indexer_cmd_tx, indexer_event_tx, indexer_event_rx, indexer_thread) =
        crate::spawn_query_loop(Some(&events_bin));

    let (preview_outcomes_tx, preview_writer_thread): (
        Option<crossbeam_channel::Sender<PreviewOutcome>>,
        Option<JoinHandle<()>>,
    ) = {
        let (ptx, prx) = crossbeam_channel::unbounded::<PreviewOutcome>();
        let log = events_bin.clone();
        let evt_tx = indexer_event_tx.clone();
        let handle = std::thread::spawn(move || {
            if let Err(e) = indexer_thread::run_preview_outcomes_writer(&log, prx, evt_tx) {
                tracing::warn!("preview outcomes writer failed: {e:#}");
            }
        });
        (Some(ptx), Some(handle))
    };
    drop(indexer_event_tx);

    let shutdown_signal = Arc::new(AtomicBool::new(false));

    // For Live cases, callers wire the picker→VM channel later (Plan 2).
    let vm_event_tx = match source {
        CaseSource::Historical(_) => None,
        CaseSource::Live { .. } => None, // populated by run_picker in plan 2
    };

    let _ = source_search_locations; // forwarded to UiState by the caller (Task 8)
    let _ = shutdown_signal.load(Ordering::Relaxed);

    Ok(CaseHandle {
        events_bin,
        sqlite_path,
        vm,
        indexer_cmd_tx: indexer_cmd_tx.expect("indexer cmd channel present for on-disk events.bin"),
        indexer_event_rx: indexer_event_rx.expect("indexer event channel present for on-disk events.bin"),
        indexer_thread,
        preview_writer_thread,
        preview_outcomes_tx,
        journal: Some(journal),
        vm_event_tx,
        shutdown_signal,
    })
}
```

> **Implementing agent — three wiring points to verify against the existing code:**
>
> 1. **`spawn_query_loop` shape.** It returns `QueryLoopHandles`, declared near `lib.rs:287` as "each component is `None` when no main log is available." Since `open_case` always has an on-disk events.bin, the cmd/event channels are guaranteed `Some`; `.expect("…")` is correct for fields typed as bare `Sender`/`Receiver`. The `indexer_thread` field on `CaseHandle` is typed `Option<JoinHandle<()>>`, so it accepts the `Option` directly.
>
> 2. **`query_event_tx` clone for the preview writer.** Today's `run_from_file` calls `query_event_tx.clone()` and hands the clone to `run_preview_outcomes_writer`. Look at the existing `lib.rs:64-73` to see how the `Option` is handled — replicate that exactly (probably `.clone()` of the `Option<Sender>`; the writer fn may take an `Option<Sender>` or unwrap internally). Do NOT rewrite the existing wiring; mirror it.
>
> 3. **Visibility.** If `spawn_query_loop` is a `fn` (not `pub fn`) inside `lib.rs`, change it to `pub(crate)` so `case::open_case` can call it. Same for any helpers it reaches into (e.g. `init_telemetry` if used from `case`).

- [ ] **Step 2: Implement `close_case`**

Replace the stub `close_case` with:

```rust
pub fn close_case(handle: CaseHandle) -> Result<()> {
    use std::sync::atomic::Ordering;

    // 1) Tell the indexer thread to shut down. The exact shutdown command
    // depends on the existing IndexerCommand variants; if there's no
    // explicit Shutdown variant, dropping the cmd_tx is sufficient — the
    // indexer loop exits on channel hangup.
    handle.shutdown_signal.store(true, Ordering::Relaxed);
    drop(handle.indexer_cmd_tx);
    drop(handle.indexer_event_rx);

    if let Some(t) = handle.indexer_thread {
        if let Err(e) = t.join() {
            tracing::warn!("indexer thread join panicked: {e:?}");
        }
    }

    // 2) Drop the preview-outcomes sender; the writer thread sees its
    // channel hang up and exits its loop.
    drop(handle.preview_outcomes_tx);
    if let Some(t) = handle.preview_writer_thread {
        if let Err(e) = t.join() {
            tracing::warn!("preview writer thread join panicked: {e:?}");
        }
    }

    // 3) Drop the live forwarding sender (no-op for historical).
    drop(handle.vm_event_tx);

    // 4) Journal: last Arc reference goes out of scope → file closed.
    drop(handle.journal);

    Ok(())
}
```

> **Implementing agent:** If the indexer thread does NOT exit cleanly on `cmd_tx` drop, find the existing shutdown semantics in `crates/utmost-gui/src/indexer_thread.rs` and use them. Do not introduce a `kill -9` style abort.

- [ ] **Step 3: Shim `run_from_file` to use `open_case` + (later) `run_picker`**

This step keeps `run_from_file` working end-to-end so existing entry points (the viewer binary, any tests that call it) continue to function. Replace the body of `run_from_file` in `crates/utmost-gui/src/lib.rs` with:

```rust
pub fn run_from_file(target: &Path, source_search_locations: Vec<PathBuf>) -> Result<()> {
    let cases = discover_cases(target)?;
    run_picker(
        cases.into_iter().map(case::CaseSource::Historical).collect(),
        source_search_locations,
    )
}
```

`run_picker` doesn't exist yet — that's Task 8. To keep this step from breaking the build, also add a temporary stub at the bottom of `lib.rs`:

```rust
pub fn run_picker(
    _initial: Vec<case::CaseSource>,
    _source_search_locations: Vec<PathBuf>,
) -> Result<()> {
    anyhow::bail!("run_picker is not implemented yet (see Task 8)");
}
```

The viewer binary's `run_from_file` call will fail at runtime until Task 8 lands; this is intentional. Tests that exercised the full run via `run_from_file` will be temporarily broken between Task 7 and Task 8 — that's expected.

- [ ] **Step 4: `cargo build` to verify everything compiles**

```bash
cargo build -p utmost-gui 2>&1 | tail -30
```

Expected: clean compile. If the indexer / preview writer signatures don't line up, adjust the calls to match — do not skip the work, fix the wiring.

- [ ] **Step 5: fmt + clippy**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -20
```

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-gui/src/case.rs crates/utmost-gui/src/lib.rs
git commit -m "$(cat <<'EOF'
refactor(gui): extract open_case/close_case from run_from_file

The per-case wiring — IndexDb open, journal, indexer thread,
preview-outcomes writer, ViewModel — moves into case::open_case
and case::close_case. run_from_file becomes a thin shim that
discovers cases and delegates to run_picker (stub for now;
implemented in the next task).

The viewer binary will not run end-to-end until Task 8 lands.
This is an intentional intermediate state.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: `run_picker` — Slint window orchestration

**Files:**
- Modify: `crates/utmost-gui/src/lib.rs` (`run_picker` full implementation)
- Modify: `crates/utmost-gui/src/slint_adapter.rs` (constructor / case-clicked / back-to-picker)

This task replaces the stub `run_picker` from Task 7 with the real one. It owns the Slint window, the case-list model, and the open/close lifecycle.

- [ ] **Step 1: Implement `run_picker`**

Replace the stub `run_picker` in `crates/utmost-gui/src/lib.rs` with:

```rust
pub fn run_picker(
    initial: Vec<case::CaseSource>,
    source_search_locations: Vec<PathBuf>,
) -> Result<()> {
    let _telemetry = init_telemetry();
    let perf = _telemetry.perf.clone();

    // Build the initial picker rows from disk. Live sources contribute
    // a Running-status placeholder until Plan 2 wires the live tap.
    let mut rows: Vec<picker::CaseRowDescriptor> = initial
        .iter()
        .map(|s| match s {
            case::CaseSource::Historical(p) => picker::build_case_row(p),
            case::CaseSource::Live { events_bin, .. } => picker::CaseRowDescriptor {
                events_bin_path: events_bin.clone(),
                source_basename: events_bin
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.trim_end_matches("-events").to_string())
                    .unwrap_or_default(),
                source_path: events_bin.display().to_string(),
                status: picker::PickerStatus::Running,
                files_found: 0,
                elapsed_ms: 0,
                started_at: String::new(),
                progress: 0.0,
                clickable: true,
            },
        })
        .collect();
    // Sort: clickable first, then by started_at desc (empty timestamps last).
    rows.sort_by(|a, b| b.started_at.cmp(&a.started_at));

    crate::slint_adapter::run_picker_window(rows, initial, source_search_locations, perf)
}
```

- [ ] **Step 2: Add `run_picker_window` to `slint_adapter.rs`**

In `crates/utmost-gui/src/slint_adapter.rs`, near the bottom of the file (before the closing `#[cfg(test)] mod tests` block if present), add:

```rust
pub fn run_picker_window(
    rows: Vec<crate::picker::CaseRowDescriptor>,
    initial_sources: Vec<crate::case::CaseSource>,
    source_search_locations: Vec<std::path::PathBuf>,
    perf: std::sync::Arc<crate::telemetry::PerfRecorder>,
) -> anyhow::Result<()> {
    use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};
    use std::rc::Rc;

    let window = MainWindow::new()?;
    let cases_model: Rc<VecModel<CaseRowData>> = Rc::new(VecModel::default());
    for (idx, row) in rows.iter().enumerate() {
        cases_model.push(CaseRowData {
            case_id: idx as i32,
            source_basename: SharedString::from(row.source_basename.as_str()),
            source_path: SharedString::from(row.source_path.as_str()),
            status: SharedString::from(row.status.as_str()),
            files_found: row.files_found as i32,
            elapsed: SharedString::from(format_elapsed(row.elapsed_ms)),
            progress: row.progress,
            clickable: row.clickable,
        });
    }
    window.set_cases(ModelRc::from(cases_model.clone()));
    window.set_show_detail(false);

    // ── Case open: clicked from picker ──
    let sources = std::rc::Rc::new(std::cell::RefCell::new(initial_sources));
    let current_handle: std::rc::Rc<std::cell::RefCell<Option<crate::case::CaseHandle>>> =
        std::rc::Rc::new(std::cell::RefCell::new(None));
    let current_ui: std::rc::Rc<std::cell::RefCell<Option<UiState>>> =
        std::rc::Rc::new(std::cell::RefCell::new(None));

    {
        let window_weak = window.as_weak();
        let sources = sources.clone();
        let current_handle = current_handle.clone();
        let current_ui = current_ui.clone();
        let search_locs = source_search_locations.clone();
        let perf = perf.clone();
        window.on_case_clicked(move |case_id| {
            let Some(window) = window_weak.upgrade() else { return; };
            let case_idx = case_id as usize;
            let src = {
                let mut s = sources.borrow_mut();
                if case_idx >= s.len() {
                    tracing::warn!("case-clicked with out-of-range index {}", case_idx);
                    return;
                }
                std::mem::replace(
                    &mut s[case_idx],
                    crate::case::CaseSource::Historical(s[case_idx].events_bin().clone()),
                )
            };
            match crate::case::open_case(src, &search_locs) {
                Ok(handle) => {
                    let vm = handle.vm.clone();
                    let indexer_event_rx = Some(handle.indexer_event_rx.clone());
                    let indexer_cmd_tx = Some(handle.indexer_cmd_tx.clone());
                    let preview_outcomes_tx = handle.preview_outcomes_tx.clone();
                    let event_log_path = Some(handle.events_bin.clone());
                    *current_handle.borrow_mut() = Some(handle);

                    match UiState::new(
                        vm,
                        search_locs.clone(),
                        event_log_path,
                        None,
                        perf.clone(),
                        preview_outcomes_tx,
                        indexer_cmd_tx,
                        indexer_event_rx,
                    ) {
                        Ok(ui) => {
                            ui.bind_to_window(&window);
                            *current_ui.borrow_mut() = Some(ui);
                            window.set_show_detail(true);
                        }
                        Err(e) => {
                            tracing::error!("UiState::new failed: {e}");
                            if let Some(h) = current_handle.borrow_mut().take() {
                                let _ = crate::case::close_case(h);
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("open_case failed: {e}");
                }
            }
        });
    }

    // ── Back button ──
    {
        let window_weak = window.as_weak();
        let current_handle = current_handle.clone();
        let current_ui = current_ui.clone();
        window.on_back_to_picker(move || {
            if let Some(ui) = current_ui.borrow_mut().take() {
                drop(ui);
            }
            if let Some(h) = current_handle.borrow_mut().take() {
                if let Err(e) = crate::case::close_case(h) {
                    tracing::warn!("close_case failed: {e}");
                }
            }
            if let Some(window) = window_weak.upgrade() {
                window.set_show_detail(false);
            }
        });
    }

    window.run()?;

    // Final cleanup on window close.
    if let Some(ui) = current_ui.borrow_mut().take() { drop(ui); }
    if let Some(h) = current_handle.borrow_mut().take() {
        let _ = crate::case::close_case(h);
    }

    Ok(())
}

fn format_elapsed(ms: u64) -> String {
    if ms < 1000 {
        format!("{}ms", ms)
    } else if ms < 60_000 {
        format!("{:.1}s", (ms as f64) / 1000.0)
    } else {
        let m = ms / 60_000;
        let s = (ms % 60_000) / 1000;
        format!("{}m {}s", m, s)
    }
}
```

> **Implementing agent:** `UiState::bind_to_window(&MainWindow)` may not exist as a method today; `UiState::new` currently does the binding internally. If that's the case, refactor `UiState::new` to:
> - Accept an `Option<&MainWindow>` so the picker can bind detail-mode UI to an already-existing window; OR
> - Split `UiState::new` into a "create" half and a "bind_to_window" half; OR
> - Have `UiState::new` create its OWN window today, and replace that with the picker's window during this refactor.
>
> Whichever shape is cleanest for the existing code — do it as part of this task. The point is: `run_picker` owns the window; `UiState` should be willing to share it.
>
> If you need to add a `Clone` impl for the indexer cmd/event channels, prefer cloning the `crossbeam_channel::Sender` / `Receiver` (already `Clone`).

- [ ] **Step 3: Build**

```bash
cargo build -p utmost-gui 2>&1 | tail -30
```

Expected: clean compile. Address any signature mismatches between `UiState::new` and what `run_picker_window` hands it.

- [ ] **Step 4: Manual smoke test — viewer launches into a picker**

Pick (or create) a test output dir that contains at least one `<slug>-events.bin` from a prior carve. Then:

```bash
cargo run -p utmost-viewer --release -- /path/to/test-output-dir
```

Verify:
- The window opens to the picker (no auto-enter into detail view).
- One row per case in the dir.
- Clicking a row enters the detail view.
- "Back" — currently no UI for the back button exists; that's wired in Task 9. Step 4 may end here for the smoke test.

If clicking doesn't work, debug with logs; do not move on.

- [ ] **Step 5: fmt + clippy**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -20
```

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-gui/src/lib.rs crates/utmost-gui/src/slint_adapter.rs
git commit -m "$(cat <<'EOF'
feat(gui): run_picker entry point with click-into-detail flow

run_picker owns the Slint window and the open/close lifecycle.
Click in the picker → open_case → UiState binds to the same window
with show-detail = true. Back-to-picker callback restores the picker.
End-to-end click-in works; back wiring + UI lands in the next task.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Detail-view back button

**Files:**
- Modify: `crates/utmost-gui/ui/detail.slint` (or wherever the detail-view chrome is — add a back button)

- [ ] **Step 1: Add the back button to the detail-view chrome**

Open `crates/utmost-gui/ui/detail.slint`. Near the top of the `DetailPage` component's layout, add a back button that fires the `back-clicked` callback (or a new `back-to-picker` callback if `back-clicked` is taken for something else).

Search `detail.slint` for the existing top-chrome / toolbar area. Add:

```slint
callback back-to-picker();

// inside the layout's top region:
TouchArea {
    height: 28px;
    width: 80px;
    Rectangle {
        background: #374151;
        border-radius: 4px;
        Text { text: "← Cases"; color: white; vertical-alignment: center; horizontal-alignment: center; }
    }
    clicked => { root.back-to-picker(); }
}
```

In `main.slint`, where the existing `DetailPage` is instantiated, wire:

```slint
DetailPage {
    // ... existing bindings ...
    back-to-picker => { root.back-to-picker(); }
}
```

- [ ] **Step 2: Build**

```bash
cargo build -p utmost-gui 2>&1 | tail -20
```

- [ ] **Step 3: Manual smoke test — back navigation**

```bash
cargo run -p utmost-viewer --release -- /path/to/test-output-dir
```

Verify:
- Click into a case → detail view appears.
- Click "← Cases" → returns to picker.
- Click the same case again → detail view re-appears, freshly bound.
- Click a different case → that case's detail view appears.

If detail-view state leaks between cases (e.g., the previous case's filter chips visible briefly), capture the symptom — Task 10 covers state reset between opens.

- [ ] **Step 4: fmt + clippy**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -20
```

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-gui/ui/detail.slint crates/utmost-gui/ui/main.slint
git commit -m "$(cat <<'EOF'
feat(gui): back-to-picker button in detail view

Adds a "← Cases" button to the detail-view chrome that fires the
back-to-picker callback. main.slint forwards it to MainWindow's
existing back-to-picker callback wired in Task 8.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: Per-case state reset on `open_case`

**Files:**
- Modify: `crates/utmost-gui/src/case.rs` (ensure `open_case` always starts from a fresh `ViewModel`)
- Modify: `crates/utmost-gui/src/slint_adapter.rs` (drop the prior UiState fully before binding a new one)

The intent: re-opening a case (or opening a different case) must NOT inherit any state from the previous open in the same process.

- [ ] **Step 1: Audit and document the reset path**

In `crates/utmost-gui/src/case.rs`, confirm that `open_case`:
- Creates a brand new `Arc<Mutex<ViewModel>>` via `ViewModel::new()` (not a clone of any process-level instance).
- Replays journal-recovered events into that fresh VM.
- Spawns a new indexer + preview writer keyed off the case's sqlite path only.

No code change should be needed if Task 7 was implemented correctly. Add a unit test in `case.rs` that proves it:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // open_case requires a real events.bin to operate on. We build a
    // minimal one (RunStarted only) and verify that the returned
    // handle's ViewModel starts at defaults.
    #[test]
    fn open_case_starts_with_default_view_model() {
        let tmp = TempDir::new().unwrap();
        let log = tmp.path().join("t-events.bin");
        // Build a minimal events.bin via the existing BincodeFileSink.
        {
            use utmost_lib::events::{BincodeFileSink, EventSink};
            let sink = BincodeFileSink::create(&log).expect("sink");
            sink.emit(&utmost_lib::events::CarveEvent::RunStarted {
                output_root: "/out".into(),
                source_image_path: "/in/t.img".into(),
                started_at: "2026-05-20T00:00:00Z".into(),
                configured_types: vec![],
                case: None,
            });
        }
        let handle = open_case(CaseSource::Historical(log.clone()), &[]).expect("open");
        let vm = handle.vm.lock().unwrap();
        assert!(vm.sources.is_empty());
        assert!(vm.bookmarks.is_empty());
        drop(vm);
        close_case(handle).expect("close");
    }
}
```

> **Implementing agent:** If `ViewModel`'s exact default field names differ, adjust the assertions to compare against `ViewModel::default()` field-by-field, or assert specific empty-state predicates.

- [ ] **Step 2: Ensure `slint_adapter::run_picker_window` drops the prior `UiState` before opening a new one**

Find the `on_case_clicked` block from Task 8. Add at the very top, before calling `open_case`:

```rust
// If the user double-clicks or rapidly navigates, ensure any prior
// open case is fully torn down before we start a new one.
if let Some(ui) = current_ui.borrow_mut().take() { drop(ui); }
if let Some(h) = current_handle.borrow_mut().take() {
    if let Err(e) = crate::case::close_case(h) {
        tracing::warn!("close_case failed during rapid reopen: {e}");
    }
}
```

- [ ] **Step 3: Run the new test**

```bash
cargo test -p utmost-gui --lib case::tests::open_case_starts_with_default_view_model
```

Expected: PASS.

- [ ] **Step 4: Manual smoke — reopen the same case, then a different one**

```bash
cargo run -p utmost-viewer --release -- /path/to/dir-with-2+-cases
```

Verify:
- Click case A → see detail.
- Back → picker.
- Click case A again → detail view re-loads from scratch (no stale state).
- Back → picker.
- Click case B → B's data, not A's.

- [ ] **Step 5: fmt + clippy**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -20
```

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-gui/src/case.rs crates/utmost-gui/src/slint_adapter.rs
git commit -m "$(cat <<'EOF'
feat(gui): per-case state reset on every open_case

Guarantees a fresh ViewModel + indexer + preview writer for every
open, so re-opening the same case or switching to a different one
never inherits state. Adds a unit test that asserts default VM.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: Wire `utmost-viewer` binary to `run_picker`

**Files:**
- Modify: `crates/utmost-viewer/src/main.rs`

- [ ] **Step 1: Update the viewer entrypoint**

Open `crates/utmost-viewer/src/main.rs`. Replace the existing body of `main`:

```rust
use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about = "Browse one or more utmost carve event logs")]
struct Args {
    /// Path to either a directory or a <stem>-events.bin file.
    target: PathBuf,

    /// Search location(s) for the original source image. May be repeated.
    #[arg(long, action = clap::ArgAction::Append)]
    source: Vec<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let cases = utmost_gui::discover_cases(&args.target)?;
    utmost_gui::run_picker(
        cases
            .into_iter()
            .map(utmost_gui::case::CaseSource::Historical)
            .collect(),
        args.source,
    )
}
```

- [ ] **Step 2: Build**

```bash
cargo build -p utmost-viewer 2>&1 | tail -20
```

Expected: clean compile.

- [ ] **Step 3: Manual smoke test — full viewer with multi-case dir**

Run a real `utmost` carve twice into the same dir so it contains at least two cases. Then:

```bash
cargo run -p utmost-viewer --release -- /path/to/multi-case-dir
```

Verify:
- Picker shows both cases (this is the bug fix from the spec — the regression you reported).
- Click one → detail view.
- Back → picker still shows both.
- Click the other → its data.

- [ ] **Step 4: fmt + clippy**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -20
```

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-viewer/src/main.rs
git commit -m "$(cat <<'EOF'
feat(viewer): switch to run_picker so multi-case dirs are browsable

Fixes the regression where utmost-viewer pointed at an output dir
with multiple events.bin files only ever showed one of them. The
viewer now discovers all cases recursively and presents them on
the picker.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: Integration tests

**Files:**
- Create: `crates/utmost-gui/tests/picker.rs`

- [ ] **Step 1: Add integration tests that exercise the picker via plain-Rust helpers**

Slint UI tests are hard to drive headlessly in Rust; this plan tests the *non-UI* halves end-to-end. Create `crates/utmost-gui/tests/picker.rs`:

```rust
//! Integration tests for the case picker. These exercise the
//! discover_cases → build_case_rows → open_case → close_case path
//! end-to-end against fixture event logs on disk. UI-side wiring is
//! exercised by manual smoke tests during development.

use tempfile::TempDir;
use utmost_gui::case::{close_case, open_case, CaseSource};
use utmost_gui::picker::{build_case_row, build_case_rows, PickerStatus};
use utmost_lib::events::{BincodeFileSink, CarveEvent, EventSink};

fn write_minimal_events_bin(path: &std::path::Path, source_image_path: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let sink = BincodeFileSink::create(path).expect("create sink");
    sink.emit(&CarveEvent::RunStarted {
        output_root: "/out".into(),
        source_image_path: source_image_path.into(),
        started_at: "2026-05-20T00:00:00Z".into(),
        configured_types: vec![],
        case: None,
    });
}

#[test]
fn picker_renders_one_row_per_case() {
    let tmp = TempDir::new().unwrap();
    write_minimal_events_bin(&tmp.path().join("a/a-events.bin"), "/in/a.img");
    write_minimal_events_bin(&tmp.path().join("b/b-events.bin"), "/in/b.img");

    let cases = utmost_gui::discover_cases(tmp.path()).unwrap();
    assert_eq!(cases.len(), 2);

    let rows = build_case_rows(&cases);
    assert_eq!(rows.len(), 2);
    let basenames: Vec<_> = rows.iter().map(|r| r.source_basename.clone()).collect();
    assert!(basenames.contains(&"a.img".to_string()));
    assert!(basenames.contains(&"b.img".to_string()));
}

#[test]
fn picker_handles_corrupt_events_bin_gracefully() {
    let tmp = TempDir::new().unwrap();
    write_minimal_events_bin(&tmp.path().join("good/good-events.bin"), "/in/good.img");
    let bad = tmp.path().join("bad/bad-events.bin");
    std::fs::create_dir_all(bad.parent().unwrap()).unwrap();
    std::fs::write(&bad, b"not a bincode file").unwrap();

    let cases = utmost_gui::discover_cases(tmp.path()).unwrap();
    let rows = build_case_rows(&cases);
    assert_eq!(rows.len(), 2);
    let bad_row = rows.iter().find(|r| r.events_bin_path == bad).unwrap();
    assert_eq!(bad_row.status, PickerStatus::Corrupt);
    assert!(!bad_row.clickable);
}

#[test]
fn picker_can_reopen_same_case_in_one_process_session() {
    let tmp = TempDir::new().unwrap();
    let log = tmp.path().join("x-events.bin");
    write_minimal_events_bin(&log, "/in/x.img");

    let h1 = open_case(CaseSource::Historical(log.clone()), &[]).expect("open 1");
    close_case(h1).expect("close 1");

    let h2 = open_case(CaseSource::Historical(log.clone()), &[]).expect("open 2");
    close_case(h2).expect("close 2");
}

#[test]
fn picker_corrupt_row_does_not_block_neighbor_cases() {
    let tmp = TempDir::new().unwrap();
    write_minimal_events_bin(&tmp.path().join("ok/ok-events.bin"), "/in/ok.img");
    let bad = tmp.path().join("bad/bad-events.bin");
    std::fs::create_dir_all(bad.parent().unwrap()).unwrap();
    std::fs::write(&bad, b"junk").unwrap();

    let cases = utmost_gui::discover_cases(tmp.path()).unwrap();
    let rows = build_case_rows(&cases);
    let ok_row = rows
        .iter()
        .find(|r| r.source_basename == "ok.img")
        .expect("ok row present");
    assert!(ok_row.clickable);
}

#[test]
fn picker_row_for_indexed_case_reports_finished_status() {
    // Build an events.bin + open it once to produce an indexed sqlite,
    // then close and ask for its picker row.
    let tmp = TempDir::new().unwrap();
    let log = tmp.path().join("done-events.bin");
    {
        let sink = BincodeFileSink::create(&log).expect("sink");
        sink.emit(&CarveEvent::RunStarted {
            output_root: "/out".into(),
            source_image_path: "/in/done.img".into(),
            started_at: "2026-05-20T00:00:00Z".into(),
            configured_types: vec![],
            case: None,
        });
        sink.emit(&CarveEvent::RunFinished {
            finished_at: "2026-05-20T00:00:01Z".into(),
            elapsed_ms: 1000,
            total_files: 0,
        });
    }
    let h = open_case(CaseSource::Historical(log.clone()), &[]).expect("open");
    close_case(h).expect("close");

    let row = build_case_row(&log);
    // After open_case the indexer should have folded the events into the
    // sqlite; the status should reflect Finished (or Indexing if catch-up
    // is still in flight — accept either).
    assert!(
        matches!(row.status, PickerStatus::Finished | PickerStatus::Indexing),
        "expected Finished or Indexing, got {:?}",
        row.status
    );
}
```

> **Implementing agent:** Some of these tests depend on `open_case` actually completing the fold within a deterministic window. If timing is flaky, the test may need to drain `indexer_event_rx` until a known terminal event arrives before calling `close_case`. Adjust as needed; do not paper over flakiness with `sleep`. If `BincodeFileSink::create` differs in name from what's shown, fix the calls — the fixture pattern (emit RunStarted + RunFinished) is what matters.

- [ ] **Step 2: Run integration tests**

```bash
cargo test -p utmost-gui --test picker -- --nocapture
```

Expected: all five tests pass.

- [ ] **Step 3: fmt + clippy**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -20
```

- [ ] **Step 4: Commit**

```bash
git add crates/utmost-gui/tests/picker.rs
git commit -m "$(cat <<'EOF'
test(gui): integration tests for picker discovery + open/close cycle

Covers: one-row-per-case rendering, corrupt-row handling without
blocking neighbors, open/close/reopen of the same case in one
process, and the indexed → Finished/Indexing transition.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 13: CLAUDE.md update — case model

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Append a "GUI: case model" section to CLAUDE.md**

Open `CLAUDE.md`. After the existing "Architecture" section (or wherever it best fits the document's flow), add:

```markdown
## GUI: case model

The GUI's home screen is a **case picker**. One `<slug>-events.bin` = one case = one row on the picker. Multiple `utmost` invocations into the same output dir produce multiple cases. Multi-source invocations (e.g. `utmost f1.img f2.img -o out/`) also produce multiple cases — one per source.

**Entry modes:**

- `utmost-viewer <dir>` — recursively scans `<dir>` (depth 8, skips hidden + symlinks) for every `<slug>-events.bin`. Each becomes a picker row.
- `utmost --gui ...` — does **not** scan. The CLI knows the input files it's carving; each gets a row. (As of plan 1, the CLI path still uses the legacy `run_live` entry — plan 2 will rebuild it on top of `run_picker`.)

**Per-case state lives in `crates/utmost-gui/src/case.rs`:**

- `CaseSource::Historical(PathBuf)` — on-disk events.bin (viewer mode).
- `CaseSource::Live { events_bin, event_rx }` — live carve (plan 2; not used in plan 1).
- `CaseHandle` — owns the case's `ViewModel`, indexer thread, journal, preview-outcomes writer, and `<slug>-index.sqlite` path. Created by `open_case`, destroyed by `close_case`. One case open at a time per process.

**Picker reads minimal metadata per row** (`crates/utmost-gui/src/picker.rs`):
1. Prefer `<slug>-index.sqlite`'s `run` row + `meta.last_event_offset`.
2. Fall back to `head_read_events_bin` (reads `RunStarted` from the head, `RunFinished` from the tail).
3. On unrecoverable failure: `PickerStatus::Corrupt`, dimmed, not clickable.

**Status values:** `Running` | `Finished` | `Interrupted` | `Indexing…` | `Unindexed` | `Corrupt`. `Unindexed` and `Indexing…` warn the user that clicking in will pay an index-build cost. The picker itself never opens `IndexDb` — only `open_case` does.

**Specs/plans:**
- Design: `docs/superpowers/specs/2026-05-20-case-selection-screen-design.md`
- Plan 1 (viewer mode): `docs/superpowers/plans/2026-05-20-case-selection-screen-viewer-mode.md` ← this plan
- Plan 2 (live-carve CLI refactor): TBD after plan 1 lands
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "$(cat <<'EOF'
docs(claude): document the GUI case model and picker semantics

Future sessions need to know: one events.bin = one case; viewer
scans recursively, CLI passes its own list; per-case state lives
in case.rs; picker reads minimal metadata without opening IndexDb.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Self-Review Checklist (for the implementing agent)

Before marking the plan complete, verify:

1. **Resolver regression fix.** Running `utmost-viewer <dir>` against a directory containing two or more `<slug>-events.bin` files (in subdirs or directly) shows them all on the picker.
2. **Click-in / back loop.** Clicking a case enters the detail view; the back button returns to the picker; clicking the same case again re-enters cleanly; clicking a different case shows that case's data.
3. **No stale state.** Re-opening the same case in one process never shows leftover state from the previous open.
4. **Corrupt rows.** A junk file named `*-events.bin` renders with `Corrupt` status, is dimmed, and does not block neighboring cases from loading.
5. **Existing tests.** `cargo test -p utmost-gui` and `cargo test -p utmost-lib` are green.
6. **Lints.** `cargo clippy --all-targets -- -D warnings` is clean. `cargo fmt --check` is clean.
7. **CLAUDE.md** has the GUI: case model section.

If any of these fails, fix the failing task before declaring the plan complete.

---

## Out of scope — Plan 2 (forthcoming)

- `utmost --gui` multi-source: per-source channel split off the carve-side `EventSink`, `CaseSource::Live` end-to-end, CLI `--gui` branch rebuilt on `run_picker`, `run_live` removal.
- Picker rows updating live during a running carve (the row-tap mechanism).
- Per-case UI-state persistence (the originally-brainstormed feature) builds on top of Plan 2's `open_case` / `close_case` hooks.
