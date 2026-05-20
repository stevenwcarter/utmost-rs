# Per-case UI-state persistence — design

**Date:** 2026-05-20
**Status:** Approved (pre-implementation)
**Depends on:** `docs/superpowers/specs/2026-05-20-case-selection-screen-design.md` (already landed via Plan 1). Builds on `open_case` / `close_case` lifecycle hooks in `crates/utmost-gui/src/case.rs`.

## Background

After running `utmost-viewer <dir>`, picking a case, configuring filters/sort/chip selections, scrolling to a particular file, and clicking back to the picker — re-opening that same case (or relaunching the viewer) starts from defaults again. Every navigation throws away the user's working context.

The case-selection screen lets the user freely move between cases in one process. Users will accumulate per-case state quickly (different files of interest in different carves; different filters needed for different data sets). Restoring that state on each case-open is the natural follow-on to having a picker at all.

## Goal

When the user opens a case (whether for the first time in a process, after backing out and re-clicking it, or in a fresh process), the GUI's filter/sort/toggle settings, layout chrome, selection, and scroll position are restored to whatever they were when that case was last closed.

## Non-goals

- **Lightbox state.** Whether the lightbox was open, its zoom/fit, etc. — out of scope. A modal popping back open on entry is surprising; not worth the complexity.
- **Picker-level state.** Which case was last open, picker scroll position, etc. — out of scope. The picker is ephemeral by design.
- **Cross-machine sync.** State stays in the case's local `<slug>-index.sqlite`; no cloud, no export.
- **Cross-version migration tooling.** The on-disk format is versioned (`v: u32`) so a future schema change can be migrated in code, but no separate migration utility.

## Design

### 1. Data model

A single new struct in `crates/utmost-gui/src/view_model.rs`, lifted by the conversion helper:

```rust
#[derive(serde::Serialize, serde::Deserialize)]
pub struct UiStateSnapshot {
    pub v: u32,                              // schema version; starts at 1
    pub filter: FilterStateSnapshot,
    pub filters_visible: bool,
    pub selected_group: Option<String>,      // Group's display name; None = "All"
    pub selection_file_id: Option<u64>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct FilterStateSnapshot {
    pub enabled_types: Vec<String>,          // FileType lowercase names
    pub enabled_partial_types: Vec<String>,
    pub bookmarked_only: bool,
    pub source_filter: Option<u32>,
    pub sort_key: String,                    // "Filename" | "Size" | "FileType" | "SourceOffset"
    pub sort_dir: String,                    // "Asc" | "Desc"
    pub bookmarked_first: bool,
    pub hide_no_preview: bool,
    pub size_range: Option<(u64, u64)>,
}
```

**Why snapshot types instead of `#[derive(Serialize)]` on `FilterState`:** `FilterState`'s `enabled_types` is `BTreeSet<FileType>`, and `FileType` lives in `utmost-lib`. Deriving serde there is a wider API-surface change than this feature warrants. Snapshot types let the on-disk shape stay stable independent of internal type churn, and concentrate validation in one place.

**Conversion is the only place that knows about validity:**

```rust
impl UiStateSnapshot {
    pub fn from_view_model(vm: &ViewModel) -> Self { ... }

    pub fn into_runtime(
        self,
        run: &RunSummary,
        sources: &[SourceRow],
    ) -> (FilterState, bool, Option<Group>, Option<FileId>);
}
```

`into_runtime` rules (all best-effort, log + drop, never error):

- Unknown `FileType` strings → silently dropped.
- `enabled_types` intersected with `run.configured_types`; off-configuration entries dropped.
- `source_filter` validated against `sources`; missing → `None`.
- `sort_key` / `sort_dir` unknown strings → default (`Filename` / `Asc`).
- `size_range` with `lo > hi` or `(0, 0)` → `None`.
- `selection_file_id` is NOT validated here — the indexer's Requery will yield `match_ids` shortly after hydration; if the saved selection isn't in that list, the existing "prune selection on Requery" path drops it.
- Future schema migration: `match snapshot.v { 1 => …, _ => default }`. Today only `v: 1` exists.

### 2. Storage I/O

Two free functions in `crates/utmost-gui/src/index_db/writer.rs` (same file as `upsert_meta`):

```rust
pub fn write_ui_state(conn: &mut SqliteConnection, snapshot: &UiStateSnapshot) -> Result<()>;
pub fn read_ui_state(conn: &mut SqliteConnection)  -> Result<Option<UiStateSnapshot>>;
```

`write_ui_state` serializes to JSON via `serde_json` and calls the existing `upsert_meta(tx, "ui_state", &json)` inside a transaction. `read_ui_state` does the existing `read_meta_str` pattern and `serde_json::from_str`; on **deserialization failure** logs `tracing::warn!` and returns `Ok(None)`. A corrupt blob auto-heals because the next debounced save overwrites it.

No new migration. `meta` exists since `0001_initial`. The blob is a new entry.

### 3. Hydration during `open_case` (synchronous)

This is the simplification enabled by Plan 1 landing. `open_case` already does `IndexDb::open(&sqlite_path)` and holds a connection. While that connection is alive, call `read_ui_state` and include the result on `CaseHandle`:

```rust
pub struct CaseHandle {
    // … existing fields from Plan 1 …
    pub ui_state_on_open: Option<UiStateSnapshot>,
}
```

The picker hands `handle.ui_state_on_open.take()` to `slint_adapter::UiState::new` as a new parameter:

```rust
pub fn new(
    window: MainWindow,
    vm: Arc<Mutex<ViewModel>>,
    // … existing params …
    ui_state_on_open: Option<UiStateSnapshot>,
) -> Result<Self, slint::PlatformError>;
```

`UiState::new`, before posting its first Requery, applies the snapshot:

1. Call `snapshot.into_runtime(&vm.run, &vm.sources)`.
2. Assign the returned `FilterState` into `vm.filter`, set `vm.filters_visible`, set `vm.selected_group`, set `vm.selection`.
3. Stash a one-shot flag `pending_scroll_to_selection: Option<FileId>` on `UiState` for the post-Requery scroll step (Section 4).
4. Set the existing `hydrating: bool` guard so the assignments don't trigger a same-frame `mark_ui_state_dirty` and re-save.

Then the existing post-`new` work in `run_picker` proceeds: post initial Requery, start the 100ms sync timer, set `show_detail = true`. The Requery uses the freshly-hydrated `vm.filter`, so the very first `MatchIds` response reflects the user's saved settings.

**If `ui_state_on_open` is `None`** (first-ever open of this case, corrupt blob, missing meta row), `UiState::new` skips the apply step entirely; defaults stand. Same behavior as today.

### 4. Selection + scroll restore

After hydration, `vm.selection` is set to the saved `file_id` (or `None`). The existing Requery → `MatchIds` round-trip is the natural place to resolve it. When `MatchIds` arrives back, `apply_match_ids` already prunes `vm.selection` if it's not present in the new list (preexisting behavior). If selection survived, the windowed-grid bridge then scrolls to bring the selected row into view.

Concretely, in the existing `MatchIds` handling path in `UiState::sync` (or wherever `apply_match_ids` is called):

```rust
if let Some(target) = self.pending_scroll_to_selection.take()
    && let Some(idx) = vm.match_ids.iter().position(|s| s.file_id == target)
{
    self.scroll_to_row(idx);   // existing helper, or trivial new one
}
```

`scroll_to_row` sets the windowed-grid's `grid-viewport-y` such that row `idx` is **centered** when possible, or top-aligned if centering would push the viewport past the end of the list. This mirrors browser "scroll-into-view, preferring center" behavior. If the saved selection is gone from the new match list, the flag is consumed without scrolling — no error, no fallback row selected.

### 5. Save cadence: dirty + debounced

The UI thread (slint_adapter) is where every state mutation already lands — chip toggles, sort changes, group-tab clicks, selection moves, filter-panel show/hide, source-filter changes, size-range slider. We piggyback on the existing handlers.

Two new fields on `UiState`:

```rust
ui_state_dirty: Cell<bool>,
ui_state_save_timer: slint::Timer,   // single-shot, restarted on each mutation
```

A new helper `mark_ui_state_dirty(&self)` sets `ui_state_dirty = true` and (re)starts the timer for ~500ms. Every mutation handler that already exists calls `mark_ui_state_dirty()` after applying its change:

- `chip-toggled`, `group-tab-clicked`
- `filters-toggle`, `bookmarked-filter-toggle`, `hide-no-preview-toggle`
- `sort-key-changed`, `sort-dir-toggle`, `bookmarked-first-toggle`
- `size-range-changed`
- selection moves (keyboard nav + tile click)
- `source-filter` changes

When the timer fires:

1. Lock VM (briefly).
2. Build `UiStateSnapshot::from_view_model(&vm)`.
3. Drop the lock.
4. Send `IndexerCommand::PersistUiState(snapshot)` on the per-case `indexer_cmd_tx`.
5. Clear `ui_state_dirty`.

Restarting the timer on every change means a burst (drag the size slider, hold an arrow key) coalesces into a single write after the user pauses.

**Why a Slint timer and not an indexer-side debouncer:** the snapshot is built from the live `ViewModel`; the UI thread is the natural producer. Debouncing on the indexer side would require sending every change as a command (wasted channel traffic) and forcing the indexer to know about UI semantics.

### 6. The `IndexerCommand::PersistUiState` handler

New variant on the existing enum in `crates/utmost-gui/src/indexer_thread.rs`:

```rust
pub enum IndexerCommand {
    Requery { /* … */ },
    FetchWindow { /* … */ },
    Shutdown,
    PersistUiState(UiStateSnapshot),   // new
    // … any other existing variants …
}
```

The query-loop thread already owns the sqlite connection. Handling the command is a one-liner:

```rust
IndexerCommand::PersistUiState(snap) => {
    if let Err(e) = write_ui_state(&mut conn, &snap) {
        tracing::warn!("write_ui_state failed: {e:#}");
    }
}
```

Errors are logged but never propagated. A failed UI-state save must not break the user's session — they'll just see the next 500ms debounce write again, which usually succeeds.

### 7. Final flush on case-close

`close_case` already sends `Shutdown` to the query loop via `shutdown_query_loop` and joins the thread. To guarantee the last debounced save lands, the UI thread must send a final `PersistUiState` **before** that shutdown happens.

Concretely, `UiState` exposes a helper:

```rust
impl UiState {
    /// If dirty, build a snapshot from the current VM and send it on the
    /// indexer command channel. Returns immediately; the actual write is
    /// async on the query-loop thread. Safe to call multiple times.
    pub fn flush_pending_ui_state(&self) {
        if !self.ui_state_dirty.get() { return; }
        if let Some(tx) = &self.indexer_cmd_tx {
            let snap = UiStateSnapshot::from_view_model(&self.vm.lock().unwrap());
            let _ = tx.send(IndexerCommand::PersistUiState(snap));
        }
        self.ui_state_dirty.set(false);
    }
}
```

`run_picker`'s `on_back_to_picker` handler (and the post-`window.run()` cleanup) calls it before dropping the UiState:

```rust
if let Some((ui, timer)) = current_ui.borrow_mut().take() {
    drop(timer);                       // stop the periodic sync first
    ui.flush_pending_ui_state();       // queue the final write
    drop(ui);
}
// shutdown_query_loop below drains commands FIFO, so the PersistUiState
// landed above is processed before Shutdown exits the loop.
```

This gives a floor of "loss bounded by the most-recent unsynced 500ms window if the process is hard-killed." A graceful back/close loses nothing.

If `close_case` happens because the carve process was killed entirely (no graceful shutdown), the most recent **committed** debounced save is the floor — periodic 500ms writes survive a crash.

### 8. Hydration must not trigger a re-save

A subtle bug to defend against: after `UiState::new` applies the snapshot to the VM, the existing UI sync would see the new chip/sort state and "render" it; if `mark_ui_state_dirty` were called from the same handlers that respond to user input, we'd risk a hydration → dirty → save loop.

A `hydrating: bool` guard on `UiState`, set during the apply step and unset before posting the first Requery, ensures `mark_ui_state_dirty` is a no-op during the apply. All mutation handlers learn:

```rust
pub fn mark_ui_state_dirty(&self) {
    if self.hydrating.get() { return; }
    self.ui_state_dirty.set(true);
    self.ui_state_save_timer.restart_for(Duration::from_millis(500));
}
```

(The `Timer::restart_for` shape is illustrative — Slint's `Timer` has `start` and `stop`; "restart" is implemented as stop + start.)

### 9. Edge cases

- **First launch:** no `ui_state` key → `read_ui_state` returns `Ok(None)` → defaults stand.
- **Pristine save:** even if the snapshot equals defaults, we still save. The simpler invariant ("dirty implies save") beats "skip-if-default" optimization.
- **Two viewers on the same case:** SQLite `busy_timeout` (already in place) serializes writes. Last writer wins on `meta.ui_state`; there's no merge — acceptable since concurrent windows on the same case is rare and the data is small.
- **Live carve still going:** `run.status == Running` is irrelevant to UI-state persistence — hydration/save run identically.
- **`hide_no_preview` flapping during preview generation:** already debounced by `preview_status_version`. Hydration doesn't change that.
- **Multi-source case:** N/A in Plan 1 (one events.bin = one case). Each case has its own sqlite and its own `ui_state`.
- **Schema drift (future `v: 2`):** the deserializer dispatches on `v`. Unknown future versions log a warning and return `Ok(None)`; user sees defaults. The next save writes the current `v: 1`, which loses the future state — acceptable for forward/back movement between client versions.

### 10. Errors (all non-fatal)

- Serialize failure: impossible in practice (snapshot is owned plain data); if it ever happens, log + drop, leave `ui_state_dirty == true` so the next change re-tries.
- `write_ui_state` SQL error: log; do not propagate. Next debounced save retries.
- `read_ui_state` deserialize failure (future schema, corrupt blob): warn, return `Ok(None)`, app proceeds with defaults. The next debounced save overwrites the corrupt blob.
- Unknown enum strings inside the snapshot: `into_runtime` drops them silently (debug log).
- `source_filter` referencing a missing source: `into_runtime` returns `None` for it.
- `size_range` with `lo > hi` or `(0, 0)`: `into_runtime` returns `None`.

### 11. Tests

| File | Test |
|---|---|
| `index_db/writer.rs` | `roundtrips_ui_state` — write/read identity for a fully-populated snapshot |
| `index_db/writer.rs` | `read_ui_state_missing_key_returns_none` |
| `index_db/writer.rs` | `read_ui_state_corrupt_blob_returns_none_and_warns` |
| `view_model.rs` | `into_runtime_drops_unknown_file_types` |
| `view_model.rs` | `into_runtime_intersects_with_configured_types` |
| `view_model.rs` | `into_runtime_clears_source_filter_for_missing_source` |
| `view_model.rs` | `into_runtime_clamps_invalid_size_range` |
| `view_model.rs` | `into_runtime_drops_bogus_sort_strings_to_default` |
| `view_model.rs` | `from_view_model_round_trips_all_fields` |
| `case.rs` | `open_case_includes_ui_state_when_meta_present` |
| `case.rs` | `open_case_ui_state_is_none_when_no_meta_row` |
| `slint_adapter.rs` (unit) | `hydration_does_not_mark_dirty` (guard test) |
| `slint_adapter.rs` (unit) | `chip_toggle_marks_ui_state_dirty` |
| `slint_adapter.rs` (unit) | `debounced_save_coalesces_burst_of_changes` (uses Slint's test event loop pattern already used elsewhere in this file) |
| `tests/ui_state_persistence.rs` (new integration) | `save_then_open_round_trips_filters_and_sort` — drives `open_case` → mutate filters → `close_case` → `open_case` again → assert restored |
| `tests/ui_state_persistence.rs` | `selection_restored_when_present_in_match_ids` |
| `tests/ui_state_persistence.rs` | `selection_dropped_when_filtered_out` |
| `tests/ui_state_persistence.rs` | `close_case_final_flush_persists_unsynced_changes` |

### 12. Dependencies

- `serde` — already in `utmost-lib`'s graph; need to verify or add to `utmost-gui`'s Cargo.toml.
- `serde_json` — not yet a `utmost-gui` dep. Add it.

No other new dependencies.

### 13. CLAUDE.md follow-on

After this lands, add a "Per-case UI-state" subsection under "GUI: case model" in CLAUDE.md. One paragraph: lives in `meta.ui_state` per case sqlite, JSON blob, versioned, save is debounced ~500ms via Slint timer + final flush on close, hydration is synchronous in `open_case`, conversion validates against the case's `configured_types` + sources.

## Implementation order (rough)

1. `UiStateSnapshot` types + `into_runtime` + `from_view_model` + unit tests. Pure data, no I/O. Smallest first.
2. `write_ui_state` / `read_ui_state` in `index_db/writer.rs` + tests.
3. `CaseHandle.ui_state_on_open` field; `open_case` reads from sqlite. Snapshot now flows from disk into the handle.
4. `IndexerCommand::PersistUiState(snapshot)` variant + query-loop handler.
5. `UiState::new` accepts the snapshot param; apply step + `hydrating: bool` + `pending_scroll_to_selection`.
6. `mark_ui_state_dirty` + debounced timer in `UiState`. Wire it into every mutation handler.
7. Final flush in `run_picker`'s `on_back_to_picker` + window-close cleanup.
8. Selection-scroll-into-view in the `MatchIds` apply path.
9. Integration tests in `tests/ui_state_persistence.rs`.
10. CLAUDE.md update.
