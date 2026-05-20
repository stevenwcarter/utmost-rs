# Case-selection screen — design

**Date:** 2026-05-20
**Status:** Approved (pre-implementation)
**Supersedes/related:** unblocks the queued "per-case UI-state persistence" spec.

## Background

The utmost GUI today shows a single landing view (the source-row list in `crates/utmost-gui/ui/main.slint`) that only ever represents one case. When the user runs multiple separate `utmost` invocations into the same output directory, only one of the resulting carves is visible in the GUI — the other events.bin files exist on disk but are unreachable.

Two compounding bugs in `crates/utmost-gui/src/lib.rs`:

1. **`resolve_sources` short-circuits** at line 413: if the target dir contains any `*-events.bin` file directly, it returns just that one and never enumerates siblings or descendants.
2. **`find_events_bin_in` returns the first `read_dir` match**, whose order is platform-dependent. Combined with bug 1, a multi-run output dir is effectively unbrowsable.

Additionally, `utmost --gui f1.img f2.img -o out/` runs both carves but threads only `plan.first()`'s events.bin into `run_live` as the "main log" — the second source's events.bin is written to disk and ignored by the GUI.

## Goal

Build a **case-selection screen** (the picker) that is the home view for both entry points:

- **`utmost-viewer <dir>`** — recursive scan of `<dir>` for every `*-events.bin`; each is one row in the picker.
- **`utmost --gui f1.img f2.img -o out/`** — no scan; the picker shows one row per source the CLI is carving (multi-source = multiple rows progressing in parallel).

Clicking a row opens the case's detail view. Clicking back returns to the picker. The same case can be opened, backed out of, and re-opened multiple times in one process.

## Non-goals (in this spec)

- **UI-state persistence per case.** That's a separate, queued spec that consumes the `open_case` / `close_case` hooks defined here.
- **Filesystem watcher** that refreshes the picker when new events.bin files appear in the viewer's target dir. Re-launch to pick up new cases. Easy to add later.
- **Source-image thumbnail or preview on picker rows.** Out of scope per brainstorming decision.
- **Run timestamps in picker rows.** Out of scope per brainstorming decision. (Multiple cases with the same source basename are distinguished by the slug portion of the events.bin filename, surfaced in the dim source-path subtitle.)
- **Concurrent open of multiple cases in one window.** One case at a time; back-and-forth navigation only.

## Terminology

| Term | Meaning |
|---|---|
| **Case** | One `<slug>-events.bin` file (and its sibling `<slug>-index.sqlite` if present). One case = one row on the picker. |
| **Source** | One input file (e.g. `f1.img`) that was passed to `utmost` for carving. A single `utmost` invocation processing N input files produces N events.bin files = N cases. Sources have nothing to do with "case grouping" — each is independent. |
| **Picker / case-selection screen** | The home view that lists all cases. Replaces the current single-case landing layout in `main.slint`. |
| **CaseSource** | Internal enum: `Historical(PathBuf)` for viewer mode (events.bin on disk) or `Live { events_bin, event_rx }` for CLI live carves (event channel shared with the carve thread). |
| **CaseHandle** | The bundle of per-case runtime state (indexer thread, journal, preview writer, ViewModel, sqlite path). Created by `open_case`, destroyed by `close_case`. One at a time. |

## Design

### 1. Discovery (two entry modes, one picker)

The picker UI is identical between modes; only the input list differs.

**Viewer mode (`utmost-viewer <dir>`):** recursive walk of `<dir>` for every `*-events.bin`. Replaces `resolve_sources`. Used **only** by the viewer binary.

```rust
fn discover_cases(target: &Path) -> Result<Vec<PathBuf>> {
    if target.is_file() {
        return Ok(vec![target.to_path_buf()]);
    }
    if !target.is_dir() {
        anyhow::bail!("target is neither a file nor a directory: {}", target.display());
    }
    let mut found = Vec::new();
    walk_for_events_bin(target, 0, &mut found)?;
    found.sort();
    found.dedup();
    if found.is_empty() {
        anyhow::bail!("no <stem>-events.bin found under {}", target.display());
    }
    Ok(found)
}

fn walk_for_events_bin(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) -> Result<()> {
    const MAX_DEPTH: usize = 8;
    if depth > MAX_DEPTH { return Ok(()); }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        let ft = entry.file_type()?;
        if ft.is_file() {
            if let Some(name) = p.file_name().and_then(|n| n.to_str())
                && name.ends_with("-events.bin") {
                out.push(p.canonicalize().unwrap_or(p));
            }
        } else if ft.is_dir() {
            let basename = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !basename.starts_with('.') {
                walk_for_events_bin(&p, depth + 1, out)?;
            }
        }
    }
    Ok(())
}
```

Behavioral notes:

- `entry.file_type()` does not follow symlinks, so we cannot loop. Symlinked directories are skipped; symlinked event-log files are accepted.
- Hidden directories (basename starts with `.`) are skipped.
- `MAX_DEPTH=8` is a soft guard against pathological trees.
- `canonicalize()` + `dedup` handles a target dir reached via a symlink that also contains real subdirs. Falls back to the raw path if canonicalize fails so discovery never errors on a single bad entry.
- Per-subdir I/O errors are downgraded to `tracing::warn!` and the subtree is skipped — one bad subdir does not abort discovery (see "Errors" below). The implementation of `walk_for_events_bin` should adjust to skip-and-warn rather than propagate.

**CLI live mode (`utmost --gui ...`):** no scan. The CLI already knows which input files it's carving and computes events.bin paths per source today (`source_dir.join(format!("{stem}-events.bin"))`, currently only done for `plan.first()`). Extend that to all sources and hand the list to the GUI as `Vec<CaseSource::Live>`.

**`CaseSource`** in `crates/utmost-gui/src/lib.rs`:

```rust
pub enum CaseSource {
    /// On-disk events.bin found via discover_cases (viewer mode).
    Historical(PathBuf),
    /// Live carve in this process. The picker registers the events.bin
    /// path now (before the file exists on disk in some cases) and
    /// subscribes to the event channel shared with the carve thread.
    Live { events_bin: PathBuf, event_rx: crossbeam_channel::Receiver<CarveEvent> },
}
```

**Entry function:**

```rust
pub fn run_picker(initial: Vec<CaseSource>, source_search_locations: Vec<PathBuf>) -> Result<()>;
```

Both `utmost-viewer`'s `main.rs` and the CLI's `--gui` branch call this. `run_from_file` and `run_live` collapse into thin shims that build the right `CaseSource` list and delegate, or are removed.

### 2. Picker UI (`main.slint`)

The current landing layout (the screen in the user's screenshot — "Status: Finished / Files: 2036 / Elapsed: 783ms / l2.img / 2036 files / Finished") is replaced by a list of clickable case rows. The existing `SourceRowData` struct stays — it's still used **inside** a case for the per-source detail.

New struct:

```slint
export struct CaseRowData {
    case_id: int,                  // index into the Rust-side case list; stable for the picker session
    source_basename: string,       // e.g. "l2.img"
    source_path: string,           // recorded path, dim subtitle
    status: string,                // "Running" | "Finished" | "Interrupted" | "Indexing…" | "Unindexed" | "Corrupt"
    files_found: int,
    elapsed: string,               // formatted, e.g. "783ms" or "1m 24s"
    progress: float,               // 0.0..1.0; meaningful for Running, 1.0 otherwise
    clickable: bool,               // false for Corrupt rows
}
```

Properties / callbacks on `MainWindow`:

```slint
in property <[CaseRowData]> cases;
in-out property <int> picker-selected-index: -1;
callback case-clicked(int);        // fires with case_id; Rust opens the case
callback back-to-picker();         // fires from detail-view "back" button
// `show-detail` already exists; picker visible when false, detail when true.
```

Layout: ListView of rows. Each row shows source-basename (primary), source-path (dim subtitle), status tag, files-found, elapsed, and an inline progress bar for `Running` cases. Sort: by `started_at` (if present in metadata) newest-first, else by path. Keyboard nav: ↑/↓/Enter/Esc; mouse click activates a row. Corrupt rows render dimmed; clicks are no-ops; tooltip on hover explains the failure.

The detail view (`show-detail = true`) already exists; a new "back" button in its top chrome fires `back-to-picker`.

### 3. Per-case metadata for picker rows (hybrid strategy)

The picker does NOT open `IndexDb` (no migration, no fold). That's deferred to `open_case`.

| Condition | Metadata source | Cost |
|---|---|---|
| `<slug>-index.sqlite` exists | `SELECT source_image_path, status, elapsed_ms, total_files, started_at FROM run WHERE id=1` plus `meta.last_event_offset` to detect "needs indexing" | One short query per case, no migration / no fold |
| Sqlite absent, events.bin exists | Stream-decode events.bin until `RunStarted` (always first); if file is complete, seek toward tail and try `RunFinished`; counts inferred from event count or `meta.last_event_offset` proxy | ~1–2 page reads per case typically |
| `CaseSource::Live` | No file reads; row starts at `status = "Running"`, `files_found = 0`. Updates flow from the live event tap (Section 4). | Free |

Status disambiguation:

- `"Running"` — Live case still flowing events, or a sqlite `status = Running` with `last_event_offset < events.bin.size`.
- `"Finished"` — sqlite `status = Finished`, or events.bin tail is a clean `RunFinished`.
- `"Interrupted"` — sqlite `status = Interrupted`, or events.bin tail is non-`RunFinished` and no live producer.
- `"Indexing…"` — sqlite exists but `last_event_offset < events.bin.size`. Click triggers catch-up.
- `"Unindexed"` — sqlite absent. Click triggers initial index build (potentially slow for large logs).
- `"Corrupt"` — head-read of events.bin failed to decode `RunStarted`. Row dimmed and not clickable.

A picker-only helper in `index_db/queries.rs` reads the small row summary without opening the full ViewModel.

### 4. Live row updates and per-source event channels

**Carve-side channel split.** Today the CLI's `--gui` path creates a single `(tx, rx)` channel that all parallel sources push into; events from f1 and f2 interleave on the same `rx` and are distinguished by `source_id`. For the picker, each `CaseSource::Live` needs its own independent event stream so the picker's per-row tap and the per-case indexer can each subscribe without demuxing.

Change the carve-side wiring so each source's `Fanout` grows a dedicated per-source `Sender<CarveEvent>` whose `Receiver` is handed to the GUI as `CaseSource::Live.event_rx`. The existing all-sources channel either goes away or stays alongside as a coarse-grained sink unused by the picker. The CLI builds the `Vec<CaseSource::Live>` (one per source) by zipping `plan` with the per-source receivers and passes it to `run_picker`.

**Picker is the central demux point.** The picker owns the one `Receiver` per live case (held by `run_picker` for the process lifetime). The picker's event loop drains each receiver and dispatches every event to two destinations: (a) always — the row's tap state (`files_found`, `progress`, status flip on `RunFinished`), and (b) only when that case is currently open — forwards into the open `CaseHandle`'s VM-update queue. Backing out of a case just stops the forward; the row keeps updating. This avoids needing a broadcast / multi-consumer channel on the carve side; one `Sender` per source on the carve side, one `Receiver` per source on the picker side.

For each `CaseSource::Live`, the picker's row tap consumes only:

- `RunStarted` → row's `source_path` (if not already known) and started_at.
- `FileFound` / file-count progress events → `files_found` and `progress`.
- `RunFinished` → flip `status` to `Finished`.

When the user clicks into a Live case, the case's indexer and ViewModel become **additional** consumers of the same fan-out (the picker's tap continues to update the row in the background so when the user backs out, the row reflects current progress).

Live taps are owned by `run_picker` for the process lifetime, not by `CaseHandle`. They survive case open/close cycles.

### 5. Per-case lifecycle (`open_case` / `close_case`)

Everything currently tangled into `run_from_file`'s body — indexer thread, journal, preview-outcomes writer, event channel, ViewModel, Slint window — gets scoped to a `CaseHandle`.

```rust
pub struct CaseHandle {
    pub events_bin: PathBuf,
    pub sqlite_path: PathBuf,                  // <stem>-index.sqlite alongside events.bin
    pub vm: Arc<Mutex<ViewModel>>,             // freshly defaulted; populated by hydrate + replay
    indexer_cmd_tx: Sender<IndexerCommand>,
    indexer_event_rx: Receiver<IndexerEvent>,
    indexer_thread: JoinHandle<()>,
    preview_writer_thread: Option<JoinHandle<()>>,
    preview_outcomes_tx: Option<Sender<PreviewOutcome>>,
    journal: Option<Arc<Journal>>,
    /// For Live cases only: the picker forwards events into this channel
    /// while the case is open. None for Historical cases.
    vm_event_tx: Option<Sender<CarveEvent>>,
    shutdown_signal: Arc<AtomicBool>,
}

fn open_case(source: CaseSource, source_search_locations: &[PathBuf]) -> Result<CaseHandle>;
fn close_case(handle: CaseHandle) -> Result<()>;
```

**`open_case` body** (mechanically what `run_from_file` does today, scoped to one case):

1. Derive sqlite path: `<stem>-index.sqlite` next to the events.bin (existing helper).
2. `IndexDb::open` (already serialized by `OPEN_GUARD`).
3. Spawn preview-outcomes writer thread bound to this sqlite + a clone of the indexer event sender.
4. Spawn journal for this events.bin; run `recover_on_open`; replay recovered events into the case's new `ViewModel`.
5. Spawn indexer thread (`spawn_query_loop`) bound to this sqlite. The indexer issues its normal init events. (The persistence spec will add `HydrateUiState` here.)
6. For `CaseSource::Live`, store the live event receiver on the handle so the case's UI tick drains progress events directly. For `CaseSource::Historical`, no live channel — the indexer fold replays the on-disk events.bin.
7. UI side (driven by `run_picker`, not `open_case` itself): swap window from picker view (`show-detail = false`) to detail view (`show-detail = true`); detail UI starts driving off `handle.vm`.

**`close_case` body:**

1. Run any "about to close" hooks. (The persistence spec adds a final UI-state flush here.)
2. Drop the live event receiver (the carve thread itself keeps running for live cases — closing the case just means the user backed out of detail view; the carve doesn't stop).
3. Send shutdown to indexer thread; join.
4. Drop `preview_outcomes_tx`; writer thread sees channel hang up; join.
5. Drop journal (last `Arc` reference → file closed).
6. UI side: swap back to picker view; picker's live taps continue updating any still-running cases.

**`run_picker`** is the new top-level entry. It owns the Slint window, the case-list model, and the live taps. On `case-clicked` it calls `open_case` and stores the handle; on `back-to-picker` it calls `close_case` and re-renders the picker. On window close, if a case is open, `close_case` runs before exit.

Pseudocode (full implementation is part of the plan):

```rust
pub fn run_picker(initial: Vec<CaseSource>, source_search_locations: Vec<PathBuf>) -> Result<()> {
    let _telemetry = init_telemetry();
    let window = MainWindow::new()?;
    let mut current: Option<CaseHandle> = None;
    let picker_cases = Arc::new(Mutex::new(build_case_rows(&initial)));
    let live_taps = spawn_live_taps(&initial, picker_cases.clone());

    window.on_case_clicked(/* open_case + swap to detail view */);
    window.on_back_to_picker(/* close_case + swap to picker view */);

    bind_picker_model_to_window(&window, picker_cases.clone());
    window.run()?;

    if let Some(h) = current.take() { close_case(h)?; }
    drop(live_taps);
    Ok(())
}
```

### 6. CLI `--gui` multi-source refactor

Today (`crates/utmost-cli/src/main.rs` around line 486):

```rust
let first = plan.first().expect("plan is non-empty for gui_enabled");
let source_dir = sinks::source_output_dir(...);
let stem = sinks::log_stem(&first.1);
let main_log = source_dir.join(format!("{stem}-events.bin"));
utmost_gui::run_live(rx, Some(main_log), perf)?;
```

Replaced by building one `CaseSource::Live` per source (each with its own dedicated per-source `Receiver` from the carve's `Fanout` — see Section 4) and calling `run_picker`. Each source's events.bin then gets its own journal + sqlite + indexer when the user clicks into that case in the picker. The existing `Fanout` on the carve side already supports multi-sink broadcasting; this adds one more per-source sink so the GUI sees each source on an independent channel.

`run_live` is removed (or shimmed to delegate to `run_picker` for compatibility — preference: removed).

### 7. Edge cases

- **Symlink loops:** handled by file-type check + `MAX_DEPTH` + canonicalize-dedup.
- **Empty / truncated `events.bin`:** head-read fails; row renders as `"Corrupt"`, dimmed, not clickable.
- **Sqlite present but stale (`last_event_offset < file.size`):** status = `"Indexing…"`; click triggers catch-up via the existing indexer fold.
- **Multiple cases for same source basename:** allowed; distinguished by the slug in the dim subtitle. Sort order is stable.
- **A case removed from disk while picker open:** viewer mode keeps the row until next launch; click surfaces "events.bin no longer exists" error.
- **Viewer pointed at a single events.bin file directly:** picker shows one row (no auto-enter).
- **Two viewer instances on the same dir, each clicks into the same case:** SQLite `busy_timeout` serializes writes. Each viewer has its own `CaseHandle`; the carve-time crash protection (journal recovery) handles any unfinished writes.
- **`--source` argument propagation:** `Args.source` flows through `run_picker` into each `open_case` call. The picker itself does no source resolution. Inside a case, the existing `source_resolver` runs unchanged for thumbnails / partial-jpeg previews.
- **`utmost-viewer` with zero cases found:** `discover_cases` returns its existing `anyhow::bail!`; viewer exits with the error.
- **`utmost --gui` with zero sources:** already impossible (CLI requires ≥1 input).

### 8. Errors (non-fatal at the picker level)

One bad case never blocks the rest.

- Discovery I/O error on one subdir: `tracing::warn!`, skip the subtree, continue.
- Head-read decode failure for one events.bin: row = `"Corrupt"`, dimmed, not clickable, tooltip on hover.
- `open_case` failure: `tracing::error!`, in-window error banner above the picker, picker stays visible.
- Indexer thread panic inside an open case: existing crash semantics; user closes window, re-launches. Out of scope to harden further here.

### 9. Tests

New file: `crates/utmost-gui/tests/picker.rs`. Additions to unit-test modules in `lib.rs` and `index_db/queries.rs`.

| File | Test |
|---|---|
| `lib.rs` (unit) | `discover_cases_finds_nested_events_bins` |
| `lib.rs` | `discover_cases_dedups_canonicalised_paths` |
| `lib.rs` | `discover_cases_skips_hidden_dirs` |
| `lib.rs` | `discover_cases_respects_max_depth` |
| `lib.rs` | `discover_cases_returns_single_when_passed_file` |
| `lib.rs` | `discover_cases_errors_on_empty_dir` |
| `lib.rs` | `discover_cases_continues_past_unreadable_subdir` |
| `tests/picker.rs` | `picker_renders_one_row_per_case` |
| `tests/picker.rs` | `picker_shows_running_status_for_live_case_until_run_finished` |
| `tests/picker.rs` | `picker_back_button_closes_case_and_returns_to_picker` |
| `tests/picker.rs` | `picker_can_reopen_same_case_in_one_process_session` |
| `tests/picker.rs` | `picker_handles_corrupt_events_bin_gracefully` |
| `tests/picker.rs` | `picker_live_row_updates_files_found_from_progress_events` |
| `tests/picker.rs` | `cli_gui_multi_source_yields_one_case_per_source` |
| `tests/picker.rs` | `viewer_dir_with_no_events_bins_errors_cleanly` |
| `index_db/queries.rs` | `read_picker_metadata_returns_row_summary` |

### 10. CLAUDE.md update

After implementation lands, add to `CLAUDE.md` (or a referenced doc):

- **Case model.** One `<slug>-events.bin` = one case. Multiple `utmost` invocations into the same output dir produce multiple cases. Multi-source invocations also produce multiple cases (one per source).
- **Entry modes.** `utmost-viewer <dir>` recursively scans for cases. `utmost --gui` does not scan — its picker shows only the sources the CLI was invoked with.
- **Per-case state.** Each case has its own `<slug>-index.sqlite`, journal, indexer thread, and ViewModel. Created on `open_case`, destroyed on `close_case`. One case open at a time per process.

## Out of scope (queued)

- **Per-case UI-state persistence.** A separate spec consumes `open_case` / `close_case` hooks to hydrate and persist filter/sort/selection per case.

## Implementation order (rough)

1. Resolver fix (`discover_cases`) + unit tests. Smallest, isolated.
2. `CaseSource` + `CaseHandle` types in `lib.rs`. No behavior change yet.
3. Extract `open_case` / `close_case` from `run_from_file`'s body. `run_from_file` becomes a shim that calls them around a single CaseSource.
4. New `run_picker` + Slint picker UI (`CaseRowData`, new properties, callbacks). Initial implementation drives a single-case picker (viewer-mode pointed at one events.bin) end-to-end.
5. Multi-case viewer path: `utmost-viewer` calls `discover_cases` and passes the full list to `run_picker`.
6. Live-tap subscriber + `CaseSource::Live` end-to-end (single-source live carve).
7. CLI `--gui` multi-source refactor: build N `CaseSource::Live`, remove `run_live`'s "main_log = first" hack.
8. Corrupt / Unindexed / Indexing edge cases + tests.
9. CLAUDE.md update.
