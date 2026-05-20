# Live-carve CLI refactor — design (Plan 2)

**Date:** 2026-05-20
**Status:** Approved (pre-implementation)
**Depends on:** Plan 1 (case-selection screen — already shipped). Builds on `open_case` / `close_case`, `CaseHandle`, `run_picker`, and the cooperative-cancel `shutdown_signal` introduced in the post-Plan-1 indexer-cancel fix.
**Supersedes:** the earlier Plan 2 sketch (in-process channels + per-source ChannelSinks + central demux). That design pre-dated the realization that the GUI and carve don't need to share lifetimes if the carve thread is joined instead of detached.

## Background

Two related problems in today's `utmost --gui` mode:

1. **Multi-source carves are mostly invisible.** The CLI's `--gui` branch attaches one shared `ChannelSink` to every source's `Fanout` and threads only `plan.first()`'s events.bin to `run_live` as "the main log." Other sources' events.bin files get written but are unreachable from the GUI.
2. **Closing the GUI mid-carve aborts the carve.** The carve thread is `std::thread::spawn`'d and never joined; when the Slint window closes and `main` returns, the process exits and the detached carve thread dies with it. By contrast, `utmost` without `--gui` carves to completion just fine — the difference is just whether the thread is joined.

The combined effect: live-carve mode is a half-feature that fights its own foundations.

## Goal

`utmost --gui f1.img f2.img -o out/` launches the picker with one Running row per source. Each row updates live as its carve progresses (file counts, status). Clicking any row enters that case's detail view at any moment — including mid-carve, with partial state visible. Clicking back returns to the picker; carves continue. **Closing the GUI window does not abort the carve.** The process stays alive until all carves finish, after which it exits cleanly. A user can re-launch `utmost-viewer <dir>` from another terminal at any point and see the same live progress.

## Non-goals

- **Daemonization / true backgrounding.** The carve runs in the same process as the (now-closed) GUI. Closing the terminal still kills it; explicit SIGINT still kills it. Daemonizing into a true background process is a separate, much-bigger architectural change.
- **In-process channels for sub-millisecond updates.** Plan 2 commits to polling at 1 Hz. Future work could attach a filesystem watcher (FSEvents / inotify) for tighter latency, but YAGNI for now.
- **Picker scanning multiple output dirs.** Discovery semantics from Plan 1 are unchanged.

## Architectural pivot vs. the earlier sketch

The earlier Plan 2 sketch tried to keep "the GUI sees events" running through in-process channels. That model only works while the GUI and the carve share a process — which they should not, because the GUI may close before the carve finishes.

The pivot: **the events.bin is the only durable communication channel between the carve and the GUI.** The carve writes events.bin (already does). The GUI reads events.bin (already does, via the indexer-writer thread for an open case). The picker reads events.bin too, now (per-row tailers). No in-process channels. No `ChannelSink`. No `CaseSource::Live`.

This collapses two scenarios — "carve is happening in this process" and "carve is happening elsewhere or already finished" — into one code path. Both look identical from the picker's perspective.

## Design

### 1. Carve-side wiring

Delete the in-process channel apparatus. `crates/utmost-cli/src/main.rs`'s `--gui` branch becomes:

```rust
#[cfg(feature = "gui")]
if settings.gui_enabled {
    let plan_clone = plan.clone();
    let base_cfg = base_config.clone();
    let output_root = args.output_directory.clone();
    let concurrent = args.concurrent_files;
    let export = settings.export_enabled;
    let run_started_clone = run_started.clone();
    let combined_specs_clone = combined_specs.clone();

    let carve_handle = std::thread::spawn(move || {
        process_files_parallel(
            &base_cfg,
            &output_root,
            &plan_clone,
            concurrent,
            export,
            None,                          // no extra sink — events.bin only
            &run_started_clone,
            &combined_specs_clone,
        )
    });

    // Build CaseSource list from the plan — same shape utmost-viewer uses.
    let cases: Vec<utmost_gui::case::CaseSource> = plan
        .iter()
        .map(|(_, src_path, src_subdir)| {
            let dir = sinks::source_output_dir(
                std::path::Path::new(&args.output_directory), src_subdir);
            let stem = sinks::log_stem(src_path);
            let events_bin = dir.join(format!("{stem}-events.bin"));
            utmost_gui::case::CaseSource::Historical(events_bin)
        })
        .collect();

    let perf = _telemetry
        .as_ref()
        .expect("_telemetry installed for GUI-bound runs")
        .perf
        .clone();
    let gui_result = utmost_gui::run_picker(cases, vec![], perf);

    eprintln!("GUI closed; carve continuing in background — close terminal to abort.");
    match carve_handle.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::error!("carve thread failed: {e:#}"),
        Err(panic) => tracing::error!("carve thread panicked: {panic:?}"),
    }
    return gui_result;
}
```

The `eprintln!` only fires when window close happens *before* the carve finishes. If the carve completes first, the message still prints — slightly noisy in the "everything finished and I'm closing the window" case but acceptable. (Optionally: check `carve_handle.is_finished()` first and skip the message if true. Implementer's choice.)

`process_files_parallel`'s `extra_sink_per_source: Option<Arc<dyn EventSink>>` parameter stays — its other callers already pass `None`. The `--gui` branch just stops constructing the `ChannelSink`.

### 2. `CaseSource` collapses

```rust
/// Where a case's events.bin lives. Single-variant for now; kept as an
/// enum so future variants (e.g. remote URL) have a place to land.
pub enum CaseSource {
    Historical(PathBuf),
}
```

- `Live { events_bin, event_rx }` variant: **deleted**.
- `CaseHandle.vm_event_tx: Option<Sender<CarveEvent>>` field: **deleted** (it only existed for Live).
- `CaseSource::events_bin()` accessor: **deleted** (single-variant pattern-match is just as readable).
- The TODO comment in `run_picker` about Live being coerced to Historical: **deleted** with its workaround.
- `open_case`'s Live guard:
  ```rust
  let CaseSource::Historical(events_bin) = source;
  let sqlite_path = picker::sqlite_path_for(&events_bin);
  ```

### 3. Indexer-writer tail loop

`rebuild_from_zero` and `resume_from` in `crates/utmost-gui/src/indexer_thread.rs` change from "exit at EOF" to "tail until shutdown_signal." Pseudocode:

```rust
const TAIL_POLL_INTERVAL_MS: u64 = 500;
const MAX_CONSECUTIVE_ERRORS: u32 = 10;

let mut files_seen: u64 = 0;
let mut last_tick_offset: u64 = /* from_or_zero */;
let mut consecutive_errors: u32 = 0;

loop {
    if let Some(s) = shutdown
        && s.load(Ordering::Relaxed)
    {
        writer.flush()?;
        return Ok(());
    }

    match reader.next_event() {
        Ok(Some(ev)) => {
            consecutive_errors = 0;
            let offset_after = reader.byte_offset()?;
            if matches!(ev, CarveEvent::FileFound { .. }) {
                files_seen += 1;
            }
            { let mut v = vm.lock().unwrap(); v.apply(&ev); }
            writer.apply(ev, offset_after)?;
            if let Some(tx) = progress
                && offset_after.saturating_sub(last_tick_offset) >= PROGRESS_TICK_BYTES
            {
                let _ = tx.send(IndexProgress::Bytes { read: offset_after });
                let _ = tx.send(IndexProgress::Files { count: files_seen });
                last_tick_offset = offset_after;
            }
        }
        Ok(None) => {
            consecutive_errors = 0;
            writer.flush()?;
            std::thread::sleep(Duration::from_millis(TAIL_POLL_INTERVAL_MS));
        }
        Err(e) => {
            consecutive_errors += 1;
            if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                tracing::warn!(
                    "indexer giving up after {consecutive_errors} consecutive errors: {e:#}",
                );
                writer.flush()?;
                return Ok(());
            }
            tracing::debug!(
                "indexer tail retry {consecutive_errors}/{MAX_CONSECUTIVE_ERRORS} after: {e:#}",
            );
            writer.flush()?;
            std::thread::sleep(Duration::from_millis(TAIL_POLL_INTERVAL_MS));
        }
    }
}
```

Invariants:
- **`writer.flush()` before every sleep**, so `last_event_offset` is durable. A hard process exit during a sleep leaves a clean resume point.
- **`shutdown_signal` is the only natural exit** (plus the error-cap fallback). Both `rebuild_from_zero` and `resume_from` reach this loop after their initial seek (rebuild seeks to 0 effectively; resume seeks to `from`).
- **The error counter resets on a successful read or a clean EOF.** Only consecutive errors count toward the cap.

### 4. Picker row tailers (persistent state + ephemeral file handle)

Two structs in `crates/utmost-gui/src/picker.rs`:

```rust
/// Persists across detail-view transitions. The picker keeps one of these
/// per known case for the lifetime of the picker session.
#[derive(Clone, Debug)]
pub(crate) struct PickerRowState {
    pub events_bin: PathBuf,
    pub files_seen: u64,
    pub last_offset: u64,
    pub started_at: String,           // empty until first successful RunStarted read
    pub source_path: String,          // from RunStarted.sources[0].filename
    pub finished: bool,
    pub corrupt_retries_remaining: u8,   // 3 → 0; 0 means stuck on Corrupt
}

/// Active tailer — holds the file handle. Lifetime: while picker is visible.
pub(crate) struct PickerRowTailer {
    pub state: PickerRowState,
    reader: BincodeFileReader,
}

impl PickerRowTailer {
    /// Open a brand-new tailer at the start of an events.bin file. Reads
    /// RunStarted to populate state.started_at + state.source_path.
    /// Returns None on file-open failure or non-RunStarted first event.
    pub(crate) fn open_fresh(events_bin: &Path) -> Option<Self>;

    /// Reopen an existing state and seek to its last_offset. Returns None
    /// if the file vanished or the seek failed.
    pub(crate) fn reopen(state: PickerRowState) -> Option<Self>;

    /// Drain any new events; advance state.files_seen / last_offset;
    /// set state.finished on RunFinished. Returns true iff state changed.
    pub(crate) fn poll(&mut self) -> bool;

    /// Build a fresh CaseRowDescriptor reflecting the tailer's current state.
    pub(crate) fn to_descriptor(&self) -> CaseRowDescriptor;
}
```

**Lifecycle:**

- **Picker startup.** For each `CaseSource::Historical(path)`, run `build_case_row(path)` to seed the initial descriptor. From its `PickerStatus`:
  - `Running` / `Indexing` / `Unindexed` → try `PickerRowTailer::open_fresh(path)`. If sqlite exists with `last_event_offset > 0`, seek there first (skip the prefix the indexer has already covered). On success, store in the active-tailers map. On failure, create a `PickerRowState` with `corrupt_retries_remaining: 3` instead.
  - `Finished` / `Interrupted` → static row; no tailer.
  - `Corrupt` → state with `corrupt_retries_remaining: 3`; the retry loop will try to open it on subsequent ticks.

- **Detail view opens** (`case-clicked` callback fires): drop all active `PickerRowTailer`s. State map stays intact. The detail view's own indexer-writer (spawned by `open_case`) takes over reading the case's events.bin.

- **Back to picker** (`back-to-picker` callback fires): for each non-`finished` state in the map, call `PickerRowTailer::reopen(state.clone())`. Tailers that fail to reopen retry on subsequent ticks via the Corrupt path. Successfully reopened tailers resume from `state.last_offset` — no re-scanning of already-consumed bytes.

- **Refresh tick** (`slint::Timer` at 1 Hz, only fires while picker visible — i.e. `show_detail == false`):
  - For each active tailer: call `tailer.poll()`. If it returned true, mark the model dirty.
  - For each state in the map without an active tailer AND with `corrupt_retries_remaining > 0`: try `PickerRowTailer::open_fresh(events_bin)`. On success: promote to active tailer; reset retry counter (no longer needed). On failure: decrement `corrupt_retries_remaining`. At 0, the row stays Corrupt for the rest of this picker session.
  - If anything changed, rebuild the Slint `cases` model from current row state + tailer descriptors. (Cache a "last rendered" descriptor per row to avoid unnecessary rebuilds.)

- **Picker exits.** `run_picker` returns → `Rc<RefCell<HashMap<_, PickerRowTailer>>>` drops → file handles close. State map drops too.

### 5. `run_picker` signature change + telemetry

```rust
pub fn run_picker(
    initial: Vec<case::CaseSource>,
    source_search_locations: Vec<PathBuf>,
    perf: Arc<telemetry::PerfRecorder>,
) -> Result<()>;
```

- `init_telemetry()` is **no longer called inside `run_picker`**. The caller owns the `Telemetry`'s `WorkerGuard`.
- Viewer binary (`crates/utmost-viewer/src/main.rs`) calls `utmost_gui::init_telemetry()` itself, holds the returned `Telemetry` until end of `main`, and passes `perf` into `run_picker`.
- CLI `--gui` branch already initialized telemetry (used by the carve thread's tracing); it passes its existing `perf` clone into `run_picker`. No double-init.

### 6. Deletions

- **`run_live`** in `crates/utmost-gui/src/lib.rs`: removed.
- **`launch_ui_with_journal`** in the same file: removed (its only caller was `run_live`).
- **`CaseSource::Live`** variant: removed.
- **`CaseHandle.vm_event_tx`** field: removed.
- **`CaseSource::events_bin()` accessor**: removed.
- **The TODO(Plan 2) comment + workaround in `run_picker`** that coerced Live entries to Historical: removed along with the variant.

CLI's `--gui` branch's `ChannelSink` construction + the `let first = plan.first().expect(...)` "main log" hack: removed.

Estimated net diff: +250 lines added (mostly tailer + tail-loop logic), −300 lines deleted (run_live + launch_ui_with_journal + Live/channel apparatus). Net: roughly −50 lines.

### 7. Edge cases

- **Carve crashes mid-run** (no `RunFinished`). Picker tailer keeps polling indefinitely (1 Hz idle). Viewer close drops tailers cleanly. Status stays `Running`.
- **GUI closes during carve.** Window close → `run_picker` returns → carve_handle.join() runs in CLI main thread. The carve thread keeps writing events.bin. Process exits when the carve finishes.
- **Ctrl-C during the post-window-close wait.** SIGINT kills all threads; events.bin truncated at last buffer flush. Acceptable.
- **Two viewers on the same dir while a carve runs.** Both safe via `busy_timeout`; both polling tailers operate independently on their own file handles.
- **Picker tailer for a deleted events.bin.** Next `next_event()` errors; corrupt-retry kicks in; after 3 failed reopens, row goes Corrupt.
- **Long-running carve, viewer open all session.** Tailer for each Running row sleeps 1Hz; memory growth is bounded; no leaks.

### 8. Errors (all non-fatal)

- `PickerRowTailer::open_fresh` failure → Corrupt retry.
- `next_event()` Err mid-frame → tail loop retries (capped at 10 in the indexer; the picker tailer caps at 3 retries via Corrupt path).
- `writer.flush()` failure in the indexer → `tracing::warn!`, return Ok (don't continue with stale offset).
- `carve_handle.join()` returning `Err`: `tracing::error!`, return the GUI's result anyway.

### 9. Tests

| File | Test |
|---|---|
| `crates/utmost-gui/src/indexer_thread.rs` | `rebuild_from_zero_tails_past_eof_until_shutdown` |
| `crates/utmost-gui/src/indexer_thread.rs` | `tail_loop_picks_up_events_appended_after_initial_eof` |
| `crates/utmost-gui/src/indexer_thread.rs` | `tail_loop_recovers_from_partial_frame_at_tail` |
| `crates/utmost-gui/src/indexer_thread.rs` | `tail_loop_gives_up_after_max_consecutive_errors` |
| `crates/utmost-gui/src/picker.rs` | `picker_row_tailer_open_fresh_reads_run_started` |
| `crates/utmost-gui/src/picker.rs` | `picker_row_tailer_advances_files_seen_on_appended_event` |
| `crates/utmost-gui/src/picker.rs` | `picker_row_tailer_flips_finished_on_run_finished` |
| `crates/utmost-gui/src/picker.rs` | `picker_row_tailer_reopen_resumes_at_last_offset` |
| `crates/utmost-gui/src/picker.rs` | `picker_row_tailer_open_fresh_returns_none_for_empty_file` |
| `crates/utmost-gui/tests/picker_live_refresh.rs` (new) | `live_carve_picker_row_updates_as_events_arrive` |
| `crates/utmost-gui/tests/picker_live_refresh.rs` | `picker_corrupt_row_recovers_within_retry_budget` |
| `crates/utmost-gui/tests/picker_live_refresh.rs` | `picker_corrupt_row_stays_corrupt_after_retry_budget_exhausted` |
| `crates/utmost-gui/tests/picker_live_refresh.rs` | `picker_tailer_resume_after_detail_view_round_trip` |

### 10. CLAUDE.md updates

Adjust the existing "GUI: case model" section:

- **Delete** the bullet about Plan 1's `run_live` still being legacy.
- **Add** to "Entry modes": "`utmost --gui` keeps the carve thread alive past window close — process exits when the carve finishes."
- **Add** a "Live updates" subsection: picker polls each Running row's events.bin at 1 Hz while the picker is visible; tailers are dropped when a case is opened in detail view and recreated on back-out using persisted offset state.

## Implementation order (rough)

1. **Indexer tail loop** (`rebuild_from_zero` + `resume_from`) + 4 unit tests. Smallest, isolated, foundational.
2. **Delete `CaseSource::Live`, `vm_event_tx`, `events_bin()` accessor**. Compile-bash through the fallout — `open_case`'s guard, `run_picker`'s Live placeholder, the TODO workaround.
3. **`PickerRowState` + `PickerRowTailer`** in `picker.rs` + 5 unit tests.
4. **`run_picker` signature change**: add `perf` parameter; remove the `init_telemetry()` call. Update viewer's main.rs to init telemetry itself.
5. **`run_picker` tailers wiring**: build the row-state map at startup; 1 Hz Slint timer; drop-on-case-clicked, recreate-on-back; corrupt-retry path.
6. **Delete `run_live` + `launch_ui_with_journal`**.
7. **CLI `--gui` branch rewrite**: drop ChannelSink; build `Vec<CaseSource::Historical>`; spawn carve as joinable handle; call `run_picker`; join carve_handle after.
8. **Integration tests** in `tests/picker_live_refresh.rs`.
9. **CLAUDE.md updates**.

About 9 tasks — same order of size as Plan 1's UI-state plan.
