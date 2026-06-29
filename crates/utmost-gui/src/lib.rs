//! Slint GUI for utmost.

pub mod case;
pub mod indexer_thread;
pub mod journal;
pub mod picker;
pub mod processor;
pub mod recovery;
pub mod slint_adapter;
pub mod telemetry;
pub mod thumb_worker;
pub mod view_model;

// Re-export shims so the GUI's existing `crate::...` paths resolve against the
// shared `utmost-index` crate after the Diesel→turso migration.
#[cfg(feature = "clip")]
pub use utmost_index::clip;
pub use utmost_index::db as index_db;
pub use utmost_index::{discover, preview, source_resolver};

pub use utmost_index::discover::discover_cases;

use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

pub use telemetry::Telemetry;
pub use view_model::ViewModel;

/// Install the GUI's file-backed `tracing` subscriber.
///
/// The returned [`Telemetry`] owns the `tracing-appender` `WorkerGuard` that
/// keeps the non-blocking log writer thread alive. Callers MUST bind the
/// returned value to a named local (e.g. `let _telemetry = init_telemetry();`)
/// so it lives for the duration of the GUI session. Binding to `_` would drop
/// the guard immediately and silently swallow log output.
pub fn init_telemetry() -> Telemetry {
    telemetry::init_subscriber()
}

pub fn run_from_file(target: &Path, source_search_locations: Vec<PathBuf>) -> Result<()> {
    let _telemetry = init_telemetry();
    let perf = _telemetry.perf.clone();
    let cases = discover_cases(target)?;
    run_picker(
        cases
            .into_iter()
            .map(case::CaseSource::Historical)
            .collect(),
        source_search_locations,
        perf,
    )
}

pub fn run_picker(
    initial: Vec<case::CaseSource>,
    source_search_locations: Vec<PathBuf>,
    perf: Arc<telemetry::PerfRecorder>,
) -> Result<()> {
    use slint::ComponentHandle;
    use std::cell::RefCell;
    use std::rc::Rc;

    // 1) Build the window once. It survives across case open/close cycles.
    let window = slint_adapter::MainWindow::new()?;

    // 2) Build initial picker rows from disk paired with their CaseSource so
    //    we can sort the pair together and keep case_id (= row index)
    //    aligned with sources[case_id].
    let mut paired: Vec<(picker::CaseRowDescriptor, case::CaseSource)> = initial
        .into_iter()
        .map(|s| {
            let case::CaseSource::Historical(p) = &s;
            let descriptor = picker::build_case_row(p);
            (descriptor, s)
        })
        .collect();
    // Sort newest first by started_at (empty timestamps land last).
    paired.sort_by(|a, b| b.0.started_at.cmp(&a.0.started_at));
    let (rows, sorted_sources): (Vec<_>, Vec<_>) = paired.into_iter().unzip();

    // Build a parallel Vec<PathBuf> in case_id order so the refresh timer can
    // look up a path by row index without borrowing sorted_sources.
    let sorted_paths: Rc<Vec<PathBuf>> = Rc::new(
        sorted_sources
            .iter()
            .map(|s| {
                let case::CaseSource::Historical(p) = s;
                p.clone()
            })
            .collect(),
    );

    // 3) Populate the Slint cases model.
    let cases_model: Rc<slint::VecModel<slint_adapter::CaseRowData>> =
        Rc::new(slint::VecModel::default());
    for (idx, row) in rows.iter().enumerate() {
        cases_model.push(slint_adapter::CaseRowData {
            case_id: idx as i32,
            source_basename: slint::SharedString::from(row.source_basename.as_str()),
            source_path: slint::SharedString::from(row.source_path.as_str()),
            status: slint::SharedString::from(row.status.as_str()),
            files_found: row.files_found as i32,
            elapsed: slint::SharedString::from(format_elapsed(row.elapsed_ms).as_str()),
            progress: row.progress,
            clickable: row.clickable,
        });
    }
    window.set_cases(slint::ModelRc::from(cases_model.clone()));
    window.set_show_detail(false);

    // 4a) Tailer and state maps — seeded from initial rows.
    use std::collections::HashMap;
    let row_states: Rc<RefCell<HashMap<PathBuf, picker::PickerRowState>>> =
        Rc::new(RefCell::new(HashMap::new()));
    let active_tailers: Rc<RefCell<HashMap<PathBuf, picker::PickerRowTailer>>> =
        Rc::new(RefCell::new(HashMap::new()));

    // Seed the row-state map. For Running/Indexing/Unindexed rows, try to
    // open a fresh tailer immediately. For Corrupt rows, create a state
    // entry that the refresh timer will retry up to 3 times.
    {
        let mut states = row_states.borrow_mut();
        let mut tailers = active_tailers.borrow_mut();
        for row in &rows {
            let path = row.events_bin_path.clone();
            match row.status {
                picker::PickerStatus::Running
                | picker::PickerStatus::Indexing
                | picker::PickerStatus::Unindexed => {
                    if let Some(tailer) = picker::PickerRowTailer::open_fresh(&path) {
                        states.insert(path.clone(), tailer.state.clone());
                        tailers.insert(path, tailer);
                    } else {
                        states.insert(path.clone(), picker::PickerRowState::for_retry(path));
                    }
                }
                picker::PickerStatus::Finished | picker::PickerStatus::Interrupted => {
                    // Static row; no tailer / no state needed.
                }
                picker::PickerStatus::Corrupt => {
                    states.insert(path.clone(), picker::PickerRowState::for_retry(path));
                }
            }
        }
    }

    // 4b) Mutable state owned by the closures. `rows` and `sorted_sources` are
    // in lockstep (built from a single zipped sort) so `case_id` (== row
    // index after sort) maps directly to `sorted_sources[case_id]`.
    let sources: Rc<RefCell<Vec<case::CaseSource>>> = Rc::new(RefCell::new(sorted_sources));
    let current_handle: Rc<RefCell<Option<case::CaseHandle>>> = Rc::new(RefCell::new(None));
    // The UiState is held in an inner `Rc` so the periodic-sync timer can
    // keep a `Weak` to it without taking ownership. The outer `Rc<RefCell<…>>`
    // is owned by both `on_case_clicked` and `on_back_to_picker` closures.
    type CurrentUi = Rc<RefCell<Option<(Rc<slint_adapter::UiState>, slint::Timer)>>>;
    let current_ui: CurrentUi = Rc::new(RefCell::new(None));

    // 5) Case-clicked callback: open_case + UiState bind + flip to detail view.
    {
        let window_weak = window.as_weak();
        let sources = sources.clone();
        let current_handle = current_handle.clone();
        let current_ui = current_ui.clone();
        let search_locs = source_search_locations.clone();
        let perf = perf.clone();
        let active_tailers = active_tailers.clone();
        window.on_case_clicked(move |case_id| {
            // Tear down any existing open case before opening a new one.
            // Set the shutdown signal *before* dropping the UI so the thumb
            // workers (which clone outcomes_tx) break out of their decode
            // loop on the next iteration instead of draining the queued
            // request backlog — otherwise the preview-writer join inside
            // close_case freezes the UI thread until the queue is empty.
            if let Some(h) = current_handle.borrow().as_ref() {
                h.shutdown_signal.store(true, Ordering::Relaxed);
            }
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

            // Drop all picker-row tailers — they hold file handles we don't need
            // while a case is open in detail view. State map stays intact.
            active_tailers.borrow_mut().clear();

            let Some(window) = window_weak.upgrade() else {
                return;
            };
            let case_idx = case_id as usize;

            // Take the events_bin path for this index.
            let events_bin = {
                let s = sources.borrow();
                if case_idx >= s.len() {
                    tracing::warn!("case-clicked: index {} out of range", case_idx);
                    return;
                }
                let case::CaseSource::Historical(p) = &s[case_idx];
                p.clone()
            };
            let src = case::CaseSource::Historical(events_bin);

            match case::open_case(src, &search_locs) {
                Ok(mut handle) => {
                    let vm = handle.vm.clone();
                    let indexer_event_rx = Some(handle.indexer_event_rx.clone());
                    let indexer_cmd_tx = Some(handle.indexer_cmd_tx.clone());
                    let preview_outcomes_tx = handle.preview_outcomes_tx.clone();
                    let progress_rx = handle.indexer_progress_rx.take();
                    let event_log_path = Some(handle.events_bin.clone());
                    let journal_arc = handle.journal.clone();
                    let thumbs_shutdown = handle.shutdown_signal.clone();
                    let process_rx = handle.process_progress_rx.take();
                    let pause_signal = handle.pause_signal.clone();
                    #[cfg(feature = "clip")]
                    let embedder_for_ui = handle.embedder.clone();

                    // Bind UiState to the existing window.
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
                        handle.ui_state_on_open.take(),
                        thumbs_shutdown,
                        Some(handle.sqlite_path.clone()),
                        process_rx,
                        pause_signal,
                        #[cfg(feature = "clip")]
                        embedder_for_ui,
                    ) {
                        Ok(ui) => {
                            if let Some(j) = journal_arc {
                                ui.set_journal(j);
                            }
                            // Post an initial Requery so the query-loop populates match_ids.
                            if let Some(tx) = &indexer_cmd_tx {
                                let mut v = vm.lock().unwrap();
                                v.current_epoch += 1;
                                let _ = tx.send(indexer_thread::IndexerCommand::Requery {
                                    filter: v.filter.clone(),
                                    epoch: v.current_epoch,
                                });
                            }
                            {
                                let mut v = vm.lock().unwrap();
                                ui.sync(&mut v);
                            }

                            // Start the 100ms timer; store it alongside the UiState so
                            // it gets dropped (and stopped) when the case closes.
                            //
                            // The UiState lives behind an Rc so the timer closure can
                            // hold a Weak and re-acquire on each tick. We MUST keep the
                            // Rc alive (not Rc::try_unwrap it out) — try_unwrap moves
                            // the inner value out of the heap allocation, leaving any
                            // outstanding Weak pointing to a dropped slot whose
                            // `upgrade()` returns None. That's how the periodic sync
                            // silently stopped firing before this fix.
                            let ui_rc = Rc::new(ui);
                            let weak_ui = Rc::downgrade(&ui_rc);
                            let vm_for_timer = vm.clone();
                            let timer = slint::Timer::default();
                            timer.start(
                                slint::TimerMode::Repeated,
                                std::time::Duration::from_millis(100),
                                move || {
                                    if let Some(ui) = weak_ui.upgrade() {
                                        if let Some(rx) = ui.recovery_rx.borrow().as_ref() {
                                            let mut v = vm_for_timer.lock().unwrap();
                                            while let Ok(ev) = rx.try_recv() {
                                                v.apply(&ev);
                                                v.recompute_visible();
                                            }
                                        }
                                        let mut v = vm_for_timer.lock().unwrap();
                                        ui.sync(&mut v);
                                    }
                                },
                            );

                            *current_ui.borrow_mut() = Some((ui_rc, timer));
                            *current_handle.borrow_mut() = Some(handle);
                            window.set_show_detail(true);
                        }
                        Err(e) => {
                            tracing::error!("UiState::new failed: {e}");
                            if let Err(ce) = case::close_case(handle) {
                                tracing::warn!("close_case after UiState::new failure: {ce}");
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

    // 6) Back-to-picker callback. The UI button itself comes in Task 9; we wire
    //    the callback handler here so it's ready.
    {
        let window_weak = window.as_weak();
        let current_handle = current_handle.clone();
        let current_ui = current_ui.clone();
        let active_tailers = active_tailers.clone();
        let row_states = row_states.clone();
        window.on_back_to_picker(move || {
            // Pre-signal shutdown so the thumb workers stop draining their
            // decode queue mid-frame. Without this they hold the last
            // outcomes_tx clones and the preview-writer join inside
            // close_case freezes the UI thread until the queue is empty.
            if let Some(h) = current_handle.borrow().as_ref() {
                h.shutdown_signal.store(true, Ordering::Relaxed);
            }
            if let Some((ui, timer)) = current_ui.borrow_mut().take() {
                drop(timer); // stop the periodic sync first
                ui.flush_pending_ui_state(); // queue final write before shutdown
                drop(ui);
            }
            if let Some(h) = current_handle.borrow_mut().take()
                && let Err(e) = case::close_case(h)
            {
                tracing::warn!("close_case on back failed: {e}");
            }

            // Recreate picker-row tailers from persisted state for any case that
            // isn't already finished.
            {
                let mut tailers = active_tailers.borrow_mut();
                let states = row_states.borrow();
                for (path, state) in states.iter() {
                    if state.finished {
                        continue;
                    }
                    if let Some(t) = picker::PickerRowTailer::reopen(state.clone()) {
                        tailers.insert(path.clone(), t);
                    }
                }
            }

            if let Some(window) = window_weak.upgrade() {
                window.set_show_detail(false);
            }
        });
    }

    // 7) Refresh timer: polls active tailers and rebuilds the cases model.
    //    Only effective while the picker is visible (show-detail == false);
    //    skip the work when a detail view is up.
    let refresh_timer = {
        let window_weak = window.as_weak();
        let active_tailers = active_tailers.clone();
        let row_states = row_states.clone();
        let cases_model = cases_model.clone();
        let sorted_sources_for_timer = sorted_paths.clone();
        let timer = slint::Timer::default();
        timer.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_secs(1),
            move || {
                let Some(window) = window_weak.upgrade() else {
                    return;
                };
                if window.get_show_detail() {
                    return;
                }

                let mut any_changed = false;

                // 1) Drain active tailers.
                {
                    let mut tailers = active_tailers.borrow_mut();
                    let mut states = row_states.borrow_mut();
                    let mut finished_paths: Vec<PathBuf> = Vec::new();
                    for (path, tailer) in tailers.iter_mut() {
                        if tailer.poll() {
                            any_changed = true;
                            states.insert(path.clone(), tailer.state.clone());
                            if tailer.state.finished {
                                finished_paths.push(path.clone());
                            }
                        }
                    }
                    for p in finished_paths {
                        tailers.remove(&p);
                    }
                }

                // 2) Corrupt-retry: for state entries without an active tailer
                //    AND with retries_remaining > 0, try open_fresh again.
                {
                    let mut tailers = active_tailers.borrow_mut();
                    let mut states = row_states.borrow_mut();
                    let retry_paths: Vec<PathBuf> = states
                        .iter()
                        .filter(|(p, s)| {
                            !tailers.contains_key(*p)
                                && !s.finished
                                && s.corrupt_retries_remaining > 0
                                && s.started_at.is_empty()
                        })
                        .map(|(p, _)| p.clone())
                        .collect();
                    for path in retry_paths {
                        match picker::PickerRowTailer::open_fresh(&path) {
                            Some(t) => {
                                states.insert(path.clone(), t.state.clone());
                                tailers.insert(path, t);
                                any_changed = true;
                            }
                            None => {
                                if let Some(s) = states.get_mut(&path) {
                                    s.corrupt_retries_remaining =
                                        s.corrupt_retries_remaining.saturating_sub(1);
                                }
                            }
                        }
                    }
                }

                // 3) Rebuild the Slint model from current tailer descriptors.
                if any_changed {
                    use slint::Model as _;
                    let tailers = active_tailers.borrow();
                    let count = cases_model.row_count();
                    for i in 0..count {
                        if let Some(path) = sorted_sources_for_timer.get(i)
                            && let Some(t) = tailers.get(path)
                        {
                            let desc = t.to_descriptor();
                            cases_model.set_row_data(
                                i,
                                slint_adapter::CaseRowData {
                                    case_id: i as i32,
                                    source_basename: slint::SharedString::from(
                                        desc.source_basename.as_str(),
                                    ),
                                    source_path: slint::SharedString::from(
                                        desc.source_path.as_str(),
                                    ),
                                    status: slint::SharedString::from(desc.status.as_str()),
                                    files_found: desc.files_found as i32,
                                    elapsed: slint::SharedString::from(
                                        format_elapsed(desc.elapsed_ms).as_str(),
                                    ),
                                    progress: desc.progress,
                                    clickable: desc.clickable,
                                },
                            );
                        }
                    }
                }
            },
        );
        timer
    };

    // 8) Run.
    window.run()?;
    drop(refresh_timer);

    // 9) Final cleanup on window close. Pre-signal shutdown so the thumb
    // workers exit on the next recv iteration instead of grinding through
    // their decode queue while the user's window is already gone.
    if let Some(h) = current_handle.borrow().as_ref() {
        h.shutdown_signal.store(true, Ordering::Relaxed);
    }
    if let Some((ui, timer)) = current_ui.borrow_mut().take() {
        drop(timer);
        ui.flush_pending_ui_state();
        drop(ui);
    }
    if let Some(h) = current_handle.borrow_mut().take() {
        let _ = case::close_case(h);
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

/// Result tuple returned by [`spawn_query_loop`]. Each component is `None`
/// when no main log is available (so the thread never started). The
/// `event_tx` clone is exposed so sibling threads (notably the
/// preview-outcomes writer) can share the same event channel and emit
/// `IndexerEvent::PreviewStatusVersion` after each batch flush.
pub(crate) type QueryLoopHandles = (
    Option<crossbeam_channel::Sender<indexer_thread::IndexerCommand>>,
    Option<crossbeam_channel::Sender<indexer_thread::IndexerEvent>>,
    Option<crossbeam_channel::Receiver<indexer_thread::IndexerEvent>>,
    Option<std::thread::JoinHandle<()>>,
);

/// Spawn the query-loop indexer thread alongside the existing preview-outcomes
/// writer. Returns the command sender, an `event_tx` clone for sibling
/// emitters, the event receiver, and the join handle — all `None` when no
/// main log is available (e.g. no `<stem>-events.bin` resolved). The
/// thread is shut down via [`shutdown_query_loop`].
pub(crate) fn spawn_query_loop(
    main_log_path: Option<&PathBuf>,
    #[cfg(feature = "clip")] embedder: utmost_index::clip::Embedder,
) -> QueryLoopHandles {
    let Some(log) = main_log_path else {
        return (None, None, None, None);
    };
    let (cmd_tx, cmd_rx) = crossbeam_channel::unbounded::<indexer_thread::IndexerCommand>();
    let (event_tx, event_rx) = crossbeam_channel::unbounded::<indexer_thread::IndexerEvent>();
    let event_tx_for_loop = event_tx.clone();
    let log = log.clone();
    let handle = std::thread::spawn(move || {
        if let Err(e) = indexer_thread::run_query_loop(
            log,
            cmd_rx,
            event_tx_for_loop,
            #[cfg(feature = "clip")]
            embedder,
        ) {
            tracing::warn!("query loop failed: {e:#}");
        }
    });
    (Some(cmd_tx), Some(event_tx), Some(event_rx), Some(handle))
}

/// Send `Shutdown` to the query-loop thread, drop the sender, and join. No-ops
/// when the thread wasn't spawned (i.e. no main log was available).
pub(crate) fn shutdown_query_loop(
    cmd_tx: Option<crossbeam_channel::Sender<indexer_thread::IndexerCommand>>,
    handle: Option<std::thread::JoinHandle<()>>,
) {
    if let Some(tx) = cmd_tx {
        let _ = tx.send(indexer_thread::IndexerCommand::Shutdown);
        drop(tx);
    }
    if let Some(h) = handle {
        let _ = h.join();
    }
}
