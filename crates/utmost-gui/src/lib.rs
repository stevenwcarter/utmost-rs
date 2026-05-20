//! Slint GUI for utmost.

pub mod case;
mod discover;
pub mod index_db;
pub mod indexer_thread;
pub mod journal;
pub mod picker;
pub mod preview;
pub mod recovery;
pub mod slint_adapter;
pub mod source_resolver;
pub mod telemetry;
pub mod thumb_worker;
pub mod view_model;

pub use discover::discover_cases;

use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use utmost_lib::events::CarveEvent;

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
    let cases = discover_cases(target)?;
    run_picker(
        cases
            .into_iter()
            .map(case::CaseSource::Historical)
            .collect(),
        source_search_locations,
    )
}

pub fn run_picker(
    initial: Vec<case::CaseSource>,
    source_search_locations: Vec<PathBuf>,
) -> Result<()> {
    use slint::ComponentHandle;
    use std::cell::RefCell;
    use std::rc::Rc;

    let telemetry = init_telemetry();
    let perf = telemetry.perf.clone();

    // 1) Build the window once. It survives across case open/close cycles.
    let window = slint_adapter::MainWindow::new()?;

    // 2) Build initial picker rows from disk (Historical) or placeholder (Live).
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
    // Sort newest first by started_at (empty timestamps land last).
    rows.sort_by(|a, b| b.started_at.cmp(&a.started_at));

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

    // 4) Mutable state owned by the closures.
    // `rows` is already sorted newest-first; rebuild sources in that same order
    // so that `case_id` (== row index after sort) maps directly to `sources[i]`.
    // TODO(Plan 2): CaseSource::Live entries are coerced to Historical here;
    // the live event_rx is discarded. Plan 2 will thread Live sources
    // through to open_case once multi-source live-mode is supported.
    let sorted_sources: Vec<case::CaseSource> = rows
        .iter()
        .map(|r| case::CaseSource::Historical(r.events_bin_path.clone()))
        .collect();
    let sources: Rc<RefCell<Vec<case::CaseSource>>> = Rc::new(RefCell::new(sorted_sources));
    let current_handle: Rc<RefCell<Option<case::CaseHandle>>> = Rc::new(RefCell::new(None));
    let current_ui: Rc<RefCell<Option<(slint_adapter::UiState, slint::Timer)>>> =
        Rc::new(RefCell::new(None));

    // 5) Case-clicked callback: open_case + UiState bind + flip to detail view.
    {
        let window_weak = window.as_weak();
        let sources = sources.clone();
        let current_handle = current_handle.clone();
        let current_ui = current_ui.clone();
        let search_locs = source_search_locations.clone();
        let perf = perf.clone();
        window.on_case_clicked(move |case_id| {
            // Tear down any existing open case before opening a new one.
            if let Some((ui, timer)) = current_ui.borrow_mut().take() {
                drop(timer);
                drop(ui);
            }
            if let Some(h) = current_handle.borrow_mut().take()
                && let Err(e) = case::close_case(h)
            {
                tracing::warn!("close_case on reopen failed: {e}");
            }

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
                s[case_idx].events_bin().clone()
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
                            let ui_rc = std::rc::Rc::new(ui);
                            let weak_ui = std::rc::Rc::downgrade(&ui_rc);
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

                            // Unwrap the Rc — UiState is !Sync/!Send so it can only
                            // live on the UI thread; no concurrent access.
                            let ui_owned = std::rc::Rc::try_unwrap(ui_rc).unwrap_or_else(|rc| {
                                // Safety: we just created it above and hold the only Rc.
                                // This branch should never be reached.
                                panic!(
                                    "unexpected Rc alias count: {}",
                                    std::rc::Rc::strong_count(&rc)
                                );
                            });

                            *current_ui.borrow_mut() = Some((ui_owned, timer));
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
        window.on_back_to_picker(move || {
            if let Some((ui, timer)) = current_ui.borrow_mut().take() {
                drop(timer);
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
    }

    // 7) Run.
    window.run()?;

    // 8) Final cleanup on window close.
    if let Some((ui, timer)) = current_ui.borrow_mut().take() {
        drop(timer);
        drop(ui);
    }
    if let Some(h) = current_handle.borrow_mut().take() {
        let _ = case::close_case(h);
    }
    // Keep telemetry alive until the very end (its WorkerGuard flushes on Drop).
    drop(telemetry);
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

pub fn run_live(
    rx: crossbeam_channel::Receiver<CarveEvent>,
    main_log_path: Option<std::path::PathBuf>,
    perf: Arc<telemetry::PerfRecorder>,
) -> Result<()> {
    // Tracing subscriber is installed by the caller (CLI's main(), or — for
    // utmost-viewer — via run_from_file's own init_telemetry call).
    let vm = Arc::new(Mutex::new(ViewModel::new()));
    let journal = main_log_path
        .as_ref()
        .map(|p| Arc::new(journal::Journal::for_main_log(p)));
    let journal_for_thread = journal.clone();
    let vm_for_thread = vm.clone();

    // Spawn a sibling writer thread when a main log is known. Events are fanned
    // out to both the VM apply loop and the SQLite writer; the writer thread
    // owns its own DB connection so VM mutation never blocks on disk I/O.
    //
    // `writer_handle` is captured and joined at the end of `run_live` so the
    // writer thread's final `flush()` (which can buffer up to 50 events or
    // sit in a 200ms timer window) is guaranteed to run before the process
    // exits.
    let (writer_tx, writer_handle): (
        Option<crossbeam_channel::Sender<CarveEvent>>,
        Option<std::thread::JoinHandle<()>>,
    ) = match main_log_path.as_ref() {
        Some(log) => {
            let (wtx, wrx) = crossbeam_channel::unbounded::<CarveEvent>();
            let log = log.clone();
            let handle = std::thread::spawn(move || {
                if let Err(e) = indexer_thread::run_live_writes(&log, wrx) {
                    tracing::warn!("live-mode index writer failed: {e:#}");
                }
            });
            (Some(wtx), Some(handle))
        }
        None => (None, None),
    };

    // Query-loop indexer thread. See `run_from_file` for details. Gated on
    // `main_log_path: Some(_)` since the thread needs an on-disk SQLite
    // file next to the `.bin` to answer queries against. Spawned before the
    // preview-outcomes writer so its `event_tx` clone can be shared with
    // the writer (which emits PreviewStatusVersion after each batch flush).
    let (query_cmd_tx, query_event_tx, query_event_rx, query_thread) =
        spawn_query_loop(main_log_path.as_ref());

    // Sibling writer for preview outcomes — see `run_from_file` for the
    // shape of the channel + thread. The `tx` clone given to the
    // ThumbWorker is dropped when the UI tears down, which lets this
    // writer see Disconnected and finalize its last batch. After each
    // SQLite flush the writer emits PreviewStatusVersion on the shared
    // event channel so the UI's hide_no_preview observer can debounce-
    // requery on a 1-second cadence.
    let (preview_outcomes_tx, preview_outcomes_handle): (
        Option<crossbeam_channel::Sender<thumb_worker::PreviewOutcome>>,
        Option<std::thread::JoinHandle<()>>,
    ) = match main_log_path.as_ref() {
        Some(log) => {
            let (ptx, prx) = crossbeam_channel::unbounded::<thumb_worker::PreviewOutcome>();
            let log = log.clone();
            let evt_tx = query_event_tx.clone();
            let handle = std::thread::spawn(move || {
                if let Err(e) = indexer_thread::run_preview_outcomes_writer(&log, prx, evt_tx) {
                    tracing::warn!("preview outcomes writer failed: {e:#}");
                }
            });
            (Some(ptx), Some(handle))
        }
        None => (None, None),
    };

    // Drop the local clone we kept just to share with the writer thread.
    drop(query_event_tx);

    // Spawn the engine-event receive thread. We capture its handle so the
    // writer_tx it owns can be dropped deterministically before we join
    // the writer thread on the way out of `run_live`.
    let recv_handle = std::thread::spawn(move || {
        while let Ok(ev) = rx.recv() {
            // Fan-out to the writer thread first so the on-disk index lags
            // the VM by at most one batch boundary.
            if let Some(tx) = &writer_tx {
                let _ = tx.send(ev.clone());
            }
            {
                let mut v = vm_for_thread.lock().unwrap();
                v.apply(&ev);
                v.recompute_visible();
            }
            // On RunFinished, fold any staged annotation events into the main log.
            if matches!(ev, CarveEvent::RunFinished { .. })
                && let Some(ref j) = journal_for_thread
                && let Err(e) = j.fold()
            {
                tracing::warn!("journal fold at RunFinished failed: {e}");
            }
            // Wake the Slint event loop so it re-syncs via the timer.
            let _ = slint::invoke_from_event_loop(|| {});
        }
        // Sender on rx hung up; dropping `writer_tx` here closes the writer
        // channel and lets the writer thread exit cleanly after its final
        // flush.
    });

    let ui_result = launch_ui_with_journal(
        vm,
        journal,
        vec![],
        main_log_path,
        None,
        perf,
        preview_outcomes_tx,
        query_cmd_tx.clone(),
        query_event_rx,
    );

    // The Slint event loop has exited. Wait for the engine's send side of
    // `rx` to hang up so the receive thread can drop its `writer_tx`, then
    // wait for the writer thread to perform its final flush. Without these
    // joins the process can exit while the writer is still in its 200ms
    // timer window, losing up to 50 events from the SQLite cache.
    let _ = recv_handle.join();
    if let Some(h) = writer_handle {
        let _ = h.join();
    }
    if let Some(h) = preview_outcomes_handle {
        let _ = h.join();
    }
    shutdown_query_loop(query_cmd_tx, query_thread);

    ui_result
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
pub(crate) fn spawn_query_loop(main_log_path: Option<&PathBuf>) -> QueryLoopHandles {
    let Some(log) = main_log_path else {
        return (None, None, None, None);
    };
    let (cmd_tx, cmd_rx) = crossbeam_channel::unbounded::<indexer_thread::IndexerCommand>();
    let (event_tx, event_rx) = crossbeam_channel::unbounded::<indexer_thread::IndexerEvent>();
    let event_tx_for_loop = event_tx.clone();
    let log = log.clone();
    let handle = std::thread::spawn(move || {
        if let Err(e) = indexer_thread::run_query_loop(log, cmd_rx, event_tx_for_loop) {
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

#[allow(clippy::too_many_arguments)]
fn launch_ui_with_journal(
    vm: Arc<Mutex<ViewModel>>,
    journal: Option<Arc<journal::Journal>>,
    source_search_locations: Vec<PathBuf>,
    event_log_path: Option<PathBuf>,
    indexer_rx: Option<crossbeam_channel::Receiver<indexer_thread::IndexProgress>>,
    perf: Arc<telemetry::PerfRecorder>,
    preview_outcomes_tx: Option<crossbeam_channel::Sender<thumb_worker::PreviewOutcome>>,
    query_cmd_tx: Option<crossbeam_channel::Sender<indexer_thread::IndexerCommand>>,
    query_event_rx: Option<crossbeam_channel::Receiver<indexer_thread::IndexerEvent>>,
) -> Result<()> {
    use slint::ComponentHandle;
    let window = slint_adapter::MainWindow::new()?;
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
    )?;
    // Install the journal so annotation callbacks can persist events.
    if let Some(j) = journal {
        ui.set_journal(j);
    }
    // Post an initial Requery so the query-loop thread populates `match_ids`
    // even when no filter/sort callback has fired yet. The query loop reads
    // the SQLite index that the indexer writer is concurrently filling, so
    // this works both for hot hydrate (rows already present) and cold
    // rebuild (rows arriving as the writer catches up; subsequent ticks
    // will issue more Requeries as filter/sort change, picking up new rows).
    if let Some(tx) = &query_cmd_tx {
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
    // Hold the UiState in an `Rc` so the timer closure (UI-thread only) can re-sync.
    let ui_rc = std::rc::Rc::new(ui);
    let weak_ui = std::rc::Rc::downgrade(&ui_rc);
    let vm_for_timer = vm.clone();
    let timer = slint::Timer::default();
    timer.start(
        slint::TimerMode::Repeated,
        std::time::Duration::from_millis(100),
        move || {
            if let Some(ui) = weak_ui.upgrade() {
                // Drain the recovery worker channel (if active) into the VM.
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
    ui_rc.window.run()?;
    drop(timer);
    Ok(())
}
