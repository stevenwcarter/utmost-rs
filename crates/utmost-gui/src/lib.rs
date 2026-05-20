//! Slint GUI for utmost.

mod discover;
pub mod index_db;
pub mod indexer_thread;
pub mod journal;
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
    // Bound to a named local so the `WorkerGuard` lives for the whole session.
    let _telemetry = init_telemetry();
    let perf = _telemetry.perf.clone();
    let vm = Arc::new(Mutex::new(ViewModel::new()));
    let files = discover_cases(target)?;

    // For single-session journal support, pick the first resolved path as the
    // main log. Multi-session replay can be extended in a follow-up task.
    let main_log_path = files.first().cloned();

    // Query-loop indexer thread: owns its own !Send `IndexDb` connection
    // and answers `Requery` / `FetchWindow` commands. The UI bumps the
    // VM's epoch and posts `Requery` on filter/sort mutations; the sync
    // tick drains `MatchIds` + `WindowFilled` responses from `query_event_rx`.
    // Spawned before the preview-outcomes writer so its `event_tx` clone
    // can be shared with the writer (which emits PreviewStatusVersion
    // after each batch flush).
    let (query_cmd_tx, query_event_tx, query_event_rx, query_thread) =
        spawn_query_loop(main_log_path.as_ref());

    // Preview-outcome channel: the ThumbWorker emits one `PreviewOutcome` per
    // terminal decode attempt; a sibling writer thread batches them into the
    // SQLite `file.preview_status` column, bumps `preview_status_version`,
    // and broadcasts the new version via the shared event channel so the
    // UI's hide_no_preview observer can refresh on a 1-second debounce.
    // Only enabled when there's a known main log to write against.
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

    // Recover any annotations from a previous session that crashed before fold.
    let journal = main_log_path
        .as_ref()
        .map(|p| Arc::new(journal::Journal::for_main_log(p)));
    if let Some(ref j) = journal {
        let recovered_events = match j.recover_on_open() {
            Ok(evs) => evs,
            Err(e) => {
                tracing::warn!("journal recover_on_open failed: {e}");
                Vec::new()
            }
        };
        for ev in &recovered_events {
            vm.lock().unwrap().apply(ev);
        }
    }

    // Spawn the indexer on a background thread. The receiver is handed to the
    // UI so the periodic 100 ms timer can drain progress messages and drive
    // the indexing overlay. Sources are still processed sequentially within
    // the worker thread; we share a single tx across sources so the UI sees
    // one continuous progress stream.
    let (tx, rx) = crossbeam_channel::unbounded();
    let vm_for_indexer = vm.clone();
    let files_for_indexer = files.clone();
    std::thread::spawn(move || {
        for path in files_for_indexer {
            let handle = indexer_thread::spawn(path, vm_for_indexer.clone(), tx.clone());
            let _ = handle.join();
        }
        // Sender drops here; the UI drain sees Finished/error per file and
        // (when all senders are gone) try_recv yields Disconnected which the
        // adapter treats the same as "no more messages".
    });

    // Tag any in-flight Running status from previous session recovery as
    // Interrupted. The new indexer run will overwrite status as it progresses.
    {
        let mut v = vm.lock().unwrap();
        if matches!(v.run.status, view_model::RunStatus::Running) {
            v.run.status = view_model::RunStatus::Interrupted;
            for s in v.sources.iter_mut() {
                if matches!(s.status, view_model::SourceStatus::Running) {
                    s.status = view_model::SourceStatus::Interrupted;
                }
            }
        }
        v.recompute_visible();
    }
    let ui_result = launch_ui_with_journal(
        vm,
        journal,
        source_search_locations,
        main_log_path,
        Some(rx),
        perf,
        preview_outcomes_tx,
        query_cmd_tx.clone(),
        query_event_rx,
    );
    // Drop our handle to the preview-outcomes channel via the UI teardown,
    // then wait for the sibling writer thread to finish its final flush so
    // no preview_status updates are lost on shutdown. The `tx` clone given
    // to the ThumbWorker is dropped when `ui_result` returns (UiState owns
    // the ThumbWorker), so the writer sees Disconnected and exits.
    if let Some(h) = preview_outcomes_handle {
        let _ = h.join();
    }
    shutdown_query_loop(query_cmd_tx, query_thread);
    ui_result
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
type QueryLoopHandles = (
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
fn spawn_query_loop(main_log_path: Option<&PathBuf>) -> QueryLoopHandles {
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
fn shutdown_query_loop(
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
    let ui = slint_adapter::UiState::new(
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
