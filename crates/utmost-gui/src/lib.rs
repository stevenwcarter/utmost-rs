//! Slint GUI for utmost.

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

use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use utmost_lib::events::CarveEvent;

pub use view_model::ViewModel;

pub fn run_from_file(target: &Path, source_search_locations: Vec<PathBuf>) -> Result<()> {
    let vm = Arc::new(Mutex::new(ViewModel::new()));
    let files = resolve_sources(target)?;

    // For single-session journal support, pick the first resolved path as the
    // main log. Multi-session replay can be extended in a follow-up task.
    let main_log_path = files.first().cloned();

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
    launch_ui_with_journal(
        vm,
        journal,
        source_search_locations,
        main_log_path,
        Some(rx),
    )
}

pub fn run_live(
    rx: crossbeam_channel::Receiver<CarveEvent>,
    main_log_path: Option<std::path::PathBuf>,
) -> Result<()> {
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

    let ui_result = launch_ui_with_journal(vm, journal, vec![], main_log_path, None);

    // The Slint event loop has exited. Wait for the engine's send side of
    // `rx` to hang up so the receive thread can drop its `writer_tx`, then
    // wait for the writer thread to perform its final flush. Without these
    // joins the process can exit while the writer is still in its 200ms
    // timer window, losing up to 50 events from the SQLite cache.
    let _ = recv_handle.join();
    if let Some(h) = writer_handle {
        let _ = h.join();
    }

    ui_result
}

fn launch_ui_with_journal(
    vm: Arc<Mutex<ViewModel>>,
    journal: Option<Arc<journal::Journal>>,
    source_search_locations: Vec<PathBuf>,
    event_log_path: Option<PathBuf>,
    indexer_rx: Option<crossbeam_channel::Receiver<indexer_thread::IndexProgress>>,
) -> Result<()> {
    use slint::ComponentHandle;
    let ui = slint_adapter::UiState::new(
        vm.clone(),
        source_search_locations,
        event_log_path,
        indexer_rx,
    )?;
    // Install the journal so annotation callbacks can persist events.
    if let Some(j) = journal {
        ui.set_journal(j);
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

fn resolve_sources(target: &Path) -> Result<Vec<PathBuf>> {
    if target.is_file() {
        return Ok(vec![target.to_path_buf()]);
    }
    if target.is_dir() {
        if let Some(direct) = find_events_bin_in(target)? {
            return Ok(vec![direct]);
        }
        let mut found = Vec::new();
        for entry in std::fs::read_dir(target)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_dir()
                && let Some(candidate) = find_events_bin_in(&p)?
            {
                found.push(candidate);
            }
        }
        if !found.is_empty() {
            return Ok(found);
        }
    }
    anyhow::bail!("no <stem>-events.bin found at {}", target.display())
}

fn find_events_bin_in(dir: &Path) -> Result<Option<PathBuf>> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_file()
            && let Some(name) = p.file_name().and_then(|n| n.to_str())
            && name.ends_with("-events.bin")
        {
            return Ok(Some(p));
        }
    }
    Ok(None)
}

#[doc(hidden)]
pub fn resolve_sources_for_test(target: &Path) -> Result<Vec<PathBuf>> {
    resolve_sources(target)
}
