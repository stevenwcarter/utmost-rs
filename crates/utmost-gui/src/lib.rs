//! Slint GUI for utmost.

pub mod journal;
pub mod preview;
pub mod recovery;
pub mod slint_adapter;
pub mod thumb_worker;
pub mod view_model;

use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use utmost_lib::events::{BincodeFileReader, CarveEvent};

pub use view_model::ViewModel;

pub fn run_from_file(target: &Path) -> Result<()> {
    let vm = Arc::new(Mutex::new(ViewModel::new()));
    let files = resolve_sources(target)?;

    // For single-session journal support, pick the first resolved path as the
    // main log. Multi-session replay can be extended in a follow-up task.
    let main_log_path = files.first().cloned();

    for path in &files {
        let mut reader = BincodeFileReader::open(path)?;
        while let Some(ev) = reader.next_event()? {
            vm.lock().unwrap().apply(&ev);
        }
    }

    // Recover any annotations from a previous session that crashed before fold.
    let journal = main_log_path.map(|p| Arc::new(journal::Journal::for_main_log(&p)));
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

    {
        let mut v = vm.lock().unwrap();
        // If we never received a RunFinished and run status is still Running,
        // mark as Interrupted.
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
    launch_ui_with_journal(vm, journal)
}

pub fn run_live(
    rx: crossbeam_channel::Receiver<CarveEvent>,
    main_log_path: Option<std::path::PathBuf>,
) -> Result<()> {
    let vm = Arc::new(Mutex::new(ViewModel::new()));
    let journal = main_log_path.map(|p| Arc::new(journal::Journal::for_main_log(&p)));
    let journal_for_thread = journal.clone();
    let vm_for_thread = vm.clone();
    std::thread::spawn(move || {
        while let Ok(ev) = rx.recv() {
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
    });
    launch_ui_with_journal(vm, journal)
}

fn launch_ui_with_journal(
    vm: Arc<Mutex<ViewModel>>,
    journal: Option<Arc<journal::Journal>>,
) -> Result<()> {
    use slint::ComponentHandle;
    let ui = slint_adapter::UiState::new(vm.clone())?;
    // Install the journal so annotation callbacks can persist events.
    if let Some(j) = journal {
        ui.set_journal(j);
    }
    {
        let v = vm.lock().unwrap();
        ui.sync(&v);
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
                let v = vm_for_timer.lock().unwrap();
                ui.sync(&v);
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
        let direct = target.join("carve_events.bin");
        if direct.exists() {
            return Ok(vec![direct]);
        }
        let mut found = Vec::new();
        for entry in std::fs::read_dir(target)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_dir() {
                let candidate = p.join("carve_events.bin");
                if candidate.exists() {
                    found.push(candidate);
                }
            }
        }
        if !found.is_empty() {
            return Ok(found);
        }
    }
    anyhow::bail!("no carve_events.bin found at {}", target.display())
}
