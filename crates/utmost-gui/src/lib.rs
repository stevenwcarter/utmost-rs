//! Slint GUI for utmost.

pub mod preview;
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
    for path in &files {
        let mut reader = BincodeFileReader::open(path)?;
        while let Some(ev) = reader.next_event()? {
            vm.lock().unwrap().apply(&ev);
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
    launch_ui(vm)
}

pub fn run_live(rx: crossbeam_channel::Receiver<CarveEvent>) -> Result<()> {
    let vm = Arc::new(Mutex::new(ViewModel::new()));
    let vm_for_thread = vm.clone();
    std::thread::spawn(move || {
        while let Ok(ev) = rx.recv() {
            let mut v = vm_for_thread.lock().unwrap();
            v.apply(&ev);
            v.recompute_visible();
            // Wake the Slint event loop so it re-syncs via the timer.
            let _ = slint::invoke_from_event_loop(|| {});
        }
    });
    launch_ui(vm)
}

fn launch_ui(vm: Arc<Mutex<ViewModel>>) -> Result<()> {
    use slint::ComponentHandle;
    let ui = slint_adapter::UiState::new(vm.clone())?;
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
