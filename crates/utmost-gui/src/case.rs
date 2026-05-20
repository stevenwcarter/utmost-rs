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
    #[allow(dead_code)]
    pub vm_event_tx: Option<Sender<CarveEvent>>,
    pub shutdown_signal: Arc<AtomicBool>,
    /// The indexer writer thread (filled by `indexer_thread::spawn`).
    /// Task 8 wires this into the UI progress display.
    #[allow(dead_code)]
    pub indexer_writer_thread: Option<JoinHandle<()>>,
    /// Progress receiver from the indexer writer thread.
    /// Task 8 wires this into the UI progress overlay.
    #[allow(dead_code)]
    pub indexer_progress_rx: Option<Receiver<crate::indexer_thread::IndexProgress>>,
}

/// Open a case: set up all per-case threads (query loop, preview-outcomes
/// writer, indexer writer) and return a [`CaseHandle`] that owns them.
/// The caller hands the handle to [`close_case`] when the user closes the case.
pub fn open_case(source: CaseSource, _source_search_locations: &[PathBuf]) -> Result<CaseHandle> {
    use crate::indexer_thread;
    use crate::journal;
    use crate::picker;
    use crate::view_model;

    let events_bin = match &source {
        CaseSource::Historical(p) => p.clone(),
        CaseSource::Live { .. } => {
            anyhow::bail!("open_case: Live variant not yet supported (Plan 2)");
        }
    };
    let sqlite_path = picker::sqlite_path_for(&events_bin);

    let vm = Arc::new(Mutex::new(ViewModel::new()));

    // 1) Query loop (indexer thread that answers Requery / FetchWindow) +
    //    preview-outcomes writer. Mirror lib.rs spawn_query_loop against this
    //    single case's events.bin.
    let (query_cmd_tx_opt, query_event_tx_opt, query_event_rx_opt, query_thread_opt) =
        crate::spawn_query_loop(Some(&events_bin));

    // For an on-disk events.bin the channels are guaranteed Some.
    let indexer_cmd_tx = query_cmd_tx_opt.expect("query_cmd_tx Some for events.bin");
    let indexer_event_rx = query_event_rx_opt.expect("query_event_rx Some for events.bin");
    let indexer_event_tx = query_event_tx_opt.expect("query_event_tx Some for events.bin");

    // Preview-outcomes writer: clone the event_tx so it can emit PreviewStatusVersion.
    let (preview_outcomes_tx, preview_writer_thread) = {
        let (ptx, prx) = crossbeam_channel::unbounded::<PreviewOutcome>();
        let log = events_bin.clone();
        let evt_tx_clone = indexer_event_tx.clone();
        let handle = std::thread::spawn(move || {
            if let Err(e) =
                indexer_thread::run_preview_outcomes_writer(&log, prx, Some(evt_tx_clone))
            {
                tracing::warn!("preview outcomes writer failed: {e:#}");
            }
        });
        (Some(ptx), Some(handle))
    };
    // The original event_tx clone we got from spawn_query_loop is no longer
    // needed here — we kept it just long enough to hand a clone to the writer.
    drop(indexer_event_tx);

    // 2) Journal recovery — replay any annotations crashed before fold.
    let journal = Arc::new(journal::Journal::for_main_log(&events_bin));
    let recovered_events = match journal.recover_on_open() {
        Ok(evs) => evs,
        Err(e) => {
            tracing::warn!("journal recover_on_open failed: {e}");
            Vec::new()
        }
    };
    for ev in &recovered_events {
        vm.lock().unwrap().apply(ev);
    }

    // 3) Spawn the indexer **writer** thread for this case's events.bin.
    //    indexer_thread::spawn(path, vm, tx) -> JoinHandle<()> that fills
    //    SQLite from the events.bin and emits IndexProgress on `progress_tx`.
    let (progress_tx, progress_rx) =
        crossbeam_channel::unbounded::<indexer_thread::IndexProgress>();
    let writer_thread = indexer_thread::spawn(events_bin.clone(), vm.clone(), progress_tx);

    // 4) Tag any in-flight Running status from previous session recovery as
    //    Interrupted (mirrors lib.rs:123-134). The new indexer run will
    //    overwrite status as it progresses.
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

    // Live cases are plan 2; the vm_event_tx slot stays None for Historical.
    let vm_event_tx = None;

    let shutdown_signal = Arc::new(AtomicBool::new(false));

    Ok(CaseHandle {
        events_bin,
        sqlite_path,
        vm,
        indexer_cmd_tx,
        indexer_event_rx,
        indexer_thread: query_thread_opt,
        preview_writer_thread,
        preview_outcomes_tx,
        journal: Some(journal),
        vm_event_tx,
        shutdown_signal,
        indexer_writer_thread: Some(writer_thread),
        indexer_progress_rx: Some(progress_rx),
    })
}

/// Tear down a case: shut down all threads in order and wait for them to exit.
pub fn close_case(handle: CaseHandle) -> Result<()> {
    use std::sync::atomic::Ordering;

    // Signal shutdown so any future cooperation point can observe it.
    handle.shutdown_signal.store(true, Ordering::Relaxed);

    // 1) Use the existing shutdown_query_loop helper to send Shutdown + drop
    //    tx + join.
    crate::shutdown_query_loop(Some(handle.indexer_cmd_tx), handle.indexer_thread);
    // indexer_event_rx is dropped here when its binding goes out of scope.
    drop(handle.indexer_event_rx);

    // 2) Drop the preview-outcomes sender so the writer thread sees
    //    Disconnected and exits its loop. Then join.
    drop(handle.preview_outcomes_tx);
    if let Some(t) = handle.preview_writer_thread
        && let Err(e) = t.join()
    {
        tracing::warn!("preview writer thread join panicked: {e:?}");
    }

    // 3) Indexer writer thread: it owns its own progress sender; the writer
    //    exits naturally when it's done reading the events.bin (or on error).
    //    Wait for it to finish so we don't leak the thread.
    drop(handle.indexer_progress_rx); // close our receiver first; thread doesn't block on it
    if let Some(t) = handle.indexer_writer_thread
        && let Err(e) = t.join()
    {
        tracing::warn!("indexer writer thread join panicked: {e:?}");
    }

    // 4) Drop live forwarding sender (no-op for Historical).
    drop(handle.vm_event_tx);

    // 5) Journal: last Arc reference goes out of scope → file closed.
    drop(handle.journal);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use utmost_lib::EventSink;
    use utmost_lib::events::{BincodeFileSink, CarveEvent, CliConfigSnapshot, SourceDescriptor};
    use utmost_lib::types::{ExecutionEnvironment, FileType};

    fn write_minimal_events_bin(path: &std::path::Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let sink = BincodeFileSink::create(path).expect("create sink");
        sink.emit(&CarveEvent::RunStarted {
            utmost_version: "test".into(),
            format_version: 1,
            started_at: "2026-05-20T00:00:00Z".into(),
            command_line: vec![],
            working_directory: "/".into(),
            execution_environment: ExecutionEnvironment {
                os_sysname: "linux".into(),
                os_release: "6.0".into(),
                os_version: "1".into(),
                host: "h".into(),
                arch: "x86_64".into(),
                uid: 0,
                start_time: "2026-05-20T00:00:00Z".into(),
            },
            cli_config: CliConfigSnapshot {
                output_directory: "/out".into(),
                types: vec![],
                disable_builtin: false,
                config_file: None,
                concurrent_files: 1,
                disable_validation: false,
                report_only: false,
                disable_report: false,
                disable_audit: false,
                disable_export: false,
                gui_enabled: false,
                quick: false,
                block_size: 512,
                prefix_filenames: false,
                write_all: false,
                keep_incomplete_jpeg: false,
            },
            case: None,
            configured_types: vec![FileType::Jpeg],
            sources: vec![SourceDescriptor {
                source_id: 0,
                filename: "/in/t.img".into(),
                total_bytes: 0,
                output_subdir: "t".into(),
            }],
            output_root: "/out".into(),
        });
        // drop flushes BufWriter
    }

    #[test]
    fn open_case_starts_with_default_view_model() {
        let tmp = TempDir::new().unwrap();
        let log = tmp.path().join("t-events.bin");
        write_minimal_events_bin(&log);

        let handle = open_case(CaseSource::Historical(log.clone()), &[]).expect("open_case");

        // Verify the VM starts at defaults: no bookmarks, no selection.
        // (sources may be populated by the indexer writer thread racing,
        //  but bookmarks and selection are always empty at ViewModel::new().)
        {
            let vm = handle.vm.lock().unwrap();
            assert!(vm.bookmarks.is_empty(), "fresh VM should have no bookmarks");
            assert_eq!(vm.selection, None, "fresh VM should have no selection");
        }

        close_case(handle).expect("close_case");
    }

    #[test]
    fn reopening_same_case_starts_fresh() {
        let tmp = TempDir::new().unwrap();
        let log = tmp.path().join("t-events.bin");
        write_minimal_events_bin(&log);

        // First open: mutate VM state to simulate in-session user actions.
        let handle = open_case(CaseSource::Historical(log.clone()), &[]).expect("first open");
        {
            let mut vm = handle.vm.lock().unwrap();
            vm.bookmarks.insert(42 as crate::view_model::FileId);
            vm.selection = Some(99 as crate::view_model::FileId);
        }
        close_case(handle).expect("first close");

        // Second open of the same case in the same process: must start fresh.
        let handle2 = open_case(CaseSource::Historical(log.clone()), &[]).expect("second open");
        {
            let vm = handle2.vm.lock().unwrap();
            assert!(
                !vm.bookmarks.contains(&(42 as crate::view_model::FileId)),
                "second open must not inherit bookmarks from first"
            );
            assert_eq!(
                vm.selection, None,
                "second open must not inherit selection from first"
            );
        }
        close_case(handle2).expect("second close");
    }
}
