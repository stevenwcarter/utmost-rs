//! Per-case runtime state. One CaseHandle for the case currently open
//! in the picker; created by [`open_case`], destroyed by [`close_case`].

use anyhow::Result;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crossbeam_channel::{Receiver, Sender};

use crate::indexer_thread::{IndexerCommand, IndexerEvent};
use crate::journal::Journal;
use crate::thumb_worker::PreviewOutcome;
use crate::view_model::ViewModel;

/// Where a case's events.bin lives. Single-variant for now; kept as an
/// enum so future variants (e.g. remote URL) have a place to land.
pub enum CaseSource {
    Historical(PathBuf),
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
    pub shutdown_signal: Arc<AtomicBool>,
    /// The indexer writer thread (filled by `indexer_thread::spawn`).
    /// Task 8 wires this into the UI progress display.
    #[allow(dead_code)]
    pub indexer_writer_thread: Option<JoinHandle<()>>,
    /// Progress receiver from the indexer writer thread.
    /// Task 8 wires this into the UI progress overlay.
    #[allow(dead_code)]
    pub indexer_progress_rx: Option<Receiver<crate::indexer_thread::IndexProgress>>,
    /// Snapshot of the case's UI state as it was when the case was last
    /// closed (or `None` for first-ever open / corrupt blob / missing key).
    /// Taken by `run_picker` and handed to `UiState::new` for hydration.
    pub ui_state_on_open: Option<crate::view_model::UiStateSnapshot>,
}

/// Open a case: set up all per-case threads (query loop, preview-outcomes
/// writer, indexer writer) and return a [`CaseHandle`] that owns them.
/// The caller hands the handle to [`close_case`] when the user closes the case.
pub fn open_case(source: CaseSource, _source_search_locations: &[PathBuf]) -> Result<CaseHandle> {
    use crate::indexer_thread;
    use crate::journal;
    use crate::picker;
    use crate::view_model;

    let CaseSource::Historical(events_bin) = &source;
    let events_bin = events_bin.clone();
    let sqlite_path = picker::sqlite_path_for(&events_bin);

    // Read the persisted UI state, if any. Done synchronously here because the
    // picker hands ui_state_on_open into UiState::new before it posts the first
    // Requery — there's no race between hydration and the first match-ids response.
    let ui_state_on_open: Option<crate::view_model::UiStateSnapshot> = {
        match crate::index_db::IndexDb::open(&sqlite_path) {
            Ok(mut tmp_db) => {
                crate::index_db::writer::read_ui_state(tmp_db.conn()).unwrap_or_else(|e| {
                    tracing::warn!("read_ui_state in open_case failed: {e:#}");
                    None
                })
            }
            Err(e) => {
                tracing::warn!("opening IndexDb for ui_state read failed: {e:#}");
                None
            }
        }
    };

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
    //    The shared shutdown_signal lets close_case ask the writer to stop
    //    mid-fold rather than blocking on the full events.bin scan; the
    //    writer flushes any pending batch on cancel so a later open
    //    Resumes from where we stopped.
    let shutdown_signal = Arc::new(AtomicBool::new(false));
    let (progress_tx, progress_rx) =
        crossbeam_channel::unbounded::<indexer_thread::IndexProgress>();
    let writer_thread = indexer_thread::spawn(
        events_bin.clone(),
        vm.clone(),
        progress_tx,
        shutdown_signal.clone(),
    );

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
        shutdown_signal,
        indexer_writer_thread: Some(writer_thread),
        indexer_progress_rx: Some(progress_rx),
        ui_state_on_open,
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

    // 4) Journal: last Arc reference goes out of scope → file closed.
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

    #[test]
    fn open_case_returns_persisted_ui_state_when_present() {
        use crate::view_model::{FilterStateSnapshot, UiStateSnapshot};
        let tmp = TempDir::new().unwrap();
        let log = tmp.path().join("t-events.bin");
        write_minimal_events_bin(&log);

        // First open: nothing persisted yet → ui_state_on_open is None.
        let h1 = open_case(CaseSource::Historical(log.clone()), &[]).expect("first open");
        assert!(
            h1.ui_state_on_open.is_none(),
            "first open has no prior state"
        );
        let sqlite_path = h1.sqlite_path.clone();
        close_case(h1).expect("first close");

        // Seed a snapshot directly into sqlite to simulate "the user did things
        // last time, debounced save fired, close_case landed the final flush."
        {
            let mut db = crate::index_db::IndexDb::open(&sqlite_path).expect("reopen sqlite");
            let snap = UiStateSnapshot {
                v: 1,
                filter: FilterStateSnapshot {
                    enabled_types: vec!["jpeg".into()],
                    enabled_partial_types: vec![],
                    bookmarked_only: true,
                    source_filter: None,
                    sort_key: "Filename".into(),
                    sort_dir: "Asc".into(),
                    bookmarked_first: false,
                    hide_no_preview: false,
                    size_range: None,
                },
                filters_visible: false,
                selected_group: Some("image".into()),
                selection_file_id: Some(7),
            };
            crate::index_db::writer::write_ui_state(db.conn(), &snap).unwrap();
        }

        // Second open: ui_state_on_open populated with what we wrote.
        let h2 = open_case(CaseSource::Historical(log.clone()), &[]).expect("second open");
        let got = h2
            .ui_state_on_open
            .as_ref()
            .expect("persisted snapshot present");
        assert_eq!(got.selection_file_id, Some(7));
        assert!(got.filter.bookmarked_only);
        assert_eq!(got.selected_group.as_deref(), Some("image"));
        close_case(h2).expect("second close");
    }
}
