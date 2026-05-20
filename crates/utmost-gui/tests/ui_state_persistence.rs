//! Integration tests for per-case UI-state persistence. Drive the
//! open_case / write_ui_state / close_case path without standing up
//! a Slint event loop (which is hard to test headlessly).

use tempfile::TempDir;
use utmost_gui::case::{CaseSource, close_case, open_case};
use utmost_gui::indexer_thread::IndexerCommand;
use utmost_gui::view_model::{FilterStateSnapshot, UiStateSnapshot};
use utmost_lib::EventSink;
use utmost_lib::events::{BincodeFileSink, CarveEvent, CliConfigSnapshot, SourceDescriptor};

fn write_minimal_events_bin(path: &std::path::Path, source_image_path: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let sink = BincodeFileSink::create(path).expect("create sink");
    sink.emit(&CarveEvent::RunStarted {
        utmost_version: "test".into(),
        format_version: 1,
        started_at: "2026-05-20T00:00:00Z".into(),
        command_line: vec![],
        working_directory: "/".into(),
        execution_environment: utmost_lib::types::ExecutionEnvironment {
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
        configured_types: vec![utmost_lib::types::FileType::Jpeg],
        sources: vec![SourceDescriptor {
            source_id: 0,
            filename: source_image_path.into(),
            total_bytes: 0,
            output_subdir: "s".into(),
        }],
        output_root: "/out".into(),
    });
}

#[test]
fn open_then_persist_then_reopen_restores_state() {
    let tmp = TempDir::new().unwrap();
    let log = tmp.path().join("t-events.bin");
    write_minimal_events_bin(&log, "/in/t.img");

    // 1) First open — no prior state.
    let h1 = open_case(CaseSource::Historical(log.clone()), &[]).expect("open 1");
    assert!(h1.ui_state_on_open.is_none());

    // 2) Send a PersistUiState command directly on the command channel,
    //    simulating what the debounced timer in UiState would do.
    let snap = UiStateSnapshot {
        v: 1,
        filter: FilterStateSnapshot {
            enabled_types: vec!["jpeg".into()],
            enabled_partial_types: vec![],
            bookmarked_only: true,
            source_filter: None,
            sort_key: "Size".into(),
            sort_dir: "Desc".into(),
            bookmarked_first: false,
            hide_no_preview: true,
            size_range: Some((100, 10_000)),
        },
        filters_visible: false,
        selected_group: Some("image".into()),
        selection_file_id: Some(42),
    };
    h1.indexer_cmd_tx
        .send(IndexerCommand::PersistUiState(snap.clone()))
        .expect("send PersistUiState");

    // 3) close_case sends Shutdown after PersistUiState, so the query
    //    loop processes both FIFO — persist lands before the thread exits.
    close_case(h1).expect("close 1");

    // 4) Second open — restored.
    let h2 = open_case(CaseSource::Historical(log.clone()), &[]).expect("open 2");
    let got = h2
        .ui_state_on_open
        .as_ref()
        .expect("snapshot present on second open");
    assert_eq!(got, &snap);
    close_case(h2).expect("close 2");
}

#[test]
fn last_writer_wins_for_queued_saves() {
    // If multiple PersistUiState commands are queued, the LAST one wins
    // (the upsert overwrites). Proves successive debounced saves
    // converge to the most recent state.
    let tmp = TempDir::new().unwrap();
    let log = tmp.path().join("t-events.bin");
    write_minimal_events_bin(&log, "/in/t.img");

    let h1 = open_case(CaseSource::Historical(log.clone()), &[]).expect("open");
    let make = |sort_key: &str| UiStateSnapshot {
        v: 1,
        filter: FilterStateSnapshot {
            enabled_types: vec![],
            enabled_partial_types: vec![],
            bookmarked_only: false,
            source_filter: None,
            sort_key: sort_key.into(),
            sort_dir: "Asc".into(),
            bookmarked_first: false,
            hide_no_preview: false,
            size_range: None,
        },
        filters_visible: true,
        selected_group: None,
        selection_file_id: None,
    };
    h1.indexer_cmd_tx
        .send(IndexerCommand::PersistUiState(make("Filename")))
        .unwrap();
    h1.indexer_cmd_tx
        .send(IndexerCommand::PersistUiState(make("Size")))
        .unwrap();
    h1.indexer_cmd_tx
        .send(IndexerCommand::PersistUiState(make("FileType")))
        .unwrap();
    close_case(h1).expect("close");

    let h2 = open_case(CaseSource::Historical(log.clone()), &[]).expect("reopen");
    let got = h2.ui_state_on_open.as_ref().expect("snapshot");
    assert_eq!(got.filter.sort_key, "FileType", "last writer wins");
    close_case(h2).expect("close");
}

#[test]
fn missing_meta_returns_none_on_first_open() {
    let tmp = TempDir::new().unwrap();
    let log = tmp.path().join("t-events.bin");
    write_minimal_events_bin(&log, "/in/t.img");

    let h = open_case(CaseSource::Historical(log.clone()), &[]).expect("open");
    assert!(h.ui_state_on_open.is_none());
    close_case(h).expect("close");
}
