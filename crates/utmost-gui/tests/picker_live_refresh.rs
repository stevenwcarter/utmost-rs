//! Integration tests for picker tail-reading behavior. Drive the
//! PickerRowTailer + state map without standing up a Slint event loop.

use std::path::Path;
use tempfile::TempDir;
use utmost_gui::picker::{PickerRowState, PickerRowTailer};
use utmost_lib::EventSink;
use utmost_lib::events::{BincodeFileSink, CarveEvent, CliConfigSnapshot, SourceDescriptor};
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::{ExecutionEnvironment, FileType};

fn write_minimal_events_bin(path: &Path, source_image_path: &str) {
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
            filename: source_image_path.into(),
            total_bytes: 0,
            output_subdir: "s".into(),
        }],
        output_root: "/out".into(),
    });
}

fn append_file_founds(path: &Path, n: u64) {
    let sink = BincodeFileSink::open_append(path).expect("append sink");
    for i in 1..=n {
        sink.emit(&CarveEvent::FileFound {
            source_id: 0,
            file: create_file_object("a.jpg", FileType::Jpeg, 0, 0, None, i),
            img_offset: 0,
            written_path: "a.jpg".into(),
        });
    }
}

#[test]
fn live_carve_picker_row_updates_as_events_arrive() {
    let tmp = TempDir::new().unwrap();
    let log = tmp.path().join("live-events.bin");
    write_minimal_events_bin(&log, "/in/live.img");

    let mut tailer = PickerRowTailer::open_fresh(&log).expect("open_fresh");
    assert_eq!(tailer.state.files_seen, 0);
    assert!(!tailer.state.finished);

    append_file_founds(&log, 5);
    assert!(tailer.poll());
    assert_eq!(tailer.state.files_seen, 5);
    assert!(!tailer.state.finished);

    append_file_founds(&log, 3);
    assert!(tailer.poll());
    assert_eq!(tailer.state.files_seen, 8);

    {
        let sink = BincodeFileSink::open_append(&log).expect("append");
        sink.emit(&CarveEvent::RunFinished {
            duration_ms: 100,
            total_files_written: 8,
        });
    }
    assert!(tailer.poll());
    assert!(tailer.state.finished);
}

#[test]
fn picker_corrupt_row_recovers_within_retry_budget() {
    let tmp = TempDir::new().unwrap();
    let log = tmp.path().join("late-events.bin");

    // File doesn't exist yet — open_fresh fails.
    assert!(PickerRowTailer::open_fresh(&log).is_none());

    let mut state = PickerRowState::for_retry(log.clone());
    assert_eq!(state.corrupt_retries_remaining, 3);

    state.corrupt_retries_remaining -= 1;
    assert!(PickerRowTailer::open_fresh(&log).is_none());
    state.corrupt_retries_remaining -= 1;
    assert!(PickerRowTailer::open_fresh(&log).is_none());

    // File appears on the third try.
    write_minimal_events_bin(&log, "/in/late.img");
    let tailer = PickerRowTailer::open_fresh(&log).expect("open_fresh after write");
    assert_eq!(tailer.state.source_path, "/in/late.img");
}

#[test]
fn picker_corrupt_row_stays_corrupt_after_retry_budget_exhausted() {
    let tmp = TempDir::new().unwrap();
    let log = tmp.path().join("never-events.bin");

    let mut state = PickerRowState::for_retry(log.clone());
    while state.corrupt_retries_remaining > 0 {
        assert!(PickerRowTailer::open_fresh(&log).is_none());
        state.corrupt_retries_remaining -= 1;
    }
    assert_eq!(state.corrupt_retries_remaining, 0);
    assert!(PickerRowTailer::open_fresh(&log).is_none());
}

#[test]
fn picker_tailer_resume_after_detail_view_round_trip() {
    let tmp = TempDir::new().unwrap();
    let log = tmp.path().join("resume-events.bin");
    write_minimal_events_bin(&log, "/in/resume.img");

    let mut tailer = PickerRowTailer::open_fresh(&log).expect("open_fresh");
    append_file_founds(&log, 5);
    tailer.poll();
    assert_eq!(tailer.state.files_seen, 5);
    let saved_state = tailer.state.clone();
    drop(tailer);

    append_file_founds(&log, 4);

    let mut tailer2 = PickerRowTailer::reopen(saved_state).expect("reopen");
    tailer2.poll();
    assert_eq!(tailer2.state.files_seen, 9, "reopen must not double-count");
}
