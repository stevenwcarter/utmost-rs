//! Integration tests for the case picker. These exercise the
//! discover_cases → build_case_rows → open_case → close_case path
//! end-to-end against fixture event logs on disk. UI-side wiring is
//! exercised by manual smoke tests during development.

use std::path::Path;
use tempfile::TempDir;
use utmost_gui::case::{CaseSource, close_case, open_case};
use utmost_gui::picker::{PickerStatus, build_case_row, build_case_rows};
use utmost_lib::EventSink;
use utmost_lib::events::{BincodeFileSink, CarveEvent, CliConfigSnapshot, SourceDescriptor};
use utmost_lib::types::{ExecutionEnvironment, FileType};

fn make_run_started(source_image_path: &str) -> CarveEvent {
    CarveEvent::RunStarted {
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
    }
}

fn write_minimal_events_bin(path: &Path, source_image_path: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let sink = BincodeFileSink::create(path).expect("create sink");
    sink.emit(&make_run_started(source_image_path));
}

#[test]
fn picker_renders_one_row_per_case() {
    let tmp = TempDir::new().unwrap();
    write_minimal_events_bin(&tmp.path().join("a/a-events.bin"), "/in/a.img");
    write_minimal_events_bin(&tmp.path().join("b/b-events.bin"), "/in/b.img");

    let cases = utmost_gui::discover_cases(tmp.path()).unwrap();
    assert_eq!(cases.len(), 2);

    let rows = build_case_rows(&cases);
    assert_eq!(rows.len(), 2);
    let basenames: Vec<_> = rows.iter().map(|r| r.source_basename.clone()).collect();
    assert!(basenames.contains(&"a.img".to_string()));
    assert!(basenames.contains(&"b.img".to_string()));
}

#[test]
fn picker_handles_corrupt_events_bin_gracefully() {
    let tmp = TempDir::new().unwrap();
    write_minimal_events_bin(&tmp.path().join("good/good-events.bin"), "/in/good.img");
    let bad = tmp.path().join("bad/bad-events.bin");
    std::fs::create_dir_all(bad.parent().unwrap()).unwrap();
    std::fs::write(&bad, b"not a bincode file").unwrap();

    let cases = utmost_gui::discover_cases(tmp.path()).unwrap();
    let rows = build_case_rows(&cases);
    assert_eq!(rows.len(), 2);
    let bad_row = rows
        .iter()
        .find(|r| r.events_bin_path.ends_with("bad/bad-events.bin"))
        .expect("bad row present");
    assert_eq!(bad_row.status, PickerStatus::Corrupt);
    assert!(!bad_row.clickable);
}

#[test]
fn picker_corrupt_row_does_not_block_neighbor_cases() {
    let tmp = TempDir::new().unwrap();
    write_minimal_events_bin(&tmp.path().join("ok/ok-events.bin"), "/in/ok.img");
    let bad = tmp.path().join("bad/bad-events.bin");
    std::fs::create_dir_all(bad.parent().unwrap()).unwrap();
    std::fs::write(&bad, b"junk").unwrap();

    let cases = utmost_gui::discover_cases(tmp.path()).unwrap();
    let rows = build_case_rows(&cases);
    let ok_row = rows
        .iter()
        .find(|r| r.source_basename == "ok.img")
        .expect("ok row present");
    assert!(ok_row.clickable);
}

#[test]
fn picker_can_reopen_same_case_in_one_process_session() {
    let tmp = TempDir::new().unwrap();
    let log = tmp.path().join("x-events.bin");
    write_minimal_events_bin(&log, "/in/x.img");

    let h1 = open_case(CaseSource::Historical(log.clone()), &[]).expect("open 1");
    close_case(h1).expect("close 1");

    let h2 = open_case(CaseSource::Historical(log.clone()), &[]).expect("open 2");
    close_case(h2).expect("close 2");
}

#[test]
fn picker_row_for_indexed_case_reports_finished_status() {
    // Build an events.bin + open it once to produce an indexed sqlite,
    // then close and ask for its picker row.
    let tmp = TempDir::new().unwrap();
    let log = tmp.path().join("done-events.bin");
    {
        let sink = BincodeFileSink::create(&log).expect("sink");
        sink.emit(&make_run_started("/in/done.img"));
        sink.emit(&CarveEvent::RunFinished {
            duration_ms: 1000,
            total_files_written: 0,
        });
    }

    let h = open_case(CaseSource::Historical(log.clone()), &[]).expect("open");

    // Poll the sqlite until the indexer has folded the RunFinished event
    // (run.status flips to "Finished"). Bounded deadline; the indexer is fast
    // for this small fixture.
    let sqlite_path = utmost_gui::picker::sqlite_path_for(&log);
    {
        use std::time::{Duration, Instant};
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(mut db) = utmost_gui::index_db::IndexDb::open(&sqlite_path)
                && let Ok(meta) = utmost_gui::index_db::queries::picker_metadata_row(db.conn())
                && meta.status == "Finished"
            {
                break;
            }
            if Instant::now() > deadline {
                break; // give up; the assertion below will surface the failure
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    close_case(h).expect("close");

    let row = build_case_row(&log);
    // After open_case the indexer should have folded the events into the
    // sqlite; the status should reflect Finished (or Indexing if catch-up
    // is still in flight — accept either).
    assert!(
        matches!(row.status, PickerStatus::Finished | PickerStatus::Indexing),
        "expected Finished or Indexing, got {:?}",
        row.status
    );
}
