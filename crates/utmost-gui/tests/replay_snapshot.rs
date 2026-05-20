//! Drives the view-model with a synthetic event sequence persisted via
//! BincodeFileSink + read back via BincodeFileReader. Asserts the final
//! view-model state matches expectations.

use utmost_gui::view_model::{RunStatus, SourceStatus, ViewModel};
use utmost_lib::events::*;
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::FileType;

fn empty_env() -> utmost_lib::types::ExecutionEnvironment {
    utmost_lib::types::ExecutionEnvironment {
        os_sysname: String::new(),
        os_release: String::new(),
        os_version: String::new(),
        host: String::new(),
        arch: String::new(),
        uid: 0,
        start_time: String::new(),
    }
}

fn empty_cli() -> CliConfigSnapshot {
    CliConfigSnapshot {
        output_directory: "out".into(),
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
    }
}

#[test]
fn replay_produces_expected_view_model() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.bin");
    let sink = BincodeFileSink::create(&path).unwrap();

    let run = CarveEvent::RunStarted {
        utmost_version: "t".into(),
        format_version: CURRENT_FORMAT_VERSION,
        started_at: "t".into(),
        command_line: vec![],
        working_directory: "/".into(),
        execution_environment: empty_env(),
        cli_config: empty_cli(),
        case: None,
        configured_types: vec![FileType::Jpeg],
        sources: vec![SourceDescriptor {
            source_id: 0,
            filename: "src.bin".into(),
            total_bytes: 1000,
            output_subdir: String::new(),
        }],
        output_root: "out".into(),
    };
    use utmost_lib::events::EventSink;
    sink.emit(&run);
    sink.emit(&CarveEvent::SourceStarted { source_id: 0 });
    let fo = create_file_object("a.jpg", FileType::Jpeg, 1024, 0, None, 1);
    sink.emit(&CarveEvent::FileFound {
        source_id: 0,
        file: fo,
        img_offset: 0,
        written_path: "a.jpg".into(),
    });
    sink.emit(&CarveEvent::ProgressTick {
        source_id: 0,
        bytes_read: 500,
    });
    sink.emit(&CarveEvent::SourceFinished {
        source_id: 0,
        bytes_read: 1000,
        duration_ms: 10,
    });
    sink.emit(&CarveEvent::RunFinished {
        duration_ms: 20,
        total_files_written: 1,
    });
    drop(sink);

    let mut reader = BincodeFileReader::open(&path).unwrap();
    let mut vm = ViewModel::new();
    while let Some(ev) = reader.next_event().unwrap() {
        vm.apply(&ev);
    }

    assert_eq!(vm.run.status, RunStatus::Finished);
    assert_eq!(vm.sources.len(), 1);
    assert_eq!(vm.sources[0].status, SourceStatus::Finished);
    // Task 12: vm.files is gone; the derived `run.total_files` counter
    // covers the per-event file accounting.
    assert_eq!(vm.run.total_files, 1);
}

#[test]
fn lightbox_select_open_navigate_esc_sequence() {
    use utmost_gui::index_db::queries::FileStub;
    use utmost_gui::view_model::{FoundFile, ViewModel};

    let mut vm = ViewModel::new();

    // Synthesize a single-source run with three JPEGs.
    let run = CarveEvent::RunStarted {
        utmost_version: "t".into(),
        format_version: CURRENT_FORMAT_VERSION,
        started_at: "t".into(),
        command_line: vec![],
        working_directory: "/".into(),
        execution_environment: empty_env(),
        cli_config: empty_cli(),
        case: None,
        configured_types: vec![FileType::Jpeg],
        sources: vec![SourceDescriptor {
            source_id: 0,
            filename: "src.bin".into(),
            total_bytes: 1000,
            output_subdir: String::new(),
        }],
        output_root: "out".into(),
    };
    vm.apply(&run);
    // Task 13: synthesize the indexer's Requery + FetchWindow response
    // directly so we can drive lightbox navigation without spinning up the
    // query-loop thread. Each file gets a stub for match_ids and a
    // FoundFile for the window.
    let mut stubs: Vec<FileStub> = Vec::new();
    let mut rows: Vec<FoundFile> = Vec::new();
    for (i, name) in ["a.jpg", "b.jpg", "c.jpg"].iter().enumerate() {
        let id = (i + 1) as u64;
        let fo = create_file_object(name, FileType::Jpeg, 1024, 0, None, id);
        vm.apply(&CarveEvent::FileFound {
            source_id: 0,
            file: fo.clone(),
            img_offset: 0,
            written_path: (*name).into(),
        });
        stubs.push(FileStub {
            file_id: id,
            filename: (*name).to_string(),
            filesize: 1024,
            file_type: FileType::Jpeg,
        });
        rows.push(FoundFile {
            id,
            source_id: 0,
            file: fo,
            written_path: (*name).into(),
            img_offset: 0,
        });
    }
    // Bump epoch so apply_* helpers don't drop our synthetic update.
    vm.current_epoch += 1;
    let epoch = vm.current_epoch;
    vm.apply_match_ids(stubs, epoch);
    vm.apply_window_filled(rows, 0, epoch);
    let ids: Vec<utmost_gui::view_model::FileId> = vm.match_ids.iter().map(|s| s.file_id).collect();
    assert_eq!(ids.len(), 3);

    // 1) Click first tile.
    vm.selection = Some(ids[0]);
    assert!(vm.lightbox.is_none());

    // 2) Open lightbox via the side panel large preview.
    vm.open_lightbox();
    assert_eq!(vm.lightbox, Some(ids[0]));

    // 3) Right arrow twice.
    vm.lightbox_next();
    assert_eq!(vm.lightbox, Some(ids[1]));
    vm.lightbox_next();
    assert_eq!(vm.lightbox, Some(ids[2]));

    // 4) ESC closes lightbox; selection is preserved.
    vm.close_or_deselect();
    assert!(vm.lightbox.is_none());
    assert_eq!(vm.selection, Some(ids[0]));

    // 5) ESC again clears the side panel.
    vm.close_or_deselect();
    assert!(vm.selection.is_none());
}
