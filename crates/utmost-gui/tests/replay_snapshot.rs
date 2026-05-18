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
    let fo = create_file_object("a.jpg", FileType::Jpeg, 1024, 0, None);
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
    assert_eq!(vm.files.len(), 1);
    assert_eq!(vm.run.total_files, 1);
}
