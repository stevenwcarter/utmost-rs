//! Shared helpers for `tests/index_db_writer_*.rs` integration tests.
//!
//! Cargo's test runner treats files in `tests/` as separate crates but
//! ignores subdirectories under `tests/`, so this module is imported via
//! `mod common;` from each test file that needs it. Subsequent Phase 3
//! tasks (3.3 – 3.13) reuse `run_started_event()` to seed a `run` row
//! before exercising the variant-specific event.

use utmost_lib::events::{CarveEvent, CaseMetadata, CliConfigSnapshot, SourceDescriptor};
use utmost_lib::types::{ExecutionEnvironment, FileType};

pub fn run_started_event() -> CarveEvent {
    CarveEvent::RunStarted {
        utmost_version: "0".into(),
        format_version: 1,
        started_at: "2026-05-19T00:00:00+0000".into(),
        command_line: vec!["utmost".into()],
        working_directory: ".".into(),
        execution_environment: ExecutionEnvironment {
            os_sysname: "linux".into(),
            os_release: "6".into(),
            os_version: "1".into(),
            host: "h".into(),
            arch: "x86_64".into(),
            uid: 1,
            start_time: "2026-05-19T00:00:00+0000".into(),
        },
        cli_config: CliConfigSnapshot {
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
        },
        case: Some(CaseMetadata {
            case_id: Some("C-1".into()),
            examiner: Some("E".into()),
            evidence_id: Some("EV".into()),
            notes: Some("n".into()),
        }),
        configured_types: vec![FileType::Jpeg],
        sources: vec![SourceDescriptor {
            source_id: 0,
            filename: "disk1.dd".into(),
            total_bytes: 4096,
            output_subdir: "output-disk1.dd".into(),
        }],
        output_root: "out".into(),
    }
}
