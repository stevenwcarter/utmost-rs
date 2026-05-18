//! Event stream for live and replayable carve runs.
//!
//! See `docs/superpowers/specs/2026-05-17-utmost-gui-design.md` for the
//! versioned binary format.

use serde::{Deserialize, Serialize};

pub const CURRENT_FORMAT_VERSION: u32 = 1;
pub const MAGIC: [u8; 4] = *b"UTMS";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileHeader {
    pub magic: [u8; 4],
    pub format_version: u32,
}

impl Default for FileHeader {
    fn default() -> Self {
        Self {
            magic: MAGIC,
            format_version: CURRENT_FORMAT_VERSION,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceDescriptor {
    pub source_id: u32,
    pub filename: String,
    pub total_bytes: u64,
    pub output_subdir: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CaseMetadata {
    #[serde(default)]
    pub case_id: Option<String>,
    #[serde(default)]
    pub examiner: Option<String>,
    #[serde(default)]
    pub evidence_id: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

impl CaseMetadata {
    pub fn is_empty(&self) -> bool {
        self.case_id.is_none()
            && self.examiner.is_none()
            && self.evidence_id.is_none()
            && self.notes.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliConfigSnapshot {
    pub output_directory: String,
    pub types: Vec<String>,
    pub disable_builtin: bool,
    pub config_file: Option<String>,
    pub concurrent_files: usize,
    pub disable_validation: bool,
    pub report_only: bool,
    pub disable_report: bool,
    pub disable_audit: bool,
    pub disable_export: bool,
    pub gui_enabled: bool,
    pub quick: bool,
    pub block_size: usize,
    pub prefix_filenames: bool,
    pub write_all: bool,
    pub keep_incomplete_jpeg: bool,
}

use crate::types::{ExecutionEnvironment, FileObject, FileType};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CarveEvent {
    RunStarted {
        utmost_version: String,
        format_version: u32,
        started_at: String,
        command_line: Vec<String>,
        working_directory: String,
        execution_environment: Box<ExecutionEnvironment>,
        cli_config: Box<CliConfigSnapshot>,
        case: Option<CaseMetadata>,
        configured_types: Vec<FileType>,
        sources: Vec<SourceDescriptor>,
        output_root: String,
    },
    SourceStarted {
        source_id: u32,
    },
    FileFound {
        source_id: u32,
        file: FileObject,
        img_offset: u64,
        written_path: String,
    },
    ProgressTick {
        source_id: u32,
        bytes_read: u64,
    },
    SourceFinished {
        source_id: u32,
        bytes_read: u64,
        duration_ms: u64,
    },
    RunFinished {
        duration_ms: u64,
        total_files_written: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::reporting::create_file_object;
    use crate::types::FileType;

    fn sample_run_started() -> CarveEvent {
        CarveEvent::RunStarted {
            utmost_version: "0.2.2".into(),
            format_version: CURRENT_FORMAT_VERSION,
            started_at: "2026-05-17T12:00:00+0000".into(),
            command_line: vec!["utmost".into(), "disk.dd".into()],
            working_directory: "/tmp".into(),
            execution_environment: Box::new(crate::types::ExecutionEnvironment {
                os_sysname: "linux".into(),
                os_release: "6.0".into(),
                os_version: "1".into(),
                host: "h".into(),
                arch: "x86_64".into(),
                uid: 1000,
                start_time: "2026-05-17T12:00:00+0000".into(),
            }),
            cli_config: Box::new(CliConfigSnapshot {
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
            }),
            case: None,
            configured_types: vec![FileType::Jpeg],
            sources: vec![SourceDescriptor {
                source_id: 0,
                filename: "disk.dd".into(),
                total_bytes: 1024,
                output_subdir: String::new(),
            }],
            output_root: "out".into(),
        }
    }

    #[test]
    fn carve_event_run_started_round_trips() {
        let ev = sample_run_started();
        let bytes = bincode::serialize(&ev).unwrap();
        let decoded: CarveEvent = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded, ev);
    }

    #[test]
    fn carve_event_source_started_round_trips() {
        let ev = CarveEvent::SourceStarted { source_id: 3 };
        let bytes = bincode::serialize(&ev).unwrap();
        assert_eq!(bincode::deserialize::<CarveEvent>(&bytes).unwrap(), ev);
    }

    #[test]
    fn carve_event_file_found_round_trips() {
        let fo = create_file_object("000001-0.jpg", FileType::Jpeg, 1024, 512, None);
        let ev = CarveEvent::FileFound {
            source_id: 0,
            file: fo,
            img_offset: 512,
            written_path: "000001-0.jpg".into(),
        };
        let bytes = bincode::serialize(&ev).unwrap();
        assert_eq!(bincode::deserialize::<CarveEvent>(&bytes).unwrap(), ev);
    }

    #[test]
    fn carve_event_progress_tick_round_trips() {
        let ev = CarveEvent::ProgressTick {
            source_id: 0,
            bytes_read: 9999,
        };
        let bytes = bincode::serialize(&ev).unwrap();
        assert_eq!(bincode::deserialize::<CarveEvent>(&bytes).unwrap(), ev);
    }

    #[test]
    fn carve_event_source_finished_round_trips() {
        let ev = CarveEvent::SourceFinished {
            source_id: 0,
            bytes_read: 1024,
            duration_ms: 50,
        };
        let bytes = bincode::serialize(&ev).unwrap();
        assert_eq!(bincode::deserialize::<CarveEvent>(&bytes).unwrap(), ev);
    }

    #[test]
    fn carve_event_run_finished_round_trips() {
        let ev = CarveEvent::RunFinished {
            duration_ms: 100,
            total_files_written: 5,
        };
        let bytes = bincode::serialize(&ev).unwrap();
        assert_eq!(bincode::deserialize::<CarveEvent>(&bytes).unwrap(), ev);
    }

    #[test]
    fn file_header_round_trips_through_bincode() {
        let header = FileHeader {
            magic: *b"UTMS",
            format_version: CURRENT_FORMAT_VERSION,
        };
        let bytes = bincode::serialize(&header).unwrap();
        let decoded: FileHeader = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.magic, *b"UTMS");
        assert_eq!(decoded.format_version, CURRENT_FORMAT_VERSION);
    }

    #[test]
    fn source_descriptor_round_trips() {
        let s = SourceDescriptor {
            source_id: 7,
            filename: "disk.dd".into(),
            total_bytes: 1024,
            output_subdir: "output-disk_dd".into(),
        };
        let bytes = bincode::serialize(&s).unwrap();
        let decoded: SourceDescriptor = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded, s);
    }

    #[test]
    fn case_metadata_round_trips_with_partial_fields() {
        let c = CaseMetadata {
            case_id: Some("CASE-1".into()),
            examiner: None,
            evidence_id: Some("E-9".into()),
            notes: None,
        };
        let bytes = bincode::serialize(&c).unwrap();
        let decoded: CaseMetadata = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded, c);
    }

    #[test]
    fn cli_config_snapshot_round_trips() {
        let cfg = CliConfigSnapshot {
            output_directory: "out".into(),
            types: vec!["jpeg".into()],
            disable_builtin: false,
            config_file: None,
            concurrent_files: 4,
            disable_validation: false,
            report_only: false,
            disable_report: false,
            disable_audit: false,
            disable_export: false,
            gui_enabled: true,
            quick: false,
            block_size: 512,
            prefix_filenames: false,
            write_all: false,
            keep_incomplete_jpeg: false,
        };
        let bytes = bincode::serialize(&cfg).unwrap();
        let decoded: CliConfigSnapshot = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded, cfg);
    }
}
