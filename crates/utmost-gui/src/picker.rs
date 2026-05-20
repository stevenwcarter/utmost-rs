//! Picker metadata: lightweight fallback reader for cases that have no
//! SQLite index yet. Reads just enough of the events.bin to populate the
//! case-selection screen without triggering a full index build.

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use utmost_lib::events::{BincodeFileReader, CarveEvent};

/// Status of a case as shown in the picker list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickerStatus {
    Running,
    Finished,
    Interrupted,
    Indexing,
    Unindexed,
    Corrupt,
}

impl PickerStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            PickerStatus::Running => "Running",
            PickerStatus::Finished => "Finished",
            PickerStatus::Interrupted => "Interrupted",
            PickerStatus::Indexing => "Indexing\u{2026}",
            PickerStatus::Unindexed => "Unindexed",
            PickerStatus::Corrupt => "Corrupt",
        }
    }
}

/// Row descriptor for a single case in the picker list.
#[derive(Debug, Clone)]
pub struct CaseRowDescriptor {
    pub events_bin_path: PathBuf,
    pub source_basename: String,
    pub source_path: String,
    pub status: PickerStatus,
    pub files_found: u64,
    pub elapsed_ms: u64,
    pub started_at: String,
    pub progress: f32,
    pub clickable: bool,
}

/// Result of reading the head (and tail scan) of an events.bin.
#[derive(Debug, Clone)]
pub struct HeadReadResult {
    pub source_image_path: String,
    pub started_at: String,
    pub finished: bool,
}

/// Open `path` as a bincode event log, read the `RunStarted` head to extract
/// `source_image_path` and `started_at`, then scan the remainder for a
/// `RunFinished` event to set `finished`.
///
/// Returns an error if the log is unreadable or does not begin with
/// `RunStarted`.
pub fn head_read_events_bin(path: &Path) -> Result<HeadReadResult> {
    let mut reader = BincodeFileReader::open(path)?;

    // First event must be RunStarted.
    let first = reader
        .next_event()?
        .ok_or_else(|| anyhow!("event log is empty (no events after header)"))?;

    let (source_image_path, started_at) = match first {
        CarveEvent::RunStarted {
            started_at,
            sources,
            ..
        } => {
            let src = sources
                .first()
                .map(|s| s.filename.clone())
                .unwrap_or_default();
            (src, started_at)
        }
        _ => {
            return Err(anyhow!("event log did not start with RunStarted"));
        }
    };

    // Scan the rest of the log for RunFinished.
    let mut finished = false;
    loop {
        match reader.next_event()? {
            None => break,
            Some(CarveEvent::RunFinished { .. }) => {
                finished = true;
                break;
            }
            Some(_) => {}
        }
    }

    Ok(HeadReadResult {
        source_image_path,
        started_at,
        finished,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use utmost_lib::EventSink;
    use utmost_lib::events::{BincodeFileSink, CarveEvent, CliConfigSnapshot, SourceDescriptor};
    use utmost_lib::types::{ExecutionEnvironment, FileType};

    fn make_run_started() -> CarveEvent {
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
                filename: "/in/a.img".into(),
                total_bytes: 0,
                output_subdir: "a".into(),
            }],
            output_root: "/out".into(),
        }
    }

    fn write_log(path: &Path, events: &[CarveEvent]) {
        let sink = BincodeFileSink::create(path).expect("create sink");
        for ev in events {
            sink.emit(ev);
        }
        // drop flushes the BufWriter
    }

    #[test]
    fn head_read_returns_source_and_unfinished_when_no_runfinished() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.bin");
        write_log(&path, &[make_run_started()]);

        let result = head_read_events_bin(&path).expect("head_read should succeed");
        assert_eq!(result.source_image_path, "/in/a.img");
        assert_eq!(result.started_at, "2026-05-20T00:00:00Z");
        assert!(
            !result.finished,
            "expected finished=false when no RunFinished"
        );
    }

    #[test]
    fn head_read_detects_runfinished_in_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.bin");
        write_log(
            &path,
            &[
                make_run_started(),
                CarveEvent::RunFinished {
                    duration_ms: 1000,
                    total_files_written: 5,
                },
            ],
        );

        let result = head_read_events_bin(&path).expect("head_read should succeed");
        assert!(
            result.finished,
            "expected finished=true when RunFinished present"
        );
    }

    #[test]
    fn head_read_errors_on_missing_run_started() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.bin");
        write_log(&path, &[CarveEvent::SourceStarted { source_id: 0 }]);

        let err = head_read_events_bin(&path).expect_err("should fail without RunStarted");
        assert!(
            format!("{err}").contains("did not start with RunStarted"),
            "unexpected error message: {err}"
        );
    }
}
