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

/// Build a CaseRowDescriptor for one events.bin path. Tries sqlite first
/// (cheap; one short SELECT); on miss, falls back to head_read_events_bin.
/// On any non-recoverable failure (e.g. RunStarted absent), returns a
/// Corrupt-status descriptor rather than propagating the error — the
/// picker must not abort on a single bad case.
pub fn build_case_row(events_bin: &Path) -> CaseRowDescriptor {
    let sqlite_path = sqlite_path_for(events_bin);

    // Source basename from the filename (fallback if we can't read the recorded path).
    let fallback_basename = events_bin
        .file_stem()
        .and_then(|s| s.to_str())
        .map(|s| s.trim_end_matches("-events").to_string())
        .unwrap_or_default();

    // 1) Try sqlite.
    if sqlite_path.exists()
        && let Ok(mut db) = crate::index_db::IndexDb::open(&sqlite_path)
        && let Ok(row) = crate::index_db::queries::picker_metadata_row(db.conn())
    {
        let events_size = std::fs::metadata(events_bin).map(|m| m.len()).unwrap_or(0);
        let needs_indexing = (row.last_event_offset as u64) < events_size;
        let status = match row.status.as_str() {
            "Running" => PickerStatus::Running,
            "Finished" if needs_indexing => PickerStatus::Indexing,
            "Finished" => PickerStatus::Finished,
            "Interrupted" if needs_indexing => PickerStatus::Indexing,
            "Interrupted" => PickerStatus::Interrupted,
            _ => PickerStatus::Interrupted,
        };
        let basename = std::path::Path::new(&row.source_image_path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&fallback_basename)
            .to_string();
        let progress = if matches!(status, PickerStatus::Running) {
            0.0
        } else {
            1.0
        };
        return CaseRowDescriptor {
            events_bin_path: events_bin.to_path_buf(),
            source_basename: basename,
            source_path: row.source_image_path,
            status,
            files_found: row.total_files as u64,
            elapsed_ms: row.elapsed_ms as u64,
            started_at: row.started_at,
            progress,
            clickable: true,
        };
    }

    // 2) Sqlite absent or unreadable; head-read the events.bin.
    match head_read_events_bin(events_bin) {
        Ok(hr) => {
            let basename = std::path::Path::new(&hr.source_image_path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(&fallback_basename)
                .to_string();
            CaseRowDescriptor {
                events_bin_path: events_bin.to_path_buf(),
                source_basename: basename,
                source_path: hr.source_image_path,
                status: PickerStatus::Unindexed, // no sqlite, regardless of head_read finished flag
                files_found: 0,
                elapsed_ms: 0,
                started_at: hr.started_at,
                progress: 0.0,
                clickable: true,
            }
        }
        Err(e) => {
            tracing::warn!(
                "build_case_row: corrupt events.bin {}: {e}",
                events_bin.display()
            );
            CaseRowDescriptor {
                events_bin_path: events_bin.to_path_buf(),
                source_basename: fallback_basename,
                source_path: events_bin.display().to_string(),
                status: PickerStatus::Corrupt,
                files_found: 0,
                elapsed_ms: 0,
                started_at: String::new(),
                progress: 0.0,
                clickable: false,
            }
        }
    }
}

/// Derive the sibling sqlite index path: `<stem>-events.bin` → `<stem>-index.sqlite`.
pub fn sqlite_path_for(events_bin: &Path) -> std::path::PathBuf {
    let mut p = events_bin.to_path_buf();
    let new_name = events_bin
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.replace("-events.bin", "-index.sqlite"))
        .unwrap_or_else(|| "index.sqlite".to_string());
    p.set_file_name(new_name);
    p
}

/// Wrap [`build_case_row`] across many events.bin paths.
pub fn build_case_rows(events_bins: &[std::path::PathBuf]) -> Vec<CaseRowDescriptor> {
    events_bins.iter().map(|p| build_case_row(p)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
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
        write_log(&path, &[make_run_started("/in/a.img")]);

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
                make_run_started("/in/a.img"),
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

    #[test]
    fn build_case_row_sqlite_path_alongside_events_bin() {
        let p = std::path::Path::new("/foo/bar/run1-events.bin");
        let sqlite = sqlite_path_for(p);
        assert_eq!(sqlite, std::path::Path::new("/foo/bar/run1-index.sqlite"));
    }

    #[test]
    fn build_case_row_unindexed_when_no_sqlite_present() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("solo-events.bin");
        write_log(&log, &[make_run_started("/in/solo.img")]);
        let row = build_case_row(&log);
        assert_eq!(row.status, PickerStatus::Unindexed);
        assert_eq!(row.source_basename, "solo.img");
        assert!(row.clickable);
    }

    #[test]
    fn build_case_row_corrupt_for_unreadable_log() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("bad-events.bin");
        std::fs::write(&log, b"not a bincode file").unwrap();
        let row = build_case_row(&log);
        assert_eq!(row.status, PickerStatus::Corrupt);
        assert!(!row.clickable);
    }
}
