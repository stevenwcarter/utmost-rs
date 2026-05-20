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
        let needs_indexing =
            row.last_event_offset < 0 || (row.last_event_offset as u64) < events_size;
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
        let progress = match status {
            PickerStatus::Running | PickerStatus::Indexing => 0.0,
            _ => 1.0,
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
                source_path: String::new(),
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

/// Persistent per-row state the picker carries to incrementally update a
/// Running row from its events.bin without re-reading the whole log on
/// each tick. Lives across detail-view transitions (drop the tailer, keep
/// the state). The picker maintains a `HashMap<PathBuf, PickerRowState>`
/// indexed by `events_bin` path.
#[derive(Clone, Debug)]
pub struct PickerRowState {
    pub events_bin: std::path::PathBuf,
    pub files_seen: u64,
    pub last_offset: u64,
    pub started_at: String,
    pub source_path: String,
    pub finished: bool,
    pub corrupt_retries_remaining: u8,
}

impl PickerRowState {
    /// Initial state when nothing has been read yet. Use only for rows
    /// that initially failed `build_case_row` (Corrupt status); rows
    /// with real metadata should be populated from the build_case_row
    /// descriptor.
    pub fn for_retry(events_bin: std::path::PathBuf) -> Self {
        Self {
            events_bin,
            files_seen: 0,
            last_offset: 0,
            started_at: String::new(),
            source_path: String::new(),
            finished: false,
            corrupt_retries_remaining: 3,
        }
    }
}

/// Active tailer: holds the file handle while the picker is visible.
/// Dropped when a case is opened in detail view; recreated on back-out
/// via [`PickerRowTailer::reopen`] using the persisted state.
pub struct PickerRowTailer {
    pub state: PickerRowState,
    reader: utmost_lib::events::BincodeFileReader,
}

impl PickerRowTailer {
    /// Open a tailer at the start of `events_bin`. Reads the first event
    /// (must be `RunStarted`) to populate `started_at` and `source_path`.
    /// Returns `None` if the file can't be opened or the first event isn't
    /// `RunStarted`.
    pub fn open_fresh(events_bin: &Path) -> Option<Self> {
        use utmost_lib::events::{BincodeFileReader, CarveEvent};
        let mut reader = BincodeFileReader::open(events_bin).ok()?;
        let first = reader.next_event().ok().flatten()?;
        let (started_at, source_path) = match first {
            CarveEvent::RunStarted {
                started_at,
                sources,
                ..
            } => {
                let sp = sources
                    .first()
                    .map(|s| s.filename.clone())
                    .unwrap_or_default();
                (started_at, sp)
            }
            _ => return None,
        };
        let last_offset = reader.byte_offset().ok()?;
        Some(Self {
            state: PickerRowState {
                events_bin: events_bin.to_path_buf(),
                files_seen: 0,
                last_offset,
                started_at,
                source_path,
                finished: false,
                corrupt_retries_remaining: 3,
            },
            reader,
        })
    }

    /// Drain any newly-available events from the reader. Returns true iff
    /// `state.files_seen` advanced or `state.finished` was set.
    pub fn poll(&mut self) -> bool {
        use utmost_lib::events::CarveEvent;
        let mut changed = false;
        loop {
            match self.reader.next_event() {
                Ok(Some(ev)) => {
                    if matches!(ev, CarveEvent::FileFound { .. }) {
                        self.state.files_seen += 1;
                        changed = true;
                    }
                    if matches!(ev, CarveEvent::RunFinished { .. }) {
                        self.state.finished = true;
                        changed = true;
                    }
                    if let Ok(off) = self.reader.byte_offset() {
                        self.state.last_offset = off;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    tracing::debug!(
                        "PickerRowTailer::poll error on {}: {e}",
                        self.state.events_bin.display()
                    );
                    break;
                }
            }
        }
        changed
    }

    /// Reopen an existing state. Opens the events.bin and seeks to
    /// `state.last_offset`; returns `None` if the file vanished or the
    /// seek failed (e.g., file was truncated below last_offset).
    pub fn reopen(state: PickerRowState) -> Option<Self> {
        use utmost_lib::events::BincodeFileReader;
        let mut reader = BincodeFileReader::open(&state.events_bin).ok()?;
        reader.seek_to(state.last_offset).ok()?;
        Some(Self { state, reader })
    }

    /// Build a fresh `CaseRowDescriptor` reflecting the tailer's current
    /// state. Used by the picker to update the Slint model on each tick.
    pub fn to_descriptor(&self) -> CaseRowDescriptor {
        let basename = std::path::Path::new(&self.state.source_path)
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                self.state
                    .events_bin
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.trim_end_matches("-events").to_string())
                    .unwrap_or_default()
            });
        let status = if self.state.finished {
            PickerStatus::Finished
        } else {
            PickerStatus::Running
        };
        let progress = if matches!(status, PickerStatus::Running) {
            0.0
        } else {
            1.0
        };
        CaseRowDescriptor {
            events_bin_path: self.state.events_bin.clone(),
            source_basename: basename,
            source_path: self.state.source_path.clone(),
            status,
            files_found: self.state.files_seen,
            elapsed_ms: 0,
            started_at: self.state.started_at.clone(),
            progress,
            clickable: true,
        }
    }
}

/// Derive the sibling sqlite index path: `<stem>-events.bin` → `<stem>-index.sqlite`.
pub fn sqlite_path_for(events_bin: &Path) -> std::path::PathBuf {
    let mut p = events_bin.to_path_buf();
    let new_name = events_bin
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_suffix("-events.bin"))
        .map(|stem| format!("{stem}-index.sqlite"))
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

    #[test]
    fn picker_row_tailer_open_fresh_reads_run_started() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("t-events.bin");
        write_log(&log, &[make_run_started("/in/t.img")]);

        let tailer = PickerRowTailer::open_fresh(&log).expect("open_fresh");
        assert_eq!(tailer.state.events_bin, log);
        assert_eq!(tailer.state.source_path, "/in/t.img");
        assert_ne!(tailer.state.started_at, "");
        assert_eq!(tailer.state.files_seen, 0);
        assert!(!tailer.state.finished);
        assert_eq!(tailer.state.corrupt_retries_remaining, 3);
    }

    #[test]
    fn picker_row_tailer_advances_files_seen_on_appended_event() {
        use utmost_lib::events::{BincodeFileSink, CarveEvent, EventSink};
        use utmost_lib::reporting::create_file_object;
        use utmost_lib::types::FileType;

        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("t-events.bin");
        write_log(&log, &[make_run_started("/in/t.img")]);

        let mut tailer = PickerRowTailer::open_fresh(&log).expect("open_fresh");
        assert_eq!(tailer.state.files_seen, 0);

        let sink = BincodeFileSink::open_append(&log).expect("append");
        sink.emit(&CarveEvent::FileFound {
            source_id: 0,
            file: create_file_object("a.jpg", FileType::Jpeg, 0, 0, None, 1),
            img_offset: 0,
            written_path: "a.jpg".into(),
        });
        drop(sink);

        let changed = tailer.poll();
        assert!(
            changed,
            "poll() must report change after FileFound appended"
        );
        assert_eq!(tailer.state.files_seen, 1);
        assert!(!tailer.state.finished);
    }

    #[test]
    fn picker_row_tailer_flips_finished_on_run_finished() {
        use utmost_lib::events::{BincodeFileSink, CarveEvent, EventSink};

        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("t-events.bin");
        write_log(&log, &[make_run_started("/in/t.img")]);

        let mut tailer = PickerRowTailer::open_fresh(&log).expect("open_fresh");
        assert!(!tailer.state.finished);

        let sink = BincodeFileSink::open_append(&log).expect("append");
        sink.emit(&CarveEvent::RunFinished {
            duration_ms: 1234,
            total_files_written: 0,
        });
        drop(sink);

        assert!(tailer.poll());
        assert!(tailer.state.finished);
    }

    #[test]
    fn picker_row_tailer_reopen_resumes_at_last_offset() {
        use utmost_lib::events::{BincodeFileSink, CarveEvent, EventSink};
        use utmost_lib::reporting::create_file_object;
        use utmost_lib::types::FileType;

        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("t-events.bin");
        write_log(&log, &[make_run_started("/in/t.img")]);

        let mut tailer = PickerRowTailer::open_fresh(&log).expect("open_fresh");
        {
            let sink = BincodeFileSink::open_append(&log).expect("append");
            for i in 1..=3u64 {
                sink.emit(&CarveEvent::FileFound {
                    source_id: 0,
                    file: create_file_object("a.jpg", FileType::Jpeg, 0, 0, None, i),
                    img_offset: 0,
                    written_path: "a.jpg".into(),
                });
            }
        }
        tailer.poll();
        assert_eq!(tailer.state.files_seen, 3);
        let snapshot_state = tailer.state.clone();
        drop(tailer);

        {
            let sink = BincodeFileSink::open_append(&log).expect("append");
            for i in 4..=5u64 {
                sink.emit(&CarveEvent::FileFound {
                    source_id: 0,
                    file: create_file_object("a.jpg", FileType::Jpeg, 0, 0, None, i),
                    img_offset: 0,
                    written_path: "a.jpg".into(),
                });
            }
        }

        let mut tailer2 = PickerRowTailer::reopen(snapshot_state).expect("reopen");
        assert!(tailer2.poll());
        assert_eq!(
            tailer2.state.files_seen, 5,
            "reopen must not re-count earlier events"
        );
    }

    #[test]
    fn picker_row_tailer_open_fresh_returns_none_for_empty_file() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("empty-events.bin");
        std::fs::write(&log, b"").unwrap();
        assert!(PickerRowTailer::open_fresh(&log).is_none());
    }

    #[test]
    fn build_case_row_indexing_when_sqlite_stale() {
        use crate::index_db::IndexDb;
        use diesel::prelude::*;

        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("stale-events.bin");

        // Write an events.bin that's non-trivially-sized so last_event_offset=0 < size.
        write_log(
            &log,
            &[
                make_run_started("/in/stale.img"),
                CarveEvent::RunFinished {
                    duration_ms: 100,
                    total_files_written: 0,
                },
            ],
        );

        // Create the sibling sqlite and seed run + meta.
        let sqlite_path = sqlite_path_for(&log);
        {
            let mut db = IndexDb::open(&sqlite_path).expect("open sqlite");
            diesel::sql_query(
                "INSERT INTO run (id, started_at, output_root, source_image_path, configured_types_json, status, elapsed_ms, total_files) \
                 VALUES (1, '2026-05-20T00:00:00Z', '/out', '/in/stale.img', '[]', 'Finished', 100, 0)",
            )
            .execute(db.conn())
            .unwrap();
            diesel::sql_query("INSERT INTO meta(key, value) VALUES ('last_event_offset', '0')")
                .execute(db.conn())
                .unwrap();
        }

        let row = build_case_row(&log);
        assert_eq!(row.status, PickerStatus::Indexing);
        assert_eq!(
            row.progress, 0.0,
            "Indexing rows must not show full progress"
        );
        assert!(row.clickable);
    }
}
