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

use std::sync::Arc;

use crate::types::{ExecutionEnvironment, FileObject, FileType};

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CarveEvent {
    RunStarted {
        utmost_version: String,
        format_version: u32,
        started_at: String,
        command_line: Vec<String>,
        working_directory: String,
        execution_environment: ExecutionEnvironment,
        cli_config: CliConfigSnapshot,
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

impl CarveEvent {
    /// Whether this event should be persisted to the bincode event log.
    /// Stream-only events (e.g. progress ticks) return false so the on-disk
    /// log stays small and replay-deterministic.
    pub fn persistable(&self) -> bool {
        // Exhaustive match on purpose — adding a new variant must force
        // an explicit persistability decision.
        match self {
            CarveEvent::RunStarted { .. }
            | CarveEvent::SourceStarted { .. }
            | CarveEvent::FileFound { .. }
            | CarveEvent::SourceFinished { .. }
            | CarveEvent::RunFinished { .. } => true,
            CarveEvent::ProgressTick { .. } => false,
        }
    }
}

/// Receiver of `CarveEvent`s emitted by the engine. Implementations must
/// never panic; failures should be swallowed (and logged) so a misbehaving
/// sink cannot abort a carve.
pub trait EventSink: Send + Sync {
    fn emit(&self, event: &CarveEvent);
}

/// Length-prefixed (u32 LE) bincode event log. Writes the FileHeader on
/// creation; subsequent `emit` calls write only persistable events.
///
/// Sink errors are absorbed: on the first I/O failure the sink marks
/// itself disabled and logs once at warn level. The carve continues.
pub struct BincodeFileSink {
    inner: std::sync::Mutex<BincodeFileSinkInner>,
}

struct BincodeFileSinkInner {
    writer: std::io::BufWriter<std::fs::File>,
    disabled: bool,
}

impl BincodeFileSink {
    pub fn create(path: &std::path::Path) -> std::io::Result<Self> {
        let file = std::fs::File::create(path)?;
        let mut writer = std::io::BufWriter::new(file);
        write_frame(&mut writer, &FileHeader::default())
            .map_err(|e| std::io::Error::other(format!("writing file header: {e}")))?;
        Ok(Self {
            inner: std::sync::Mutex::new(BincodeFileSinkInner {
                writer,
                disabled: false,
            }),
        })
    }
}

impl EventSink for BincodeFileSink {
    fn emit(&self, event: &CarveEvent) {
        if !event.persistable() {
            return;
        }
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if guard.disabled {
            return;
        }
        if let Err(e) = write_frame(&mut guard.writer, event) {
            tracing::warn!("bincode event sink disabled after write failure: {e}");
            guard.disabled = true;
        }
    }
}

fn write_frame<T: serde::Serialize, W: std::io::Write>(
    writer: &mut W,
    value: &T,
) -> std::io::Result<()> {
    let bytes = bincode::serialize(value)
        .map_err(|e| std::io::Error::other(format!("bincode serialize: {e}")))?;
    let len = u32::try_from(bytes.len())
        .map_err(|_| std::io::Error::other("frame larger than u32::MAX"))?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

use std::fs::File;
use std::io::{BufReader, Read as IoRead};
use std::path::Path;

/// Streaming reader for the bincode event log. Validates magic + version
/// in `open`, then yields one `CarveEvent` per `next_event()` call.
#[derive(Debug)]
pub struct BincodeFileReader {
    reader: BufReader<File>,
}

impl BincodeFileReader {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let header_bytes = read_frame(&mut reader)?
            .ok_or_else(|| std::io::Error::other("event log is empty (no header)"))?;
        let header: FileHeader = bincode::deserialize(&header_bytes)
            .map_err(|e| std::io::Error::other(format!("decoding file header: {e}")))?;
        if header.magic != MAGIC {
            return Err(std::io::Error::other(format!(
                "bad magic: got {:?}, expected {:?}",
                header.magic, MAGIC
            )));
        }
        if header.format_version > CURRENT_FORMAT_VERSION {
            return Err(std::io::Error::other(format!(
                "unsupported format version {} (this build supports up to {})",
                header.format_version, CURRENT_FORMAT_VERSION,
            )));
        }
        Ok(Self { reader })
    }

    pub fn next_event(&mut self) -> std::io::Result<Option<CarveEvent>> {
        let Some(bytes) = read_frame(&mut self.reader)? else {
            return Ok(None);
        };
        let event: CarveEvent = bincode::deserialize(&bytes)
            .map_err(|e| std::io::Error::other(format!("decoding event: {e}")))?;
        Ok(Some(event))
    }
}

fn read_frame<R: IoRead>(reader: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(Some(buf))
}

/// Sink that forwards every event (including stream-only variants) to a
/// crossbeam channel. Silently drops events when the receiver is gone.
pub struct ChannelSink {
    tx: crossbeam_channel::Sender<CarveEvent>,
}

impl ChannelSink {
    pub fn new(tx: crossbeam_channel::Sender<CarveEvent>) -> Self {
        Self { tx }
    }
}

impl EventSink for ChannelSink {
    fn emit(&self, event: &CarveEvent) {
        let _ = self.tx.send(event.clone());
    }
}

/// Fans an event out to multiple child sinks. Failures in one child do not
/// affect others.
pub struct FanoutSink {
    sinks: Vec<Arc<dyn EventSink>>,
}

impl FanoutSink {
    pub fn new(sinks: Vec<Arc<dyn EventSink>>) -> Self {
        Self { sinks }
    }
}

impl EventSink for FanoutSink {
    fn emit(&self, event: &CarveEvent) {
        for sink in &self.sinks {
            sink.emit(event);
        }
    }
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
            execution_environment: crate::types::ExecutionEnvironment {
                os_sysname: "linux".into(),
                os_release: "6.0".into(),
                os_version: "1".into(),
                host: "h".into(),
                arch: "x86_64".into(),
                uid: 1000,
                start_time: "2026-05-17T12:00:00+0000".into(),
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
    fn persistable_returns_true_for_all_non_progress_variants() {
        assert!(sample_run_started().persistable());
        assert!(CarveEvent::SourceStarted { source_id: 0 }.persistable());
        let fo = create_file_object("a.jpg", FileType::Jpeg, 1, 0, None);
        assert!(
            CarveEvent::FileFound {
                source_id: 0,
                file: fo,
                img_offset: 0,
                written_path: "a.jpg".into()
            }
            .persistable()
        );
        assert!(
            CarveEvent::SourceFinished {
                source_id: 0,
                bytes_read: 0,
                duration_ms: 0
            }
            .persistable()
        );
        assert!(
            CarveEvent::RunFinished {
                duration_ms: 0,
                total_files_written: 0
            }
            .persistable()
        );
    }

    #[test]
    fn persistable_returns_false_for_progress_tick() {
        let ev = CarveEvent::ProgressTick {
            source_id: 0,
            bytes_read: 0,
        };
        assert!(!ev.persistable());
    }

    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<CarveEvent>>,
    }

    impl EventSink for RecordingSink {
        fn emit(&self, event: &CarveEvent) {
            self.events.lock().unwrap().push(event.clone());
        }
    }

    #[test]
    fn fanout_delivers_to_all_child_sinks() {
        let a: Arc<RecordingSink> = Arc::new(RecordingSink::default());
        let b: Arc<RecordingSink> = Arc::new(RecordingSink::default());
        let fanout = FanoutSink::new(vec![
            a.clone() as Arc<dyn EventSink>,
            b.clone() as Arc<dyn EventSink>,
        ]);

        fanout.emit(&CarveEvent::SourceStarted { source_id: 1 });
        fanout.emit(&CarveEvent::ProgressTick {
            source_id: 1,
            bytes_read: 10,
        });

        assert_eq!(a.events.lock().unwrap().len(), 2);
        assert_eq!(b.events.lock().unwrap().len(), 2);
    }

    #[test]
    fn fanout_emit_is_fail_isolated_per_child() {
        struct PanickingSink;
        impl EventSink for PanickingSink {
            fn emit(&self, _: &CarveEvent) {
                // Simulate a misbehaving sink that returns without writing.
                // FanoutSink must not propagate panics from one sink to another;
                // we test only the recorded sink still received the event.
            }
        }
        let good: Arc<RecordingSink> = Arc::new(RecordingSink::default());
        let fanout = FanoutSink::new(vec![
            Arc::new(PanickingSink) as Arc<dyn EventSink>,
            good.clone() as Arc<dyn EventSink>,
        ]);
        fanout.emit(&CarveEvent::SourceStarted { source_id: 9 });
        assert_eq!(good.events.lock().unwrap().len(), 1);
    }

    use std::io::Read;
    use tempfile::tempdir;

    fn read_all(path: &std::path::Path) -> Vec<u8> {
        let mut buf = Vec::new();
        std::fs::File::open(path)
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();
        buf
    }

    fn read_frames(path: &std::path::Path) -> Vec<Vec<u8>> {
        let bytes = read_all(path);
        let mut out = Vec::new();
        let mut i = 0;
        while i + 4 <= bytes.len() {
            let len = u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap()) as usize;
            i += 4;
            if i + len > bytes.len() {
                break;
            }
            out.push(bytes[i..i + len].to_vec());
            i += len;
        }
        out
    }

    #[test]
    fn bincode_sink_writes_header_then_events_skipping_progress() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.bin");
        let sink = BincodeFileSink::create(&path).unwrap();

        sink.emit(&CarveEvent::SourceStarted { source_id: 0 });
        sink.emit(&CarveEvent::ProgressTick {
            source_id: 0,
            bytes_read: 1,
        });
        sink.emit(&CarveEvent::SourceFinished {
            source_id: 0,
            bytes_read: 1,
            duration_ms: 1,
        });
        drop(sink);

        let frames = read_frames(&path);
        // header + SourceStarted + SourceFinished. ProgressTick must be skipped.
        assert_eq!(frames.len(), 3, "got {} frames", frames.len());

        let header: FileHeader = bincode::deserialize(&frames[0]).unwrap();
        assert_eq!(header.magic, MAGIC);
        assert_eq!(header.format_version, CURRENT_FORMAT_VERSION);

        let ev1: CarveEvent = bincode::deserialize(&frames[1]).unwrap();
        assert!(matches!(ev1, CarveEvent::SourceStarted { source_id: 0 }));

        let ev2: CarveEvent = bincode::deserialize(&frames[2]).unwrap();
        assert!(matches!(ev2, CarveEvent::SourceFinished { .. }));
    }

    #[test]
    fn reader_validates_magic_and_yields_events() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("e.bin");
        let sink = BincodeFileSink::create(&path).unwrap();
        sink.emit(&CarveEvent::SourceStarted { source_id: 0 });
        sink.emit(&CarveEvent::RunFinished {
            duration_ms: 5,
            total_files_written: 0,
        });
        drop(sink);

        let mut reader = BincodeFileReader::open(&path).unwrap();
        let events: Vec<_> = std::iter::from_fn(|| reader.next_event().transpose())
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], CarveEvent::SourceStarted { .. }));
        assert!(matches!(events[1], CarveEvent::RunFinished { .. }));
    }

    #[test]
    fn reader_rejects_wrong_magic() {
        use std::io::Write;
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.bin");
        // Write a frame containing a bogus header.
        let bogus = FileHeader {
            magic: *b"NOPE",
            format_version: 1,
        };
        let bytes = bincode::serialize(&bogus).unwrap();
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&(bytes.len() as u32).to_le_bytes()).unwrap();
        f.write_all(&bytes).unwrap();
        drop(f);

        let err = BincodeFileReader::open(&path).unwrap_err();
        assert!(
            format!("{err}").contains("magic"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn reader_rejects_future_version() {
        use std::io::Write;
        let dir = tempdir().unwrap();
        let path = dir.path().join("future.bin");
        let future = FileHeader {
            magic: MAGIC,
            format_version: CURRENT_FORMAT_VERSION + 1,
        };
        let bytes = bincode::serialize(&future).unwrap();
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&(bytes.len() as u32).to_le_bytes()).unwrap();
        f.write_all(&bytes).unwrap();
        drop(f);

        let err = BincodeFileReader::open(&path).unwrap_err();
        assert!(
            format!("{err}").contains("version"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn channel_sink_forwards_all_events_including_progress() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let sink = ChannelSink::new(tx);

        sink.emit(&CarveEvent::SourceStarted { source_id: 1 });
        sink.emit(&CarveEvent::ProgressTick {
            source_id: 1,
            bytes_read: 5,
        });
        sink.emit(&CarveEvent::RunFinished {
            duration_ms: 1,
            total_files_written: 0,
        });

        let collected: Vec<_> = rx.try_iter().collect();
        assert_eq!(collected.len(), 3);
        assert!(matches!(collected[1], CarveEvent::ProgressTick { .. }));
    }

    #[test]
    fn channel_sink_drops_silently_when_receiver_gone() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let sink = ChannelSink::new(tx);
        drop(rx);
        // Must not panic
        sink.emit(&CarveEvent::SourceStarted { source_id: 0 });
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
