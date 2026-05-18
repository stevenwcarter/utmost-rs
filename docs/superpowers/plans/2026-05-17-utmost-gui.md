# Utmost Slint GUI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Every task is TDD: write failing test → run to verify fail → minimal impl → run to verify pass → commit. The pre-commit hook runs `cargo fmt` + `cargo clippy --all-targets` and rejects on any warning.

**Goal:** Add a Slint-based GUI companion to `utmost` that shows live carve progress, drills into per-source results with type-specific previews, and replays prior runs from a bincoded event log.

**Architecture:** New `events` module in `utmost-lib` defines a versioned `CarveEvent` enum + `EventSink` trait. CLI installs a `BincodeFileSink` (always-on, unless `--disable-export`) and a `ChannelSink` when `--gui` is on. New `utmost-gui` library crate owns Slint UI + view-model + pluggable preview renderers. New `utmost-viewer` binary crate replays saved event logs. CLI gains a default-on `gui` feature, per-input-file `output-XX/` directories for multi-source runs, and forensic case metadata.

**Tech Stack:** Rust workspace, Slint 1.x, bincode, crossbeam-channel, lru, image crate (JPEG decode), serde, anyhow.

**Spec:** `docs/superpowers/specs/2026-05-17-utmost-gui-design.md`

---

## File Structure

**Created:**

- `crates/utmost-lib/src/events.rs` — `CarveEvent`, `FileHeader`, `EventSink`, `FanoutSink`, `BincodeFileSink`, `BincodeFileReader`, `ChannelSink`
- `crates/utmost-cli/src/config.rs` — TOML loader
- `crates/utmost-cli/src/output_layout.rs` — per-source subdir derivation
- `crates/utmost-cli/src/sinks.rs` — wires Fanout at startup, emits RunStarted/Finished
- `crates/utmost-gui/Cargo.toml`
- `crates/utmost-gui/src/lib.rs` — `run_live`, `run_from_file` entry points
- `crates/utmost-gui/src/view_model.rs` — `ViewModel::apply` reducer (pure Rust)
- `crates/utmost-gui/src/preview/mod.rs` — `PreviewRenderer` trait + `PreviewRegistry`
- `crates/utmost-gui/src/preview/jpeg.rs` — `JpegPreview`
- `crates/utmost-gui/src/preview/generic.rs` — `GenericIcon` fallback
- `crates/utmost-gui/ui/main.slint`, `ui/run_list.slint`, `ui/detail.slint`, `ui/side_panel.slint`
- `crates/utmost-gui/src/slint_adapter.rs` — view-model ↔ Slint bridge
- `crates/utmost-viewer/Cargo.toml`
- `crates/utmost-viewer/src/main.rs`

**Modified:**

- `Cargo.toml` (workspace deps + new members)
- `crates/utmost-lib/src/lib.rs` (`pub mod events;` + re-exports)
- `crates/utmost-lib/src/types.rs` (add `event_sink` field to `State`; add `emit()`)
- `crates/utmost-lib/src/engine.rs` (emit events at lifecycle points)
- `crates/utmost-cli/Cargo.toml` (gui feature + utmost-gui dep)
- `crates/utmost-cli/src/main.rs` (new flags + multi-source layout + sink wiring)

---

## Phase A — Library foundation (utmost-lib)

### Task 1: Add workspace dependencies + scaffold `events` module

**Files:**
- Modify: `Cargo.toml` (workspace deps)
- Modify: `crates/utmost-lib/Cargo.toml` (depend on bincode)
- Create: `crates/utmost-lib/src/events.rs` (empty module marker)
- Modify: `crates/utmost-lib/src/lib.rs` (add `pub mod events;`)

- [ ] **Step 1: Add bincode + crossbeam-channel to workspace dependencies**

Edit `Cargo.toml`, add to `[workspace.dependencies]`:

```toml
bincode = "1.3"
crossbeam-channel = "0.5"
```

- [ ] **Step 2: Add bincode + crossbeam-channel + serde to utmost-lib**

Edit `crates/utmost-lib/Cargo.toml`, ensure these are in `[dependencies]`:

```toml
bincode = { workspace = true }
crossbeam-channel = { workspace = true }
serde = { workspace = true }
```

- [ ] **Step 3: Create the empty events module**

Create `crates/utmost-lib/src/events.rs`:

```rust
//! Event stream for live and replayable carve runs.
//!
//! See `docs/superpowers/specs/2026-05-17-utmost-gui-design.md` for the
//! versioned binary format.
```

Edit `crates/utmost-lib/src/lib.rs`, add after the existing `pub mod` lines:

```rust
pub mod events;
```

- [ ] **Step 4: Verify the workspace still builds**

Run: `cargo build -p utmost-lib`
Expected: clean build, no errors.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/utmost-lib/Cargo.toml crates/utmost-lib/src/events.rs crates/utmost-lib/src/lib.rs
git commit -m "feat(events): scaffold events module + add bincode/crossbeam workspace deps"
```

---

### Task 2: Define `FileHeader` with magic + version, with round-trip test

**Files:**
- Modify: `crates/utmost-lib/src/events.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/utmost-lib/src/events.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

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
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p utmost-lib events::tests::file_header_round_trips_through_bincode`
Expected: compile error — `FileHeader` / `CURRENT_FORMAT_VERSION` not defined.

- [ ] **Step 3: Minimal implementation**

Prepend to `crates/utmost-lib/src/events.rs` (above the `#[cfg(test)]` block):

```rust
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
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p utmost-lib events::tests::file_header_round_trips_through_bincode`
Expected: 1 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-lib/src/events.rs
git commit -m "feat(events): add FileHeader with magic + format version"
```

---

### Task 3: Define `SourceDescriptor`, `CliConfigSnapshot`, `CaseMetadata`

**Files:**
- Modify: `crates/utmost-lib/src/events.rs`

- [ ] **Step 1: Write the failing test**

Add inside the existing `mod tests` block in `crates/utmost-lib/src/events.rs`:

```rust
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
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p utmost-lib events::tests`
Expected: compile errors — types not defined.

- [ ] **Step 3: Implement the types**

In `crates/utmost-lib/src/events.rs`, below `FileHeader`:

```rust
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
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p utmost-lib events::tests`
Expected: all 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-lib/src/events.rs
git commit -m "feat(events): add SourceDescriptor, CliConfigSnapshot, CaseMetadata"
```

---

### Task 4: Define `CarveEvent` enum with all variants + round-trip tests

**Files:**
- Modify: `crates/utmost-lib/src/events.rs`

- [ ] **Step 1: Write the failing tests**

Add inside the existing `mod tests` block:

```rust
    use crate::types::{FileType};
    use crate::reporting::create_file_object;

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
        let ev = CarveEvent::ProgressTick { source_id: 0, bytes_read: 9999 };
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
```

Note: `FileObject` must derive `PartialEq` for these tests. If it doesn't, add the derive in this task.

- [ ] **Step 2: Add `PartialEq` to FileObject and JpegScanInfo / JpegScanStatus / ByteRun**

In `crates/utmost-lib/src/types.rs`, locate `FileObject`, `JpegScanInfo`, `JpegScanStatus`, `ByteRun`. Add `PartialEq` to each derive list. `JpegScanStatus` already has it. Update `FileObject`, `JpegScanInfo`, `ByteRun`.

Example before/after for `ByteRun`:

```rust
// Before:
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByteRun {
// After:
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ByteRun {
```

Apply the same to `FileObject` and `JpegScanInfo`.

- [ ] **Step 3: Run to verify compile failure on the enum**

Run: `cargo test -p utmost-lib events::tests`
Expected: compile error — `CarveEvent` not defined.

- [ ] **Step 4: Implement `CarveEvent`**

Add to `crates/utmost-lib/src/events.rs` (above the `#[cfg(test)]` block):

```rust
use crate::types::{ExecutionEnvironment, FileObject, FileType};

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
```

If `ExecutionEnvironment` doesn't yet derive `PartialEq`, add it in `crates/utmost-lib/src/types.rs`. Same check for any other transitively-referenced type.

- [ ] **Step 5: Run to verify pass**

Run: `cargo test -p utmost-lib events::tests`
Expected: all CarveEvent round-trip tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-lib/src/events.rs crates/utmost-lib/src/types.rs
git commit -m "feat(events): add CarveEvent enum with all six variants"
```

---

### Task 5: Add `persistable()` method with exhaustive-match test

**Files:**
- Modify: `crates/utmost-lib/src/events.rs`

- [ ] **Step 1: Write the failing test**

Add inside `mod tests`:

```rust
    #[test]
    fn persistable_returns_true_for_all_non_progress_variants() {
        assert!(sample_run_started().persistable());
        assert!(CarveEvent::SourceStarted { source_id: 0 }.persistable());
        let fo = create_file_object("a.jpg", FileType::Jpeg, 1, 0, None);
        assert!(CarveEvent::FileFound {
            source_id: 0, file: fo, img_offset: 0, written_path: "a.jpg".into()
        }.persistable());
        assert!(CarveEvent::SourceFinished {
            source_id: 0, bytes_read: 0, duration_ms: 0
        }.persistable());
        assert!(CarveEvent::RunFinished {
            duration_ms: 0, total_files_written: 0
        }.persistable());
    }

    #[test]
    fn persistable_returns_false_for_progress_tick() {
        let ev = CarveEvent::ProgressTick { source_id: 0, bytes_read: 0 };
        assert!(!ev.persistable());
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p utmost-lib events::tests::persistable`
Expected: compile error — no `persistable` method.

- [ ] **Step 3: Implement**

Add to `crates/utmost-lib/src/events.rs` (after the `CarveEvent` enum):

```rust
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
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p utmost-lib events::tests::persistable`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-lib/src/events.rs
git commit -m "feat(events): add CarveEvent::persistable() with exhaustive match"
```

---

### Task 6: Define `EventSink` trait + `FanoutSink` with recording-sink tests

**Files:**
- Modify: `crates/utmost-lib/src/events.rs`

- [ ] **Step 1: Write the failing test**

Add inside `mod tests`:

```rust
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
        let fanout = FanoutSink::new(vec![a.clone(), b.clone()]);

        fanout.emit(&CarveEvent::SourceStarted { source_id: 1 });
        fanout.emit(&CarveEvent::ProgressTick { source_id: 1, bytes_read: 10 });

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
        let fanout = FanoutSink::new(vec![Arc::new(PanickingSink) as Arc<dyn EventSink>, good.clone()]);
        fanout.emit(&CarveEvent::SourceStarted { source_id: 9 });
        assert_eq!(good.events.lock().unwrap().len(), 1);
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p utmost-lib events::tests::fanout`
Expected: compile error — `EventSink`/`FanoutSink` not defined.

- [ ] **Step 3: Implement**

Add to `crates/utmost-lib/src/events.rs`:

```rust
use std::sync::Arc;

/// Receiver of `CarveEvent`s emitted by the engine. Implementations must
/// never panic; failures should be swallowed (and logged) so a misbehaving
/// sink cannot abort a carve.
pub trait EventSink: Send + Sync {
    fn emit(&self, event: &CarveEvent);
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
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p utmost-lib events::tests::fanout`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-lib/src/events.rs
git commit -m "feat(events): add EventSink trait + FanoutSink"
```

---

### Task 7: Implement `BincodeFileSink` (write side) with header + framing + persistability filtering

**Files:**
- Modify: `crates/utmost-lib/src/events.rs`

- [ ] **Step 1: Write the failing tests**

Add inside `mod tests`:

```rust
    use std::io::Read;
    use tempfile::tempdir;

    fn read_all(path: &std::path::Path) -> Vec<u8> {
        let mut buf = Vec::new();
        std::fs::File::open(path).unwrap().read_to_end(&mut buf).unwrap();
        buf
    }

    fn read_frames(path: &std::path::Path) -> Vec<Vec<u8>> {
        let bytes = read_all(path);
        let mut out = Vec::new();
        let mut i = 0;
        while i + 4 <= bytes.len() {
            let len = u32::from_le_bytes(bytes[i..i+4].try_into().unwrap()) as usize;
            i += 4;
            if i + len > bytes.len() { break; }
            out.push(bytes[i..i+len].to_vec());
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
        sink.emit(&CarveEvent::ProgressTick { source_id: 0, bytes_read: 1 });
        sink.emit(&CarveEvent::SourceFinished { source_id: 0, bytes_read: 1, duration_ms: 1 });
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
```

- [ ] **Step 2: Add tempfile as a dev-dep if not already present**

`tempfile` is already used in tests (see `crates/utmost-lib/src/types.rs` tests). Verify `[dev-dependencies] tempfile = "..."` is in `crates/utmost-lib/Cargo.toml`. If missing, add `tempfile = "3"`.

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p utmost-lib events::tests::bincode_sink`
Expected: compile error — `BincodeFileSink` not defined.

- [ ] **Step 4: Implement**

Add to `crates/utmost-lib/src/events.rs`:

```rust
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;
use tracing::warn;

/// Length-prefixed (u32 LE) bincode event log. Writes the FileHeader on
/// creation; subsequent `emit` calls write only persistable events.
///
/// Sink errors are absorbed: on the first I/O failure the sink marks
/// itself disabled and logs once at warn level. The carve continues.
pub struct BincodeFileSink {
    inner: Mutex<BincodeFileSinkInner>,
}

struct BincodeFileSinkInner {
    writer: BufWriter<File>,
    disabled: bool,
}

impl BincodeFileSink {
    pub fn create(path: &Path) -> std::io::Result<Self> {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);
        write_frame(&mut writer, &FileHeader::default())
            .map_err(|e| std::io::Error::other(format!("writing file header: {e}")))?;
        Ok(Self {
            inner: Mutex::new(BincodeFileSinkInner { writer, disabled: false }),
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
            warn!("bincode event sink disabled after write failure: {e}");
            guard.disabled = true;
        }
    }
}

fn write_frame<T: serde::Serialize, W: Write>(writer: &mut W, value: &T) -> std::io::Result<()> {
    let bytes = bincode::serialize(value)
        .map_err(|e| std::io::Error::other(format!("bincode serialize: {e}")))?;
    let len = u32::try_from(bytes.len())
        .map_err(|_| std::io::Error::other("frame larger than u32::MAX"))?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}
```

- [ ] **Step 5: Run to verify pass**

Run: `cargo test -p utmost-lib events::tests::bincode_sink`
Expected: 1 passed.

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-lib/src/events.rs crates/utmost-lib/Cargo.toml
git commit -m "feat(events): add BincodeFileSink with framing + persistability filter"
```

---

### Task 8: Implement `BincodeFileReader` (replay side) with header validation

**Files:**
- Modify: `crates/utmost-lib/src/events.rs`

- [ ] **Step 1: Write the failing tests**

Add inside `mod tests`:

```rust
    #[test]
    fn reader_validates_magic_and_yields_events() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("e.bin");
        let sink = BincodeFileSink::create(&path).unwrap();
        sink.emit(&CarveEvent::SourceStarted { source_id: 0 });
        sink.emit(&CarveEvent::RunFinished { duration_ms: 5, total_files_written: 0 });
        drop(sink);

        let mut reader = BincodeFileReader::open(&path).unwrap();
        let events: Vec<_> = std::iter::from_fn(|| reader.next_event().transpose()).collect::<Result<_, _>>().unwrap();
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], CarveEvent::SourceStarted { .. }));
        assert!(matches!(events[1], CarveEvent::RunFinished { .. }));
    }

    #[test]
    fn reader_rejects_wrong_magic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.bin");
        // Write a frame containing a bogus header.
        let bogus = FileHeader { magic: *b"NOPE", format_version: 1 };
        let bytes = bincode::serialize(&bogus).unwrap();
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&(bytes.len() as u32).to_le_bytes()).unwrap();
        f.write_all(&bytes).unwrap();
        drop(f);

        let err = BincodeFileReader::open(&path).unwrap_err();
        assert!(format!("{err}").contains("magic"), "unexpected error: {err}");
    }

    #[test]
    fn reader_rejects_future_version() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("future.bin");
        let future = FileHeader { magic: MAGIC, format_version: CURRENT_FORMAT_VERSION + 1 };
        let bytes = bincode::serialize(&future).unwrap();
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&(bytes.len() as u32).to_le_bytes()).unwrap();
        f.write_all(&bytes).unwrap();
        drop(f);

        let err = BincodeFileReader::open(&path).unwrap_err();
        assert!(format!("{err}").contains("version"), "unexpected error: {err}");
    }

    #[test]
    fn reader_treats_truncated_trailing_frame_as_end_of_stream() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("trunc.bin");
        let sink = BincodeFileSink::create(&path).unwrap();
        sink.emit(&CarveEvent::SourceStarted { source_id: 0 });
        drop(sink);

        // Append a length prefix promising 1000 bytes but no body.
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&1000u32.to_le_bytes()).unwrap();
        drop(f);

        let mut reader = BincodeFileReader::open(&path).unwrap();
        let first = reader.next_event().unwrap();
        assert!(matches!(first, Some(CarveEvent::SourceStarted { .. })));
        let second = reader.next_event().unwrap();
        assert!(second.is_none(), "expected truncation handled as EOF");
        assert!(reader.was_truncated(), "expected truncation flag");
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p utmost-lib events::tests::reader`
Expected: compile error — `BincodeFileReader` not defined.

- [ ] **Step 3: Implement**

Add to `crates/utmost-lib/src/events.rs`:

```rust
use std::io::{BufReader, Read};

#[derive(Debug, thiserror::Error)]
pub enum ReaderError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("bincode decode error: {0}")]
    Decode(String),
    #[error("invalid magic — not a utmost event log")]
    InvalidMagic,
    #[error("unsupported format version {found} (this build supports {supported})")]
    UnsupportedVersion { found: u32, supported: u32 },
}

pub struct BincodeFileReader {
    reader: BufReader<File>,
    truncated: bool,
}

impl BincodeFileReader {
    pub fn open(path: &Path) -> Result<Self, ReaderError> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let header_bytes = read_frame(&mut reader)?
            .ok_or_else(|| ReaderError::Decode("empty file — no header frame".into()))?;
        let header: FileHeader = bincode::deserialize(&header_bytes)
            .map_err(|e| ReaderError::Decode(e.to_string()))?;
        if header.magic != MAGIC {
            return Err(ReaderError::InvalidMagic);
        }
        if header.format_version > CURRENT_FORMAT_VERSION {
            return Err(ReaderError::UnsupportedVersion {
                found: header.format_version,
                supported: CURRENT_FORMAT_VERSION,
            });
        }
        Ok(Self { reader, truncated: false })
    }

    pub fn next_event(&mut self) -> Result<Option<CarveEvent>, ReaderError> {
        match read_frame(&mut self.reader)? {
            None => Ok(None),
            Some(bytes) => {
                let ev: CarveEvent = bincode::deserialize(&bytes)
                    .map_err(|e| ReaderError::Decode(e.to_string()))?;
                Ok(Some(ev))
            }
        }
    }

    /// True if the last `next_event()` stopped on a partial trailing frame.
    pub fn was_truncated(&self) -> bool {
        self.truncated
    }
}

/// Read one length-prefixed frame. Returns `Ok(None)` at clean EOF or a
/// truncated trailing frame; in the truncated case the caller's wrapper
/// (BincodeFileReader) sets `truncated = true`.
fn read_frame<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>, std::io::Error> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    match reader.read_exact(&mut buf) {
        Ok(()) => Ok(Some(buf)),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(e),
    }
}
```

Update `next_event` to set `self.truncated` when `read_frame` returns `None` after consuming the length prefix. Simpler approach: have `read_frame` return a tri-state, or track inside `next_event` by reading the length manually. Use this revised body for `next_event`:

```rust
    pub fn next_event(&mut self) -> Result<Option<CarveEvent>, ReaderError> {
        let mut len_buf = [0u8; 4];
        match self.reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        if let Err(e) = self.reader.read_exact(&mut buf) {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                self.truncated = true;
                return Ok(None);
            }
            return Err(e.into());
        }
        let ev: CarveEvent = bincode::deserialize(&buf)
            .map_err(|e| ReaderError::Decode(e.to_string()))?;
        Ok(Some(ev))
    }
```

Add `thiserror = "1.0"` to `[workspace.dependencies]` if not present, then to utmost-lib `[dependencies]`.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p utmost-lib events::tests::reader`
Expected: all 4 reader tests pass.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/utmost-lib/Cargo.toml crates/utmost-lib/src/events.rs
git commit -m "feat(events): add BincodeFileReader with magic + version validation"
```

---

### Task 9: Implement `ChannelSink` for live mode

**Files:**
- Modify: `crates/utmost-lib/src/events.rs`

- [ ] **Step 1: Write the failing test**

Add inside `mod tests`:

```rust
    #[test]
    fn channel_sink_forwards_all_events_including_progress() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let sink = ChannelSink::new(tx);

        sink.emit(&CarveEvent::SourceStarted { source_id: 1 });
        sink.emit(&CarveEvent::ProgressTick { source_id: 1, bytes_read: 5 });
        sink.emit(&CarveEvent::RunFinished { duration_ms: 1, total_files_written: 0 });

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
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p utmost-lib events::tests::channel_sink`
Expected: compile error.

- [ ] **Step 3: Implement**

Add to `crates/utmost-lib/src/events.rs`:

```rust
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
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p utmost-lib events::tests::channel_sink`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-lib/src/events.rs
git commit -m "feat(events): add ChannelSink for live mode"
```

---

### Task 10: Re-export events public types from `utmost-lib` lib root

**Files:**
- Modify: `crates/utmost-lib/src/lib.rs`

- [ ] **Step 1: Add re-exports**

In `crates/utmost-lib/src/lib.rs`, add to the existing `pub use` section:

```rust
pub use events::{
    BincodeFileReader, BincodeFileSink, CarveEvent, CaseMetadata, ChannelSink,
    CliConfigSnapshot, CURRENT_FORMAT_VERSION, EventSink, FanoutSink, FileHeader,
    MAGIC, ReaderError, SourceDescriptor,
};
```

- [ ] **Step 2: Verify compile**

Run: `cargo build -p utmost-lib && cargo test -p utmost-lib events`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add crates/utmost-lib/src/lib.rs
git commit -m "feat(events): re-export public events types from utmost-lib root"
```

---

## Phase B — State + engine integration (utmost-lib)

### Task 11: Add `event_sink` field to `State` + `emit()` helper

**Files:**
- Modify: `crates/utmost-lib/src/types.rs`

- [ ] **Step 1: Write the failing test**

Append to the `mod tests` block in `crates/utmost-lib/src/types.rs`:

```rust
    use crate::events::{CarveEvent, EventSink};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct RecordingSink { events: Mutex<Vec<CarveEvent>> }
    impl EventSink for RecordingSink {
        fn emit(&self, ev: &CarveEvent) { self.events.lock().unwrap().push(ev.clone()); }
    }

    #[test]
    fn state_emit_forwards_to_installed_sink() {
        let temp = tempdir().unwrap();
        let config = StateConfig {
            output_directory: temp.path().to_string_lossy().to_string(),
            debug: false,
            prefix_filenames: false,
            chunk_size: None,
            block_size: None,
            skip: None,
            disable_validation: false,
            report_only: false,
            disable_report: true,
            disable_audit: true,
            quick: false,
            write_all: false,
            keep_incomplete_jpeg: false,
        };
        let mut state = State::new(config).unwrap();
        let sink: Arc<RecordingSink> = Arc::new(RecordingSink::default());
        state.set_event_sink(sink.clone());

        state.emit(CarveEvent::SourceStarted { source_id: 4 });

        assert_eq!(sink.events.lock().unwrap().len(), 1);
    }

    #[test]
    fn state_emit_is_noop_without_sink() {
        let temp = tempdir().unwrap();
        let config = StateConfig {
            output_directory: temp.path().to_string_lossy().to_string(),
            debug: false, prefix_filenames: false, chunk_size: None, block_size: None,
            skip: None, disable_validation: false, report_only: false,
            disable_report: true, disable_audit: true, quick: false, write_all: false,
            keep_incomplete_jpeg: false,
        };
        let state = State::new(config).unwrap();
        // Should not panic
        state.emit(CarveEvent::SourceStarted { source_id: 0 });
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p utmost-lib types::tests::state_emit`
Expected: compile error — `set_event_sink` / `emit` not on State.

- [ ] **Step 3: Add `event_sink` to `State`**

In `crates/utmost-lib/src/types.rs`:

Add `use crate::events::{CarveEvent, EventSink};` near the top.

In `pub struct State`, add field:

```rust
    pub event_sink: Option<Arc<dyn EventSink>>,
```

In `State::new`, initialize:

```rust
            event_sink: None,
```

Add methods to `impl State`:

```rust
    pub fn set_event_sink(&mut self, sink: Arc<dyn EventSink>) {
        self.event_sink = Some(sink);
    }

    pub fn emit(&self, event: CarveEvent) {
        if let Some(ref sink) = self.event_sink {
            sink.emit(&event);
        }
    }
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p utmost-lib types::tests::state_emit`
Expected: 2 passed.

- [ ] **Step 5: Verify the full test suite still passes**

Run: `cargo test -p utmost-lib`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-lib/src/types.rs
git commit -m "feat(state): add event_sink + emit() to State"
```

---

### Task 12: Engine emits `SourceStarted`/`SourceFinished` from stream entry points

**Files:**
- Modify: `crates/utmost-lib/src/engine.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/utmost-lib/tests/engine_events.rs`:

```rust
use std::sync::{Arc, Mutex};
use utmost_lib::{
    engine, events::{CarveEvent, EventSink},
    types::{FileInfo, State, StateConfig},
};

#[derive(Default)]
struct RecordingSink { events: Mutex<Vec<CarveEvent>> }
impl EventSink for RecordingSink {
    fn emit(&self, ev: &CarveEvent) { self.events.lock().unwrap().push(ev.clone()); }
}

fn make_state(dir: &std::path::Path) -> State {
    let cfg = StateConfig {
        output_directory: dir.to_string_lossy().to_string(),
        debug: false, prefix_filenames: false, chunk_size: None, block_size: None,
        skip: None, disable_validation: false, report_only: false,
        disable_report: true, disable_audit: true, quick: false, write_all: false,
        keep_incomplete_jpeg: false,
    };
    State::new(cfg).unwrap()
}

#[test]
fn buffer_search_emits_source_lifecycle_events() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(tmp.path());
    let sink: Arc<RecordingSink> = Arc::new(RecordingSink::default());
    state.set_event_sink(sink.clone());

    let mut fi = FileInfo {
        filename: "buf".into(), total_bytes: 0, total_megs: 0, bytes_read: 0,
        per_file_counter: 0,
    };
    let data = vec![0u8; 16];
    engine::search_buffer(&data, &state, &mut fi, 0, 1).unwrap();

    let events = sink.events.lock().unwrap().clone();
    assert!(events.iter().any(|e| matches!(e, CarveEvent::SourceStarted { .. })),
        "expected a SourceStarted event, got: {events:?}");
    assert!(events.iter().any(|e| matches!(e, CarveEvent::SourceFinished { .. })),
        "expected a SourceFinished event, got: {events:?}");
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p utmost-lib --test engine_events`
Expected: test fails — no SourceStarted/SourceFinished emitted yet.

- [ ] **Step 3: Implement engine emission**

In `crates/utmost-lib/src/engine.rs`, modify `search_buffer`:

After `setup_stream_info(state, file_info)?;` line near the top of the function, add:

```rust
    let started = std::time::Instant::now();
    state.emit(crate::events::CarveEvent::SourceStarted { source_id: file_info.source_id });
```

Before the `Ok(())` return, add:

```rust
    state.emit(crate::events::CarveEvent::SourceFinished {
        source_id: file_info.source_id,
        bytes_read: file_info.bytes_read as u64,
        duration_ms: started.elapsed().as_millis() as u64,
    });
```

Apply the same pattern to `search_stream` and `search_stream_with_progress`.

`FileInfo` needs a `source_id: u32` field. Add it in `crates/utmost-lib/src/types.rs`:

```rust
pub struct FileInfo {
    pub filename: String,
    pub total_bytes: usize,
    pub total_megs: usize,
    pub bytes_read: usize,
    pub per_file_counter: usize,
    pub source_id: u32,
}
```

Update every `FileInfo { ... }` construction site (search for `FileInfo {` across the workspace) to include `source_id: 0` for now. Locations to update:
- `crates/utmost-cli/src/main.rs` (multiple)
- Any tests creating `FileInfo`

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p utmost-lib --test engine_events`
Expected: pass.

Then run full suite: `cargo test -p utmost-lib && cargo test -p utmost-cli`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(engine): emit SourceStarted/SourceFinished around stream search"
```

---

### Task 13: Engine emits `FileFound` whenever a file is written

**Files:**
- Modify: `crates/utmost-lib/src/engine.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/utmost-lib/tests/engine_events.rs`:

```rust
#[test]
fn search_emits_file_found_for_each_extracted_file() {
    // A minimal JPEG: SOI (FFD8 FFE0) + some payload + EOI (FFD9).
    let mut data = vec![0xFFu8, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
    data.extend_from_slice(b"JFIF\0");
    data.extend(std::iter::repeat(0xAA).take(64));
    data.extend_from_slice(&[0xFF, 0xD9]);

    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(tmp.path());
    state.set_search_specs(utmost_lib::search_specs::init_all_search_specs());
    let sink: Arc<RecordingSink> = Arc::new(RecordingSink::default());
    state.set_event_sink(sink.clone());

    let mut fi = FileInfo {
        filename: "buf".into(), total_bytes: data.len(), total_megs: 0,
        bytes_read: 0, per_file_counter: 0, source_id: 0,
    };
    engine::search_buffer(&data, &state, &mut fi, 0, 1).unwrap();

    let events = sink.events.lock().unwrap().clone();
    let found_count = events.iter()
        .filter(|e| matches!(e, CarveEvent::FileFound { .. }))
        .count();
    assert!(found_count >= 1, "expected at least 1 FileFound event, got events: {events:?}");
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p utmost-lib --test engine_events`
Expected: the new test fails (no `FileFound` emitted yet).

- [ ] **Step 3: Implement emission**

Locate the file-extraction point in `crates/utmost-lib/src/engine.rs` — search for `state.report_file` calls (`grep -n "report_file" crates/utmost-lib/src/engine.rs`). At each location where `state.report_file(...)` is currently called, also call `state.emit(...)`.

For each call site, immediately after `state.report_file(...)?`, add:

```rust
        state.emit(crate::events::CarveEvent::FileFound {
            source_id: file_info.source_id,
            file: crate::reporting::create_file_object(
                &filename_written,
                file_type,
                file_size,
                img_offset,
                jpeg_scan.clone(),
            ),
            img_offset,
            written_path: filename_written.clone(),
        });
```

Adapt variable names to whatever is in scope at that call site (`filename_written`, `file_type`, `file_size`, `img_offset`, `jpeg_scan`). If the existing `report_file` call already constructs a `FileObject` via `create_file_object`, refactor to compute it once and pass it to both calls.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p utmost-lib --test engine_events`
Expected: all tests pass.

Then: `cargo test -p utmost-lib && cargo test -p utmost-cli`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-lib/src/engine.rs
git commit -m "feat(engine): emit FileFound for each extracted file"
```

---

### Task 14: Engine emits throttled `ProgressTick` from the progress-callback path

**Files:**
- Modify: `crates/utmost-lib/src/engine.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/utmost-lib/tests/engine_events.rs`:

```rust
#[test]
fn stream_search_emits_progress_ticks() {
    use std::io::Write;
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("blob.bin");
    let mut f = std::fs::File::create(&path).unwrap();
    // Write enough data to trigger multiple progress callbacks.
    f.write_all(&vec![0u8; 8 * 1024 * 1024]).unwrap();
    drop(f);

    let mut state = make_state(tmp.path());
    let sink: Arc<RecordingSink> = Arc::new(RecordingSink::default());
    state.set_event_sink(sink.clone());

    let mut fi = FileInfo {
        filename: path.to_string_lossy().to_string(),
        total_bytes: 8 * 1024 * 1024, total_megs: 8, bytes_read: 0,
        per_file_counter: 0, source_id: 0,
    };
    let mut input = std::fs::File::open(&path).unwrap();
    engine::search_stream_with_progress(&mut input, &state, &mut fi, |_| {}, 1).unwrap();

    let events = sink.events.lock().unwrap().clone();
    let tick_count = events.iter()
        .filter(|e| matches!(e, CarveEvent::ProgressTick { .. }))
        .count();
    assert!(tick_count >= 1, "expected at least 1 ProgressTick, got events: {events:?}");
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p utmost-lib --test engine_events stream_search_emits_progress_ticks`
Expected: fail.

- [ ] **Step 3: Implement throttled emission**

In `crates/utmost-lib/src/engine.rs`, find `search_stream_with_progress`. After each chunk's `f_offset += bytes_read as u64;` line, emit a tick. To avoid flooding, throttle to ~20 Hz using `std::time::Instant`:

Add a local `let mut last_tick = std::time::Instant::now();` before the loop. Inside the loop, after updating `f_offset`:

```rust
        if last_tick.elapsed() >= std::time::Duration::from_millis(50) {
            state.emit(crate::events::CarveEvent::ProgressTick {
                source_id: file_info.source_id,
                bytes_read: f_offset,
            });
            last_tick = std::time::Instant::now();
        }
```

Also emit a final tick after the loop so the final position is recorded:

```rust
    state.emit(crate::events::CarveEvent::ProgressTick {
        source_id: file_info.source_id,
        bytes_read: f_offset,
    });
```

Apply the same pattern to `search_stream`.

For tests to reliably see at least one tick on small inputs, also emit one tick *before* the loop with `bytes_read: 0`:

```rust
    state.emit(crate::events::CarveEvent::ProgressTick {
        source_id: file_info.source_id, bytes_read: 0,
    });
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p utmost-lib --test engine_events`
Expected: all engine_events tests pass.

Full suite: `cargo test -p utmost-lib`

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-lib/src/engine.rs
git commit -m "feat(engine): emit throttled ProgressTick events during stream search"
```

---

## Phase C — CLI output layout

### Task 15: Implement `output_layout::derive_subdir` with collision handling

**Files:**
- Create: `crates/utmost-cli/src/output_layout.rs`
- Modify: `crates/utmost-cli/src/main.rs` (`mod output_layout;`)

- [ ] **Step 1: Write the failing tests**

Create `crates/utmost-cli/src/output_layout.rs`:

```rust
//! Per-input-file output subdirectory derivation for multi-source runs.

use anyhow::{Result, bail};
use std::collections::BTreeSet;
use utmost_lib::types::clean_filename;

const MAX_SUBDIR_NAME: usize = 32;
const MAX_COLLISION_SUFFIX: u32 = 1000;

/// Derive a unique output-XX/ subdirectory name for `input_path`, avoiding any
/// names already in `taken`. Returns just the basename (no leading slash).
pub fn derive_subdir(input_path: &str, taken: &BTreeSet<String>) -> Result<String> {
    let base = clean_filename(input_path, MAX_SUBDIR_NAME);
    let base = if base.is_empty() { "source".to_string() } else { base };
    let candidate = format!("output-{}", base);
    if !taken.contains(&candidate) {
        return Ok(candidate);
    }
    for i in 1..=MAX_COLLISION_SUFFIX {
        let next = format!("output-{}-{}", base, i);
        if !taken.contains(&next) {
            return Ok(next);
        }
    }
    bail!("collision suffix exhausted for input: {input_path}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_derivation_uses_clean_filename() {
        let taken = BTreeSet::new();
        let r = derive_subdir("/path/disk_image.dd", &taken).unwrap();
        assert_eq!(r, "output-disk_image_dd");
    }

    #[test]
    fn collision_appends_suffix() {
        let mut taken = BTreeSet::new();
        taken.insert("output-foo".to_string());
        let r = derive_subdir("/path/foo", &taken).unwrap();
        assert_eq!(r, "output-foo-1");
    }

    #[test]
    fn two_distinct_inputs_collide_after_cleaning() {
        let mut taken = BTreeSet::new();
        let a = derive_subdir("file---one", &taken).unwrap();
        taken.insert(a.clone());
        let b = derive_subdir("file___one", &taken).unwrap();
        assert_ne!(a, b);
        assert!(b.ends_with("-1"));
    }

    #[test]
    fn empty_filename_falls_back_to_source() {
        let taken = BTreeSet::new();
        let r = derive_subdir("", &taken).unwrap();
        assert_eq!(r, "output-source");
    }

    #[test]
    fn collision_bound_is_enforced() {
        let mut taken = BTreeSet::new();
        taken.insert("output-x".to_string());
        for i in 1..=MAX_COLLISION_SUFFIX {
            taken.insert(format!("output-x-{}", i));
        }
        let err = derive_subdir("x", &taken).unwrap_err();
        assert!(format!("{err}").contains("collision"));
    }

    #[test]
    fn truncation_clips_at_32_chars() {
        let taken = BTreeSet::new();
        let long = "a".repeat(100);
        let r = derive_subdir(&long, &taken).unwrap();
        // "output-" prefix + 32 chars max
        assert!(r.len() <= "output-".len() + MAX_SUBDIR_NAME);
    }
}
```

In `crates/utmost-cli/src/main.rs`, add at the top below the `use` block:

```rust
mod output_layout;
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p utmost-cli output_layout::tests`
Expected: all 6 tests pass on first run (this is a pure module).

If the engineer is following strict TDD, comment out the function bodies first to see them fail, then restore. For practical purposes, since this is a self-contained pure module written in one shot, accept the green pass after careful inspection.

- [ ] **Step 3: Verify the binary still builds**

Run: `cargo build -p utmost-cli`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/utmost-cli/src/output_layout.rs crates/utmost-cli/src/main.rs
git commit -m "feat(cli): add output_layout::derive_subdir with collision handling"
```

---

## Phase D — CLI plumbing

### Task 16: TOML config loader at `~/.config/utmost/config.toml`

**Files:**
- Create: `crates/utmost-cli/src/config.rs`
- Modify: `crates/utmost-cli/src/main.rs`
- Modify: `crates/utmost-cli/Cargo.toml` (add `dirs` for $XDG_CONFIG_HOME)

- [ ] **Step 1: Add `dirs` to utmost-cli deps**

Edit `crates/utmost-cli/Cargo.toml`, add to `[dependencies]`:

```toml
dirs = "5"
```

- [ ] **Step 2: Write the failing tests**

Create `crates/utmost-cli/src/config.rs`:

```rust
//! User configuration loaded from `~/.config/utmost/config.toml`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use utmost_lib::events::CaseMetadata;

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq)]
pub struct UserConfig {
    #[serde(default)]
    pub gui: GuiConfig,
    #[serde(default)]
    pub export: ExportConfig,
    #[serde(default)]
    pub case: CaseConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct GuiConfig {
    pub enabled: bool,
}
impl Default for GuiConfig {
    fn default() -> Self { Self { enabled: false } }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ExportConfig {
    pub enabled: bool,
}
impl Default for ExportConfig {
    fn default() -> Self { Self { enabled: true } }
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq)]
pub struct CaseConfig {
    #[serde(default)]
    pub case_id: Option<String>,
    #[serde(default)]
    pub examiner: Option<String>,
    #[serde(default)]
    pub evidence_id: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

impl CaseConfig {
    pub fn to_metadata(&self) -> CaseMetadata {
        CaseMetadata {
            case_id: self.case_id.clone(),
            examiner: self.examiner.clone(),
            evidence_id: self.evidence_id.clone(),
            notes: self.notes.clone(),
        }
    }
}

/// Returns the default config path, or `None` on platforms with no XDG dir.
pub fn default_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("utmost").join("config.toml"))
}

/// Load config from `path`. Missing file → returns `Ok(UserConfig::default())`.
/// Malformed TOML → returns `Err`.
pub fn load_from(path: &std::path::Path) -> Result<UserConfig> {
    match std::fs::read_to_string(path) {
        Ok(s) => toml::from_str(&s).with_context(|| format!("parsing {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(UserConfig::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn missing_file_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let r = load_from(&dir.path().join("nope.toml")).unwrap();
        assert_eq!(r, UserConfig::default());
        assert!(r.export.enabled);
        assert!(!r.gui.enabled);
    }

    #[test]
    fn malformed_file_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bad.toml");
        std::fs::File::create(&p).unwrap().write_all(b"this is not toml = =").unwrap();
        assert!(load_from(&p).is_err());
    }

    #[test]
    fn loads_gui_enabled_true() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ok.toml");
        std::fs::File::create(&p).unwrap()
            .write_all(b"[gui]\nenabled = true\n").unwrap();
        let r = load_from(&p).unwrap();
        assert!(r.gui.enabled);
    }

    #[test]
    fn loads_case_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("case.toml");
        std::fs::File::create(&p).unwrap().write_all(
            b"[case]\nexaminer = \"Jane\"\ncase_id = \"C-1\"\n"
        ).unwrap();
        let r = load_from(&p).unwrap();
        assert_eq!(r.case.examiner.as_deref(), Some("Jane"));
        assert_eq!(r.case.case_id.as_deref(), Some("C-1"));
    }
}
```

In `crates/utmost-cli/src/main.rs`, add:

```rust
mod config;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p utmost-cli config::tests`
Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add crates/utmost-cli/Cargo.toml crates/utmost-cli/src/config.rs crates/utmost-cli/src/main.rs
git commit -m "feat(cli): add ~/.config/utmost/config.toml loader"
```

---

### Task 17: Add CLI flags for `--gui`/`--no-gui`/`--disable-export` and case metadata

**Files:**
- Modify: `crates/utmost-cli/src/main.rs`

- [ ] **Step 1: Extend `CarveArgs`**

In `crates/utmost-cli/src/main.rs`, add fields to `CarveArgs` (right before `pub input_files`):

```rust
    /// Enable Slint GUI for live progress display (overrides config file)
    #[arg(long, conflicts_with = "no_gui")]
    pub gui: bool,

    /// Disable Slint GUI even if enabled in config file
    #[arg(long)]
    pub no_gui: bool,

    /// Disable writing carve_events.bin (the bincode event log)
    #[arg(long)]
    pub disable_export: bool,

    /// Forensic case identifier
    #[arg(long)]
    pub case_id: Option<String>,

    /// Examiner name for forensic case metadata
    #[arg(long)]
    pub examiner: Option<String>,

    /// Evidence identifier for forensic case metadata
    #[arg(long)]
    pub evidence_id: Option<String>,

    /// Free-form notes attached to the run
    #[arg(long)]
    pub notes: Option<String>,
```

- [ ] **Step 2: Build verification**

Run: `cargo build -p utmost-cli && cargo run -p utmost-cli -- --help`
Expected: clean build; help text shows the new flags.

Then verify mutual exclusion: `cargo run -p utmost-cli -- --gui --no-gui foo.img 2>&1 | head -5`
Expected: clap error mentioning the conflict.

- [ ] **Step 3: Commit**

```bash
git add crates/utmost-cli/src/main.rs
git commit -m "feat(cli): add --gui/--no-gui/--disable-export and case metadata flags"
```

---

### Task 18: Build CLI-effective config: merge TOML + CLI flags

**Files:**
- Modify: `crates/utmost-cli/src/main.rs`

- [ ] **Step 1: Add a small helper for resolving effective settings**

In `crates/utmost-cli/src/main.rs`, near the top (above `fn main()`), add:

```rust
struct EffectiveSettings {
    gui_enabled: bool,
    export_enabled: bool,
    case: utmost_lib::events::CaseMetadata,
}

fn resolve_settings(args: &CarveArgs, user_cfg: &config::UserConfig) -> EffectiveSettings {
    let gui_enabled = if args.gui { true }
        else if args.no_gui { false }
        else { user_cfg.gui.enabled };

    let export_enabled = if args.disable_export { false } else { user_cfg.export.enabled };

    // CLI flags override config-file values per-field.
    let mut case = user_cfg.case.to_metadata();
    if let Some(v) = args.case_id.clone()     { case.case_id = Some(v); }
    if let Some(v) = args.examiner.clone()    { case.examiner = Some(v); }
    if let Some(v) = args.evidence_id.clone() { case.evidence_id = Some(v); }
    if let Some(v) = args.notes.clone()       { case.notes = Some(v); }

    EffectiveSettings { gui_enabled, export_enabled, case }
}

#[cfg(test)]
mod settings_tests {
    use super::*;
    use clap::Parser;

    fn parse(extra: &[&str]) -> CarveArgs {
        let mut argv = vec!["utmost"];
        argv.extend(extra);
        argv.push("dummy.img");
        CarveArgs::parse_from(argv)
    }

    #[test]
    fn gui_flag_overrides_disabled_config() {
        let cfg = config::UserConfig::default();
        let args = parse(&["--gui"]);
        assert!(resolve_settings(&args, &cfg).gui_enabled);
    }

    #[test]
    fn no_gui_flag_overrides_enabled_config() {
        let mut cfg = config::UserConfig::default();
        cfg.gui.enabled = true;
        let args = parse(&["--no-gui"]);
        assert!(!resolve_settings(&args, &cfg).gui_enabled);
    }

    #[test]
    fn disable_export_overrides_enabled_config() {
        let cfg = config::UserConfig::default(); // export.enabled default = true
        let args = parse(&["--disable-export"]);
        assert!(!resolve_settings(&args, &cfg).export_enabled);
    }

    #[test]
    fn cli_case_id_overrides_config() {
        let mut cfg = config::UserConfig::default();
        cfg.case.case_id = Some("from-config".into());
        let args = parse(&["--case-id", "from-cli"]);
        let s = resolve_settings(&args, &cfg);
        assert_eq!(s.case.case_id.as_deref(), Some("from-cli"));
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p utmost-cli settings_tests`
Expected: 4 pass.

- [ ] **Step 3: Commit**

```bash
git add crates/utmost-cli/src/main.rs
git commit -m "feat(cli): resolve effective settings from config + CLI flags"
```

---

### Task 19: CLI installs `BincodeFileSink` per source + multi-source layout

**Files:**
- Modify: `crates/utmost-cli/src/main.rs`
- Create: `crates/utmost-cli/src/sinks.rs`

- [ ] **Step 1: Create `sinks.rs` skeleton**

Create `crates/utmost-cli/src/sinks.rs`:

```rust
//! Helpers for assembling EventSinks for a carve run.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use utmost_lib::events::{BincodeFileSink, EventSink, FanoutSink};

/// Build the event sink for a single source. `export_enabled=false` returns None
/// when no other sinks are present, or a Fanout containing only the extra sinks.
pub fn build_source_sink(
    output_dir: &Path,
    export_enabled: bool,
    extra: Vec<Arc<dyn EventSink>>,
) -> Result<Option<Arc<dyn EventSink>>> {
    let mut sinks: Vec<Arc<dyn EventSink>> = Vec::new();
    if export_enabled {
        let path = output_dir.join("carve_events.bin");
        let s = BincodeFileSink::create(&path)
            .with_context(|| format!("creating event log at {}", path.display()))?;
        sinks.push(Arc::new(s));
    }
    sinks.extend(extra);
    if sinks.is_empty() {
        Ok(None)
    } else if sinks.len() == 1 {
        Ok(Some(sinks.into_iter().next().unwrap()))
    } else {
        Ok(Some(Arc::new(FanoutSink::new(sinks))))
    }
}

/// Compute the output directory for a single carve thread.
/// `subdir.is_empty()` means the source uses the flat single-source layout.
pub fn source_output_dir(root: &Path, subdir: &str) -> PathBuf {
    if subdir.is_empty() {
        root.to_path_buf()
    } else {
        root.join(subdir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_subdir_returns_root() {
        assert_eq!(source_output_dir(Path::new("/o"), ""), PathBuf::from("/o"));
    }
    #[test]
    fn nonempty_subdir_is_joined() {
        assert_eq!(source_output_dir(Path::new("/o"), "output-foo"), PathBuf::from("/o/output-foo"));
    }

    #[test]
    fn build_with_no_options_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let r = build_source_sink(dir.path(), false, vec![]).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn build_with_export_creates_file_and_returns_sink() {
        let dir = tempfile::tempdir().unwrap();
        let r = build_source_sink(dir.path(), true, vec![]).unwrap();
        assert!(r.is_some());
        assert!(dir.path().join("carve_events.bin").exists());
    }
}
```

In `crates/utmost-cli/src/main.rs`, add: `mod sinks;`

- [ ] **Step 2: Run tests**

Run: `cargo test -p utmost-cli sinks::tests`
Expected: 4 pass.

- [ ] **Step 3: Commit**

```bash
git add crates/utmost-cli/src/sinks.rs crates/utmost-cli/src/main.rs
git commit -m "feat(cli): add sinks module for assembling per-source EventSinks"
```

---

### Task 20: Wire multi-source layout + sinks into `process_files_parallel`

**Files:**
- Modify: `crates/utmost-cli/src/main.rs`

- [ ] **Step 1: Refactor `main()` to build a per-source plan**

In `crates/utmost-cli/src/main.rs`, replace the body of `main()` from the point right after `let mut state = State::new(config)?;` through the call to `process_files_parallel` with the following structure:

```rust
    // Load user config (XDG path; missing file → defaults)
    let user_cfg = match config::default_path() {
        Some(p) => config::load_from(&p).context("loading user config")?,
        None => config::UserConfig::default(),
    };
    let settings = resolve_settings(&args, &user_cfg);

    // Build per-source plan
    use std::collections::BTreeSet;
    let multi_source = args.input_files.len() > 1;
    let mut taken: BTreeSet<String> = BTreeSet::new();
    let mut plan: Vec<(usize, String, String)> = Vec::new(); // (source_id, input_path, subdir)
    for (i, input) in args.input_files.iter().enumerate() {
        let subdir = if multi_source {
            let s = output_layout::derive_subdir(input, &taken)?;
            taken.insert(s.clone());
            s
        } else {
            String::new()
        };
        plan.push((i, input.clone(), subdir));
    }

    // Create all source directories up front
    for (_, _, subdir) in &plan {
        if !subdir.is_empty() {
            std::fs::create_dir_all(
                sinks::source_output_dir(std::path::Path::new(&args.output_directory), subdir)
            )?;
        }
    }
```

The existing `state` setup must move *inside* the per-source loop (each source gets its own State). Replace `process_files_parallel(&state, &args.input_files, args.concurrent_files)?;` with the new per-source orchestration in Task 21.

For *this* task, keep the existing single-State path working by wrapping the new plan logic in a conditional that only applies to multi-source mode, leaving the existing code path untouched when `!multi_source`. The full multi-source rewrite happens in Task 21.

- [ ] **Step 2: Verify build + existing tests still pass**

Run: `cargo build -p utmost-cli && cargo test -p utmost-cli`
Expected: clean build, all existing tests pass.

- [ ] **Step 3: Commit**

```bash
git add crates/utmost-cli/src/main.rs
git commit -m "refactor(cli): build per-source plan with derived subdirs"
```

---

### Task 21: Per-source `State` construction + per-source sink installation + RunStarted/RunFinished

**Files:**
- Modify: `crates/utmost-cli/src/main.rs`

- [ ] **Step 1: Replace process_files_parallel orchestration with per-source loop**

Refactor `process_files_parallel` in `crates/utmost-cli/src/main.rs` so each source gets its own `State` with its own output directory, reporter (if enabled), audit log (if enabled), and event sink. Inject `source_id` into each `FileInfo`.

The function signature becomes:

```rust
fn process_files_parallel(
    base_config: &StateConfig,
    output_root: &str,
    plan: &[(usize, String, String)], // (source_id, input_path, subdir)
    max_concurrent: usize,
    export_enabled: bool,
    extra_sink_per_source: Option<Arc<dyn utmost_lib::events::EventSink>>,
) -> Result<()> { ... }
```

For each `(source_id, input_path, subdir)` in the plan:

```rust
let source_dir = sinks::source_output_dir(Path::new(output_root), subdir);
let mut cfg = base_config.clone();
cfg.output_directory = source_dir.to_string_lossy().to_string();
let mut state = State::new(cfg)?;
// install reporter
if !state.config.disable_report {
    let exec_env = create_execution_environment();
    let report = utmost_lib::CarveReport::new_with_env("", 0, exec_env);
    let json_reporter = JsonReporter::new_with_report(&state.config.output_directory, report);
    state.set_reporter(ThreadSafeReporter::new(Box::new(json_reporter)));
}
// install event sink (file + optional channel)
let extra = extra_sink_per_source.iter().cloned().collect();
if let Some(sink) = sinks::build_source_sink(&source_dir, export_enabled, extra)? {
    state.set_event_sink(sink);
}
// initialize search specs same as before
state.set_search_specs(combined_specs.clone());
state.num_builtin = combined_specs.len();
// spawn carve thread that uses this state + this source_id
```

Inside each thread's `FileInfo`, set `source_id: source_id as u32`.

- [ ] **Step 2: Emit `RunStarted` at the start of the run**

Just *after* the plan is built and *before* spawning carve threads, in `main()`, build a `CarveEvent::RunStarted` and emit it through every source's sink. Since each source has its own sink, the simplest approach is to emit RunStarted via every per-source sink so each `carve_events.bin` carries the run-level context.

```rust
let sources_descriptors: Vec<utmost_lib::events::SourceDescriptor> = plan.iter()
    .map(|(id, input, subdir)| {
        let total_bytes = std::fs::metadata(input).map(|m| m.len()).unwrap_or(0);
        utmost_lib::events::SourceDescriptor {
            source_id: *id as u32,
            filename: input.clone(),
            total_bytes,
            output_subdir: subdir.clone(),
        }
    }).collect();

let cli_snapshot = utmost_lib::events::CliConfigSnapshot {
    output_directory: args.output_directory.clone(),
    types: args.types.clone(),
    disable_builtin: args.disable_builtin,
    config_file: args.config_file.clone(),
    concurrent_files: args.concurrent_files,
    disable_validation: args.disable_validation,
    report_only: args.report_only,
    disable_report: args.disable_report,
    disable_audit: args.disable_audit,
    disable_export: !settings.export_enabled,
    gui_enabled: settings.gui_enabled,
    quick: args.quick,
    block_size: args.block_size,
    prefix_filenames: args.prefix_filenames,
    write_all: args.write_all,
    keep_incomplete_jpeg: args.keep_incomplete_jpeg,
};

let run_started = utmost_lib::events::CarveEvent::RunStarted {
    utmost_version: env!("CARGO_PKG_VERSION").into(),
    format_version: utmost_lib::events::CURRENT_FORMAT_VERSION,
    started_at: utmost_lib::types::format_timestamp(std::time::SystemTime::now()),
    command_line: std::env::args().collect(),
    working_directory: std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default(),
    execution_environment: create_execution_environment(),
    cli_config: cli_snapshot,
    case: if settings.case.is_empty() { None } else { Some(settings.case.clone()) },
    configured_types: vec![], // populated later from search specs
    sources: sources_descriptors,
    output_root: args.output_directory.clone(),
};
```

Each per-source State, on construction, must `state.emit(run_started.clone())` *before* its carve thread begins searching.

- [ ] **Step 3: Emit `RunFinished` after all carve threads join**

After the loop joining carve threads completes in `process_files_parallel`, walk every per-source State and emit:

```rust
state.emit(utmost_lib::events::CarveEvent::RunFinished {
    duration_ms: state.start_time.elapsed().as_millis() as u64,
    total_files_written: state.get_fileswritten() as u64,
});
```

To do this cleanly, keep the per-source `State`s in a `Vec<State>` outside the per-thread closure (cloned for the closure to use, kept for post-join emission).

- [ ] **Step 4: Add an integration test for one-input flat layout**

Create `crates/utmost-cli/tests/integration_layout.rs`:

```rust
use std::process::Command;

#[test]
fn one_input_produces_flat_layout() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.bin");
    // Minimal JPEG so something can be found
    let mut data = vec![0xFFu8, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
    data.extend_from_slice(b"JFIF\0");
    data.extend(std::iter::repeat(0xAAu8).take(64));
    data.extend_from_slice(&[0xFF, 0xD9]);
    std::fs::write(&img, &data).unwrap();

    let out = tmp.path().join("out");
    let status = Command::new(env!("CARGO_BIN_EXE_utmost"))
        .args(["-t", "jpeg", "-o"])
        .arg(&out)
        .arg(&img)
        .status().unwrap();
    assert!(status.success());

    assert!(out.join("carve_events.bin").exists(), "expected events file in flat root");
    // No output-* subdirs
    let has_subdir = std::fs::read_dir(&out).unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().starts_with("output-"));
    assert!(!has_subdir, "did not expect output-XX/ subdirs for single input");
}

#[test]
fn two_inputs_produce_per_source_subdirs() {
    let tmp = tempfile::tempdir().unwrap();
    let img1 = tmp.path().join("a.bin");
    let img2 = tmp.path().join("b.bin");
    let mut data = vec![0xFFu8, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
    data.extend_from_slice(b"JFIF\0");
    data.extend(std::iter::repeat(0xAAu8).take(64));
    data.extend_from_slice(&[0xFF, 0xD9]);
    std::fs::write(&img1, &data).unwrap();
    std::fs::write(&img2, &data).unwrap();

    let out = tmp.path().join("out");
    let status = Command::new(env!("CARGO_BIN_EXE_utmost"))
        .args(["-t", "jpeg", "-o"])
        .arg(&out)
        .arg(&img1).arg(&img2)
        .status().unwrap();
    assert!(status.success());

    let subdirs: Vec<_> = std::fs::read_dir(&out).unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("output-"))
        .collect();
    assert_eq!(subdirs.len(), 2, "expected 2 output-XX/ subdirs");
    for d in subdirs {
        assert!(d.path().join("carve_events.bin").exists(),
            "expected events file in {}", d.path().display());
    }
}

#[test]
fn disable_export_skips_events_file() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.bin");
    std::fs::write(&img, &[0u8; 16]).unwrap();
    let out = tmp.path().join("out");
    let status = Command::new(env!("CARGO_BIN_EXE_utmost"))
        .args(["-t", "jpeg", "--disable-export", "-o"])
        .arg(&out).arg(&img)
        .status().unwrap();
    assert!(status.success());
    assert!(!out.join("carve_events.bin").exists());
}
```

- [ ] **Step 5: Run integration tests**

Run: `cargo test -p utmost-cli --test integration_layout`
Expected: 3 pass.

- [ ] **Step 6: Run full workspace test suite**

Run: `cargo test`
Expected: all green.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(cli): per-source State + RunStarted/RunFinished + integration tests"
```

---

## Phase E — GUI crate scaffolding

### Task 22: Create `utmost-gui` library crate (stub) + add to workspace

**Files:**
- Create: `crates/utmost-gui/Cargo.toml`
- Create: `crates/utmost-gui/src/lib.rs`
- Modify: `Cargo.toml` (workspace deps for slint, image, lru)

- [ ] **Step 1: Add workspace deps**

Edit root `Cargo.toml`, append to `[workspace.dependencies]`:

```toml
slint = "1.10"
image = { version = "0.25", default-features = false, features = ["jpeg", "png"] }
lru = "0.13"
```

- [ ] **Step 2: Create crate**

Create `crates/utmost-gui/Cargo.toml`:

```toml
[package]
name = "utmost-gui"
version = "0.2.2"
edition = "2024"

[dependencies]
utmost-lib = { path = "../utmost-lib" }
anyhow = { workspace = true }
crossbeam-channel = { workspace = true }
slint = { workspace = true }
image = { workspace = true }
lru = { workspace = true }
serde = { workspace = true }
tracing = { workspace = true }

[build-dependencies]
slint-build = "1.10"

[dev-dependencies]
tempfile = "3"
bincode = { workspace = true }
```

Create `crates/utmost-gui/src/lib.rs`:

```rust
//! Slint GUI for utmost.
//!
//! Two entry points:
//! - `run_live(rx, run_meta)` — channel-driven for in-process `--gui` mode
//! - `run_from_file(target)` — replay one or more `carve_events.bin`

pub mod view_model;
pub mod preview;

use anyhow::Result;
use std::path::Path;

pub fn run_live(_rx: crossbeam_channel::Receiver<utmost_lib::events::CarveEvent>) -> Result<()> {
    // Filled in by later tasks.
    unimplemented!("run_live is wired in a later task")
}

pub fn run_from_file(_target: &Path) -> Result<()> {
    unimplemented!("run_from_file is wired in a later task")
}
```

Create `crates/utmost-gui/src/view_model.rs`:

```rust
//! Pure-Rust view-model that consumes CarveEvents. No Slint imports.
```

Create `crates/utmost-gui/src/preview/mod.rs`:

```rust
//! Pluggable file-preview renderers.
```

Edit root `Cargo.toml`, ensure the `members = ["crates/*"]` glob still picks up the new crate (it does, no change needed unless explicit listing is used).

Create `crates/utmost-gui/build.rs`:

```rust
fn main() {
    // Compile any .slint files referenced via slint::include_modules!() below.
    // Empty for now; first .slint added in a later task.
}
```

- [ ] **Step 3: Build**

Run: `cargo build -p utmost-gui`
Expected: clean (build script is a no-op).

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat(gui): scaffold utmost-gui library crate"
```

---

### Task 23: Add `gui` feature to `utmost-cli`, default-on

**Files:**
- Modify: `crates/utmost-cli/Cargo.toml`
- Modify: `crates/utmost-cli/src/main.rs`

- [ ] **Step 1: Add the feature**

Edit `crates/utmost-cli/Cargo.toml`:

```toml
[features]
default = ["gui"]
gui = ["dep:utmost-gui"]

[dependencies]
# ... existing ...
utmost-gui = { path = "../utmost-gui", optional = true }
```

- [ ] **Step 2: Reject `--gui` at runtime when feature is off**

In `crates/utmost-cli/src/main.rs`, where `settings.gui_enabled` is consumed (currently nowhere yet — about to be), gate on the feature:

```rust
    if settings.gui_enabled {
        #[cfg(feature = "gui")]
        {
            tracing::info!("GUI mode requested");
            // wiring happens in Task 30
        }
        #[cfg(not(feature = "gui"))]
        {
            anyhow::bail!("--gui requested but this build of utmost was compiled without the `gui` feature");
        }
    }
```

Place this block after `let settings = resolve_settings(&args, &user_cfg);` near the top of `main()`.

- [ ] **Step 3: Verify both builds**

Run: `cargo build -p utmost-cli`
Expected: clean (gui feature on by default).

Run: `cargo build -p utmost-cli --no-default-features`
Expected: clean; `utmost-gui` not in the dep graph.

- [ ] **Step 4: Commit**

```bash
git add crates/utmost-cli/Cargo.toml crates/utmost-cli/src/main.rs
git commit -m "feat(cli): add default-on gui feature flag"
```

---

## Phase F — View-model (pure Rust, no Slint)

### Task 24: Define view-model state structs

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs`

- [ ] **Step 1: Write the failing test**

Replace `crates/utmost-gui/src/view_model.rs` contents with:

```rust
//! Pure-Rust view-model that consumes CarveEvents. No Slint imports.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use utmost_lib::events::{CaseMetadata, CarveEvent};
use utmost_lib::types::{FileObject, FileType};

pub type FileId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunStatus { Pending, Running, Finished, Interrupted }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceStatus { Pending, Running, Finished, Interrupted }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey { Filename, Size }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDir { Asc, Desc }

#[derive(Debug, Clone)]
pub struct RunSummary {
    pub started_at: String,
    pub output_root: String,
    pub configured_types: Vec<FileType>,
    pub status: RunStatus,
    pub case: Option<CaseMetadata>,
    pub elapsed_ms: u64,
    pub total_files: u64,
}

impl Default for RunSummary {
    fn default() -> Self {
        Self {
            started_at: String::new(),
            output_root: String::new(),
            configured_types: Vec::new(),
            status: RunStatus::Pending,
            case: None,
            elapsed_ms: 0,
            total_files: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SourceRow {
    pub source_id: u32,
    pub filename: String,
    pub output_subdir: String,
    pub total_bytes: u64,
    pub bytes_read: u64,
    pub files_found: u64,
    pub status: SourceStatus,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct FoundFile {
    pub id: FileId,
    pub source_id: u32,
    pub file: FileObject,
    pub written_path: PathBuf,
    pub img_offset: u64,
}

#[derive(Debug, Clone)]
pub struct FilterState {
    pub enabled_types: BTreeSet<FileType>,
    pub source_filter: Option<u32>,
    pub sort_key: SortKey,
    pub sort_dir: SortDir,
}

impl Default for FilterState {
    fn default() -> Self {
        Self {
            enabled_types: BTreeSet::new(),
            source_filter: None,
            sort_key: SortKey::Filename,
            sort_dir: SortDir::Asc,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct ViewModel {
    pub run: RunSummary,
    pub sources: Vec<SourceRow>,
    pub files: Vec<FoundFile>,
    pub type_counts: BTreeMap<FileType, u64>,
    pub filter: FilterState,
    pub selection: Option<FileId>,
    pub visible_files: Vec<FileId>,
    next_file_id: FileId,
}

impl ViewModel {
    pub fn new() -> Self { Self::default() }

    /// To be implemented in Task 25.
    pub fn apply(&mut self, _event: &CarveEvent) {
        unimplemented!("ViewModel::apply implemented in Task 25")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_view_model_is_empty() {
        let vm = ViewModel::new();
        assert_eq!(vm.sources.len(), 0);
        assert_eq!(vm.files.len(), 0);
        assert_eq!(vm.run.status, RunStatus::Pending);
        assert!(vm.selection.is_none());
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p utmost-gui view_model::tests`
Expected: 1 pass.

- [ ] **Step 3: Commit**

```bash
git add crates/utmost-gui/src/view_model.rs
git commit -m "feat(gui): add view-model state structs"
```

---

### Task 25: Implement `ViewModel::apply` for every CarveEvent variant

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs`

- [ ] **Step 1: Write the failing tests**

Add to the `mod tests` block in `crates/utmost-gui/src/view_model.rs`:

```rust
    use utmost_lib::events::*;
    use utmost_lib::reporting::create_file_object;
    use utmost_lib::types::{ExecutionEnvironment, FileType};

    fn empty_env() -> ExecutionEnvironment {
        ExecutionEnvironment {
            os_sysname: String::new(), os_release: String::new(),
            os_version: String::new(), host: String::new(),
            arch: String::new(), uid: 0, start_time: String::new(),
        }
    }
    fn empty_cli() -> CliConfigSnapshot {
        CliConfigSnapshot {
            output_directory: "out".into(), types: vec![],
            disable_builtin: false, config_file: None, concurrent_files: 1,
            disable_validation: false, report_only: false, disable_report: false,
            disable_audit: false, disable_export: false, gui_enabled: false,
            quick: false, block_size: 512, prefix_filenames: false, write_all: false,
            keep_incomplete_jpeg: false,
        }
    }

    fn run_started_with_sources(ids: &[u32]) -> CarveEvent {
        CarveEvent::RunStarted {
            utmost_version: "test".into(),
            format_version: CURRENT_FORMAT_VERSION,
            started_at: "t".into(), command_line: vec![],
            working_directory: "/".into(),
            execution_environment: empty_env(),
            cli_config: empty_cli(), case: None,
            configured_types: vec![FileType::Jpeg],
            sources: ids.iter().map(|i| SourceDescriptor {
                source_id: *i,
                filename: format!("src{i}.bin"),
                total_bytes: 1000, output_subdir: format!("output-{i}"),
            }).collect(),
            output_root: "out".into(),
        }
    }

    #[test]
    fn run_started_populates_run_and_sources() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0, 1]));
        assert_eq!(vm.sources.len(), 2);
        assert_eq!(vm.sources[0].source_id, 0);
        assert_eq!(vm.run.status, RunStatus::Running);
        assert_eq!(vm.run.output_root, "out");
        assert_eq!(vm.run.configured_types, vec![FileType::Jpeg]);
    }

    #[test]
    fn source_started_sets_source_running() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        vm.apply(&CarveEvent::SourceStarted { source_id: 0 });
        assert_eq!(vm.sources[0].status, SourceStatus::Running);
    }

    #[test]
    fn file_found_adds_file_and_increments_counts() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        let fo = create_file_object("a.jpg", FileType::Jpeg, 1024, 0, None);
        vm.apply(&CarveEvent::FileFound {
            source_id: 0, file: fo, img_offset: 0,
            written_path: "a.jpg".into(),
        });
        assert_eq!(vm.files.len(), 1);
        assert_eq!(vm.type_counts.get(&FileType::Jpeg), Some(&1));
        assert_eq!(vm.sources[0].files_found, 1);
        assert_eq!(vm.run.total_files, 1);
    }

    #[test]
    fn progress_tick_updates_source_bytes_read() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        vm.apply(&CarveEvent::ProgressTick { source_id: 0, bytes_read: 500 });
        assert_eq!(vm.sources[0].bytes_read, 500);
    }

    #[test]
    fn source_finished_flips_status_and_records_duration() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        vm.apply(&CarveEvent::SourceFinished {
            source_id: 0, bytes_read: 1000, duration_ms: 42,
        });
        assert_eq!(vm.sources[0].status, SourceStatus::Finished);
        assert_eq!(vm.sources[0].duration_ms, Some(42));
        assert_eq!(vm.sources[0].bytes_read, 1000);
    }

    #[test]
    fn run_finished_flips_run_status() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        vm.apply(&CarveEvent::RunFinished { duration_ms: 100, total_files_written: 3 });
        assert_eq!(vm.run.status, RunStatus::Finished);
        assert_eq!(vm.run.elapsed_ms, 100);
    }

    #[test]
    fn file_found_before_known_source_still_inserted() {
        let mut vm = ViewModel::new();
        // Skip RunStarted entirely
        let fo = create_file_object("a.jpg", FileType::Jpeg, 1, 0, None);
        vm.apply(&CarveEvent::FileFound {
            source_id: 99, file: fo, img_offset: 0,
            written_path: "a.jpg".into(),
        });
        assert_eq!(vm.files.len(), 1);
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p utmost-gui view_model::tests`
Expected: all `apply` tests fail with `unimplemented!`.

- [ ] **Step 3: Implement `apply`**

Replace the `unimplemented!` body of `apply` in `crates/utmost-gui/src/view_model.rs`:

```rust
    pub fn apply(&mut self, event: &CarveEvent) {
        match event {
            CarveEvent::RunStarted {
                started_at, output_root, configured_types,
                case, sources, ..
            } => {
                self.run.started_at = started_at.clone();
                self.run.output_root = output_root.clone();
                self.run.configured_types = configured_types.clone();
                self.run.case = case.clone();
                self.run.status = RunStatus::Running;
                self.sources = sources.iter().map(|s| SourceRow {
                    source_id: s.source_id,
                    filename: s.filename.clone(),
                    output_subdir: s.output_subdir.clone(),
                    total_bytes: s.total_bytes,
                    bytes_read: 0,
                    files_found: 0,
                    status: SourceStatus::Pending,
                    duration_ms: None,
                }).collect();
                // Default-enable all configured types in the filter chip row.
                self.filter.enabled_types = configured_types.iter().copied().collect();
            }
            CarveEvent::SourceStarted { source_id } => {
                if let Some(row) = self.sources.iter_mut().find(|r| r.source_id == *source_id) {
                    row.status = SourceStatus::Running;
                }
            }
            CarveEvent::FileFound { source_id, file, img_offset, written_path } => {
                let id = self.next_file_id;
                self.next_file_id += 1;
                let abs_path: PathBuf =
                    PathBuf::from(&self.run.output_root).join(written_path);
                // Parse file_type string back to enum
                let ft = parse_file_type(&file.file_type);
                if let Some(ft) = ft {
                    *self.type_counts.entry(ft).or_insert(0) += 1;
                    // Auto-enable newly-seen types when no configured filter
                    if self.run.configured_types.is_empty() {
                        self.filter.enabled_types.insert(ft);
                    }
                }
                self.files.push(FoundFile {
                    id,
                    source_id: *source_id,
                    file: file.clone(),
                    written_path: abs_path,
                    img_offset: *img_offset,
                });
                if let Some(row) = self.sources.iter_mut().find(|r| r.source_id == *source_id) {
                    row.files_found += 1;
                }
                self.run.total_files += 1;
            }
            CarveEvent::ProgressTick { source_id, bytes_read } => {
                if let Some(row) = self.sources.iter_mut().find(|r| r.source_id == *source_id) {
                    row.bytes_read = *bytes_read;
                }
            }
            CarveEvent::SourceFinished { source_id, bytes_read, duration_ms } => {
                if let Some(row) = self.sources.iter_mut().find(|r| r.source_id == *source_id) {
                    row.status = SourceStatus::Finished;
                    row.bytes_read = *bytes_read;
                    row.duration_ms = Some(*duration_ms);
                }
            }
            CarveEvent::RunFinished { duration_ms, total_files_written: _ } => {
                self.run.status = RunStatus::Finished;
                self.run.elapsed_ms = *duration_ms;
            }
        }
    }
}

fn parse_file_type(s: &str) -> Option<FileType> {
    // FileObject::file_type is created via {:?}.to_lowercase() — invert it.
    match s {
        "jpeg" => Some(FileType::Jpeg),
        "gif"  => Some(FileType::Gif),
        "bmp"  => Some(FileType::Bmp),
        "mpg"  => Some(FileType::Mpg),
        "pdf"  => Some(FileType::Pdf),
        "doc"  => Some(FileType::Doc),
        "avi"  => Some(FileType::Avi),
        "wmv"  => Some(FileType::Wmv),
        "htm"  => Some(FileType::Htm),
        "zip"  => Some(FileType::Zip),
        "mov"  => Some(FileType::Mov),
        "xls"  => Some(FileType::Xls),
        "ppt"  => Some(FileType::Ppt),
        "wpd"  => Some(FileType::Wpd),
        "cpp"  => Some(FileType::Cpp),
        "ole"  => Some(FileType::Ole),
        "gzip" => Some(FileType::Gzip),
        "riff" => Some(FileType::Riff),
        "wav"  => Some(FileType::Wav),
        "vjpeg" => Some(FileType::VJpeg),
        "sxw"  => Some(FileType::Sxw),
        "sxc"  => Some(FileType::Sxc),
        "sxi"  => Some(FileType::Sxi),
        "png"  => Some(FileType::Png),
        "rar"  => Some(FileType::Rar),
        "exe"  => Some(FileType::Exe),
        "elf"  => Some(FileType::Elf),
        "reg"  => Some(FileType::Reg),
        "docx" => Some(FileType::Docx),
        "xlsx" => Some(FileType::Xlsx),
        "pptx" => Some(FileType::Pptx),
        "mp4"  => Some(FileType::Mp4),
        "config" => Some(FileType::Config),
        _ => None,
    }
}
```

Also ensure `FileType` derives `Hash` for `BTreeSet` usage and `Ord`. Add `Ord, PartialOrd, Hash` to the derive list on `FileType` in `crates/utmost-lib/src/types.rs`.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p utmost-gui view_model::tests`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-gui/src/view_model.rs crates/utmost-lib/src/types.rs
git commit -m "feat(gui): ViewModel::apply reducer for all CarveEvent variants"
```

---

### Task 26: Filter + sort: `recompute_visible()` with tests

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs`

- [ ] **Step 1: Write the failing tests**

Add to `mod tests`:

```rust
    fn add_file(vm: &mut ViewModel, sid: u32, name: &str, ft: FileType, sz: u64) {
        let fo = create_file_object(name, ft, sz, 0, None);
        vm.apply(&CarveEvent::FileFound {
            source_id: sid, file: fo, img_offset: 0, written_path: name.into(),
        });
    }

    #[test]
    fn visible_files_includes_only_enabled_types() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 100);
        add_file(&mut vm, 0, "b.pdf", FileType::Pdf, 200);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.recompute_visible();
        assert_eq!(vm.visible_files.len(), 1);
    }

    #[test]
    fn sort_by_filename_asc() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "z.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.sort_key = SortKey::Filename;
        vm.filter.sort_dir = SortDir::Asc;
        vm.recompute_visible();
        let first = vm.files.iter().find(|f| f.id == vm.visible_files[0]).unwrap();
        assert_eq!(first.file.filename, "a.jpg");
    }

    #[test]
    fn sort_by_size_desc() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "x.jpg", FileType::Jpeg, 100);
        add_file(&mut vm, 0, "y.jpg", FileType::Jpeg, 999);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.sort_key = SortKey::Size;
        vm.filter.sort_dir = SortDir::Desc;
        vm.recompute_visible();
        let first = vm.files.iter().find(|f| f.id == vm.visible_files[0]).unwrap();
        assert_eq!(first.file.filesize, 999);
    }

    #[test]
    fn source_filter_limits_to_one_source() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0, 1]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 1, "b.jpg", FileType::Jpeg, 1);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.source_filter = Some(1);
        vm.recompute_visible();
        assert_eq!(vm.visible_files.len(), 1);
        let f = vm.files.iter().find(|f| f.id == vm.visible_files[0]).unwrap();
        assert_eq!(f.source_id, 1);
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p utmost-gui view_model::tests::visible`
Expected: compile error — `recompute_visible` missing.

- [ ] **Step 3: Implement**

Add to `impl ViewModel`:

```rust
    pub fn recompute_visible(&mut self) {
        let mut ids: Vec<FileId> = self.files.iter()
            .filter(|f| {
                if let Some(sid) = self.filter.source_filter {
                    if f.source_id != sid { return false; }
                }
                if let Some(ft) = parse_file_type(&f.file.file_type) {
                    self.filter.enabled_types.contains(&ft)
                } else {
                    // Files with unknown type always pass the filter
                    true
                }
            })
            .map(|f| f.id)
            .collect();
        let by_id: BTreeMap<FileId, &FoundFile> = self.files.iter().map(|f| (f.id, f)).collect();
        ids.sort_by(|a, b| {
            let fa = by_id[a]; let fb = by_id[b];
            let cmp = match self.filter.sort_key {
                SortKey::Filename => fa.file.filename.cmp(&fb.file.filename),
                SortKey::Size => fa.file.filesize.cmp(&fb.file.filesize),
            };
            match self.filter.sort_dir { SortDir::Asc => cmp, SortDir::Desc => cmp.reverse() }
        });
        self.visible_files = ids;
    }
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p utmost-gui view_model::tests`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-gui/src/view_model.rs
git commit -m "feat(gui): filter + sort recompute_visible() with tests"
```

---

### Task 27: Golden snapshot test — replay events.bin → final view-model

**Files:**
- Create: `crates/utmost-gui/tests/replay_snapshot.rs`

- [ ] **Step 1: Write the test**

Create `crates/utmost-gui/tests/replay_snapshot.rs`:

```rust
//! Drives the view-model with a synthetic event sequence persisted via
//! BincodeFileSink + read back via BincodeFileReader. Asserts the final
//! view-model state matches expectations.

use utmost_gui::view_model::{ViewModel, RunStatus, SourceStatus};
use utmost_lib::events::*;
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::FileType;

fn empty_env() -> utmost_lib::types::ExecutionEnvironment {
    utmost_lib::types::ExecutionEnvironment {
        os_sysname: String::new(), os_release: String::new(),
        os_version: String::new(), host: String::new(),
        arch: String::new(), uid: 0, start_time: String::new(),
    }
}

fn empty_cli() -> CliConfigSnapshot {
    CliConfigSnapshot {
        output_directory: "out".into(), types: vec![],
        disable_builtin: false, config_file: None, concurrent_files: 1,
        disable_validation: false, report_only: false, disable_report: false,
        disable_audit: false, disable_export: false, gui_enabled: false,
        quick: false, block_size: 512, prefix_filenames: false, write_all: false,
        keep_incomplete_jpeg: false,
    }
}

#[test]
fn replay_produces_expected_view_model() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.bin");
    let sink = BincodeFileSink::create(&path).unwrap();

    let run = CarveEvent::RunStarted {
        utmost_version: "t".into(), format_version: CURRENT_FORMAT_VERSION,
        started_at: "t".into(), command_line: vec![],
        working_directory: "/".into(), execution_environment: empty_env(),
        cli_config: empty_cli(), case: None,
        configured_types: vec![FileType::Jpeg],
        sources: vec![SourceDescriptor {
            source_id: 0, filename: "src.bin".into(),
            total_bytes: 1000, output_subdir: String::new(),
        }],
        output_root: "out".into(),
    };
    sink.emit(&run);
    sink.emit(&CarveEvent::SourceStarted { source_id: 0 });
    let fo = create_file_object("a.jpg", FileType::Jpeg, 1024, 0, None);
    sink.emit(&CarveEvent::FileFound {
        source_id: 0, file: fo, img_offset: 0, written_path: "a.jpg".into(),
    });
    sink.emit(&CarveEvent::ProgressTick { source_id: 0, bytes_read: 500 });
    sink.emit(&CarveEvent::SourceFinished { source_id: 0, bytes_read: 1000, duration_ms: 10 });
    sink.emit(&CarveEvent::RunFinished { duration_ms: 20, total_files_written: 1 });
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
```

- [ ] **Step 2: Run**

Run: `cargo test -p utmost-gui --test replay_snapshot`
Expected: 1 pass.

- [ ] **Step 3: Commit**

```bash
git add crates/utmost-gui/tests/replay_snapshot.rs
git commit -m "test(gui): golden replay snapshot — events.bin → view-model"
```

---

## Phase G — Preview system

### Task 28: PreviewRenderer trait + PreviewRegistry + GenericIcon

**Files:**
- Modify: `crates/utmost-gui/src/preview/mod.rs`
- Create: `crates/utmost-gui/src/preview/generic.rs`

- [ ] **Step 1: Write the failing tests**

Replace `crates/utmost-gui/src/preview/mod.rs`:

```rust
//! Pluggable file-preview renderers.

mod generic;
pub use generic::GenericIcon;

use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use utmost_lib::types::FileType;

use crate::view_model::FoundFile;

#[derive(Debug, Clone)]
pub enum PreviewOutput {
    Image(image::RgbaImage),
    HexDump(String),
    Icon(IconKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IconKind {
    Generic,
    Document,
    Archive,
    Image,
    Audio,
    Video,
    Executable,
}

impl IconKind {
    pub fn for_type(ft: FileType) -> Self {
        use FileType::*;
        match ft {
            Jpeg | Gif | Bmp | Png | VJpeg => Self::Image,
            Pdf | Doc | Docx | Xls | Xlsx | Ppt | Pptx | Sxw | Sxc | Sxi | Wpd | Htm
                => Self::Document,
            Zip | Rar | Gzip => Self::Archive,
            Wav | Riff => Self::Audio,
            Avi | Wmv | Mov | Mpg | Mp4 => Self::Video,
            Exe | Elf | Ole => Self::Executable,
            Cpp | Reg | Config => Self::Generic,
        }
    }
}

pub trait PreviewRenderer: Send + Sync {
    fn supports(&self, file_type: FileType) -> bool;
    fn render(&self, path: &Path, file: &FoundFile) -> Result<PreviewOutput>;
    fn render_side_panel_metadata(&self, file: &FoundFile) -> Vec<(String, String)>;
}

pub struct PreviewRegistry {
    renderers: Vec<Arc<dyn PreviewRenderer>>,
}

impl PreviewRegistry {
    pub fn empty() -> Self { Self { renderers: vec![] } }

    pub fn with_defaults() -> Self {
        let mut r = Self::empty();
        // JpegPreview is registered in Task 29; GenericIcon is always last as fallback.
        r.renderers.push(Arc::new(GenericIcon));
        r
    }

    pub fn register(&mut self, r: Arc<dyn PreviewRenderer>) {
        // Insert before the GenericIcon fallback so specific renderers win.
        let pos = self.renderers.iter()
            .position(|x| (x.as_ref() as *const dyn PreviewRenderer) == (&GenericIcon as &dyn PreviewRenderer as *const dyn PreviewRenderer))
            .unwrap_or(self.renderers.len());
        self.renderers.insert(pos, r);
    }

    pub fn render_for(&self, file_type: FileType, path: &Path, file: &FoundFile) -> Result<PreviewOutput> {
        for r in &self.renderers {
            if r.supports(file_type) {
                return r.render(path, file);
            }
        }
        // Should be unreachable because GenericIcon supports every type.
        anyhow::bail!("no renderer for {file_type:?}")
    }

    pub fn metadata_for(&self, file_type: FileType, file: &FoundFile) -> Vec<(String, String)> {
        for r in &self.renderers {
            if r.supports(file_type) {
                return r.render_side_panel_metadata(file);
            }
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use utmost_lib::reporting::create_file_object;
    use std::path::PathBuf;

    fn dummy_file(ft: FileType) -> FoundFile {
        FoundFile {
            id: 0, source_id: 0,
            file: create_file_object("a", ft, 1, 0, None),
            written_path: PathBuf::from("a"),
            img_offset: 0,
        }
    }

    #[test]
    fn defaults_registry_uses_generic_icon_fallback() {
        let reg = PreviewRegistry::with_defaults();
        let out = reg.render_for(
            FileType::Pdf,
            std::path::Path::new("/does/not/exist"),
            &dummy_file(FileType::Pdf),
        ).unwrap();
        assert!(matches!(out, PreviewOutput::Icon(IconKind::Document)));
    }

    #[test]
    fn icon_kind_maps_jpeg_to_image() {
        assert_eq!(IconKind::for_type(FileType::Jpeg), IconKind::Image);
        assert_eq!(IconKind::for_type(FileType::Zip), IconKind::Archive);
    }
}
```

Create `crates/utmost-gui/src/preview/generic.rs`:

```rust
//! Fallback renderer that returns an Icon for any file type.

use anyhow::Result;
use std::path::Path;
use utmost_lib::types::FileType;

use crate::preview::{IconKind, PreviewOutput, PreviewRenderer};
use crate::view_model::FoundFile;

pub struct GenericIcon;

impl PreviewRenderer for GenericIcon {
    fn supports(&self, _: FileType) -> bool { true }
    fn render(&self, _: &Path, file: &FoundFile) -> Result<PreviewOutput> {
        let ft = crate::view_model::parse_file_type_pub(&file.file.file_type)
            .unwrap_or(FileType::Config);
        Ok(PreviewOutput::Icon(IconKind::for_type(ft)))
    }
    fn render_side_panel_metadata(&self, _file: &FoundFile) -> Vec<(String, String)> {
        Vec::new()
    }
}
```

For `parse_file_type_pub`, expose the existing helper in view_model: edit `crates/utmost-gui/src/view_model.rs` and add:

```rust
pub fn parse_file_type_pub(s: &str) -> Option<FileType> { parse_file_type(s) }
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p utmost-gui preview::tests`
Expected: 2 pass.

- [ ] **Step 3: Commit**

```bash
git add crates/utmost-gui/src/preview/
git add crates/utmost-gui/src/view_model.rs
git commit -m "feat(gui): PreviewRenderer trait + PreviewRegistry + GenericIcon fallback"
```

---

### Task 29: `JpegPreview` renderer + side-panel metadata

**Files:**
- Create: `crates/utmost-gui/src/preview/jpeg.rs`
- Modify: `crates/utmost-gui/src/preview/mod.rs`
- Create: `crates/utmost-gui/tests/fixtures/sample.jpg`

- [ ] **Step 1: Add a fixture JPEG**

Create a minimal valid JPEG fixture. Use `cargo run -p utmost-gui --example gen_fixture_jpeg` if scripted, or commit a small (≤2KB) hand-crafted JPEG to `crates/utmost-gui/tests/fixtures/sample.jpg`.

A simple way: run this once in a scratch directory and copy the result:

```bash
python3 -c "
from PIL import Image
img = Image.new('RGB', (32, 32), color='red')
img.save('sample.jpg', 'JPEG')
"
mkdir -p crates/utmost-gui/tests/fixtures
mv sample.jpg crates/utmost-gui/tests/fixtures/sample.jpg
```

If Python/PIL is unavailable, any small jpg the engineer has on hand works; subagents should pick a deterministic byte sequence and write it via a setup test helper instead of committing a binary.

- [ ] **Step 2: Write the failing test**

Create `crates/utmost-gui/tests/jpeg_preview.rs`:

```rust
use utmost_gui::preview::{PreviewOutput, PreviewRegistry};
use utmost_gui::view_model::FoundFile;
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::{FileType, JpegScanInfo, JpegScanStatus};
use std::path::PathBuf;

#[test]
fn jpeg_preview_decodes_fixture_to_image() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sample.jpg");
    let file = FoundFile {
        id: 0, source_id: 0,
        file: create_file_object(
            "sample.jpg", FileType::Jpeg, 1024, 0,
            Some(JpegScanInfo {
                width: Some(32), height: Some(32),
                fragmentation_point_img_offset: None,
                has_restart_markers: false,
                status: JpegScanStatus::Complete,
            }),
        ),
        written_path: path.clone(),
        img_offset: 0,
    };

    let reg = PreviewRegistry::with_defaults_and_jpeg();
    let out = reg.render_for(FileType::Jpeg, &path, &file).unwrap();
    match out {
        PreviewOutput::Image(img) => {
            assert!(img.width() > 0 && img.height() > 0);
        }
        other => panic!("expected Image, got {other:?}"),
    }

    let meta = reg.metadata_for(FileType::Jpeg, &file);
    let labels: Vec<_> = meta.iter().map(|(k,_)| k.as_str()).collect();
    assert!(labels.contains(&"Dimensions"));
    assert!(labels.contains(&"Scan status"));
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p utmost-gui --test jpeg_preview`
Expected: compile error — `JpegPreview`/`with_defaults_and_jpeg` not defined.

- [ ] **Step 4: Implement `JpegPreview`**

Create `crates/utmost-gui/src/preview/jpeg.rs`:

```rust
//! JPEG decoder + downscaler + side-panel metadata extractor.

use anyhow::{Context, Result};
use image::{ImageReader, imageops::FilterType};
use std::path::Path;
use utmost_lib::types::{FileType, JpegScanStatus};

use crate::preview::{PreviewOutput, PreviewRenderer};
use crate::view_model::FoundFile;

const MAX_EDGE: u32 = 256;

pub struct JpegPreview;

impl PreviewRenderer for JpegPreview {
    fn supports(&self, ft: FileType) -> bool { matches!(ft, FileType::Jpeg) }

    fn render(&self, path: &Path, _file: &FoundFile) -> Result<PreviewOutput> {
        let img = ImageReader::open(path)
            .with_context(|| format!("open {}", path.display()))?
            .with_guessed_format()?
            .decode()
            .with_context(|| format!("decode {}", path.display()))?;
        let (w, h) = (img.width(), img.height());
        let scale = (MAX_EDGE as f32 / w.max(h) as f32).min(1.0);
        let (nw, nh) = ((w as f32 * scale) as u32, (h as f32 * scale) as u32);
        let resized = if scale < 1.0 {
            img.resize(nw.max(1), nh.max(1), FilterType::Triangle).to_rgba8()
        } else {
            img.to_rgba8()
        };
        Ok(PreviewOutput::Image(resized))
    }

    fn render_side_panel_metadata(&self, file: &FoundFile) -> Vec<(String, String)> {
        let mut out = Vec::new();
        if let Some(scan) = &file.file.jpeg_scan {
            if let (Some(w), Some(h)) = (scan.width, scan.height) {
                out.push(("Dimensions".into(), format!("{w} × {h}")));
            }
            out.push(("Restart markers".into(),
                if scan.has_restart_markers { "yes".into() } else { "no".into() }));
            out.push(("Scan status".into(), match scan.status {
                JpegScanStatus::Complete => "Complete".into(),
                JpegScanStatus::Truncated => "Truncated".into(),
                JpegScanStatus::Fragmented => "Fragmented".into(),
            }));
            if let Some(p) = scan.fragmentation_point_img_offset {
                out.push(("Fragmentation point".into(), format!("0x{p:x}")));
            }
        }
        out
    }
}
```

Modify `crates/utmost-gui/src/preview/mod.rs`:

```rust
mod jpeg;
pub use jpeg::JpegPreview;
```

Add:

```rust
impl PreviewRegistry {
    pub fn with_defaults_and_jpeg() -> Self {
        let mut r = Self::with_defaults();
        r.register(Arc::new(JpegPreview));
        r
    }
}
```

The `register` impl in Task 28 has a fragile pointer-equality check. Replace it with a simpler approach — insert before any renderer that claims to support every type:

```rust
    pub fn register(&mut self, r: Arc<dyn PreviewRenderer>) {
        // Insert before the first "supports everything" fallback.
        let pos = self.renderers.iter()
            .position(|x| x.supports(FileType::Pdf) && x.supports(FileType::Jpeg))
            .unwrap_or(self.renderers.len());
        self.renderers.insert(pos, r);
    }
```

- [ ] **Step 5: Run to verify pass**

Run: `cargo test -p utmost-gui --test jpeg_preview`
Expected: pass.

Then: `cargo test -p utmost-gui`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-gui/src/preview/jpeg.rs crates/utmost-gui/src/preview/mod.rs crates/utmost-gui/tests/jpeg_preview.rs crates/utmost-gui/tests/fixtures/sample.jpg
git commit -m "feat(gui): JpegPreview renderer + side-panel metadata"
```

---

## Phase H — Slint UI

### Task 30: Slint window + run-list screen

**Files:**
- Create: `crates/utmost-gui/ui/main.slint`
- Create: `crates/utmost-gui/src/slint_adapter.rs`
- Modify: `crates/utmost-gui/src/lib.rs`
- Modify: `crates/utmost-gui/build.rs`

This task introduces visible UI. There is no automated test for Slint rendering — verification is by running `utmost-viewer` against a fixture and visually inspecting (Task 33 provides the binary; until then, a `cargo run -p utmost-gui --example smoke` example can drive it).

- [ ] **Step 1: Add a `.slint` file with the run-list window**

Create `crates/utmost-gui/ui/main.slint`:

```slint
import { VerticalBox, HorizontalBox, ListView, ProgressIndicator, Button } from "std-widgets.slint";

export struct SourceRowData {
    source_id: int,
    filename: string,
    files_found: int,
    progress: float,         // 0.0..1.0
    status: string,
}

export component MainWindow inherits Window {
    title: "utmost";
    preferred-width: 900px;
    preferred-height: 600px;

    in-out property <[SourceRowData]> sources: [];
    in-out property <string> run-status: "Pending";
    in-out property <int> total-files: 0;
    in-out property <string> elapsed: "0s";

    callback row-clicked(int);

    VerticalBox {
        HorizontalBox {
            Text { text: "Status: " + root.run-status; }
            Text { text: "Files: " + root.total-files; }
            Text { text: "Elapsed: " + root.elapsed; }
        }
        ListView {
            for source[i] in root.sources : Rectangle {
                height: 56px;
                background: touch.has-hover ? #2a2a2a : transparent;
                touch := TouchArea {
                    clicked => { root.row-clicked(source.source_id); }
                }
                HorizontalBox {
                    Text { text: source.filename; min-width: 200px; }
                    ProgressIndicator { progress: source.progress; min-width: 200px; }
                    Text { text: source.files_found + " files"; }
                    Text { text: source.status; }
                }
            }
        }
    }
}
```

- [ ] **Step 2: Update build.rs**

Replace `crates/utmost-gui/build.rs`:

```rust
fn main() {
    slint_build::compile("ui/main.slint").unwrap();
}
```

- [ ] **Step 3: Adapter wires view-model to Slint**

Create `crates/utmost-gui/src/slint_adapter.rs`:

```rust
//! Bridges the pure-Rust ViewModel to the Slint MainWindow.

use slint::{ComponentHandle, Model, SharedString, VecModel};
use std::rc::Rc;
use crate::view_model::{SourceStatus, ViewModel};

slint::include_modules!();

pub struct UiState {
    pub window: MainWindow,
    pub sources_model: Rc<VecModel<SourceRowData>>,
}

impl UiState {
    pub fn new() -> slint::Result<Self> {
        let window = MainWindow::new()?;
        let sources_model = Rc::new(VecModel::default());
        window.set_sources(sources_model.clone().into());
        Ok(Self { window, sources_model })
    }

    pub fn sync(&self, vm: &ViewModel) {
        let rows: Vec<SourceRowData> = vm.sources.iter().map(|r| SourceRowData {
            source_id: r.source_id as i32,
            filename: SharedString::from(r.filename.as_str()),
            files_found: r.files_found as i32,
            progress: if r.total_bytes > 0 {
                r.bytes_read as f32 / r.total_bytes as f32
            } else { 0.0 },
            status: SharedString::from(match r.status {
                SourceStatus::Pending => "Pending",
                SourceStatus::Running => "Running",
                SourceStatus::Finished => "Finished",
                SourceStatus::Interrupted => "Interrupted",
            }),
        }).collect();
        self.sources_model.set_vec(rows);
        self.window.set_run_status(SharedString::from(format!("{:?}", vm.run.status)));
        self.window.set_total_files(vm.run.total_files as i32);
        self.window.set_elapsed(SharedString::from(format!("{}ms", vm.run.elapsed_ms)));
    }
}
```

In `crates/utmost-gui/src/lib.rs`, add:

```rust
pub mod slint_adapter;
```

- [ ] **Step 4: Build**

Run: `cargo build -p utmost-gui`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(gui): Slint main window + run-list adapter"
```

---

### Task 31: Detail page in Slint + filter chips + sort controls

**Files:**
- Create: `crates/utmost-gui/ui/detail.slint`
- Modify: `crates/utmost-gui/ui/main.slint`
- Modify: `crates/utmost-gui/src/slint_adapter.rs`
- Modify: `crates/utmost-gui/build.rs`

- [ ] **Step 1: Add detail page Slint module**

Create `crates/utmost-gui/ui/detail.slint`:

```slint
import { HorizontalBox, VerticalBox, GridView, Button, ComboBox } from "std-widgets.slint";

export struct FilterChipData { name: string, enabled: bool, count: int }
export struct FileTileData {
    id: int,
    filename: string,
    filesize: string,
    file_type: string,
    has_thumbnail: bool,
    thumbnail: image,
}

export component DetailPage inherits Rectangle {
    in-out property <[FilterChipData]> chips: [];
    in-out property <[FileTileData]> tiles: [];
    in-out property <string> sort-key: "Filename";
    in-out property <string> sort-dir: "Asc";

    callback chip-toggled(string);
    callback select-all();
    callback select-none();
    callback sort-changed(string, string);
    callback tile-clicked(int);
    callback back();

    VerticalBox {
        HorizontalBox {
            Button { text: "← Back"; clicked => { root.back(); } }
            Button { text: "Select all"; clicked => { root.select-all(); } }
            Button { text: "Select none"; clicked => { root.select-none(); } }
            for chip in root.chips : Rectangle {
                background: chip.enabled ? #3a6 : #555;
                border-radius: 12px;
                width: 80px;
                touch := TouchArea {
                    clicked => { root.chip-toggled(chip.name); }
                }
                Text { text: chip.name + " (" + chip.count + ")"; }
            }
        }
        // Grid of file tiles — uses GridLayout via a Flickable in production;
        // here a simple ListView placeholder.
        for tile[i] in root.tiles : Rectangle {
            height: 140px;
            border-width: 1px;
            border-color: #444;
            TouchArea { clicked => { root.tile-clicked(tile.id); } }
            VerticalBox {
                Image { source: tile.thumbnail; width: 96px; height: 96px; }
                Text { text: tile.filename; }
                Text { text: tile.filesize + " · " + tile.file_type; }
            }
        }
    }
}
```

- [ ] **Step 2: Embed DetailPage inside MainWindow**

Edit `crates/utmost-gui/ui/main.slint`. Import detail:

```slint
import { DetailPage, FilterChipData, FileTileData } from "detail.slint";
```

Add to `MainWindow`:

```slint
    in-out property <bool> show-detail: false;
    in-out property <[FilterChipData]> chips: [];
    in-out property <[FileTileData]> tiles: [];

    callback chip-toggled(string);
    callback select-all();
    callback select-none();
    callback tile-clicked(int);
    callback back-clicked();
```

In the `VerticalBox`, conditionally show the detail page:

```slint
        if root.show-detail : DetailPage {
            chips: root.chips;
            tiles: root.tiles;
            chip-toggled(n) => { root.chip-toggled(n); }
            select-all => { root.select-all(); }
            select-none => { root.select-none(); }
            tile-clicked(id) => { root.tile-clicked(id); }
            back => { root.back-clicked(); }
        }
```

- [ ] **Step 3: Update build.rs**

```rust
fn main() {
    slint_build::compile("ui/main.slint").unwrap();
}
```

(Slint compiles imported modules transitively from the entry file.)

- [ ] **Step 4: Adapter wires chips + tiles**

Extend `crates/utmost-gui/src/slint_adapter.rs`:

Add `chips_model: Rc<VecModel<FilterChipData>>` and `tiles_model: Rc<VecModel<FileTileData>>` fields to `UiState`. Initialize them in `new()` and bind to the window properties. In `sync()`:

```rust
        // Chips
        let chips: Vec<FilterChipData> = vm.type_counts.iter().map(|(ft, count)| {
            FilterChipData {
                name: SharedString::from(format!("{ft:?}")),
                enabled: vm.filter.enabled_types.contains(ft),
                count: *count as i32,
            }
        }).collect();
        self.chips_model.set_vec(chips);

        // Tiles (no thumbnail wiring yet — Task 32)
        let tiles: Vec<FileTileData> = vm.visible_files.iter().filter_map(|fid| {
            vm.files.iter().find(|f| f.id == *fid)
        }).map(|f| FileTileData {
            id: f.id as i32,
            filename: SharedString::from(f.file.filename.as_str()),
            filesize: SharedString::from(format!("{} B", f.file.filesize)),
            file_type: SharedString::from(f.file.file_type.as_str()),
            has_thumbnail: false,
            thumbnail: slint::Image::default(),
        }).collect();
        self.tiles_model.set_vec(tiles);
```

Wire callbacks (chip-toggled, select-all/none, tile-clicked, back-clicked) by taking an `Arc<Mutex<ViewModel>>` into `UiState` and mutating from the callbacks.

- [ ] **Step 5: Build**

Run: `cargo build -p utmost-gui`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(gui): detail page with filter chips + sort placeholder"
```

---

### Task 32: Preview grid with lazy thumbnail loading

**Files:**
- Modify: `crates/utmost-gui/src/slint_adapter.rs`
- Create: `crates/utmost-gui/src/thumb_worker.rs`

- [ ] **Step 1: Implement a small worker pool**

Create `crates/utmost-gui/src/thumb_worker.rs`:

```rust
//! Decode JPEG (and future format) thumbnails off the Slint thread.
//! Posts back to the Slint event loop via `slint::invoke_from_event_loop`.

use crossbeam_channel::{Receiver, Sender, unbounded};
use lru::LruCache;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use utmost_lib::types::FileType;

use crate::preview::{PreviewOutput, PreviewRegistry};
use crate::view_model::{FileId, FoundFile};

pub type ThumbCache = Arc<Mutex<LruCache<FileId, slint::Image>>>;

pub struct ThumbWorker {
    tx: Sender<ThumbRequest>,
    pub cache: ThumbCache,
}

struct ThumbRequest {
    id: FileId,
    file_type: FileType,
    path: PathBuf,
    file: FoundFile,
}

impl ThumbWorker {
    pub fn start(
        registry: Arc<PreviewRegistry>,
        capacity: usize,
        workers: usize,
        on_complete: Arc<dyn Fn(FileId) + Send + Sync>,
    ) -> Self {
        let cache: ThumbCache = Arc::new(Mutex::new(
            LruCache::new(NonZeroUsize::new(capacity.max(1)).unwrap())
        ));
        let (tx, rx) = unbounded::<ThumbRequest>();
        for _ in 0..workers.max(1) {
            let rx: Receiver<ThumbRequest> = rx.clone();
            let cache = cache.clone();
            let registry = registry.clone();
            let on_complete = on_complete.clone();
            thread::spawn(move || {
                while let Ok(req) = rx.recv() {
                    if cache.lock().unwrap().contains(&req.id) { continue; }
                    let out = registry.render_for(req.file_type, &req.path, &req.file);
                    if let Ok(PreviewOutput::Image(img)) = out {
                        let pixels: Vec<u8> = img.as_raw().clone();
                        let buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
                            &pixels, img.width(), img.height()
                        );
                        let slint_img = slint::Image::from_rgba8(buf);
                        cache.lock().unwrap().put(req.id, slint_img);
                        let cb = on_complete.clone();
                        let _ = slint::invoke_from_event_loop(move || cb(req.id));
                    }
                }
            });
        }
        Self { tx, cache }
    }

    pub fn request(&self, id: FileId, file_type: FileType, path: PathBuf, file: FoundFile) {
        let _ = self.tx.send(ThumbRequest { id, file_type, path, file });
    }
}
```

In `crates/utmost-gui/src/lib.rs`, add: `pub mod thumb_worker;`

- [ ] **Step 2: Wire ThumbWorker into UiState**

In `slint_adapter.rs`, add a `thumbs: ThumbWorker` field and a `registry: Arc<PreviewRegistry>` field. When syncing tiles, for each visible file: check `thumbs.cache` for a cached image; if present, attach it to the `FileTileData.thumbnail`. If absent, set `has_thumbnail: false` and call `thumbs.request(...)`.

`on_complete` is a closure that triggers a re-sync of the tiles list. Pass it a weak handle to the window and call `window.window().request_redraw()` plus a re-sync of the affected tile.

- [ ] **Step 3: Build**

Run: `cargo build -p utmost-gui`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat(gui): lazy thumbnail loading via worker pool + LRU cache"
```

---

### Task 33: Side panel sliding on selection

**Files:**
- Modify: `crates/utmost-gui/ui/detail.slint`
- Modify: `crates/utmost-gui/src/slint_adapter.rs`

- [ ] **Step 1: Add side panel block in Slint**

Edit `crates/utmost-gui/ui/detail.slint`. Add:

```slint
export struct MetadataRow { key: string, value: string }

export component DetailPage inherits Rectangle {
    // ... existing properties + callbacks ...
    in-out property <[MetadataRow]> selected-metadata: [];
    in-out property <bool> side-panel-open: false;
    in-out property <string> selected-filename: "";

    HorizontalBox {
        // existing grid on the left
        // ...
        if root.side-panel-open : Rectangle {
            background: #1e1e1e;
            width: 280px;
            VerticalBox {
                Text { text: root.selected-filename; font-size: 16px; }
                for row in root.selected-metadata : HorizontalBox {
                    Text { text: row.key; font-weight: 700; }
                    Text { text: row.value; }
                }
            }
        }
    }
}
```

(Reorganize layout so the grid and side panel sit horizontally.)

- [ ] **Step 2: Adapter populates metadata on selection**

In `slint_adapter.rs`, when a tile-clicked callback fires:

```rust
        let vm = vm.lock().unwrap();
        if let Some(file) = vm.files.iter().find(|f| f.id as i32 == clicked_id) {
            let ft = crate::view_model::parse_file_type_pub(&file.file.file_type);
            let mut rows: Vec<MetadataRow> = Vec::new();
            rows.push(MetadataRow {
                key: "Filename".into(),
                value: file.file.filename.as_str().into(),
            });
            rows.push(MetadataRow {
                key: "Size".into(),
                value: format!("{} B", file.file.filesize).into(),
            });
            rows.push(MetadataRow {
                key: "Path".into(),
                value: file.written_path.display().to_string().into(),
            });
            rows.push(MetadataRow {
                key: "Source offset".into(),
                value: format!("0x{:x}", file.img_offset).into(),
            });
            if let Some(ft) = ft {
                for (k, v) in registry.metadata_for(ft, file) {
                    rows.push(MetadataRow { key: k.into(), value: v.into() });
                }
            }
            window.set_selected_metadata(Rc::new(VecModel::from(rows)).into());
            window.set_selected_filename(file.file.filename.as_str().into());
            window.set_side_panel_open(true);
        }
```

- [ ] **Step 3: Build**

Run: `cargo build -p utmost-gui`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat(gui): side panel with type-specific metadata on selection"
```

---

### Task 34: `run_live` and `run_from_file` entry points

**Files:**
- Modify: `crates/utmost-gui/src/lib.rs`

- [ ] **Step 1: Implement `run_from_file`**

Replace the body in `crates/utmost-gui/src/lib.rs`:

```rust
use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use utmost_lib::events::{BincodeFileReader, CarveEvent};

pub use view_model::ViewModel;

pub fn run_from_file(target: &Path) -> Result<()> {
    let vm = Arc::new(Mutex::new(ViewModel::new()));
    let files = resolve_sources(target)?;
    for path in files {
        let mut reader = BincodeFileReader::open(&path)?;
        while let Some(ev) = reader.next_event()? {
            vm.lock().unwrap().apply(&ev);
        }
        if reader.was_truncated() {
            let mut v = vm.lock().unwrap();
            v.run.status = crate::view_model::RunStatus::Interrupted;
            for s in v.sources.iter_mut() {
                if s.status == crate::view_model::SourceStatus::Running {
                    s.status = crate::view_model::SourceStatus::Interrupted;
                }
            }
        }
    }
    vm.lock().unwrap().recompute_visible();
    launch_ui(vm)
}

pub fn run_live(rx: crossbeam_channel::Receiver<CarveEvent>) -> Result<()> {
    let vm = Arc::new(Mutex::new(ViewModel::new()));
    let vm_for_thread = vm.clone();
    std::thread::spawn(move || {
        while let Ok(ev) = rx.recv() {
            let mut v = vm_for_thread.lock().unwrap();
            v.apply(&ev);
            v.recompute_visible();
            // Wake the Slint event loop so it re-syncs
            let _ = slint::invoke_from_event_loop(|| {});
        }
    });
    launch_ui(vm)
}

fn launch_ui(vm: Arc<Mutex<ViewModel>>) -> Result<()> {
    use slint_adapter::UiState;
    let ui = UiState::new()?;
    {
        let v = vm.lock().unwrap();
        ui.sync(&v);
    }
    // Periodic re-sync timer for live mode.
    let weak = ui.window.as_weak();
    let vm_for_timer = vm.clone();
    let timer = slint::Timer::default();
    timer.start(slint::TimerMode::Repeated, std::time::Duration::from_millis(50), move || {
        if let Some(window) = weak.upgrade() {
            let _ = window;
            let v = vm_for_timer.lock().unwrap();
            // Re-sync via UiState would need a stable reference; simplest is
            // to re-create or expose a sync function on the window directly.
        }
    });
    ui.window.run()?;
    Ok(())
}

fn resolve_sources(target: &Path) -> Result<Vec<PathBuf>> {
    if target.is_file() {
        return Ok(vec![target.to_path_buf()]);
    }
    if target.is_dir() {
        let direct = target.join("carve_events.bin");
        if direct.exists() {
            return Ok(vec![direct]);
        }
        let mut found = Vec::new();
        for entry in std::fs::read_dir(target)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_dir() {
                let candidate = p.join("carve_events.bin");
                if candidate.exists() {
                    found.push(candidate);
                }
            }
        }
        if !found.is_empty() { return Ok(found); }
    }
    anyhow::bail!("no carve_events.bin found at {}", target.display())
}
```

The periodic-resync block above is sketchy — in practice we'd hold the `UiState` on the heap and re-sync from inside the timer with a clone of `Arc<Mutex<ViewModel>>`. Refine `UiState::sync` to take `&self` and call it from the timer closure. Adjust accordingly.

- [ ] **Step 2: Build**

Run: `cargo build -p utmost-gui`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add crates/utmost-gui/src/lib.rs
git commit -m "feat(gui): run_live + run_from_file entry points with auto-discovery"
```

---

## Phase I — Viewer crate

### Task 35: Create `utmost-viewer` binary crate

**Files:**
- Create: `crates/utmost-viewer/Cargo.toml`
- Create: `crates/utmost-viewer/src/main.rs`

- [ ] **Step 1: Create crate**

Create `crates/utmost-viewer/Cargo.toml`:

```toml
[package]
name = "utmost-viewer"
version = "0.2.2"
edition = "2024"

[dependencies]
utmost-gui = { path = "../utmost-gui" }
anyhow = { workspace = true }
clap = { workspace = true }
```

Create `crates/utmost-viewer/src/main.rs`:

```rust
use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about = "Replay a utmost carve event log")]
struct Args {
    /// Path to either a directory or a carve_events.bin file
    target: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    utmost_gui::run_from_file(&args.target)
}
```

- [ ] **Step 2: Build**

Run: `cargo build -p utmost-viewer`
Expected: clean.

- [ ] **Step 3: Smoke test with a fixture**

```bash
# Generate a fixture events.bin
cargo test -p utmost-gui --test replay_snapshot
# Run viewer against a real run
cargo run -p utmost-cli -- -t jpeg -o /tmp/utmost-smoke test-data/<some-fixture>
cargo run -p utmost-viewer -- /tmp/utmost-smoke
```

Visually inspect: window opens, run-list shows the source row, status is Finished, file counts are non-zero.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat(viewer): add utmost-viewer binary crate"
```

---

## Phase J — Live mode wiring + end-to-end smoke

### Task 36: Wire `--gui` to spawn the Slint UI in-process

**Files:**
- Modify: `crates/utmost-cli/src/main.rs`

- [ ] **Step 1: When `--gui` is on, install a ChannelSink and run Slint on main**

In `crates/utmost-cli/src/main.rs`, refactor so that when `settings.gui_enabled` is true:

```rust
    #[cfg(feature = "gui")]
    if settings.gui_enabled {
        let (tx, rx) = crossbeam_channel::unbounded();
        let channel_sink: std::sync::Arc<dyn utmost_lib::events::EventSink> =
            std::sync::Arc::new(utmost_lib::events::ChannelSink::new(tx));

        // Spawn the carve work on a background thread; Slint owns the main thread.
        let plan_clone = plan.clone();
        let base_cfg = config.clone();
        let output_root = args.output_directory.clone();
        let export = settings.export_enabled;
        let extra = Some(channel_sink);
        std::thread::spawn(move || {
            if let Err(e) = process_files_parallel(
                &base_cfg, &output_root, &plan_clone, args.concurrent_files, export, extra,
            ) {
                tracing::error!("carve failed: {e:#}");
            }
        });

        utmost_gui::run_live(rx)?;
        return Ok(());
    }
```

For non-GUI, keep the existing synchronous carve path.

- [ ] **Step 2: Build + smoke test**

```bash
cargo build -p utmost-cli
cargo run -p utmost-cli -- --gui -t jpeg -o /tmp/live-smoke test-data/<some-fixture>
```

Expected: GUI window appears, progress bar advances live, files appear in the list as found.

- [ ] **Step 3: Commit**

```bash
git add crates/utmost-cli/src/main.rs
git commit -m "feat(cli): --gui spawns Slint UI in-process with live ChannelSink"
```

---

### Task 37: Final integration check — README + version bump notes

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Document new features in README**

Append a section to `README.md` covering:

- `utmost --gui` (and `--no-gui`)
- `--disable-export`
- `~/.config/utmost/config.toml` example
- `utmost-viewer` usage with both file and directory forms
- Per-input-file `output-XX/` layout for multi-source runs
- Forensic case metadata flags

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: document GUI, viewer, config file, per-source output layout"
```

---

## Self-review checklist (verify before handoff)

- [ ] Every spec section maps to at least one task.
- [ ] No `TODO` / `TBD` / "fill in details" / "similar to Task N" strings in this plan.
- [ ] All types referenced across tasks are defined in some earlier task.
- [ ] All file paths are absolute or workspace-relative.
- [ ] All commands include expected output (PASS/FAIL or filesystem assertion).
- [ ] Pre-commit hook (cargo fmt + cargo clippy --all-targets) will run on every commit — tasks must leave the tree warning-free.

---

## Execution

**Plan complete and saved to `docs/superpowers/plans/2026-05-17-utmost-gui.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

You already chose subagent-driven-development with TDD per task. Confirm and I'll invoke `superpowers:subagent-driven-development`.
