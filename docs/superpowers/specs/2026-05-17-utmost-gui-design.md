# Utmost Slint GUI — Design

**Date:** 2026-05-17
**Status:** Approved
**Author:** Steven Carter (with brainstorming assistance)

## 1. Overview

Add a Slint-based GUI companion to the `utmost` file carving tool. The GUI
shows live progress of a carve run, lets the user drill into per-source
results, and renders type-specific previews of carved files. The same UI also
works as a standalone viewer pointed at the output of a prior run.

The GUI is powered by a new bincoded event stream written to disk during every
carve run (unless explicitly disabled). The live `--gui` mode uses the same
event vocabulary delivered over an in-process channel.

## 2. Goals / Non-goals

**Goals**

- Real-time per-source progress display during a carve run.
- Drill-down detail page showing a virtualized grid of file previews per
  source (or across all sources).
- Type-specific preview rendering with a pluggable trait so adding new file
  types is one impl + one registration.
- Side-panel metadata view with both common fields and type-specific fields.
- Filter chip row that respects the carve's configured types and toggles
  visibility in the grid (does not affect the engine).
- Filename + filesize sort providers in the detail grid.
- Bincoded event log written to disk for every run, replayable by a
  standalone `utmost-viewer` binary.
- Forensic case metadata (case id, examiner, evidence id, notes) carried
  through the event log.
- GUI compiled in by default but behind a feature flag so users can build a
  Slint-free CLI.

**Non-goals**

- No visual regression testing on Slint output.
- No live editing of search specs from the GUI.
- No re-decoding of every file format in v1 — JPEG previews ship; everything
  else falls back to a generic icon until a dedicated renderer is added.
- No alteration of engine behavior based on filter chip state.

## 3. Crate layout

```
utmost-lib                    (existing)
  └─ events.rs                NEW — CarveEvent, EventSink, FanoutSink,
                              FileHeader, BincodeFileSink helpers

utmost-cli                    (existing)
  ├─ config.rs                NEW — ~/.config/utmost/config.toml loader
  ├─ output_layout.rs         NEW — output-XX/ subdir derivation
  ├─ sinks.rs                 NEW — wires up FanoutSink at startup
  └─ feature = "gui"          NEW — pulls in utmost-gui, --gui flag

utmost-gui                    NEW LIBRARY CRATE
  ├─ Cargo.toml               slint, image, crossbeam-channel, lru
  ├─ ui/                      .slint files
  ├─ view_model.rs            CarveEvent reducer (pure Rust, no Slint)
  ├─ preview/
  │    ├─ mod.rs              PreviewRenderer trait, PreviewRegistry
  │    ├─ jpeg.rs             JpegPreview (ships day one)
  │    └─ generic.rs          GenericIcon fallback for every other type
  └─ lib.rs                   pub fn run_live(rx, run_meta)
                              pub fn run_from_file(target)

utmost-viewer                 NEW BINARY CRATE
  └─ main.rs                  clap + auto-discovery + utmost_gui::run_from_file
```

**Dependency direction:** `utmost-cli` and `utmost-viewer` both depend on
`utmost-gui`; `utmost-gui` depends on `utmost-lib`; `utmost-lib` depends on
nothing GUI-related. Slint never enters the CLI build unless the `gui`
feature is enabled.

**`utmost-cli` feature flag:**

```toml
[features]
default = ["gui"]
gui = ["dep:utmost-gui"]
```

Building with `cargo build -p utmost-cli --no-default-features` produces a
Slint-free binary; `--gui` becomes a clap-time error in that build, but the
bincode export still works.

`utmost-viewer` lives in its own crate; opting out of the CLI's `gui` feature
does not remove it. Anyone who wants a fully Slint-free build simply does not
build `utmost-viewer`.

`bincode` is added to `[workspace.dependencies]` and shared across crates.

## 4. Event vocabulary

### 4.1 File header (first frame)

```rust
pub struct FileHeader {
    pub magic: [u8; 4],         // b"UTMS"
    pub format_version: u32,    // CURRENT_FORMAT_VERSION = 1
}

pub const CURRENT_FORMAT_VERSION: u32 = 1;
```

The header is written as a length-prefixed bincode frame, identical to event
framing, but is the first frame. Readers deserialize it first, validate magic
and version, then deserialize subsequent frames as `CarveEvent`. Wrong magic
or unsupported version is a hard error before any event is processed.

### 4.2 CarveEvent enum

```rust
pub enum CarveEvent {
    RunStarted {
        utmost_version: String,
        format_version: u32,             // mirrors header for robustness
        started_at: String,              // ISO-8601 with offset

        command_line: Vec<String>,       // std::env::args
        working_directory: String,
        execution_environment: ExecutionEnvironment, // reuse existing struct

        cli_config: CliConfigSnapshot,
        case: Option<CaseMetadata>,

        configured_types: Vec<FileType>, // empty == "all"
        sources: Vec<SourceDescriptor>,
        output_root: String,
    },
    SourceStarted   { source_id: u32 },
    FileFound {
        source_id: u32,
        file: FileObject,                // existing utmost-lib type
        img_offset: u64,
        written_path: String,            // relative to output_root
    },
    ProgressTick    { source_id: u32, bytes_read: u64 },   // stream-only
    SourceFinished  { source_id: u32, bytes_read: u64, duration_ms: u64 },
    RunFinished     { duration_ms: u64, total_files_written: u64 },
}

impl CarveEvent {
    pub fn persistable(&self) -> bool {
        !matches!(self, CarveEvent::ProgressTick { .. })
    }
}

pub struct SourceDescriptor {
    pub source_id: u32,
    pub filename: String,
    pub total_bytes: u64,
    pub output_subdir: String,           // empty in single-source flat mode
}

pub struct CliConfigSnapshot {
    pub output_directory: String,
    pub types: Vec<String>,              // raw -t input
    pub disable_builtin: bool,
    pub config_file: Option<String>,
    pub concurrent_files: usize,
    pub disable_validation: bool,
    pub report_only: bool,
    pub disable_report: bool,
    pub disable_audit: bool,
    pub disable_export: bool,            // skip writing carve_events.bin
    pub gui_enabled: bool,
    pub quick: bool,
    pub block_size: usize,
    pub prefix_filenames: bool,
    pub write_all: bool,
    pub keep_incomplete_jpeg: bool,
}

pub struct CaseMetadata {
    pub case_id: Option<String>,
    pub examiner: Option<String>,
    pub evidence_id: Option<String>,
    pub notes: Option<String>,
}
```

### 4.3 Persistability rule

`BincodeFileSink` calls `event.persistable()` and skips writing when false.
Live channel sinks ignore the flag and forward everything. `ProgressTick` is
the only stream-only variant in v1.

### 4.4 Forward compatibility

- Adding a new `CarveEvent` variant requires bumping `CURRENT_FORMAT_VERSION`.
- Adding a new `Option<_>` field to `CaseMetadata` or `CliConfigSnapshot`
  uses `#[serde(default)]` and also bumps the format version so the GUI can
  selectively enable UI for it.
- Removing/renaming a field requires a bump and a versioned reader branch.

## 5. Event sink design

```rust
pub trait EventSink: Send + Sync {
    fn emit(&self, event: &CarveEvent);
}

pub struct FanoutSink { sinks: Vec<Arc<dyn EventSink>> }

pub struct BincodeFileSink {
    inner: Mutex<BincodeFileSinkInner>,
}
struct BincodeFileSinkInner {
    writer: BufWriter<File>,
    disabled: bool,                      // set on first I/O error
}

pub struct ChannelSink {
    tx: crossbeam_channel::Sender<CarveEvent>,
}
```

`State` gains `event_sink: Option<Arc<dyn EventSink>>`. The engine calls
`state.emit(...)` which is a no-op when no sink is installed. `emit` returns
`()` — sink failures must not abort a carve.

`BincodeFileSink`:

- Opens the file lazily on first `emit` and writes the `FileHeader` frame.
- On any I/O failure, sets `disabled = true` and logs once at `warn`.
- Framing: `u32 LE length || bincoded bytes`. No trailing terminator;
  trailing partial frame at EOF == interrupted run.

`FanoutSink` is fail-isolated per child sink.

## 6. Per-input-file output layout

**Single input:** unchanged from today. All artifacts live directly in
`--output-directory`.

**2+ inputs:** each input gets `output-XX/` under `--output-directory`, where
`XX = clean_filename(filename, 32)` (reusing the existing helper). On
collision with an already-allocated name, append `-1`, `-2`, …. Collision
loop is bounded at 1000 attempts; exceeding the bound is a hard error.

Each subdirectory contains:

```
output-disk_image_dd/
  ├─ <carved files...>
  ├─ audit_log.txt
  ├─ carve_report.json
  └─ carve_events.bin
```

The mapping `(input_path → subdir_name → source_id)` is captured in
`RunStarted::sources` so the viewer never has to re-derive the algorithm.

**Per-source vs process-wide state.** In single-source mode the reporter,
audit log, and bincode sink remain process-wide as today (one `State`, one
set of output files).

In multi-source mode each input file gets its own `JsonReporter`, audit
file, and `BincodeFileSink` rooted in its `output-XX/` subdirectory. The
existing `State` struct is extended so its `reporter`, `audit_file`, and
new `event_sink` fields can be overridden per carve thread before the
thread starts work — either by cloning `State` and swapping the relevant
`Arc<...>` fields, or by introducing a per-source wrapper (`SourceState`)
that the engine accepts. Implementation picks whichever is least
disruptive to the existing engine API; both are sketched at planning time.

The live `ChannelSink` (when `--gui` is on) is *shared* across all
sources — there is one event stream per run. Per-source identity is
carried via `source_id` on every event.

## 7. Data flow

### 7.1 Live mode (`--gui`)

```
utmost-cli main
  ├─ build per-source EventSink fanouts:
  │     - BincodeFileSink (always-on unless --disable-export)
  │     - ChannelSink::new(tx) (only when --gui)
  ├─ spawn carve threads (existing process_files_parallel, each calls
  │     state.emit(...))
  └─ on main thread (Slint requires main-thread on macOS):
        utmost_gui::run_live(rx, run_meta)
            └─ Slint event loop polls non-blocking each frame, drains
               pending events into ViewModel::apply, refreshes models.
```

When the engine emits `RunFinished`, the channel stays open and the GUI
remains usable. Closing the window terminates the process.

### 7.2 Replay mode (`utmost-viewer`)

Invocation forms:

- `utmost-viewer ./output/output-foo/carve_events.bin` — single session
- `utmost-viewer ./output` — directory, auto-discover:
  - contains `carve_events.bin` directly → single session
  - contains `output-XX/` with their own `carve_events.bin` → multi-session

Replay iterates the file(s), feeding each `CarveEvent` to the same
`ViewModel::apply` reducer used in live mode. Truncated trailing frame ⇒
session marked `Interrupted`, banner displayed.

## 8. View-model and UI structure

### 8.1 View-model (pure Rust, no Slint imports)

```rust
pub struct ViewModel {
    pub run: RunSummary,
    pub sources: Vec<SourceRow>,         // indexed by source_id
    pub files: Vec<FoundFile>,
    pub type_counts: BTreeMap<FileType, u64>,
    pub filter: FilterState,
    pub selection: Option<FileId>,
    pub visible_files: Vec<FileId>,      // filter+sort applied
}

pub struct RunSummary {
    pub started_at: String,
    pub configured_types: Vec<FileType>,
    pub output_root: String,
    pub status: RunStatus,               // Running | Finished | Interrupted
    pub case: Option<CaseMetadata>,
    pub elapsed_ms: u64,
    pub total_files: u64,
}

pub struct SourceRow {
    pub source_id: u32,
    pub filename: String,
    pub output_subdir: String,
    pub total_bytes: u64,
    pub bytes_read: u64,                 // ProgressTick (live only)
    pub files_found: u64,
    pub status: SourceStatus,            // Pending|Running|Finished|Interrupted
    pub duration_ms: Option<u64>,
}

pub struct FoundFile {
    pub id: FileId,                      // monotonic
    pub source_id: u32,
    pub file: FileObject,
    pub written_path: PathBuf,           // absolute, resolved
    pub img_offset: u64,
}

pub struct FilterState {
    pub enabled_types: BTreeSet<FileType>,
    pub source_filter: Option<u32>,      // None = all sources
    pub sort_key: SortKey,                // Filename | Size
    pub sort_dir: SortDir,                // Asc | Desc
}
```

`ViewModel::apply(&mut self, ev: &CarveEvent)` is the only mutation point.

### 8.2 Screens

**Run list (landing).** Top bar shows run status, elapsed time, total files
written, total bytes scanned, and (if present) case metadata. Below: a list
of `SourceRow`s — filename, per-row progress bar, files-found count by type
chip, status. "All sources" pseudo-row at the top. Click a row → detail
page filtered to that source.

**Detail page.** Top bar: filter chip row (one chip per configured type;
muted if `type_counts == 0`; "Select all" / "Select none" buttons). Below:
sort controls (filename ↑↓, size ↑↓). Main area: virtualized grid of preview
tiles. Side panel slides in on tile selection. Back button returns to the
run list.

Filter and sort always run in the view-model. The Slint model receives only
the resulting `visible_files` IDs, not full file structs.

### 8.3 Preview tile lifecycle

When a tile becomes visible (or near-visible), the GUI dispatches a preview
request to a small worker pool (2–4 threads). The worker calls
`PreviewRenderer::render(path, file)`, the result is cached in
`LruCache<FileId, PreviewOutput>`, and Slint is notified via
`invoke_from_event_loop` to refresh that tile. Already-cached tiles render
instantly.

### 8.4 PreviewRenderer trait

```rust
pub trait PreviewRenderer: Send + Sync {
    fn supports(&self, file_type: FileType) -> bool;
    fn render(&self, path: &Path, file: &FoundFile) -> Result<PreviewOutput>;
    fn render_side_panel_metadata(&self, file: &FoundFile) -> Vec<(String, String)>;
}

pub enum PreviewOutput {
    Image(RgbaImage),                    // JPEG today; PNG/BMP/GIF later
    HexDump(String),                     // fallback for binary types
    Icon(IconKind),                      // generic file-type icon
}

pub struct PreviewRegistry {
    renderers: Vec<Arc<dyn PreviewRenderer>>, // ordered, first match wins
}
```

**Day-one renderers:**
- `JpegPreview` — uses `image` crate, decode + scale to ~256px max edge.
- `GenericIcon` — fallback for every other type, returns `Icon(IconKind::*)`.

Adding a new type (e.g. PNG) is one new `PreviewRenderer` impl + one
registration call in `PreviewRegistry::default()`. No other code changes.

### 8.5 Side panel

Common fields: filename, full output path, size, file type, source filename,
byte offset in source.

Type-specific fields: returned by `PreviewRenderer::render_side_panel_metadata`.

JPEG-specific (from existing `JpegScanInfo`): width × height, restart
markers (yes/no), scan status (Complete | Truncated | Fragmented),
fragmentation point img-offset if present.

## 9. Configuration

`~/.config/utmost/config.toml`, read at CLI startup (XDG-respecting).

```toml
[gui]
enabled = true                     # equivalent to --gui by default

[export]
enabled = true                     # write carve_events.bin

[case]
examiner = "Jane Doe"
case_id  = "CASE-2026-0001"
# evidence_id, notes optional
```

CLI flags override the file:

- `--gui` / `--no-gui` (only one of these can be passed; mutual exclusion)
- `--disable-export` (matches existing `--disable-report` / `--disable-audit` convention)
- `--case-id <id>`, `--examiner <name>`, `--evidence-id <id>`, `--notes <text>`

Missing config file: silent, defaults apply. Malformed TOML: hard error
before carve starts.

## 10. Error handling

**Engine + sinks.** Sink errors are non-fatal. `state.emit(...)` returns `()`.
Each sink internally logs once at `warn` on failure and continues.
`BincodeFileSink` opens lazily; on I/O failure sets `disabled` and stops.
`FanoutSink` is fail-isolated per child.

**CLI.** Multi-source dir derivation:
- Filesystem create error → existing error path, run aborts.
- Collision-fallback exhaustion at 1000 attempts → hard error.

Config file:
- Missing → silent.
- Malformed → hard error before carve starts.

`--gui` on a `--no-default-features` build → clap-time validator error.

**GUI live mode.**
- Channel disconnect → banner, run status → `Interrupted`. UI stays usable.
- Preview render failure → tile falls back to `GenericIcon` with a warning
  glyph; logged at `debug` only (carved data is expected to occasionally be
  broken).
- All Slint model updates happen on the Slint thread via
  `invoke_from_event_loop`.

**Viewer.**
- File missing/unreadable/wrong magic → hard error, exit non-zero, no window.
- Truncated trailing frame → parse what we can, status `Interrupted`, banner.
- `format_version > CURRENT_FORMAT_VERSION` → hard error naming both
  versions. No partial loads.

## 11. Testing strategy

### 11.1 utmost-lib::events (unit)

- Round-trip every `CarveEvent` variant through bincode.
- `persistable()` correct for every variant (match-based test forces update
  when adding variants).
- `FanoutSink` with two recording sinks delivers all events to both.
- `BincodeFileSink` writes only persistable events; header is first frame.
- `FileHeader` magic mismatch / version mismatch produce typed errors.

### 11.2 utmost-cli::output_layout (unit)

- Basic derivation: `disk_image.dd` → `output-disk_image_dd`.
- Collision: two distinct inputs cleaning to same name → `-1`, `-2`.
- Bound: 1001 colliding inputs → error.
- Truncation: long filename clips at 32 chars deterministically.
- Edge: empty/weird-only filename → sane fallback `output-source-1`.

### 11.3 utmost-cli (integration)

- End-to-end against a small fixture image:
  - One input → flat layout preserved.
  - Two inputs → two `output-XX/`, each with its own report + events.
  - `--disable-export` → no `carve_events.bin` written.
  - Bincoded events round-trip and the final view-model matches a snapshot.

### 11.4 utmost-gui::view_model (unit, no Slint)

- File counts per type accumulate correctly across sources.
- Filter chip toggling changes `visible_files` without mutating `files`.
- Sort key changes reorder `visible_files` correctly.
- Out-of-order events produce the right final state.
- `SourceFinished` flips source status; `RunFinished` flips run status.
- Golden test: replay a captured `carve_events.bin` and snapshot the
  final view-model.

### 11.5 utmost-gui::preview (unit)

- `PreviewRegistry::render_for(file_type)` returns the right renderer.
- `JpegPreview::render` on a known-good fixture returns a non-empty
  `RgbaImage` of the expected aspect ratio (within 1px).
- `JpegPreview::render` on a corrupt fixture returns `Err`.

### 11.6 Not tested

- Slint rendering output (no visual regression).
- Live channel performance under extreme event rates (add only if a problem
  surfaces).

## 12. Open items / future work

- Source-image hashing for tamper-evident forensics reports. Not in v1
  because hashing TB-scale images by default is too expensive; could be
  added behind a flag.
- PNG / BMP / GIF preview renderers. Trivial to add post-v1 — one impl
  each.
- Multi-session viewer UX when many sessions are open (tabbed? side
  list?). Defer until we hit the use case.
- Live spec mutation from the GUI (dynamic toggling of carve types
  mid-run). Out of scope.
