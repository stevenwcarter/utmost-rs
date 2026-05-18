# GUI Recovery Variants & Forensic Annotations — Design

**Date:** 2026-05-18
**Status:** Approved
**Author:** Steven Carter (with brainstorming assistance)

## 1. Overview

Extend `utmost-gui` and the bincoded event log to surface multiple recovery
candidates for partial (truncated / fragmented) JPEGs and to capture three
kinds of user annotations during forensic review: bookmarks, free-text notes,
and "mark as best variant" decisions.

Every new relationship and annotation persists in the same `carve_events.bin`
file so opening a session in the future restores the full state. A journal
sidecar (`carve_events.pending`) provides crash-safety for annotations made
during a live carve and is folded back into the main log when the run
finishes.

The data model is generic — annotation and recovery-candidate events
reference files by an opaque `file_id: u64` — but JPEG is the only producer
of recovery candidates in v1.

## 2. Goals / Non-goals

**Goals**

- Surface recovery candidates for partial JPEGs in the side panel and a new
  "variant viewer" modal, with vertical-scroll layouts only.
- Allow the user to bookmark files, attach free-text notes, and choose one
  recovery variant as canonical for each partial original.
- Persist annotations and variant relationships in `carve_events.bin` so they
  survive viewer relaunches and machine moves.
- Add filter chips: a "Partial JPG" chip parallel to "JPG" (per type), and a
  "Bookmarked" chip.
- Trigger recovery from inside the GUI with a per-session "Run recovery"
  button + a `keep_candidates` selector (default 5, cap 10).
- Stable cross-artifact file identity via a new `file_id: u64` on
  `FileObject`, propagated to `carve_report.json`, `carve_report.xml` (DFXML),
  `audit_log.txt`, and `recover_report.json`.

**Non-goals**

- Generalising recovery beyond JPEG. The data model is generic; only JPEG
  emits `RecoveryCandidate` events in v1.
- Editing or deleting notes. Append-only forever; the user "corrects" by
  writing a follow-up note.
- Bookmarking recovery variants individually — only the originals.
- Cross-session annotation sync between separate `carve_events.bin` files.
- Configuration of the GUI `keep_candidates` default / cap via the user
  config file. (Tracked as a separate follow-up issue.)
- Format-version bump. `CURRENT_FORMAT_VERSION` stays `1` because the
  bincoded format has not been published; Steve's only test file will be
  regenerated.

## 3. Crate layout

```
utmost-lib                                  (existing)
  ├─ events.rs            EXTEND  new variants + file_id on FileFound
  ├─ types.rs             EXTEND  file_id on FileObject; JpegScanStatus untouched
  ├─ jpeg_recover.rs      EXTEND  retain top-N candidates, emit new events,
  │                                 accept output_event_log path
  └─ engine.rs            EXTEND  allocate & emit file_id; audit-log lines
                                  prefixed with [fid=…]

utmost-cli                                  (existing)
  └─ main.rs              EXTEND  RecoverArgs already has --candidates; default
                                  stays 3; thread keep_candidates through

utmost-gui                                  (existing)
  ├─ src/view_model.rs    EXTEND  new state for variants, bookmarks, notes,
  │                                 best_choices, recovery_state, variant_viewer,
  │                                 partial filter chips, journal-sidecar I/O
  ├─ src/slint_adapter.rs EXTEND  wire new properties + callbacks; chip row;
  │                                 keyboard shortcuts (b / n / m)
  ├─ src/recovery.rs      NEW     background recovery runner used by "Run
  │                                 recovery" button; appends events to bincode
  ├─ src/journal.rs       NEW     append + replay of carve_events.pending
  ├─ ui/main.slint        EXTEND  chip row, side panel (notes, variants, button)
  ├─ ui/variant_viewer.slint  NEW  modal sibling to lightbox
  └─ ui/lightbox.slint    EXTEND  footer buttons (Bookmark, Note, Mark best)

utmost-viewer                               (existing)
  └─ main.rs              UNCHANGED — picks up new behaviour via utmost-gui
```

## 4. Event vocabulary

Format version stays **`CURRENT_FORMAT_VERSION = 1`**. Steve's local test
output will be regenerated; no migration code is written.

### 4.1 Extended `FileFound`

`FileFound` itself is structurally unchanged — `file_id` lives on the
embedded `FileObject`, the single source of truth:

```rust
CarveEvent::FileFound {
    source_id: u32,
    file: FileObject,                // FileObject now carries file_id
    img_offset: u64,
    written_path: String,
}
```

`FileObject` (`utmost-lib/src/types.rs`) gains:

```rust
pub struct FileObject {
    pub file_id: u64,                // NEW — engine-allocated, monotonic per session
    pub filename: String,
    pub filesize: u64,
    pub file_type: String,
    pub byte_runs: Vec<ByteRun>,
    pub jpeg_scan: Option<JpegScanInfo>,
}
```

Code that needs a file's id reads it via `event.file.file_id`. Other event
variants (`RecoveryCandidate`, `Bookmark`, `Note`, `MarkAsBest`) carry
`file_id` as a top-level scalar because they do not embed a full
`FileObject`.

Allocation:

- A single `Arc<AtomicU64>` lives in `State`; both carve threads and the
  recovery pass consume from the same counter.
- The recovery pass, when invoked against an existing `carve_events.bin`,
  seeds its allocator from `1 + max(file_id seen)` after a pre-scan of the
  log.
- `file_id` is sourced *only* from `CarveEvent::FileFound`. `FoundFile.id`
  in the GUI view-model becomes a thin alias of `file.file_id`.

### 4.2 Recovery events

```rust
pub enum RecoveryMethod { DirectContinuation, FragmentReassembly }

CarveEvent::RecoveryStarted {
    started_at: String,             // ISO-8601 with offset
    keep_candidates: usize,         // how many variants per partial were requested
    search_window: usize,
    block_size: usize,
    min_entropy_score: f64,
    huffman_validation: bool,
}

CarveEvent::RecoveryCandidate {
    original_file_id: u64,          // the partial JPEG
    candidate_file_id: u64,         // the recovered candidate (also has its own FileFound)
    rank: u32,                      // 1-indexed, 1 = highest-scoring
    method: RecoveryMethod,
    entropy_score: f64,
    ff_validity_score: Option<f64>,
    huffman_mcu_count: Option<usize>,
    continuation_img_offset: u64,
}

CarveEvent::RecoveryFinished {
    duration_ms: u64,
    partials_processed: u32,
    candidates_written: u32,
}
```

Emission order during a recovery run: `RecoveryStarted` once → for each
partial JPEG → for each surviving candidate `FileFound` then
`RecoveryCandidate` (in rank order) → at end `RecoveryFinished`.

### 4.3 Annotation events

```rust
CarveEvent::Bookmark {
    file_id: u64,
    bookmarked: bool,               // false = un-bookmark; latest event wins
    at: String,                     // ISO-8601 with offset
}

CarveEvent::Note {
    note_id: u64,                   // monotonic per session; never reused
    file_id: u64,
    text: String,                   // arbitrary user-entered text; no max length enforced
    at: String,
}

CarveEvent::MarkAsBest {
    original_file_id: u64,          // the partial JPEG
    chosen_file_id: u64,            // either the original itself or one of its variants
    at: String,                     // latest event per original_file_id wins
}
```

Append-only semantics:

- No `NoteEdited`, no `NoteDeleted`. Users correct a note by writing a
  follow-up note.
- `Bookmark` and `MarkAsBest` are *last-writer-wins* per their key; older
  events with the same key are preserved on disk but superseded in the
  view-model.

### 4.4 Persistability

All seven new variants return `true` from `CarveEvent::persistable()`. They
are written to:

- `carve_events.bin` (in-stream for recovery events, appended for
  annotations on flush — see §6).
- The fanout to a `ChannelSink` (live mode) is unchanged: every variant
  reaches the GUI in real time.

## 5. Audit log, carve report, recover report

`file_id` is threaded through every cross-artifact file reference:

- **`audit_log.txt`** — every "Found:" line prefixes the id:
  ```
  [fid=42] Found: 00000123.jpg @ 0xdeadbeef (size 152103)
  ```
  Existing "Discarded:" / "Skipped:" lines, when they reference a written
  file, gain the same `[fid=…]` prefix. Lines that don't correspond to a
  written file are unchanged.

- **`carve_report.json`** — `FileObject.file_id` serialises automatically
  through `serde`.

- **`carve_report.xml`** (DFXML) — add a new element under each
  `<fileobject>`:
  ```xml
  <fileobject>
    <utmost:file_id>42</utmost:file_id>
    <filename>00000123.jpg</filename>
    ...
  </fileobject>
  ```
  Schema namespace is the project's existing `utmost:` extension.

- **`recover_report.json`** — `RecoveredFile` gains `file_id: u64` and
  `original_file_id: u64`, mirroring the `RecoveryCandidate` event.

## 6. Annotation persistence and journal sidecar

### 6.1 File layout

Alongside each `carve_events.bin` we add a same-framing sidecar:

```
output-disk_image_dd/
  ├─ carve_events.bin          (main, length-prefixed bincode frames)
  └─ carve_events.pending      (NEW — same framing; lives only while
                                  annotations are queued)
```

In multi-source runs each `output-XX/` gets its own pair.

### 6.2 Writer rules

- **Engine** writes `carve_events.bin` only. Never touches `.pending`.
- **GUI** writes `carve_events.pending` only while the engine is active. Also
  writes `carve_events.bin` directly during folding (see §6.4).
- **Recovery pass** writes both `carve_events.bin` (its own events, in
  append mode) and never touches `.pending` (recovery cannot run concurrently
  with the engine — see §7.2).

Single-writer invariant per file is preserved at all times.

### 6.3 Live mode flow

1. User performs an annotation action in the GUI.
2. View-model applies the event in memory immediately (responsive UI).
3. View-model serialises the event and appends a single framed record to
   `carve_events.pending`. `fsync` is best-effort — the sidecar is a
   crash-safety net, not the source of truth.
4. The event is also pushed onto an in-memory queue for the post-run fold.
5. On `CarveEvent::RunFinished` from the engine, the GUI:
   a. Opens `carve_events.bin` in append mode.
   b. Iterates the in-memory queue, writing each event to the main log.
   c. Deletes `carve_events.pending`.
   d. Clears the in-memory queue.

The engine must flush its `BincodeFileSink` and drop it *before* dispatching
`RunFinished` to the in-process `ChannelSink`. Concretely: the carve
driver's post-loop sequence is `sink.flush() → drop(sink) → channel.emit(
RunFinished)`. This guarantees the GUI's append in step (a) sees a closed,
fully-written main log. The append flow is otherwise tolerant — POSIX
`O_APPEND` writes are atomic per call, so even a brief overlap would be safe
for crash recovery, but the strict-ordering rule eliminates the question.

Failures during fold leave `carve_events.pending` intact for the next
session to recover — the GUI logs a warning and does *not* clear the queue.

### 6.4 Replay / viewer flow

When `utmost-viewer` or any GUI opens a session directory:

1. Read `carve_events.bin` → apply events to view-model.
2. If `carve_events.pending` exists:
   a. Read each framed event; apply to view-model (their effect is
      identical to having read them in §1).
   b. Append every read event to `carve_events.bin`.
   c. Delete `carve_events.pending`.

Any malformed trailing frame in `.pending` is treated like a malformed
trailing frame in `.bin`: read up to the last good frame, log warn, drop the
rest.

### 6.5 Annotation actions while no `.bin` file exists yet

If the GUI is launched but the engine has not yet produced
`carve_events.bin` (e.g. live mode mid-startup), annotation actions are
disabled in the UI. The "Run recovery" button is also disabled. Once a
single `RunStarted` event has been observed and the bincode sink is
established, annotations unlock.

## 7. Recovery pass integration

### 7.1 Producing top-N candidates

`utmost-lib/src/jpeg_recover.rs` is extended:

- The `for rc in ranked { … break; }` loop (current line ~448) is replaced
  with a counter that writes up to `config.keep_candidates` candidates that
  produce a valid EOI on reassembly. Existing `max_candidates` (Layer-1
  filter pool) is preserved and unchanged.
- Output filenames: `<stem>_recovered_<rank>.jpg` where `<rank>` is
  1-indexed. (For `keep_candidates = 1` this matches today's
  `<stem>_recovered.jpg` only in spirit; the new naming is consistent across
  all cases. Steve's test file will be regenerated regardless.)
- For each written candidate:
  1. Allocate `file_id` from the shared counter (see §7.3).
  2. Build a `FileObject` for the candidate (with `file_id`).
  3. Emit `CarveEvent::FileFound { file_id, source_id, file, … }` to the
     event log.
  4. Emit `CarveEvent::RecoveryCandidate { original_file_id,
     candidate_file_id, rank, method, … }`.
  5. Append a row to `recover_report.json` (existing JSON, now with
     `file_id` and `original_file_id`).

`RecoveryConfig` gains:

```rust
pub struct RecoveryConfig {
    // …existing fields…
    pub keep_candidates: usize,   // NEW — default 3 from CLI, default 5 from GUI, cap 10
}
```

A new `RecoveryConfig::with_event_log(path)` method lets callers point the
recovery pass at an existing `carve_events.bin` for append-mode emission.

### 7.2 GUI "Run recovery" button

- Renders in the side panel whenever `recovery_state == NotRun` and at least
  one partial JPEG exists.
- Adjacent numeric stepper / select for `keep_candidates`. Bounds: `1..=10`.
  Default value: `5`.
- Click handler:
  1. Set `recovery_state = Running`.
  2. Spawn a background thread (existing GUI thread-pool conventions) that
     calls a new high-level `utmost_gui::recovery::run_in_background(...)`
     wrapper around `recover_fragmented_jpegs`.
  3. Recovery feeds its events through an in-process `ChannelSink` *plus*
     appending to `carve_events.bin`. The GUI view-model consumes from the
     channel just like a live carve.
- The button is *not* available during a live carve (`recovery_state` is
  forced to `Disabled` while engine is running). Live carves can be
  annotated; recovery must wait for the carve to finish.

The recovery pass and the engine are mutually exclusive writers to
`carve_events.bin`. Enforced by:

- Refusing to start recovery while `run.status == Running`.
- Refusing to start a carve while a recovery is in progress (only relevant
  in long-running viewer sessions; engine entry is CLI-driven so this is
  defensive only).

### 7.3 `file_id` continuity

When recovery starts against a pre-existing `carve_events.bin`:

1. Pre-scan the log to find `max_file_id`.
2. Initialise the recovery allocator to `max_file_id + 1`.
3. Persist allocator state implicitly: every emitted `FileFound` rewrites
   the high-water mark. No separate counter file needed.

If recovery runs immediately after a carve in the same process (live mode →
manual recovery), the existing in-memory `AtomicU64` is reused — no
pre-scan needed.

## 8. View-model and UI

### 8.1 View-model state additions

```rust
pub struct ViewModel {
    // ── existing ──
    pub run: RunSummary,
    pub sources: Vec<SourceRow>,
    pub files: Vec<FoundFile>,
    pub type_counts: BTreeMap<FileType, u64>,
    pub filter: FilterState,
    pub selection: Option<FileId>,
    pub visible_files: Vec<FileId>,
    pub lightbox: Option<FileId>,
    pub lightbox_view: LightboxView,

    // ── NEW ──
    pub variants: BTreeMap<FileId, VariantSet>,        // keyed by original file_id
    pub variant_of: BTreeMap<FileId, FileId>,          // candidate_file_id → original_file_id
    pub bookmarks: BTreeSet<FileId>,
    pub notes: BTreeMap<FileId, Vec<NoteEntry>>,
    pub best_choices: BTreeMap<FileId, FileId>,
    pub partial_counts: BTreeMap<FileType, u64>,
    pub recovery_state: RecoveryUiState,
    pub variant_viewer: Option<FileId>,                // Some(original_id) when modal open
    pub note_input: Option<NoteInputState>,
    next_note_id: u64,
}

pub enum RecoveryUiState { Disabled, NotRun, Running, Finished }

pub struct VariantSet {
    pub original_id: FileId,
    pub variant_ids: Vec<FileId>,    // rank order
}

pub struct NoteEntry {
    pub note_id: u64,
    pub text: String,
    pub at: String,
}

pub struct NoteInputState {
    pub target: FileId,
    pub draft: String,
}
```

### 8.2 Filter changes

```rust
pub struct FilterState {
    pub enabled_types: BTreeSet<FileType>,             // existing — complete-only
    pub enabled_partial_types: BTreeSet<FileType>,     // NEW — "Partial X" chips
    pub bookmarked_only: bool,                         // NEW
    pub source_filter: Option<u32>,
    pub sort_key: SortKey,
    pub sort_dir: SortDir,
}
```

`recompute_visible()`:

1. Skip recovery-candidate files (those with `variant_of` membership) —
   variants only appear in the variant strip / viewer, never the main grid.
2. For remaining files: a file passes the type test if
   - status == Complete && `enabled_types.contains(ft)`, OR
   - status != Complete && `enabled_partial_types.contains(ft)`.
3. If `bookmarked_only`, also require `bookmarks.contains(&file_id)`.
4. Apply existing source/sort logic.

`partial_counts` is incremented on `FileFound` when the file has
`jpeg_scan.status != Complete`. The type-chip row in `.slint` renders one
chip per non-zero count in `type_counts`; the partial chip row renders one
per non-zero `partial_counts` entry. The chips can be toggled independently.

### 8.3 Event reducer additions

In `ViewModel::apply`, handle:

- `FileFound` → if the file is a recovery candidate (its `file_id` appears
  as `candidate_file_id` in a later `RecoveryCandidate` event), it is *not*
  pushed onto `files` for the main grid; rather, it's kept in a parallel
  `variant_files: BTreeMap<FileId, FoundFile>`. But since order of events is
  `FileFound` then `RecoveryCandidate`, the reducer can't know at
  `FileFound` time whether the file is a variant. Implementation: always
  push onto `files`; the `recompute_visible()` step filters out anything
  with a `variant_of` entry. Net effect: a candidate appears briefly in the
  main grid for the few microseconds between its `FileFound` and its
  `RecoveryCandidate`; on the next `recompute_visible()` (triggered by the
  candidate event) it disappears. Acceptable.
- `RecoveryCandidate` → extend `variants[original_id].variant_ids`, set
  `variant_of[candidate_id] = original_id`, trigger
  `recompute_visible()`.
- `RecoveryStarted` → `recovery_state = Running`.
- `RecoveryFinished` → `recovery_state = Finished`.
- `Bookmark` → `bookmarks.insert/remove(file_id)` per `bookmarked`.
- `Note` → `notes.entry(file_id).or_default().push(NoteEntry { … })`,
  `next_note_id = max(next_note_id, note_id + 1)`.
- `MarkAsBest` → `best_choices.insert(original_file_id, chosen_file_id)`.

### 8.4 New view-model methods (input side)

```rust
impl ViewModel {
    pub fn toggle_bookmark(&mut self, file_id: FileId) -> CarveEvent;
    pub fn add_note(&mut self, file_id: FileId, text: String) -> CarveEvent;
    pub fn mark_as_best(&mut self, original_id: FileId, chosen_id: FileId) -> CarveEvent;
    pub fn open_variant_viewer(&mut self);
    pub fn close_variant_viewer(&mut self);
    pub fn open_lightbox_for_variant(&mut self, variant_id: FileId);
    pub fn start_recovery_request(&mut self, keep_candidates: usize) -> Option<RecoveryRequest>;
}
```

These methods both mutate state *and* return the event that the journal /
log writer should persist. The slint adapter is responsible for routing the
returned event to the journal sidecar (live mode) or directly to
`carve_events.bin` (viewer mode).

### 8.5 UI structure

`utmost-gui/ui/main.slint`:

- Chip row (existing) gains:
  - "Partial X" chips per `FileType` present in `partial_counts`, rendered
    immediately after the corresponding "X" chip.
  - "Bookmarked" chip at the right end of the row (count = `bookmarks.len()`).
- Side panel:
  - Filename row now shows `★` (bookmark toggle) and `＋ Note` buttons.
  - **Notes section** between metadata and variants. Renders existing notes
    chronologically and an inline `<textarea>` for new ones. Submit appends a
    `Note` event.
  - **Variants section** (only when selection has variants): 2-column
    vertical-scrolling mini-grid + "Open variant viewer" button below.

`utmost-gui/ui/variant_viewer.slint` (NEW):

- Modal sibling to lightbox. Header with filename and ✕ button. Esc closes.
- 3-column gallery grid of variants including original at index 0.
- Keyboard: ←/→ moves selection, Enter / double-click opens lightbox in
  variant mode (lightbox's nav list is the variant set).
- The "★" in a thumbnail's corner indicates the current `best_choices` value.

`utmost-gui/ui/lightbox.slint`:

- Footer button row gains three buttons:
  - **★ Bookmark** (visible whenever the current file is a top-level file in
    the grid; toggles `Bookmark` event for the current `file_id`).
  - **＋ Note** (opens an inline note-input overlay; submit adds `Note`).
  - **★ Mark as best variant** (visible only when the lightbox is in
    variant-mode — i.e. `variant_viewer.is_some()` and the current file_id
    is in `variants[original].variant_ids`). Submits `MarkAsBest`.
- Nav list (the existing left/right arrow target) switches to the variant
  set when entering the lightbox from the variant viewer / side-panel
  mini-grid.

### 8.6 Keyboard shortcuts

Global when a file is selected (grid, side panel, variant viewer, or
lightbox):

- `b` — toggle bookmark on selection (no-op if selection is a variant).
- `n` — focus / open the note input for selection.
- `m` — mark current variant as best (no-op outside variant context).

Existing shortcuts unchanged.

## 9. Multi-source mode

Each `output-XX/` subdirectory contains its own `carve_events.bin` and
optionally its own `carve_events.pending`. The view-model tracks the active
source, and journal writes go to the matching `.pending` file.

For replay (`utmost-viewer ./output`), the viewer iterates each
subdirectory's pair and applies events session by session, exactly as
today's multi-session replay does.

## 10. Testing

### 10.1 Unit tests (utmost-lib)

- `events.rs`: round-trip every new variant through bincode.
- `events.rs`: `persistable()` returns true for every new variant.
- `jpeg_recover.rs`: synthetic image with N plausible continuations →
  recovery emits N `FileFound` + N `RecoveryCandidate` events; on disk we
  see N `<stem>_recovered_<rank>.jpg` files.
- `jpeg_recover.rs`: `keep_candidates = 1` matches today's behaviour
  (single file written, `<rank> = 1`).
- `jpeg_recover.rs`: `file_id` seeding from a pre-populated event log
  resumes from `max_seen + 1`.

### 10.2 Unit tests (utmost-gui view-model)

- `apply(RecoveryCandidate)` populates `variants` and `variant_of`.
- `recompute_visible()` excludes variants from the main grid.
- `partial_counts` tracks JPEG scan-status correctly across events.
- Two parallel chip toggles ("JPG" vs "Partial JPG") yield independent
  visibility sets.
- `toggle_bookmark()` returns the right event and updates state.
- `add_note()` allocates monotonic `note_id`s.
- `mark_as_best()` last-writer-wins per original.
- Journal replay: a `.pending` file with three events, applied on top of a
  `.bin` log, results in identical state to a single `.bin` log containing
  those events appended.

### 10.3 Integration tests (utmost-gui)

- Live mode: emit a carve session through a `ChannelSink`, perform a
  bookmark + a note via the view-model API, emit `RunFinished`, verify
  `.pending` was deleted and `.bin` contains the appended events.
- Crash simulation: write a `.pending` file with two events directly (no
  fold), open the viewer, verify both events are visible *and* `.bin` now
  contains them and `.pending` is gone.
- Recovery: run the recovery pipeline against a partial-JPEG fixture
  through `utmost_gui::recovery::run_in_background`, observe events arrive
  via the view-model channel, verify `carve_events.bin` was appended.
- Variant viewer: open partial JPEG, open variant viewer, navigate with
  arrow keys, double-click → lightbox uses variant set as nav list,
  press `m` → `MarkAsBest` event written, ★ appears on chosen thumb.

### 10.4 Property / fuzz testing

- Journal replay is idempotent: applying a `.pending` to view-model state
  V → V' produces the same state as opening a `.bin` that already contained
  those events.

## 11. Backwards compatibility

`CURRENT_FORMAT_VERSION = 1` is preserved. Pre-existing `carve_events.bin`
files from before this change must be regenerated; this is acceptable
because the format has not been published.

The decision to skip a version bump is recorded in
`memory/project_event_log_format_unshared.md` and applies only until the
format is shared externally.

## 12. Deferred work (issue)

A follow-up GitHub issue tracks moving the GUI `keep_candidates` default (5)
and cap (10) into the user config file (`~/.config/utmost/config.toml`), so
forensic teams can pin a project-wide policy. Issue created at the end of
the brainstorming flow.

## 13. Open questions

None at design time. Implementation may surface clarifications around:

- Whether the recovery thread should batch event emits to reduce
  `carve_events.bin` fsync pressure.
- How the variant viewer handles >9 variants (probably scroll; current cap
  is 10).
- Exact icon / label copy for the three lightbox buttons.

These are implementation details and are handled in the plan, not here.
