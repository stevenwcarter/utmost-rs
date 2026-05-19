# GUI SQLite Index — Fast Case Load & Per-Source Layout

**Status:** Approved
**Date:** 2026-05-19
**Author:** Steve Carter

## Problem

Opening a finished case in the Utmost GUI is slow. A real workload of
`carve_events.bin` at 43 MB with ~286,000 `FileFound` events takes many seconds
to replay synchronously on the main thread before the window appears. The user
sees nothing until the entire log has been decoded, applied to the in-memory
`ViewModel`, and `recompute_visible()` has run. Forensic scans of this scale
are not unusual, and larger ones will follow; the current loader does not have
a viable scaling story.

This work has two goals:

1. **Window-up time.** The Slint window must appear within ~100 ms regardless
   of case size, with case metadata and source list immediately visible and a
   progress indicator covering the tile grid until the index is ready.
2. **Subsequent opens.** A one-time post-process should produce an on-disk
   index that lets every later open of the same case complete in well under a
   second, with no overlay shown (the data is just there).

A second-order requirement surfaced during design: each scanned source must
own a clearly-named, self-contained set of artifacts on disk, so that files
copied or exported out of a case are unambiguously identifiable.

## Non-Goals

- Replacing the in-memory `ViewModel` as the UI's primary data source. The
  SQLite index is a fast-load cache and the foundation for future query-driven
  features; it is not yet the source of truth that the UI reads from.
- Backwards compatibility with the previous `carve_events.bin` filename. This
  layout has no published external users; the rename is a clean break.
- Lazy/paginated loading, full-text search, multi-source SQL aggregation, and
  user-cancellable indexing. These are deferred to follow-up issues.
- WASM support for the index. SQLite/Diesel live in `utmost-gui` only;
  `utmost-lib` remains WASM-safe.

## Architecture Overview

```
                ┌─ SQLite present & at log size? ─ yes ─→ hydrate VM from SQLite (Path C)
open(target) ─→ ┤
                └─ no/partial ─→ stream log → SQLite + VM (Paths A/Resume)
```

All SQLite code lives in `crates/utmost-gui/src/index_db/`. The event log
format (`utmost_lib::events`) and `BincodeFileReader` are unchanged.

### Crate dependencies (added to `utmost-gui` only)

| Crate | Version | Notes |
|---|---|---|
| `diesel` | `2` | Features: `sqlite`, `returning_clauses_for_sqlite_3_35` |
| `diesel_migrations` | `2` | Embedded migrations via `embed_migrations!` |
| `libsqlite3-sys` | `0.30` | `bundled` feature — no system SQLite dependency |

Workspace `Cargo.toml` adds matching `[workspace.dependencies]` entries.

### Threading model

- The Slint window opens on the main thread within ~100 ms; the `ViewModel`
  is created empty, the UI binds to it, and the Slint event loop starts.
- A background `IndexerThread` does the work — either rebuilding the index
  from `<stem>-events.bin`, resuming from a partial index, or hydrating the
  VM from a complete index. It communicates with the UI through a
  `crossbeam_channel::Sender<IndexProgress>`.
- The existing 100 ms Slint timer in `launch_ui_with_journal` already syncs
  VM → UI; it gains one extra responsibility: draining `IndexProgress`
  messages and updating the loading-overlay properties on `MainWindow`.
- The loading overlay is shown only if the indexer has been running for more
  than 250 ms and is not yet `Finished`. Under that threshold, the warm
  hydration path never flashes the overlay.

### Artifact layout (per source)

```
output/
├── disk1_dd/
│   ├── disk1_dd-events.bin       ← engine-authored, append-only (renamed)
│   ├── disk1_dd-index.sqlite     ← GUI-owned cache (new)
│   ├── disk1_dd-events.pending   ← annotation journal sidecar (renamed)
│   └── <extracted files…>
└── disk2_dd/
    ├── disk2_dd-events.bin
    ├── disk2_dd-index.sqlite
    ├── disk2_dd-events.pending
    └── <extracted files…>
```

Naming convention: source-stem-first. `ls` groups all artifacts for a given
source together, and a file copied out of context retains its provenance in
the name. The stem is derived from the source image filename (e.g.
`disk1.dd` → `disk1_dd`) by the existing `output_subdir` derivation.

Each source has its own `BincodeFileSink`, its own `Journal`, its own
SQLite. When the GUI opens a case directory containing multiple per-source
subdirs, it loads all of them into one merged `ViewModel` (the existing
behavior); each source's SQLite is opened independently.

## SQLite Schema

### Driver settings (applied on every connection open)

- `PRAGMA journal_mode = WAL` — concurrent reader + writer for live mode.
- `PRAGMA synchronous = NORMAL` — safe under WAL, materially faster than
  `FULL` for our write volume.
- `PRAGMA foreign_keys = ON`.
- `diesel_migrations::MigrationHarness::run_pending_migrations` — applies
  any embedded migrations. Schema versioning is Diesel's own
  `__diesel_schema_migrations` table; no manual `user_version` tracking.

### Initial migration: `0001_initial`

```sql
-- key/value bag for cache-staleness tracking and small singletons
CREATE TABLE meta (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);
-- Stored keys: run_started_at, last_event_offset, last_event_count, indexed_at

-- Run metadata (one row per database)
CREATE TABLE run (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    started_at TEXT NOT NULL,
    output_root TEXT NOT NULL,
    source_image_path TEXT NOT NULL,
    configured_types_json TEXT NOT NULL,
    case_id TEXT, examiner TEXT, evidence_id TEXT, case_notes TEXT,
    status TEXT NOT NULL,        -- 'Running' | 'Finished' | 'Interrupted'
    elapsed_ms INTEGER NOT NULL DEFAULT 0,
    total_files INTEGER NOT NULL DEFAULT 0
);

-- Per-source rows; typically one per DB but the table supports merged views
CREATE TABLE source (
    source_id INTEGER PRIMARY KEY NOT NULL,
    filename TEXT NOT NULL,
    output_subdir TEXT NOT NULL,
    total_bytes INTEGER NOT NULL,
    bytes_read INTEGER NOT NULL DEFAULT 0,
    files_found INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    duration_ms INTEGER
);

-- Files: one row per FileFound event
CREATE TABLE file (
    file_id INTEGER PRIMARY KEY NOT NULL,    -- engine-allocated id
    source_id INTEGER NOT NULL REFERENCES source(source_id),
    filename TEXT NOT NULL,
    filesize INTEGER NOT NULL,
    file_type TEXT NOT NULL,
    img_offset INTEGER NOT NULL,
    written_path TEXT NOT NULL,
    byte_runs_json TEXT NOT NULL DEFAULT '[]',
    -- JpegScanInfo flattened; NULL for non-JPEGs
    jpeg_status TEXT,
    jpeg_complete_offset INTEGER,
    jpeg_first_ff_offset INTEGER,
    jpeg_dqt_count INTEGER,
    jpeg_sos_count INTEGER,
    jpeg_dht_count INTEGER
);
CREATE INDEX idx_file_source     ON file(source_id);
CREATE INDEX idx_file_type       ON file(file_type);
CREATE INDEX idx_file_size       ON file(filesize);
CREATE INDEX idx_file_img_offset ON file(img_offset);

-- Annotations.
-- Note: file_id references are NOT declared as foreign keys. SQLite
-- enforces FKs per-statement (not deferred to COMMIT), and the event
-- log does not guarantee that a FileFound row for, say, a recovery
-- candidate has been inserted in the same transaction before a
-- Bookmark/Note/MarkAsBest/variant row that references it. An index
-- still keys these for fast joins.
CREATE TABLE bookmark (
    file_id INTEGER PRIMARY KEY NOT NULL,
    at TEXT NOT NULL
);

CREATE TABLE note (
    note_id INTEGER PRIMARY KEY NOT NULL,
    file_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    at TEXT NOT NULL
);
CREATE INDEX idx_note_file ON note(file_id);

CREATE TABLE best_choice (
    original_file_id INTEGER PRIMARY KEY NOT NULL,
    chosen_file_id INTEGER NOT NULL,
    at TEXT NOT NULL
);

-- Recovery pass
CREATE TABLE recovery_run (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    started_at TEXT NOT NULL,
    keep_candidates INTEGER NOT NULL,
    search_window INTEGER NOT NULL,
    block_size INTEGER NOT NULL,
    min_entropy_score REAL NOT NULL,
    huffman_validation INTEGER NOT NULL,
    finished_duration_ms INTEGER,
    partials_processed INTEGER,
    candidates_written INTEGER
);

CREATE TABLE variant (
    original_file_id INTEGER NOT NULL,
    candidate_file_id INTEGER NOT NULL,
    rank INTEGER NOT NULL,
    method TEXT NOT NULL,    -- 'direct_continuation' | 'fragment_reassembly'
    entropy_score REAL NOT NULL,
    ff_validity_score REAL,
    huffman_mcu_count INTEGER,
    continuation_img_offset INTEGER NOT NULL,
    PRIMARY KEY (original_file_id, candidate_file_id)
);
CREATE INDEX idx_variant_candidate ON variant(candidate_file_id);
```

### Schema notes

- `file.file_id` is the engine-allocated `FileObject.file_id` — durable
  across renames, canonical handle in the event log. The GUI-local
  `FoundFile.id` counter is kept as-is for this PR (it is the key for
  `image_cache`, `thumbnail_ready`, and several Slint property
  bindings); on hydration, fresh local ids are allocated as if the
  events were being replayed. Unifying the two id spaces is a
  follow-up refactor.
- `byte_runs` is stored as JSON. It is never queried; the parse cost on
  detail-view open is negligible.
- `JpegScanInfo` is flattened into nullable columns on `file` so the
  detail panel needs no JOIN.
- `recovery_run` is a single-row table; its row is absent if recovery has
  not run.

### Diesel patterns

- `schema.rs` is generated once via `diesel print-schema` and checked in.
  The Diesel CLI is **not** required at runtime or in CI.
- Each table maps to an `Insertable` + `Queryable` struct in
  `index_db::models`.
- Bulk inserts go through `diesel::insert_into(...).values(&batch)
  .execute(tx)` inside a single transaction containing all the row
  updates plus the `last_event_offset` advance for one batch (~5,000
  rows or 200 ms, whichever comes first).

## Loading Flow

### `IndexProgress` channel protocol

```rust
enum IndexProgress {
    Started { total_bytes: Option<u64> },  // .bin size, when known
    Bytes { read: u64 },                   // monotonic non-decreasing
    Files { count: u64 },                  // monotonic non-decreasing
    Finished,
    Error(String),
}
```

Progress is reported by **bytes read**, not by event count. The event
count would require a pre-scan we don't want to pay for. The label below
the bar shows files-indexed-so-far for user-facing context.

### Decision tree on open

```rust
fn open_decision(bin: &Path, db: &mut SqliteConnection) -> OpenAction {
    let bin_size = fs::metadata(bin)?.len();
    let meta = read_meta(db);

    let mut reader = BincodeFileReader::open(bin)?;
    let first = reader.next_event()?.ok_or(Empty)?;
    let CarveEvent::RunStarted { started_at, .. } = &first
        else { return RebuildFromZero };

    match (meta.run_started_at, meta.last_event_offset) {
        (None, _)                                       => RebuildFromZero,
        (Some(rec), _)         if rec != *started_at   => WipeAndRebuild,
        (Some(_), Some(off))   if off == bin_size      => HydrateAndDone,
        (Some(_), Some(off))   if off  < bin_size      => Resume { from: off },
        (Some(_), Some(off))   if off  > bin_size      => WipeAndRebuild,
        _                                              => RebuildFromZero,
    }
}
```

Four outcomes:

- **HydrateAndDone** — bulk `SELECT` into the VM, finish. No overlay unless
  this somehow exceeds 250 ms.
- **Resume { from }** — hydrate VM from current SQLite first, then seek
  the `BincodeFileReader` to `from` and stream the remainder into both VM
  and DB. Overlay shows "Resuming index…" with the bar starting at
  `from / bin_size`.
- **RebuildFromZero** — fresh DB, stream the whole `.bin`.
- **WipeAndRebuild** — `DELETE FROM` every domain table (leaving
  `__diesel_schema_migrations` intact), then `RebuildFromZero`.

### Cache identity

The SQLite is keyed to a specific run. `meta` stores:

| Key | Value |
|---|---|
| `run_started_at` | `started_at` from the first `RunStarted` event we indexed. |
| `last_event_offset` | Byte offset in `.bin` immediately past the last fully-committed event. |
| `last_event_count` | Total events committed. Diagnostic + progress. |
| `indexed_at` | Last commit timestamp. Diagnostic. |

Identity is `run_started_at`, not file size or mtime. The latter two are
only used for the offset comparison.

### Atomic offset advancement (resume safety)

Every batched flush is one transaction that updates rows **and**
`last_event_offset` together:

```rust
conn.transaction(|tx| -> QueryResult<()> {
    diesel::insert_into(file::table).values(&batched_files).execute(tx)?;
    diesel::insert_into(bookmark::table).values(&batched_bookmarks).execute(tx)?;
    // … other tables as the batch contains
    diesel::update(meta::table.find("last_event_offset"))
        .set(meta::value.eq(new_offset.to_string()))
        .execute(tx)?;
    diesel::update(meta::table.find("last_event_count"))
        .set(meta::value.eq(new_count.to_string()))
        .execute(tx)?;
    Ok(())
})?;
```

If the process dies before commit, SQLite rolls back; the offset and the
rows stay in lockstep. If it dies after commit, both have advanced
together. There is never a "rows without offset" or "offset without
rows" state on disk.

`BincodeFileReader` exposes a new `byte_offset() -> u64` accessor (the
underlying `Seek::stream_position()` minus the `BufReader`'s buffered
remainder). The writer snapshots this value after each successful
`next_event()` to know where to seek to on resume.

### Resume flow

1. Open log, validate header, read first event (must be `RunStarted`).
2. Hydrate the VM from SQLite, populating everything indexed so far.
3. `Reader.seek(SeekFrom::Start(last_event_offset))`.
4. Stream-loop: for each remaining event, `vm.apply(ev)` and
   `IndexDbWriter::apply(ev)` (batched as above).
5. On completion, mark the run status appropriately if a `RunFinished`
   was encountered in the resumed range.

The user experience: window appears within ~100 ms, case metadata and
already-indexed files visible immediately, overlay shows resume progress
starting at the appropriate fraction. When indexing completes, the
overlay fades and the grid reflects the full set.

### Live mode interaction

`run_live` is the simpler case: the indexer thread is the only SQLite
writer, doesn't need a decision tree, and goes straight to
writer-attached-to-channel. After every `vm.apply(&ev)` inside the
existing receive loop, also call `IndexDbWriter::apply(&ev)`. Batches
flush every N events or every 200 ms; a final flush runs on
`RunFinished`. If the GUI is killed mid-run and reopened as a replay,
the next open hits **Resume** — exactly the same code path.

### Progress overlay (Slint)

Three new properties on `MainWindow`:

```slint
in property <bool>  indexing-active;
in property <int>   indexing-files;
in property <float> indexing-progress;   // 0.0..1.0
```

The overlay sits in `main.slint` over the tile-grid area only (not the
title bar or sources panel — those stay live). Filter chips, sort
controls, and search inputs are disabled while `indexing-active` is
true.

The 250 ms threshold lives in `UiState::sync`: `indexing-active` is set
to true only if the indexer has been running >250 ms and isn't done.
Warm hydration under 250 ms never flashes the overlay.

### Error handling

| Failure | Behavior |
|---|---|
| Migration apply fails | Surface error in the overlay slot; do not auto-delete the DB. Tell the user the path. |
| Log read error mid-rebuild | Abort; surface error; leave partial SQLite. Next open detects offset mismatch and either resumes or wipes. |
| Future-version `.sqlite` | Migration error surfaced; user told to remove the file. |
| Future-version `.bin` | Error from `BincodeFileReader::open` surfaced. |
| WAL contention with running engine | Benign by design (WAL allows concurrent reader + writer). |
| Process killed mid-rebuild | Next open hits **Resume** thanks to atomic offset advance. |

### Cancellation

Not in v1. Closing the window mid-indexing detaches the indexer thread;
the next batch boundary is the de-facto cancel point. State on disk is
always coherent (resume-safe) because of the atomic offset rule.
Adding a cancel handle is a follow-up issue.

## Testing Strategy

### Unit tests (in `crates/utmost-gui/src/index_db/`)

- Migration applies cleanly on an empty DB; `__diesel_schema_migrations`
  has one row.
- Round-trip per table: insert via `Insertable`, read via `Queryable`,
  assert equal.
- `IndexDbWriter::apply` per `CarveEvent` variant — one event in,
  expected row(s) out.
- Bulk-insert batching: 12,500 events with a 5,000-row threshold produces
  exactly three transactions and 12,500 rows.
- `last_event_offset` advances atomically: injecting a panic mid-flush
  leaves rows and offset in lockstep (both unchanged).
- `open_decision` truth table over all seven cases.

### Integration tests (in `crates/utmost-gui/tests/`)

Each writes a synthetic `.bin` via `BincodeFileSink`, runs the loader,
asserts on resulting VM and SQLite state.

- `index_db_cold_open.rs` — first-ever open creates the `.sqlite` and
  populates the VM.
- `index_db_warm_open.rs` — second open does not touch the `.bin`;
  hydration completes within budget.
- `index_db_resume_after_partial.rs` — abort indexer mid-stream;
  reopen; assert Resume action and no duplicate rows.
- `index_db_new_run_wipes.rs` — replace `.bin` with a new run;
  reopen; assert WipeAndRebuild and only the new run's events remain.
- `index_db_live_writes.rs` — run live mode; verify SQLite contents
  and `last_event_offset == .bin size`.
- `index_db_progress_signals.rs` — verify the channel emits
  `Started → Bytes…(monotonic) → Files…(monotonic) → Finished`.
- `index_db_per_source_isolation.rs` — two source subdirs, each gets
  its own `.sqlite`; merged VM is the union.

### Benches (in `crates/utmost-gui/benches/`, `#[ignore]` in CI)

- `bench_cold_rebuild_286k` — target < 5 s on a modest dev machine.
- `bench_warm_hydrate_286k` — target < 250 ms so the overlay stays
  hidden in the common case.

### Test data helper

`crates/utmost-gui/tests/common/synthetic_log.rs` exposes
`pub fn write_log(path: &Path, n_files: usize) -> (u64, String)`.
Existing integration tests (`replay_snapshot.rs`,
`journal_roundtrip.rs`) keep their hand-rolled fixtures; new tests use
the helper.

### Not tested

- SQLite-level concurrency (trusted upstream).
- Diesel migration framework correctness (trusted upstream).
- Visual rendering of the overlay (not part of existing conventions).
  We test the Slint property bindings, not the pixel output.

## File Inventory

### New files

| Path | Purpose |
|---|---|
| `crates/utmost-gui/migrations/0001_initial/up.sql` | Schema. |
| `crates/utmost-gui/migrations/0001_initial/down.sql` | `DROP TABLE` per table. |
| `crates/utmost-gui/diesel.toml` | Points `print_schema` at `src/index_db/schema.rs`. |
| `crates/utmost-gui/src/index_db/mod.rs` | Public surface. |
| `crates/utmost-gui/src/index_db/schema.rs` | Generated, checked in. |
| `crates/utmost-gui/src/index_db/models.rs` | Row structs. |
| `crates/utmost-gui/src/index_db/writer.rs` | `IndexDbWriter` + batching. |
| `crates/utmost-gui/src/index_db/hydrate.rs` | VM hydration. |
| `crates/utmost-gui/src/indexer_thread.rs` | Background thread + decision tree. |
| `crates/utmost-gui/tests/common/synthetic_log.rs` | Test helper. |
| `crates/utmost-gui/tests/index_db_*.rs` | Seven integration tests. |
| `crates/utmost-gui/benches/index_load.rs` | Two ignored Criterion benches. |

### Modified files

| Path | Change |
|---|---|
| `crates/utmost-gui/Cargo.toml` | Add diesel deps. |
| `crates/utmost-gui/src/lib.rs` | Route loader through indexer thread; per-source-stem discovery. |
| `crates/utmost-gui/src/journal.rs` | Pending sidecar named `<stem>-events.pending`. |
| `crates/utmost-gui/src/slint_adapter.rs` | Three new overlay properties; channel drain in 100 ms timer; disable filters/sort while indexing. |
| `crates/utmost-gui/ui/main.slint` | Conditional overlay card. |
| `crates/utmost-lib/src/events.rs` | `BincodeFileReader::byte_offset()` accessor. |
| `crates/utmost-cli/src/main.rs` | Per-source `<stem>-events.bin` + per-source `BincodeFileSink` + per-source `Journal`. |
| `crates/utmost-cli/src/sinks.rs` | If multi-source fan-out routes through here, ditto. |
| `crates/utmost-lib/src/engine.rs` | Main-log path construction (if not entirely in CLI). |
| `Cargo.toml` (workspace) | Add `diesel`, `diesel_migrations`, `libsqlite3-sys` to `[workspace.dependencies]`. |
| `README.md` | Updated artifact layout. |

## Rollout

Eight ordered steps. Each leaves the workspace compiling and existing
tests green:

1. **Per-source rename + plumbing.** Engine writes `<stem>-events.bin`,
   `Journal` writes `<stem>-events.pending`, `resolve_sources` finds by
   stem. No DB yet.
2. **Diesel deps + empty migration + `IndexDb::open`.** Schema applies
   on connection open; no reads or writes from the GUI yet.
3. **`IndexDbWriter` with per-variant `apply`.** Standalone; covered by
   unit tests; not yet wired into the loader.
4. **Hydration path.** `ViewModel::populate_from_db`. Unit-tested via
   synthetic rows.
5. **`open_decision` + cold rebuild wired into `run_from_file`.**
   First-open is slow; second-open uses `HydrateAndDone`.
   `index_db_cold_open` and `index_db_warm_open` pass.
6. **Resume path.** `Resume { from }` + atomic offset advance.
   `index_db_resume_after_partial` passes.
7. **`WipeAndRebuild` + new-run detection.**
   `index_db_new_run_wipes` passes.
8. **Live mode + progress UI.** `run_live` writes incrementally;
   Slint overlay with the 250 ms threshold; filters/sort disabled
   while indexing. `index_db_live_writes` and
   `index_db_progress_signals` pass; manual smoke against the
   43 MB / 286k test case.

The feature ships behind no flag; step 8 is the default loader path.

## Out of Scope (deferred to follow-up issues)

- Lazy / paginated file loading — query SQLite on filter/sort changes
  instead of holding `vm.files` in memory. **Issue #2.**
- FTS5 virtual table for filename + note search. **Issue #3.**
- Multi-source aggregated SQL queries via `ATTACH DATABASE`. **Issue #4.**
- Cancel button on the loading card. **Issue #5.**
- Visual regression / perf-tripwire CI tests for the loading UI.
  **Issue #6.**
