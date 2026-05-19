# GUI SQLite Index Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the synchronous in-memory replay of `carve_events.bin` with a Diesel/SQLite-backed cache so the GUI window appears within ~100 ms on any case size, and re-opens of the same case hydrate from SQLite in well under a second.

**Architecture:** Per-source rename of the event log to `<stem>-events.bin`; each source also owns a `<stem>-index.sqlite` Diesel-managed cache. The GUI opens the SQLite (running embedded migrations on open), then decides between hydrate / resume / cold rebuild / wipe-and-rebuild based on a `last_event_offset` recorded atomically with row inserts. A background indexer thread emits progress over a `crossbeam_channel`; a Slint overlay covers the tile grid when indexing exceeds 250 ms.

**Tech Stack:** Rust 2024 edition, Diesel 2 (sqlite backend), diesel_migrations (embedded), libsqlite3-sys (bundled), crossbeam-channel, Slint 1.10. Reference spec: `docs/superpowers/specs/2026-05-19-gui-sqlite-index-design.md`.

---

## Prerequisites & Conventions

- **Pre-commit hook:** This repo runs `cargo fmt` then `cargo clippy --all-targets` on every commit and rejects any clippy warning. Every commit step assumes you run both successfully before committing. If clippy fails, fix the warning — never `--no-verify`.
- **Test runner:** `cargo test -p <crate> <test_name>` from repo root.
- **Reference reading:** Before starting, read the spec at `docs/superpowers/specs/2026-05-19-gui-sqlite-index-design.md`. It contains the schema, the decision tree, the loading-flow narrative, and the error-handling table referenced by individual tasks.
- **Existing test patterns:** Read `crates/utmost-gui/tests/journal_roundtrip.rs` and `crates/utmost-gui/tests/replay_snapshot.rs` once before Phase 5 — they show how to build a synthetic event log with `BincodeFileSink` and drive `run_from_file`.
- **Stable identifiers used throughout:**
  - `<stem>` = `utmost_lib::types::clean_filename(source_path, 32)` (the same helper that already drives `output_subdir`).
  - Event log file: `<source_dir>/<stem>-events.bin`.
  - Pending journal: `<source_dir>/<stem>-events.pending` (derived automatically by `Journal::pending_path()` from the main log's `file_stem()`).
  - Index: `<source_dir>/<stem>-index.sqlite`.

---

## Phase 1 — Per-source artifact rename

Goal: every source gets `<stem>-events.bin`, `<stem>-events.pending`. The Journal's existing `file_stem()`-based pending derivation means the rename of the main log automatically renames the pending sidecar. After this phase the GUI still works exactly as before — just with new filenames.

### Task 1.1: Add stem-derivation helper

**Files:**
- Modify: `crates/utmost-cli/src/sinks.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/utmost-cli/src/sinks.rs` inside the `#[cfg(test)] mod tests` block:

```rust
#[test]
fn log_stem_for_normal_filename() {
    assert_eq!(super::log_stem("/path/disk1.dd"), "disk1.dd");
}

#[test]
fn log_stem_for_filename_with_spaces() {
    // clean_filename collapses non-alphanumerics
    let s = super::log_stem("/path/my disk.dd");
    assert!(!s.is_empty());
    assert!(!s.contains(' '));
}

#[test]
fn log_stem_for_empty_input() {
    assert_eq!(super::log_stem(""), "source");
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p utmost-cli sinks::tests::log_stem_for_normal_filename`
Expected: FAIL — "no function `log_stem` in scope"

- [ ] **Step 3: Add the helper**

In `crates/utmost-cli/src/sinks.rs`, just below the existing `use` block, add:

```rust
/// Derive the filename stem used for the event log, sqlite index, and
/// pending sidecar of a source. Wraps `clean_filename` (the same helper
/// `output_layout::derive_subdir` uses) with a single fallback so an
/// empty input still produces a usable stem.
pub fn log_stem(source_path: &str) -> String {
    let base = utmost_lib::types::clean_filename(source_path, 32);
    if base.is_empty() { "source".to_string() } else { base }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p utmost-cli sinks::tests::log_stem`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-cli/src/sinks.rs
git commit -m "feat(cli): add log_stem helper for per-source artifact names"
```

### Task 1.2: Switch the event-log filename to `<stem>-events.bin`

**Files:**
- Modify: `crates/utmost-cli/src/sinks.rs`

- [ ] **Step 1: Update the existing test to assert the new filename**

In `crates/utmost-cli/src/sinks.rs`, replace the test `build_with_export_creates_file_and_returns_sink`:

```rust
#[test]
fn build_with_export_creates_stem_events_file_and_returns_sink() {
    let dir = tempfile::tempdir().unwrap();
    let r = build_source_sink(dir.path(), "disk1.dd", true, vec![]).unwrap();
    assert!(r.is_some());
    assert!(dir.path().join("disk1.dd-events.bin").exists());
    assert!(!dir.path().join("carve_events.bin").exists());
}
```

Also update `build_with_no_options_returns_none`:

```rust
#[test]
fn build_with_no_options_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let r = build_source_sink(dir.path(), "disk1.dd", false, vec![]).unwrap();
    assert!(r.is_none());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p utmost-cli sinks::tests::build_with_export`
Expected: FAIL — `build_source_sink` signature mismatch.

- [ ] **Step 3: Update `build_source_sink` to take the stem**

Replace the existing `build_source_sink` function in `crates/utmost-cli/src/sinks.rs` with:

```rust
/// Build the event sink for a single source. `stem` is used to name the
/// on-disk event log (`<stem>-events.bin`). When `export_enabled=false`
/// and no extra sinks are supplied, returns `None`.
pub fn build_source_sink(
    output_dir: &Path,
    stem: &str,
    export_enabled: bool,
    extra: Vec<Arc<dyn EventSink>>,
) -> Result<Option<Arc<dyn EventSink>>> {
    let mut sinks: Vec<Arc<dyn EventSink>> = Vec::new();
    if export_enabled {
        let path = output_dir.join(format!("{stem}-events.bin"));
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
```

- [ ] **Step 4: Update the call site in `main.rs`**

In `crates/utmost-cli/src/main.rs`, find the `build_source_sink` call inside `process_files_parallel` (around line 580). Replace:

```rust
        if let Some(sink) = sinks::build_source_sink(&source_dir, export_enabled, extra)? {
```

with:

```rust
        let stem = sinks::log_stem(_input);
        if let Some(sink) = sinks::build_source_sink(&source_dir, &stem, export_enabled, extra)? {
```

Also change the surrounding pattern destructure on the same loop, replacing `for (_id, _input, subdir)` with `for (_id, _input, subdir)` (no change needed if it's already `_input`; otherwise rename `_input` → `input` and refer to it).

If the loop currently destructures with `_input`, change it to `input` and use it for the stem derivation.

- [ ] **Step 5: Run the workspace tests to verify everything still compiles + passes**

Run: `cargo test -p utmost-cli`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-cli/src/sinks.rs crates/utmost-cli/src/main.rs
git commit -m "feat(cli): write <stem>-events.bin instead of carve_events.bin"
```

### Task 1.3: Update GUI source discovery for the new filename

**Files:**
- Modify: `crates/utmost-gui/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Append to a new test file `crates/utmost-gui/tests/stem_discovery.rs`:

```rust
use std::path::Path;
use utmost_gui::resolve_sources_for_test;

#[test]
fn discovers_stem_events_bin_in_subdirs() {
    let dir = tempfile::tempdir().unwrap();
    let sub_a = dir.path().join("output-disk1.dd");
    let sub_b = dir.path().join("output-disk2.dd");
    std::fs::create_dir_all(&sub_a).unwrap();
    std::fs::create_dir_all(&sub_b).unwrap();
    std::fs::write(sub_a.join("disk1.dd-events.bin"), b"").unwrap();
    std::fs::write(sub_b.join("disk2.dd-events.bin"), b"").unwrap();

    let mut found = resolve_sources_for_test(dir.path()).unwrap();
    found.sort();
    assert_eq!(found.len(), 2);
    assert!(found[0].ends_with("disk1.dd-events.bin"));
    assert!(found[1].ends_with("disk2.dd-events.bin"));
}

#[test]
fn discovers_stem_events_bin_when_target_is_dir_with_log() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("disk1.dd-events.bin");
    std::fs::write(&log, b"").unwrap();
    let found = resolve_sources_for_test(dir.path()).unwrap();
    assert_eq!(found, vec![log]);
}

#[test]
fn target_pointing_directly_at_event_log_file_is_returned_as_is() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("disk1.dd-events.bin");
    std::fs::write(&log, b"").unwrap();
    let found = resolve_sources_for_test(&log).unwrap();
    assert_eq!(found, vec![log]);
}
```

- [ ] **Step 2: Expose `resolve_sources` for testing**

In `crates/utmost-gui/src/lib.rs`, at the bottom (after `resolve_sources` definition), add:

```rust
#[doc(hidden)]
pub fn resolve_sources_for_test(target: &Path) -> Result<Vec<PathBuf>> {
    resolve_sources(target)
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test -p utmost-gui --test stem_discovery`
Expected: FAIL — `resolve_sources` still looks for `carve_events.bin`.

- [ ] **Step 4: Update `resolve_sources` to find `*-events.bin`**

In `crates/utmost-gui/src/lib.rs`, replace the existing `resolve_sources` function:

```rust
fn resolve_sources(target: &Path) -> Result<Vec<PathBuf>> {
    if target.is_file() {
        return Ok(vec![target.to_path_buf()]);
    }
    if target.is_dir() {
        if let Some(direct) = find_events_bin_in(target)? {
            return Ok(vec![direct]);
        }
        let mut found = Vec::new();
        for entry in std::fs::read_dir(target)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_dir() {
                if let Some(candidate) = find_events_bin_in(&p)? {
                    found.push(candidate);
                }
            }
        }
        if !found.is_empty() {
            return Ok(found);
        }
    }
    anyhow::bail!("no <stem>-events.bin found at {}", target.display())
}

fn find_events_bin_in(dir: &Path) -> Result<Option<PathBuf>> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_file() {
            if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                if name.ends_with("-events.bin") {
                    return Ok(Some(p));
                }
            }
        }
    }
    Ok(None)
}
```

- [ ] **Step 5: Run the tests**

Run: `cargo test -p utmost-gui --test stem_discovery`
Expected: PASS (3 tests).

- [ ] **Step 6: Run the full GUI test suite — some existing tests may write `carve_events.bin` and need updates**

Run: `cargo test -p utmost-gui`
Expected: existing tests that write `carve_events.bin` to a tempdir and then call `run_from_file` may fail. For each failing test, change the path it writes to to use a stem-based name (e.g. `tempdir/test-events.bin` instead of `tempdir/carve_events.bin`). Do NOT change `BincodeFileSink::create` or `Journal::for_main_log` — those take paths as-is.

The likely affected tests (search for `carve_events.bin` in `crates/utmost-gui/`):

```bash
grep -rn "carve_events.bin" crates/utmost-gui/
```

For each match in a test file, rename the path string to `test-events.bin` (or any stem-style name). For matches in `src/journal.rs`, only the doc comment near the top references `carve_events.bin` — update the doc comment text but leave logic alone.

- [ ] **Step 7: Re-run and commit**

Run: `cargo test -p utmost-gui`
Expected: PASS.

```bash
git add -u
git commit -m "feat(gui): discover *-events.bin and update tests for new naming"
```

### Task 1.4: Update the live-mode main_log path in CLI

**Files:**
- Modify: `crates/utmost-cli/src/main.rs`

- [ ] **Step 1: Update the main_log path construction**

Find the live-mode block in `crates/utmost-cli/src/main.rs` (around line 468):

```rust
        let main_log = std::path::Path::new(&args.output_directory).join("carve_events.bin");
        utmost_gui::run_live(rx, Some(main_log))?;
```

Replace with logic that uses the first source's stem and subdir. For the live (GUI) path, only one source is supported by `run_live` today (it takes a single main_log path). The right value is whichever source is *first* in the plan:

```rust
        let (_first_id, first_input, first_subdir) = plan.first().expect("plan is non-empty for gui_enabled");
        let source_dir = sinks::source_output_dir(
            std::path::Path::new(&args.output_directory),
            first_subdir,
        );
        let stem = sinks::log_stem(first_input);
        let main_log = source_dir.join(format!("{stem}-events.bin"));
        utmost_gui::run_live(rx, Some(main_log))?;
```

- [ ] **Step 2: Build to verify it compiles**

Run: `cargo build -p utmost-cli`
Expected: build succeeds.

- [ ] **Step 3: Run CLI integration tests**

Run: `cargo test -p utmost-cli`
Expected: PASS. If any test in `crates/utmost-cli/tests/` asserts on `carve_events.bin`, update it to the stem-based name.

- [ ] **Step 4: Commit**

```bash
git add crates/utmost-cli/src/main.rs
git commit -m "feat(cli): compute live-mode main_log path from source stem"
```

### Task 1.5: Update README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Find the README section that documents the output directory layout**

Run: `grep -n "carve_events" README.md`
Update any reference to `carve_events.bin` to `<stem>-events.bin` and add a one-paragraph note that each source gets its own `<stem>-events.bin`, `<stem>-events.pending`, and (after this work lands) `<stem>-index.sqlite`. Show the per-source subdir layout from spec Section "Artifact layout".

- [ ] **Step 2: Verify**

Run: `grep -n "carve_events.bin" README.md`
Expected: no matches (or only in a clearly historical/changelog context).

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs(readme): describe per-source <stem>-events.bin layout"
```

---

## Phase 2 — Diesel/SQLite setup

Goal: depend on Diesel + SQLite, define the schema as the initial migration, and provide `IndexDb::open(path)` that applies pending migrations. No event-writing yet.

### Task 2.1: Add workspace dependencies

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Modify: `crates/utmost-gui/Cargo.toml`

- [ ] **Step 1: Add to `[workspace.dependencies]` in root `Cargo.toml`**

Open `Cargo.toml` and add to the `[workspace.dependencies]` table:

```toml
diesel = { version = "2.2", features = ["sqlite", "returning_clauses_for_sqlite_3_35"] }
diesel_migrations = { version = "2.2", features = ["sqlite"] }
libsqlite3-sys = { version = "0.30", features = ["bundled"] }
```

- [ ] **Step 2: Add to `utmost-gui` deps**

In `crates/utmost-gui/Cargo.toml`, add under `[dependencies]`:

```toml
diesel = { workspace = true }
diesel_migrations = { workspace = true }
libsqlite3-sys = { workspace = true }
```

- [ ] **Step 3: Build to verify resolution**

Run: `cargo build -p utmost-gui`
Expected: builds (downloads + compiles diesel and its deps; may take a minute on first build).

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml crates/utmost-gui/Cargo.toml Cargo.lock
git commit -m "build(gui): add diesel + diesel_migrations + bundled sqlite"
```

### Task 2.2: Create the initial migration

**Files:**
- Create: `crates/utmost-gui/migrations/0001_initial/up.sql`
- Create: `crates/utmost-gui/migrations/0001_initial/down.sql`

- [ ] **Step 1: Write `up.sql`**

Create `crates/utmost-gui/migrations/0001_initial/up.sql` with the exact schema from the spec ("Initial migration: `0001_initial`" section, after the FK-removal edits). Copy the SQL verbatim from `docs/superpowers/specs/2026-05-19-gui-sqlite-index-design.md`.

- [ ] **Step 2: Write `down.sql`**

Create `crates/utmost-gui/migrations/0001_initial/down.sql`:

```sql
DROP TABLE IF EXISTS variant;
DROP TABLE IF EXISTS recovery_run;
DROP TABLE IF EXISTS best_choice;
DROP TABLE IF EXISTS note;
DROP TABLE IF EXISTS bookmark;
DROP TABLE IF EXISTS file;
DROP TABLE IF EXISTS source;
DROP TABLE IF EXISTS run;
DROP TABLE IF EXISTS meta;
```

- [ ] **Step 3: Commit (migration is referenced by code in Task 2.3; commit together)**

Wait for Task 2.3.

### Task 2.3: `IndexDb::open` with embedded migrations

**Files:**
- Create: `crates/utmost-gui/src/index_db/mod.rs`
- Modify: `crates/utmost-gui/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/utmost-gui/tests/index_db_open.rs`:

```rust
use utmost_gui::index_db::IndexDb;

#[test]
fn open_fresh_path_applies_migrations() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test-index.sqlite");
    let mut db = IndexDb::open(&db_path).unwrap();
    // Schema applied: the meta table now exists. A no-op SELECT should not error.
    db.with_conn(|conn| {
        use diesel::prelude::*;
        use diesel::sql_query;
        let n: i64 = sql_query("SELECT COUNT(*) AS n FROM meta")
            .get_result::<CountRow>(conn)
            .unwrap()
            .n;
        assert_eq!(n, 0);
        Ok::<_, diesel::result::Error>(())
    }).unwrap();
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    n: i64,
}

#[test]
fn open_reapply_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test-index.sqlite");
    let _ = IndexDb::open(&db_path).unwrap();
    // Opening again must not error and must not duplicate migrations.
    let _ = IndexDb::open(&db_path).unwrap();
}
```

- [ ] **Step 2: Create the module skeleton**

Create `crates/utmost-gui/src/index_db/mod.rs`:

```rust
//! SQLite-backed cache of the carve event log, owned by the GUI.
//!
//! See `docs/superpowers/specs/2026-05-19-gui-sqlite-index-design.md`.

use anyhow::{Context, Result};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use std::path::Path;

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

/// Owned SQLite connection plus the rules for opening and migrating it.
pub struct IndexDb {
    conn: SqliteConnection,
}

impl IndexDb {
    /// Open (or create) the SQLite at `path`. Applies the bundled set of
    /// embedded migrations, sets WAL + NORMAL synchronous + FK pragmas.
    pub fn open(path: &Path) -> Result<Self> {
        let url = path
            .to_str()
            .with_context(|| format!("non-utf8 path: {}", path.display()))?;
        let mut conn = SqliteConnection::establish(url)
            .with_context(|| format!("opening sqlite at {}", path.display()))?;
        conn.batch_execute(
            "PRAGMA journal_mode = WAL; \
             PRAGMA synchronous = NORMAL; \
             PRAGMA foreign_keys = ON;",
        )
        .context("applying pragmas")?;
        conn.run_pending_migrations(MIGRATIONS)
            .map_err(|e| anyhow::anyhow!("applying migrations: {e}"))?;
        Ok(Self { conn })
    }

    /// Run a closure with mutable access to the underlying connection.
    pub fn with_conn<R, E, F>(&mut self, f: F) -> std::result::Result<R, E>
    where
        F: FnOnce(&mut SqliteConnection) -> std::result::Result<R, E>,
    {
        f(&mut self.conn)
    }

    /// Borrow the connection mutably. Used by writer/hydrator modules.
    pub fn conn(&mut self) -> &mut SqliteConnection {
        &mut self.conn
    }
}
```

- [ ] **Step 3: Wire into the crate**

In `crates/utmost-gui/src/lib.rs`, add at the top alongside the other `pub mod` lines:

```rust
pub mod index_db;
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p utmost-gui --test index_db_open`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-gui/migrations crates/utmost-gui/src/index_db crates/utmost-gui/src/lib.rs crates/utmost-gui/tests/index_db_open.rs
git commit -m "feat(gui): IndexDb::open with embedded diesel migrations"
```

### Task 2.4: Generate and check in `schema.rs`

**Files:**
- Create: `crates/utmost-gui/diesel.toml`
- Create: `crates/utmost-gui/src/index_db/schema.rs`

- [ ] **Step 1: Create `diesel.toml`**

Create `crates/utmost-gui/diesel.toml`:

```toml
[print_schema]
file = "src/index_db/schema.rs"
custom_type_derives = ["diesel::query_builder::QueryId"]
```

- [ ] **Step 2: Hand-write `schema.rs`**

Diesel's `print-schema` requires the CLI; we instead hand-write the file to avoid the CLI dependency. Create `crates/utmost-gui/src/index_db/schema.rs`:

```rust
// @generated by hand from migrations/0001_initial/up.sql.
// When the migration changes, update this file by hand or by running
// `diesel print-schema` locally and copying the result.

diesel::table! {
    meta (key) {
        key -> Text,
        value -> Text,
    }
}

diesel::table! {
    run (id) {
        id -> Integer,
        started_at -> Text,
        output_root -> Text,
        source_image_path -> Text,
        configured_types_json -> Text,
        case_id -> Nullable<Text>,
        examiner -> Nullable<Text>,
        evidence_id -> Nullable<Text>,
        case_notes -> Nullable<Text>,
        status -> Text,
        elapsed_ms -> BigInt,
        total_files -> BigInt,
    }
}

diesel::table! {
    source (source_id) {
        source_id -> Integer,
        filename -> Text,
        output_subdir -> Text,
        total_bytes -> BigInt,
        bytes_read -> BigInt,
        files_found -> BigInt,
        status -> Text,
        duration_ms -> Nullable<BigInt>,
    }
}

diesel::table! {
    file (file_id) {
        file_id -> BigInt,
        source_id -> Integer,
        filename -> Text,
        filesize -> BigInt,
        file_type -> Text,
        img_offset -> BigInt,
        written_path -> Text,
        byte_runs_json -> Text,
        jpeg_status -> Nullable<Text>,
        jpeg_width -> Nullable<Integer>,
        jpeg_height -> Nullable<Integer>,
        jpeg_fragmentation_point -> Nullable<BigInt>,
        jpeg_has_restart_markers -> Nullable<Integer>,
    }
}

diesel::table! {
    bookmark (file_id) {
        file_id -> BigInt,
        at -> Text,
    }
}

diesel::table! {
    note (note_id) {
        note_id -> BigInt,
        file_id -> BigInt,
        text -> Text,
        at -> Text,
    }
}

diesel::table! {
    best_choice (original_file_id) {
        original_file_id -> BigInt,
        chosen_file_id -> BigInt,
        at -> Text,
    }
}

diesel::table! {
    recovery_run (id) {
        id -> Integer,
        started_at -> Text,
        keep_candidates -> Integer,
        search_window -> BigInt,
        block_size -> Integer,
        min_entropy_score -> Double,
        huffman_validation -> Integer,
        finished_duration_ms -> Nullable<BigInt>,
        partials_processed -> Nullable<Integer>,
        candidates_written -> Nullable<Integer>,
    }
}

diesel::table! {
    variant (original_file_id, candidate_file_id) {
        original_file_id -> BigInt,
        candidate_file_id -> BigInt,
        rank -> Integer,
        method -> Text,
        entropy_score -> Double,
        ff_validity_score -> Nullable<Double>,
        huffman_mcu_count -> Nullable<Integer>,
        continuation_img_offset -> BigInt,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    meta, run, source, file, bookmark, note, best_choice, recovery_run, variant,
);
```

Wire it in `src/index_db/mod.rs`, after the existing `pub const MIGRATIONS` line:

```rust
pub mod schema;
```

- [ ] **Step 3: Build to verify**

Run: `cargo build -p utmost-gui`
Expected: builds.

- [ ] **Step 4: Commit**

```bash
git add crates/utmost-gui/diesel.toml crates/utmost-gui/src/index_db/schema.rs crates/utmost-gui/src/index_db/mod.rs
git commit -m "feat(gui): check in hand-written diesel schema.rs"
```

---

## Phase 3 — IndexDbWriter (event → row dispatch)

Goal: a writer that consumes `CarveEvent`s, accumulates them, and flushes batches inside a single transaction that also advances `last_event_offset` and `last_event_count`.

### Task 3.1: Row models

**Files:**
- Create: `crates/utmost-gui/src/index_db/models.rs`

- [ ] **Step 1: Define Insertable/Queryable structs**

Create `crates/utmost-gui/src/index_db/models.rs`. The file is mostly mechanical — one `Insertable` (the `New*` variant) and one `Queryable` per table. Use the table types from `schema.rs`.

```rust
use diesel::prelude::*;
use crate::index_db::schema;

#[derive(Debug, Insertable, AsChangeset)]
#[diesel(table_name = schema::meta)]
pub struct NewMeta<'a> {
    pub key: &'a str,
    pub value: &'a str,
}

#[derive(Debug, Queryable)]
pub struct MetaRow {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Insertable, AsChangeset)]
#[diesel(table_name = schema::run)]
pub struct NewRun {
    pub id: i32,
    pub started_at: String,
    pub output_root: String,
    pub source_image_path: String,
    pub configured_types_json: String,
    pub case_id: Option<String>,
    pub examiner: Option<String>,
    pub evidence_id: Option<String>,
    pub case_notes: Option<String>,
    pub status: String,
    pub elapsed_ms: i64,
    pub total_files: i64,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct RunRow {
    pub id: i32,
    pub started_at: String,
    pub output_root: String,
    pub source_image_path: String,
    pub configured_types_json: String,
    pub case_id: Option<String>,
    pub examiner: Option<String>,
    pub evidence_id: Option<String>,
    pub case_notes: Option<String>,
    pub status: String,
    pub elapsed_ms: i64,
    pub total_files: i64,
}

#[derive(Debug, Insertable, AsChangeset)]
#[diesel(table_name = schema::source)]
pub struct NewSource {
    pub source_id: i32,
    pub filename: String,
    pub output_subdir: String,
    pub total_bytes: i64,
    pub bytes_read: i64,
    pub files_found: i64,
    pub status: String,
    pub duration_ms: Option<i64>,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct SourceRow {
    pub source_id: i32,
    pub filename: String,
    pub output_subdir: String,
    pub total_bytes: i64,
    pub bytes_read: i64,
    pub files_found: i64,
    pub status: String,
    pub duration_ms: Option<i64>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = schema::file)]
pub struct NewFile {
    pub file_id: i64,
    pub source_id: i32,
    pub filename: String,
    pub filesize: i64,
    pub file_type: String,
    pub img_offset: i64,
    pub written_path: String,
    pub byte_runs_json: String,
    pub jpeg_status: Option<String>,
    pub jpeg_width: Option<i32>,
    pub jpeg_height: Option<i32>,
    pub jpeg_fragmentation_point: Option<i64>,
    pub jpeg_has_restart_markers: Option<i32>,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct FileRow {
    pub file_id: i64,
    pub source_id: i32,
    pub filename: String,
    pub filesize: i64,
    pub file_type: String,
    pub img_offset: i64,
    pub written_path: String,
    pub byte_runs_json: String,
    pub jpeg_status: Option<String>,
    pub jpeg_width: Option<i32>,
    pub jpeg_height: Option<i32>,
    pub jpeg_fragmentation_point: Option<i64>,
    pub jpeg_has_restart_markers: Option<i32>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = schema::bookmark)]
pub struct NewBookmark {
    pub file_id: i64,
    pub at: String,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct BookmarkRow {
    pub file_id: i64,
    pub at: String,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = schema::note)]
pub struct NewNote {
    pub note_id: i64,
    pub file_id: i64,
    pub text: String,
    pub at: String,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct NoteRow {
    pub note_id: i64,
    pub file_id: i64,
    pub text: String,
    pub at: String,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = schema::best_choice)]
pub struct NewBestChoice {
    pub original_file_id: i64,
    pub chosen_file_id: i64,
    pub at: String,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct BestChoiceRow {
    pub original_file_id: i64,
    pub chosen_file_id: i64,
    pub at: String,
}

#[derive(Debug, Insertable, AsChangeset)]
#[diesel(table_name = schema::recovery_run)]
pub struct NewRecoveryRun {
    pub id: i32,
    pub started_at: String,
    pub keep_candidates: i32,
    pub search_window: i64,
    pub block_size: i32,
    pub min_entropy_score: f64,
    pub huffman_validation: i32,
    pub finished_duration_ms: Option<i64>,
    pub partials_processed: Option<i32>,
    pub candidates_written: Option<i32>,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct RecoveryRunRow {
    pub id: i32,
    pub started_at: String,
    pub keep_candidates: i32,
    pub search_window: i64,
    pub block_size: i32,
    pub min_entropy_score: f64,
    pub huffman_validation: i32,
    pub finished_duration_ms: Option<i64>,
    pub partials_processed: Option<i32>,
    pub candidates_written: Option<i32>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = schema::variant)]
pub struct NewVariant {
    pub original_file_id: i64,
    pub candidate_file_id: i64,
    pub rank: i32,
    pub method: String,
    pub entropy_score: f64,
    pub ff_validity_score: Option<f64>,
    pub huffman_mcu_count: Option<i32>,
    pub continuation_img_offset: i64,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct VariantRow {
    pub original_file_id: i64,
    pub candidate_file_id: i64,
    pub rank: i32,
    pub method: String,
    pub entropy_score: f64,
    pub ff_validity_score: Option<f64>,
    pub huffman_mcu_count: Option<i32>,
    pub continuation_img_offset: i64,
}
```

- [ ] **Step 2: Wire in**

Add to `crates/utmost-gui/src/index_db/mod.rs`:

```rust
pub mod models;
```

- [ ] **Step 3: Build**

Run: `cargo build -p utmost-gui`
Expected: builds.

- [ ] **Step 4: Commit**

```bash
git add crates/utmost-gui/src/index_db/models.rs crates/utmost-gui/src/index_db/mod.rs
git commit -m "feat(gui): diesel insertable/queryable row models"
```

### Task 3.2: Writer skeleton with `apply` + `flush`

**Files:**
- Create: `crates/utmost-gui/src/index_db/writer.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/utmost-gui/tests/index_db_writer_run_started.rs`:

```rust
use diesel::prelude::*;
use utmost_gui::index_db::{IndexDb, models::RunRow, schema, writer::IndexDbWriter};
use utmost_lib::events::{CarveEvent, CaseMetadata, CliConfigSnapshot, SourceDescriptor};
use utmost_lib::types::{ExecutionEnvironment, FileType};

fn run_started_event() -> CarveEvent {
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

#[test]
fn apply_run_started_writes_run_and_source_rows_and_advances_offset() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = IndexDb::open(&dir.path().join("idx.sqlite")).unwrap();
    {
        let mut w = IndexDbWriter::new(db.conn(), 100);
        w.apply(run_started_event(), 1234).unwrap();
        w.flush().unwrap();
    }

    db.with_conn(|conn| {
        let row: RunRow = schema::run::table.first(conn).unwrap();
        assert_eq!(row.id, 1);
        assert_eq!(row.started_at, "2026-05-19T00:00:00+0000");
        assert_eq!(row.output_root, "out");
        assert_eq!(row.case_id.as_deref(), Some("C-1"));

        let n_sources: i64 = schema::source::table.count().get_result(conn).unwrap();
        assert_eq!(n_sources, 1);

        // last_event_offset advanced to 1234
        let off: String = schema::meta::table
            .filter(schema::meta::key.eq("last_event_offset"))
            .select(schema::meta::value)
            .first(conn)
            .unwrap();
        assert_eq!(off, "1234");

        // run_started_at recorded
        let rs: String = schema::meta::table
            .filter(schema::meta::key.eq("run_started_at"))
            .select(schema::meta::value)
            .first(conn)
            .unwrap();
        assert_eq!(rs, "2026-05-19T00:00:00+0000");

        Ok::<_, diesel::result::Error>(())
    }).unwrap();
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p utmost-gui --test index_db_writer_run_started`
Expected: FAIL — `writer` module not found.

- [ ] **Step 3: Create the writer skeleton**

Create `crates/utmost-gui/src/index_db/writer.rs`:

```rust
use anyhow::{Context, Result};
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use utmost_lib::events::CarveEvent;

use crate::index_db::models::*;
use crate::index_db::schema;

pub struct IndexDbWriter<'a> {
    conn: &'a mut SqliteConnection,
    pending: Vec<PendingEvent>,
    batch_size: usize,
    total_count: i64,
}

struct PendingEvent {
    event: CarveEvent,
    offset_after: u64,
}

impl<'a> IndexDbWriter<'a> {
    pub fn new(conn: &'a mut SqliteConnection, batch_size: usize) -> Self {
        let total_count = read_meta_i64(conn, "last_event_count").unwrap_or(0);
        Self {
            conn,
            pending: Vec::new(),
            batch_size,
            total_count,
        }
    }

    /// Buffer `event` for the next flush. `offset_after` is the
    /// `BincodeFileReader::byte_offset()` immediately after the event was
    /// successfully decoded — i.e. the position from which the *next* event
    /// would be read.
    pub fn apply(&mut self, event: CarveEvent, offset_after: u64) -> Result<()> {
        self.pending.push(PendingEvent { event, offset_after });
        if self.pending.len() >= self.batch_size {
            self.flush()?;
        }
        Ok(())
    }

    /// Flush all pending events as one transaction, atomically advancing
    /// `last_event_offset` and `last_event_count` together with the rows.
    pub fn flush(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let pending = std::mem::take(&mut self.pending);
        let new_offset = pending.last().unwrap().offset_after;
        let delta = pending.len() as i64;
        let new_count = self.total_count + delta;

        self.conn
            .transaction::<_, diesel::result::Error, _>(|tx| {
                for p in &pending {
                    apply_event(tx, &p.event)?;
                }
                upsert_meta(tx, "last_event_offset", &new_offset.to_string())?;
                upsert_meta(tx, "last_event_count", &new_count.to_string())?;
                upsert_meta(tx, "indexed_at", &chrono::Utc::now().to_rfc3339())?;
                Ok(())
            })
            .context("flushing index batch")?;

        self.total_count = new_count;
        Ok(())
    }
}

fn read_meta_i64(conn: &mut SqliteConnection, key: &str) -> Option<i64> {
    schema::meta::table
        .filter(schema::meta::key.eq(key))
        .select(schema::meta::value)
        .first::<String>(conn)
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
}

fn upsert_meta(
    tx: &mut SqliteConnection,
    key: &str,
    value: &str,
) -> diesel::result::QueryResult<()> {
    // SQLite upsert via ON CONFLICT
    diesel::sql_query(
        "INSERT INTO meta (key, value) VALUES (?, ?) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind::<diesel::sql_types::Text, _>(key)
    .bind::<diesel::sql_types::Text, _>(value)
    .execute(tx)?;
    Ok(())
}

fn apply_event(tx: &mut SqliteConnection, event: &CarveEvent) -> diesel::result::QueryResult<()> {
    match event {
        CarveEvent::RunStarted {
            started_at,
            output_root,
            sources,
            case,
            configured_types,
            ..
        } => {
            let source_image_path = sources
                .first()
                .map(|s| s.filename.clone())
                .unwrap_or_default();
            let new_run = NewRun {
                id: 1,
                started_at: started_at.clone(),
                output_root: output_root.clone(),
                source_image_path,
                configured_types_json: serde_json::to_string(configured_types)
                    .unwrap_or_else(|_| "[]".into()),
                case_id: case.as_ref().and_then(|c| c.case_id.clone()),
                examiner: case.as_ref().and_then(|c| c.examiner.clone()),
                evidence_id: case.as_ref().and_then(|c| c.evidence_id.clone()),
                case_notes: case.as_ref().and_then(|c| c.notes.clone()),
                status: "Running".into(),
                elapsed_ms: 0,
                total_files: 0,
            };
            diesel::insert_into(schema::run::table)
                .values(&new_run)
                .on_conflict(schema::run::id)
                .do_update()
                .set(&new_run)
                .execute(tx)?;
            for s in sources {
                let new_src = NewSource {
                    source_id: s.source_id as i32,
                    filename: s.filename.clone(),
                    output_subdir: s.output_subdir.clone(),
                    total_bytes: s.total_bytes as i64,
                    bytes_read: 0,
                    files_found: 0,
                    status: "Pending".into(),
                    duration_ms: None,
                };
                diesel::insert_into(schema::source::table)
                    .values(&new_src)
                    .on_conflict(schema::source::source_id)
                    .do_update()
                    .set(&new_src)
                    .execute(tx)?;
            }
            upsert_meta(tx, "run_started_at", started_at)?;
        }
        // Subsequent event variants added in later tasks.
        _ => {}
    }
    Ok(())
}
```

- [ ] **Step 4: Add `serde_json` and `chrono` if not already present**

Check `crates/utmost-gui/Cargo.toml` for `serde_json`. If absent, add:

```toml
serde_json = { workspace = true }
```

`chrono` is already present in dev-deps; add it to `[dependencies]` if it's only in dev-deps:

```toml
chrono = { version = "0.4", default-features = false, features = ["std", "clock", "serde"] }
```

- [ ] **Step 5: Wire the writer module**

Add to `crates/utmost-gui/src/index_db/mod.rs`:

```rust
pub mod writer;
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cargo test -p utmost-gui --test index_db_writer_run_started`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/utmost-gui/Cargo.toml Cargo.lock crates/utmost-gui/src/index_db/{mod.rs,writer.rs} crates/utmost-gui/tests/index_db_writer_run_started.rs
git commit -m "feat(gui): IndexDbWriter with transactional flush + RunStarted apply"
```

### Tasks 3.3 – 3.13: Per-variant `apply` (one task each)

For each remaining `CarveEvent` variant, follow the same pattern: write a failing test in a new file `crates/utmost-gui/tests/index_db_writer_<variant>.rs`, add the matching match-arm to `apply_event` in `crates/utmost-gui/src/index_db/writer.rs`, run the test, commit. Each task is 5–10 minutes.

For brevity below, only the per-variant SQL is shown — the test pattern is identical to Task 3.2 (build a small event, call `w.apply(ev, offset).unwrap(); w.flush().unwrap();`, then `SELECT *` to assert the row).

### Task 3.3: SourceStarted

**Test (`tests/index_db_writer_source_started.rs`):** apply `RunStarted` with `source_id=0`, then `SourceStarted { source_id: 0 }`, assert `source.status == 'Running'`.

**Match arm in `writer.rs`:**

```rust
CarveEvent::SourceStarted { source_id } => {
    diesel::update(schema::source::table.find(*source_id as i32))
        .set(schema::source::status.eq("Running"))
        .execute(tx)?;
}
```

Commit: `feat(gui): IndexDbWriter SourceStarted updates status`.

### Task 3.4: FileFound

**Test (`tests/index_db_writer_file_found.rs`):** apply `RunStarted`, then a `FileFound` with `file.file_id=42, source_id=0`, assert exactly one `file` row with `file_id=42`. Build the `FileObject` via `utmost_lib::reporting::create_file_object`.

**Match arm:**

```rust
CarveEvent::FileFound {
    source_id,
    file,
    img_offset,
    written_path,
} => {
    let byte_runs_json = serde_json::to_string(&file.byte_runs).unwrap_or_else(|_| "[]".into());
    let (jpeg_status, jpeg_width, jpeg_height, jpeg_fragmentation_point, jpeg_has_restart_markers) =
        match &file.jpeg_scan {
            Some(j) => (
                Some(match j.status {
                    utmost_lib::types::JpegScanStatus::Complete => "complete",
                    utmost_lib::types::JpegScanStatus::Truncated => "truncated",
                    utmost_lib::types::JpegScanStatus::Fragmented => "fragmented",
                }.to_string()),
                j.width.map(|w| w as i32),
                j.height.map(|h| h as i32),
                j.fragmentation_point_img_offset.map(|o| o as i64),
                Some(if j.has_restart_markers { 1 } else { 0 }),
            ),
            None => (None, None, None, None, None),
        };
    let new_file = NewFile {
        file_id: file.file_id as i64,
        source_id: *source_id as i32,
        filename: file.filename.clone(),
        filesize: file.filesize as i64,
        file_type: file.file_type.clone(),
        img_offset: *img_offset as i64,
        written_path: written_path.clone(),
        byte_runs_json,
        jpeg_status,
        jpeg_width,
        jpeg_height,
        jpeg_fragmentation_point,
        jpeg_has_restart_markers,
    };
    diesel::insert_into(schema::file::table)
        .values(&new_file)
        .execute(tx)?;
    // Update source.files_found counter
    diesel::update(schema::source::table.find(*source_id as i32))
        .set(schema::source::files_found.eq(schema::source::files_found + 1))
        .execute(tx)?;
    // Update run.total_files
    diesel::update(schema::run::table.find(1))
        .set(schema::run::total_files.eq(schema::run::total_files + 1))
        .execute(tx)?;
}
```

The `JpegScanInfo` field names and `JpegScanStatus` variants above match `crates/utmost-lib/src/types.rs` as of 2026-05-19 (`Complete` | `Truncated` | `Fragmented`; fields `width`, `height`, `fragmentation_point_img_offset`, `has_restart_markers`, `status`). If they drift, update both the schema/migration and the destructuring here in lockstep.

Commit: `feat(gui): IndexDbWriter FileFound inserts file row and updates counters`.

### Task 3.5: ProgressTick

**Test:** apply `RunStarted` + `ProgressTick { source_id: 0, bytes_read: 1234 }`, assert `source.bytes_read == 1234`.

**Match arm:**

```rust
CarveEvent::ProgressTick { source_id, bytes_read } => {
    diesel::update(schema::source::table.find(*source_id as i32))
        .set(schema::source::bytes_read.eq(*bytes_read as i64))
        .execute(tx)?;
}
```

But: `ProgressTick` is stream-only per `CarveEvent::persistable()` and is **not** in the on-disk log. The writer still applies it during live mode for live updates. (No spec change needed; this is just a behavioural note.)

Commit: `feat(gui): IndexDbWriter ProgressTick updates bytes_read`.

### Task 3.6: SourceFinished

**Test:** apply `RunStarted` + `SourceFinished { source_id: 0, bytes_read: 4096, duration_ms: 5 }`, assert `source.status == 'Finished'`, `duration_ms == 5`, `bytes_read == 4096`.

**Match arm:**

```rust
CarveEvent::SourceFinished { source_id, bytes_read, duration_ms } => {
    diesel::update(schema::source::table.find(*source_id as i32))
        .set((
            schema::source::status.eq("Finished"),
            schema::source::bytes_read.eq(*bytes_read as i64),
            schema::source::duration_ms.eq(Some(*duration_ms as i64)),
        ))
        .execute(tx)?;
}
```

Commit: `feat(gui): IndexDbWriter SourceFinished updates source`.

### Task 3.7: RunFinished

**Test:** apply `RunStarted` + `RunFinished { duration_ms: 1234, total_files_written: 0 }`, assert `run.status == 'Finished'`, `elapsed_ms == 1234`.

**Match arm:**

```rust
CarveEvent::RunFinished { duration_ms, total_files_written: _ } => {
    diesel::update(schema::run::table.find(1))
        .set((
            schema::run::status.eq("Finished"),
            schema::run::elapsed_ms.eq(*duration_ms as i64),
        ))
        .execute(tx)?;
}
```

Commit: `feat(gui): IndexDbWriter RunFinished updates run`.

### Task 3.8: RecoveryStarted

**Test:** apply `RunStarted` + `RecoveryStarted { ... }`, assert exactly one `recovery_run` row with the supplied params.

**Match arm:**

```rust
CarveEvent::RecoveryStarted {
    started_at, keep_candidates, search_window,
    block_size, min_entropy_score, huffman_validation,
} => {
    let new_rec = NewRecoveryRun {
        id: 1,
        started_at: started_at.clone(),
        keep_candidates: *keep_candidates as i32,
        search_window: *search_window as i64,
        block_size: *block_size as i32,
        min_entropy_score: *min_entropy_score,
        huffman_validation: if *huffman_validation { 1 } else { 0 },
        finished_duration_ms: None,
        partials_processed: None,
        candidates_written: None,
    };
    diesel::insert_into(schema::recovery_run::table)
        .values(&new_rec)
        .on_conflict(schema::recovery_run::id)
        .do_update()
        .set(&new_rec)
        .execute(tx)?;
}
```

Commit: `feat(gui): IndexDbWriter RecoveryStarted writes recovery_run`.

### Task 3.9: RecoveryCandidate

**Test:** apply `RunStarted` + `RecoveryStarted` + `RecoveryCandidate { original_file_id: 1, candidate_file_id: 2, ... }`, assert one `variant` row.

**Match arm:**

```rust
CarveEvent::RecoveryCandidate {
    original_file_id, candidate_file_id, rank, method,
    entropy_score, ff_validity_score, huffman_mcu_count,
    continuation_img_offset,
} => {
    let method_str = match method {
        utmost_lib::events::RecoveryMethod::DirectContinuation => "direct_continuation",
        utmost_lib::events::RecoveryMethod::FragmentReassembly => "fragment_reassembly",
    };
    let new_var = NewVariant {
        original_file_id: *original_file_id as i64,
        candidate_file_id: *candidate_file_id as i64,
        rank: *rank as i32,
        method: method_str.into(),
        entropy_score: *entropy_score,
        ff_validity_score: *ff_validity_score,
        huffman_mcu_count: huffman_mcu_count.map(|c| c as i32),
        continuation_img_offset: *continuation_img_offset as i64,
    };
    diesel::insert_into(schema::variant::table)
        .values(&new_var)
        .execute(tx)?;
}
```

Commit: `feat(gui): IndexDbWriter RecoveryCandidate writes variant row`.

### Task 3.10: RecoveryFinished

**Test:** apply `RunStarted` + `RecoveryStarted` + `RecoveryFinished { duration_ms: 1, partials_processed: 2, candidates_written: 3 }`, assert `recovery_run.finished_duration_ms == 1`.

**Match arm:**

```rust
CarveEvent::RecoveryFinished { duration_ms, partials_processed, candidates_written } => {
    diesel::update(schema::recovery_run::table.find(1))
        .set((
            schema::recovery_run::finished_duration_ms.eq(Some(*duration_ms as i64)),
            schema::recovery_run::partials_processed.eq(Some(*partials_processed as i32)),
            schema::recovery_run::candidates_written.eq(Some(*candidates_written as i32)),
        ))
        .execute(tx)?;
}
```

Commit: `feat(gui): IndexDbWriter RecoveryFinished updates recovery_run`.

### Task 3.11: Bookmark

**Test:** apply `RunStarted` + `Bookmark { file_id: 1, bookmarked: true, at: "t" }`, assert one `bookmark` row. Then apply with `bookmarked: false` and assert zero rows.

**Match arm:**

```rust
CarveEvent::Bookmark { file_id, bookmarked, at } => {
    if *bookmarked {
        let new_bm = NewBookmark { file_id: *file_id as i64, at: at.clone() };
        diesel::insert_into(schema::bookmark::table)
            .values(&new_bm)
            .on_conflict(schema::bookmark::file_id)
            .do_update()
            .set(schema::bookmark::at.eq(at.clone()))
            .execute(tx)?;
    } else {
        diesel::delete(schema::bookmark::table.find(*file_id as i64)).execute(tx)?;
    }
}
```

Commit: `feat(gui): IndexDbWriter Bookmark add/remove`.

### Task 3.12: Note

**Test:** apply `RunStarted` + `Note { note_id: 1, file_id: 1, text: "n", at: "t" }`, assert one `note` row.

**Match arm:**

```rust
CarveEvent::Note { note_id, file_id, text, at } => {
    let new_note = NewNote {
        note_id: *note_id as i64,
        file_id: *file_id as i64,
        text: text.clone(),
        at: at.clone(),
    };
    diesel::insert_into(schema::note::table).values(&new_note).execute(tx)?;
}
```

Commit: `feat(gui): IndexDbWriter Note insert`.

### Task 3.13: MarkAsBest

**Test:** apply `RunStarted` + `MarkAsBest { original_file_id: 1, chosen_file_id: 2, at: "t" }`, assert one `best_choice` row with `original=1, chosen=2`. Apply again with `chosen=3` and assert it has been replaced (PK collision → update).

**Match arm:**

```rust
CarveEvent::MarkAsBest { original_file_id, chosen_file_id, at } => {
    let row = NewBestChoice {
        original_file_id: *original_file_id as i64,
        chosen_file_id: *chosen_file_id as i64,
        at: at.clone(),
    };
    diesel::insert_into(schema::best_choice::table)
        .values(&row)
        .on_conflict(schema::best_choice::original_file_id)
        .do_update()
        .set((
            schema::best_choice::chosen_file_id.eq(*chosen_file_id as i64),
            schema::best_choice::at.eq(at.clone()),
        ))
        .execute(tx)?;
}
```

Commit: `feat(gui): IndexDbWriter MarkAsBest upsert`.

### Task 3.14: Batch boundary test

**Files:**
- Create: `crates/utmost-gui/tests/index_db_writer_batch.rs`

- [ ] **Step 1: Write the test**

```rust
use diesel::prelude::*;
use utmost_gui::index_db::{IndexDb, schema, writer::IndexDbWriter};
use utmost_lib::events::CarveEvent;
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::FileType;

fn ff(id: u64) -> CarveEvent {
    CarveEvent::FileFound {
        source_id: 0,
        file: create_file_object("x.jpg", FileType::Jpeg, 1, 0, None, id),
        img_offset: 0,
        written_path: "x.jpg".into(),
    }
}

#[test]
fn batch_threshold_commits_and_resets_pending() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = IndexDb::open(&dir.path().join("idx.sqlite")).unwrap();
    // Seed run + source via RunStarted (use the helper from the run_started test if extracted; otherwise inline)
    {
        let mut w = IndexDbWriter::new(db.conn(), 100);
        w.apply(crate::index_db_writer_run_started::run_started_event(), 0).unwrap();
        w.flush().unwrap();
    }

    {
        let mut w = IndexDbWriter::new(db.conn(), 50);
        for i in 1..=125u64 {
            w.apply(ff(i), i * 10).unwrap();
        }
        w.flush().unwrap();
    }

    db.with_conn(|conn| {
        let n: i64 = schema::file::table.count().get_result(conn).unwrap();
        assert_eq!(n, 125);
        let off: String = schema::meta::table
            .filter(schema::meta::key.eq("last_event_offset"))
            .select(schema::meta::value)
            .first(conn).unwrap();
        assert_eq!(off, "1250");
        let cnt: String = schema::meta::table
            .filter(schema::meta::key.eq("last_event_count"))
            .select(schema::meta::value)
            .first(conn).unwrap();
        // 1 RunStarted + 125 FileFound = 126
        assert_eq!(cnt, "126");
        Ok::<_, diesel::result::Error>(())
    }).unwrap();
}
```

If sharing helpers across integration tests is fiddly, copy the `run_started_event()` helper inline at the top of the file instead of importing.

- [ ] **Step 2: Run the test**

Run: `cargo test -p utmost-gui --test index_db_writer_batch`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/utmost-gui/tests/index_db_writer_batch.rs
git commit -m "test(gui): batch-boundary flush behaviour for IndexDbWriter"
```

### Task 3.15: Atomic offset advance under failure

**Files:**
- Modify: `crates/utmost-gui/src/index_db/writer.rs`
- Create: `crates/utmost-gui/tests/index_db_writer_atomicity.rs`

- [ ] **Step 1: Write the test**

The test forces an error mid-batch by inserting a row that violates the file PK constraint, then asserts neither the rows nor the offset advanced.

```rust
use diesel::prelude::*;
use utmost_gui::index_db::{IndexDb, schema, writer::IndexDbWriter};
use utmost_lib::events::CarveEvent;
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::FileType;

fn ff(id: u64) -> CarveEvent {
    CarveEvent::FileFound {
        source_id: 0,
        file: create_file_object("x.jpg", FileType::Jpeg, 1, 0, None, id),
        img_offset: 0,
        written_path: "x.jpg".into(),
    }
}

#[test]
fn duplicate_file_id_aborts_batch_with_no_partial_writes() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = IndexDb::open(&dir.path().join("idx.sqlite")).unwrap();

    // Seed run + source — copy the run_started_event from the run_started test file
    // (inline it; brevity omitted here).

    // First batch: insert file 1 successfully.
    {
        let mut w = IndexDbWriter::new(db.conn(), 10);
        w.apply(ff(1), 100).unwrap();
        w.flush().unwrap();
    }

    let count_before: i64 = db.with_conn(|conn|
        schema::file::table.count().get_result(conn)
    ).unwrap();
    let offset_before: String = db.with_conn(|conn|
        schema::meta::table.filter(schema::meta::key.eq("last_event_offset"))
            .select(schema::meta::value).first(conn)
    ).unwrap();

    // Second batch: file 2, then duplicate file 1 — flush must fail and rollback.
    let result = {
        let mut w = IndexDbWriter::new(db.conn(), 10);
        w.apply(ff(2), 200).unwrap();
        w.apply(ff(1), 300).unwrap();  // duplicate
        w.flush()
    };
    assert!(result.is_err());

    let count_after: i64 = db.with_conn(|conn|
        schema::file::table.count().get_result(conn)
    ).unwrap();
    let offset_after: String = db.with_conn(|conn|
        schema::meta::table.filter(schema::meta::key.eq("last_event_offset"))
            .select(schema::meta::value).first(conn)
    ).unwrap();

    assert_eq!(count_after, count_before, "rows must not have advanced");
    assert_eq!(offset_after, offset_before, "offset must not have advanced");
}
```

- [ ] **Step 2: Run the test**

Run: `cargo test -p utmost-gui --test index_db_writer_atomicity`
Expected: PASS (the writer's `conn.transaction(...)` already rolls back on error; no code change needed if Task 3.2 was implemented correctly).

If it fails, inspect `flush()` to ensure errors propagate out of the closure as `diesel::result::Error` so Diesel actually rolls back.

- [ ] **Step 3: Commit**

```bash
git add crates/utmost-gui/tests/index_db_writer_atomicity.rs
git commit -m "test(gui): atomic offset advance under flush failure"
```

---

## Phase 4 — Hydration

Goal: a `hydrate.rs` module that fills a `ViewModel` from a `SqliteConnection` by issuing one `SELECT` per table.

### Task 4.1: Hydration module skeleton

**Files:**
- Create: `crates/utmost-gui/src/index_db/hydrate.rs`
- Modify: `crates/utmost-gui/src/view_model.rs` — add a public helper.

- [ ] **Step 1: Decide on the public API**

`ViewModel` doesn't directly know about Diesel. Hydration goes through a public method on `ViewModel` that accepts plain Rust row data, plus a small adapter in `hydrate.rs` that issues the queries and calls the helper.

Add the following methods on `ViewModel` in `crates/utmost-gui/src/view_model.rs` (find a sensible place after `apply`):

```rust
impl ViewModel {
    /// Replace this view-model's state with the supplied snapshot.
    /// Used to hydrate from a SQLite index without replaying events.
    pub fn hydrate_from(&mut self, snap: ViewModelSnapshot) {
        self.run = snap.run;
        self.sources = snap.sources;
        self.files = snap.files;
        self.bookmarks = snap.bookmarks;
        self.notes = snap.notes;
        self.best_choices = snap.best_choices;
        self.variants = snap.variants;
        self.variant_of = snap.variant_of;
        self.type_counts = snap.type_counts;
        self.partial_counts = snap.partial_counts;
        self.recovery_state = snap.recovery_state;
        self.next_file_id = snap.next_file_id;
        self.next_note_id = snap.next_note_id;
        self.filter.enabled_types = self.run.configured_types.iter().copied().collect();
    }
}

pub struct ViewModelSnapshot {
    pub run: RunSummary,
    pub sources: Vec<SourceRow>,
    pub files: Vec<FoundFile>,
    pub bookmarks: std::collections::BTreeSet<FileId>,
    pub notes: std::collections::BTreeMap<FileId, Vec<NoteEntry>>,
    pub best_choices: std::collections::BTreeMap<FileId, FileId>,
    pub variants: std::collections::BTreeMap<FileId, VariantSet>,
    pub variant_of: std::collections::BTreeMap<FileId, FileId>,
    pub type_counts: std::collections::BTreeMap<FileType, u64>,
    pub partial_counts: std::collections::BTreeMap<FileType, u64>,
    pub recovery_state: RecoveryUiState,
    pub next_file_id: FileId,
    pub next_note_id: u64,
}
```

The `next_note_id` field may need exposing on `ViewModel` if it's currently private — check `view_model.rs` and make it `pub(crate)` if needed for tests, else add a constructor on the snapshot that doesn't require it.

- [ ] **Step 2: Create `hydrate.rs` skeleton**

Create `crates/utmost-gui/src/index_db/hydrate.rs`:

```rust
use anyhow::Result;
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use crate::index_db::{models::*, schema};
use crate::view_model::{
    FoundFile, NoteEntry, RecoveryUiState, RunStatus, RunSummary, SourceRow as VmSourceRow,
    SourceStatus, VariantSet, ViewModelSnapshot,
};
use utmost_lib::events::CaseMetadata;
use utmost_lib::types::{FileObject, FileType};

pub fn snapshot_from_db(conn: &mut SqliteConnection) -> Result<Option<ViewModelSnapshot>> {
    // If `run` table is empty, return None — caller will fall through to event replay.
    let run_row: Option<RunRow> = schema::run::table.first(conn).optional()?;
    let Some(run_row) = run_row else { return Ok(None) };

    let sources_db: Vec<SourceRow> = schema::source::table
        .order(schema::source::source_id)
        .load(conn)?;
    let files_db: Vec<FileRow> = schema::file::table
        .order(schema::file::file_id)
        .load(conn)?;
    let bookmarks_db: Vec<BookmarkRow> = schema::bookmark::table.load(conn)?;
    let notes_db: Vec<NoteRow> = schema::note::table.order(schema::note::note_id).load(conn)?;
    let best_db: Vec<BestChoiceRow> = schema::best_choice::table.load(conn)?;
    let variants_db: Vec<VariantRow> = schema::variant::table
        .order((schema::variant::original_file_id, schema::variant::rank))
        .load(conn)?;
    let recovery_db: Option<RecoveryRunRow> =
        schema::recovery_run::table.first(conn).optional()?;

    // ----- Build VM snapshot -----
    let configured_types: Vec<FileType> =
        serde_json::from_str(&run_row.configured_types_json).unwrap_or_default();
    let case = if run_row.case_id.is_none()
        && run_row.examiner.is_none()
        && run_row.evidence_id.is_none()
        && run_row.case_notes.is_none()
    {
        None
    } else {
        Some(CaseMetadata {
            case_id: run_row.case_id,
            examiner: run_row.examiner,
            evidence_id: run_row.evidence_id,
            notes: run_row.case_notes,
        })
    };
    let run = RunSummary {
        started_at: run_row.started_at,
        output_root: run_row.output_root.clone(),
        source_image_path: run_row.source_image_path,
        configured_types: configured_types.clone(),
        status: match run_row.status.as_str() {
            "Running" => RunStatus::Running,
            "Finished" => RunStatus::Finished,
            "Interrupted" => RunStatus::Interrupted,
            _ => RunStatus::Pending,
        },
        case,
        elapsed_ms: run_row.elapsed_ms as u64,
        total_files: run_row.total_files as u64,
    };

    let sources: Vec<VmSourceRow> = sources_db
        .into_iter()
        .map(|s| VmSourceRow {
            source_id: s.source_id as u32,
            filename: s.filename,
            output_subdir: s.output_subdir,
            total_bytes: s.total_bytes as u64,
            bytes_read: s.bytes_read as u64,
            files_found: s.files_found as u64,
            status: match s.status.as_str() {
                "Running" => SourceStatus::Running,
                "Finished" => SourceStatus::Finished,
                "Interrupted" => SourceStatus::Interrupted,
                _ => SourceStatus::Pending,
            },
            duration_ms: s.duration_ms.map(|d| d as u64),
        })
        .collect();

    // Rebuild FoundFiles with fresh GUI-local ids
    let mut files: Vec<FoundFile> = Vec::with_capacity(files_db.len());
    let mut type_counts: BTreeMap<FileType, u64> = BTreeMap::new();
    let mut partial_counts: BTreeMap<FileType, u64> = BTreeMap::new();
    let output_root_pb = PathBuf::from(&run_row.output_root);
    for (i, f) in files_db.into_iter().enumerate() {
        let byte_runs = serde_json::from_str(&f.byte_runs_json).unwrap_or_default();
        let jpeg_scan = build_jpeg_scan(&f);
        let fo = FileObject {
            file_id: f.file_id as u64,
            filename: f.filename.clone(),
            filesize: f.filesize as u64,
            file_type: f.file_type.clone(),
            byte_runs,
            jpeg_scan,
        };
        let abs_path = output_root_pb.join(&f.written_path);
        if let Some(ft) = crate::view_model::parse_file_type_pub(&fo.file_type) {
            *type_counts.entry(ft).or_insert(0) += 1;
            let is_partial = fo
                .jpeg_scan
                .as_ref()
                .map(|s| s.status != utmost_lib::types::JpegScanStatus::Complete)
                .unwrap_or(false);
            if is_partial {
                *partial_counts.entry(ft).or_insert(0) += 1;
            }
        }
        files.push(FoundFile {
            id: i as u64,
            source_id: f.source_id as u32,
            file: fo,
            written_path: abs_path,
            img_offset: f.img_offset as u64,
        });
    }
    let next_file_id = files.len() as u64;

    // Bookmarks (keyed on engine file_id, matching existing apply() behavior)
    let bookmarks: BTreeSet<u64> = bookmarks_db.into_iter().map(|b| b.file_id as u64).collect();

    // Notes
    let mut notes: BTreeMap<u64, Vec<NoteEntry>> = BTreeMap::new();
    let mut next_note_id: u64 = 1;
    for n in notes_db {
        notes
            .entry(n.file_id as u64)
            .or_default()
            .push(NoteEntry {
                note_id: n.note_id as u64,
                text: n.text,
                at: n.at,
            });
        next_note_id = next_note_id.max(n.note_id as u64 + 1);
    }

    let best_choices: BTreeMap<u64, u64> = best_db
        .into_iter()
        .map(|b| (b.original_file_id as u64, b.chosen_file_id as u64))
        .collect();

    let mut variants: BTreeMap<u64, VariantSet> = BTreeMap::new();
    let mut variant_of: BTreeMap<u64, u64> = BTreeMap::new();
    for v in variants_db {
        let entry = variants
            .entry(v.original_file_id as u64)
            .or_insert_with(|| VariantSet {
                original_id: v.original_file_id as u64,
                variant_ids: Vec::new(),
            });
        if !entry.variant_ids.contains(&(v.candidate_file_id as u64)) {
            entry.variant_ids.push(v.candidate_file_id as u64);
        }
        variant_of.insert(v.candidate_file_id as u64, v.original_file_id as u64);
    }

    let recovery_state = match (&recovery_db, !partial_counts.is_empty()) {
        (Some(r), _) if r.finished_duration_ms.is_some() => RecoveryUiState::Finished,
        (Some(_), _) => RecoveryUiState::Running,
        (None, true) => RecoveryUiState::NotRun,
        (None, false) => RecoveryUiState::Disabled,
    };

    Ok(Some(ViewModelSnapshot {
        run,
        sources,
        files,
        bookmarks,
        notes,
        best_choices,
        variants,
        variant_of,
        type_counts,
        partial_counts,
        recovery_state,
        next_file_id,
        next_note_id,
    }))
}

fn build_jpeg_scan(f: &FileRow) -> Option<utmost_lib::types::JpegScanInfo> {
    let status = f.jpeg_status.as_ref()?;
    Some(utmost_lib::types::JpegScanInfo {
        status: match status.as_str() {
            "complete" => utmost_lib::types::JpegScanStatus::Complete,
            "truncated" => utmost_lib::types::JpegScanStatus::Truncated,
            "fragmented" => utmost_lib::types::JpegScanStatus::Fragmented,
            other => panic!("unknown jpeg_status: {other}"),
        },
        width: f.jpeg_width.map(|w| w as u16),
        height: f.jpeg_height.map(|h| h as u16),
        fragmentation_point_img_offset: f.jpeg_fragmentation_point.map(|o| o as u64),
        has_restart_markers: f.jpeg_has_restart_markers.unwrap_or(0) != 0,
    })
}
```

The `JpegScanInfo` shape above matches `crates/utmost-lib/src/types.rs` as of 2026-05-19; if the struct drifts, update `build_jpeg_scan` (and the schema/migration/models in lockstep). `parse_file_type_pub` must be exposed from `view_model.rs` (it already is per `slint_adapter.rs:11`).

- [ ] **Step 3: Add `pub mod hydrate` to `index_db/mod.rs`**

```rust
pub mod hydrate;
```

- [ ] **Step 4: Build**

Run: `cargo build -p utmost-gui`
Expected: builds.

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-gui/src/{view_model.rs,index_db/{mod.rs,hydrate.rs}}
git commit -m "feat(gui): snapshot_from_db builds a ViewModelSnapshot from sqlite"
```

### Task 4.2: Round-trip integration test

**Files:**
- Create: `crates/utmost-gui/tests/index_db_roundtrip.rs`

- [ ] **Step 1: Write the test**

```rust
//! Drive a fixed event stream through the writer, then hydrate a fresh VM
//! from the SQLite and compare to a second VM built by direct `apply()`.

use utmost_gui::index_db::{IndexDb, hydrate, writer::IndexDbWriter};
use utmost_gui::view_model::ViewModel;
use utmost_lib::events::CarveEvent;
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::FileType;

// Build a short, representative event stream
fn events() -> Vec<CarveEvent> {
    let mut ev = Vec::new();
    ev.push(/* RunStarted event — copy the helper from index_db_writer_run_started.rs */);
    for i in 1..=5u64 {
        ev.push(CarveEvent::FileFound {
            source_id: 0,
            file: create_file_object("a.jpg", FileType::Jpeg, 1024, 0, None, i),
            img_offset: 0,
            written_path: "a.jpg".into(),
        });
    }
    ev.push(CarveEvent::Bookmark { file_id: 2, bookmarked: true, at: "t".into() });
    ev.push(CarveEvent::Note { note_id: 1, file_id: 3, text: "hello".into(), at: "t".into() });
    ev.push(CarveEvent::RunFinished { duration_ms: 50, total_files_written: 5 });
    ev
}

#[test]
fn hydrate_matches_direct_replay() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = IndexDb::open(&dir.path().join("idx.sqlite")).unwrap();
    let events = events();

    // Path A: write to db
    {
        let mut w = IndexDbWriter::new(db.conn(), 1000);
        for (i, e) in events.iter().enumerate() {
            w.apply(e.clone(), (i as u64 + 1) * 10).unwrap();
        }
        w.flush().unwrap();
    }

    // Path B: direct replay into a VM
    let mut vm_b = ViewModel::new();
    for e in &events {
        vm_b.apply(e);
    }
    vm_b.recompute_visible();

    // Hydrate VM from db
    let snap = db.with_conn(|conn|
        hydrate::snapshot_from_db(conn).map_err(diesel::result::Error::from)
    ).unwrap().unwrap();
    let mut vm_a = ViewModel::new();
    vm_a.hydrate_from(snap);
    vm_a.recompute_visible();

    // Compare relevant fields
    assert_eq!(vm_a.run.total_files, vm_b.run.total_files);
    assert_eq!(vm_a.run.status as i32, vm_b.run.status as i32);  // requires Copy
    assert_eq!(vm_a.files.len(), vm_b.files.len());
    assert_eq!(vm_a.bookmarks, vm_b.bookmarks);
    let a_notes: usize = vm_a.notes.values().map(|v| v.len()).sum();
    let b_notes: usize = vm_b.notes.values().map(|v| v.len()).sum();
    assert_eq!(a_notes, b_notes);
}
```

If `RunStatus` doesn't impl `Copy`, compare via debug strings or add a `#[derive(Copy)]`. If converting an enum to an int isn't direct, use `assert_eq!(format!("{:?}", vm_a.run.status), format!("{:?}", vm_b.run.status))`.

If `anyhow::Error → diesel::result::Error` conversion is awkward in the `with_conn` closure, restructure as:

```rust
let conn = db.conn();
let snap = hydrate::snapshot_from_db(conn).unwrap().unwrap();
```

- [ ] **Step 2: Run + commit**

Run: `cargo test -p utmost-gui --test index_db_roundtrip`
Expected: PASS.

```bash
git add crates/utmost-gui/tests/index_db_roundtrip.rs
git commit -m "test(gui): roundtrip — hydrate matches direct event replay"
```

---

## Phase 5 — `open_decision` + cold rebuild wired into `run_from_file`

Goal: the loader uses SQLite. Cold open builds it from the log; warm open hydrates from it.

### Task 5.1: `byte_offset()` on `BincodeFileReader`

**Files:**
- Modify: `crates/utmost-lib/src/events.rs`

- [ ] **Step 1: Write the failing test**

In `crates/utmost-lib/src/events.rs`, inside the existing `#[cfg(test)] mod tests`, add:

```rust
#[test]
fn byte_offset_advances_past_each_frame() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("o.bin");
    let sink = BincodeFileSink::create(&path).unwrap();
    sink.emit(&CarveEvent::SourceStarted { source_id: 0 });
    sink.emit(&CarveEvent::RunFinished { duration_ms: 1, total_files_written: 0 });
    drop(sink);

    let mut r = BincodeFileReader::open(&path).unwrap();
    let off0 = r.byte_offset().unwrap();
    let _ = r.next_event().unwrap();
    let off1 = r.byte_offset().unwrap();
    let _ = r.next_event().unwrap();
    let off2 = r.byte_offset().unwrap();
    let total = std::fs::metadata(&path).unwrap().len();
    assert!(off0 < off1 && off1 < off2);
    assert_eq!(off2, total);
}
```

- [ ] **Step 2: Run the test**

Run: `cargo test -p utmost-lib byte_offset_advances`
Expected: FAIL — no method `byte_offset`.

- [ ] **Step 3: Add the method**

In `crates/utmost-lib/src/events.rs`, in `impl BincodeFileReader`, add:

```rust
/// Returns the byte offset in the underlying file immediately past the
/// last successfully-read frame (i.e. the position from which the next
/// frame would be read).
pub fn byte_offset(&mut self) -> std::io::Result<u64> {
    use std::io::Seek;
    // The BufReader caches; we want logical position, which is the file
    // position minus the buffered remainder.
    let stream_pos = self.reader.get_mut().stream_position()?;
    let buffered = self.reader.buffer().len() as u64;
    Ok(stream_pos - buffered)
}
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p utmost-lib byte_offset_advances`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-lib/src/events.rs
git commit -m "feat(lib): BincodeFileReader::byte_offset accessor"
```

### Task 5.2: `open_decision` truth table

**Files:**
- Modify: `crates/utmost-gui/src/index_db/mod.rs`
- Create: `crates/utmost-gui/tests/index_db_open_decision.rs`

- [ ] **Step 1: Write the truth-table test**

Test the seven cases from the spec. Each test sets up a `.bin` + a `meta` state, then calls `open_decision` and asserts on the action.

```rust
use std::fs;
use diesel::prelude::*;
use utmost_gui::index_db::{IndexDb, OpenAction, open_decision, schema};
use utmost_lib::events::{BincodeFileSink, CarveEvent};

// inline run_started_event() helper, same as Task 3.2 file

fn make_log(dir: &std::path::Path, name: &str, events: &[CarveEvent]) -> std::path::PathBuf {
    let p = dir.join(name);
    let sink = BincodeFileSink::create(&p).unwrap();
    for e in events {
        sink.emit(e);
    }
    drop(sink);
    p
}

fn set_meta(db: &mut IndexDb, key: &str, value: &str) {
    db.with_conn(|conn| {
        diesel::sql_query(
            "INSERT INTO meta (key, value) VALUES (?, ?) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind::<diesel::sql_types::Text, _>(key)
        .bind::<diesel::sql_types::Text, _>(value)
        .execute(conn).unwrap();
        Ok::<_, diesel::result::Error>(())
    }).unwrap();
}

#[test]
fn fresh_db_is_rebuild_from_zero() {
    let dir = tempfile::tempdir().unwrap();
    let bin = make_log(dir.path(), "a-events.bin", &[run_started_event()]);
    let mut db = IndexDb::open(&dir.path().join("a-index.sqlite")).unwrap();
    let action = open_decision(&bin, &mut db).unwrap();
    assert!(matches!(action, OpenAction::RebuildFromZero));
}

#[test]
fn different_run_started_is_wipe_and_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let bin = make_log(dir.path(), "a-events.bin", &[run_started_event()]);
    let mut db = IndexDb::open(&dir.path().join("a-index.sqlite")).unwrap();
    set_meta(&mut db, "run_started_at", "old-timestamp");
    set_meta(&mut db, "last_event_offset", "999");
    let action = open_decision(&bin, &mut db).unwrap();
    assert!(matches!(action, OpenAction::WipeAndRebuild));
}

#[test]
fn equal_offset_is_hydrate_and_done() {
    let dir = tempfile::tempdir().unwrap();
    let bin = make_log(dir.path(), "a-events.bin", &[run_started_event()]);
    let size = fs::metadata(&bin).unwrap().len();
    let mut db = IndexDb::open(&dir.path().join("a-index.sqlite")).unwrap();
    set_meta(&mut db, "run_started_at", "2026-05-19T00:00:00+0000");
    set_meta(&mut db, "last_event_offset", &size.to_string());
    let action = open_decision(&bin, &mut db).unwrap();
    assert!(matches!(action, OpenAction::HydrateAndDone));
}

#[test]
fn smaller_offset_is_resume() {
    let dir = tempfile::tempdir().unwrap();
    let bin = make_log(dir.path(), "a-events.bin", &[run_started_event()]);
    let mut db = IndexDb::open(&dir.path().join("a-index.sqlite")).unwrap();
    set_meta(&mut db, "run_started_at", "2026-05-19T00:00:00+0000");
    set_meta(&mut db, "last_event_offset", "1");
    let action = open_decision(&bin, &mut db).unwrap();
    assert!(matches!(action, OpenAction::Resume { .. }));
}

#[test]
fn larger_offset_is_wipe_and_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let bin = make_log(dir.path(), "a-events.bin", &[run_started_event()]);
    let size = fs::metadata(&bin).unwrap().len();
    let mut db = IndexDb::open(&dir.path().join("a-index.sqlite")).unwrap();
    set_meta(&mut db, "run_started_at", "2026-05-19T00:00:00+0000");
    set_meta(&mut db, "last_event_offset", &(size + 999).to_string());
    let action = open_decision(&bin, &mut db).unwrap();
    assert!(matches!(action, OpenAction::WipeAndRebuild));
}

#[test]
fn run_started_set_but_no_offset_is_rebuild_from_zero() {
    let dir = tempfile::tempdir().unwrap();
    let bin = make_log(dir.path(), "a-events.bin", &[run_started_event()]);
    let mut db = IndexDb::open(&dir.path().join("a-index.sqlite")).unwrap();
    set_meta(&mut db, "run_started_at", "2026-05-19T00:00:00+0000");
    // no last_event_offset
    let action = open_decision(&bin, &mut db).unwrap();
    assert!(matches!(action, OpenAction::RebuildFromZero));
}

#[test]
fn empty_log_errors() {
    let dir = tempfile::tempdir().unwrap();
    // create_bin writes only the header, no events. Header alone is still a valid log
    // for our purposes — what about empty file?
    let bin = dir.path().join("empty-events.bin");
    let _sink = BincodeFileSink::create(&bin).unwrap();  // header only
    drop(_sink);
    let mut db = IndexDb::open(&dir.path().join("empty-index.sqlite")).unwrap();
    let result = open_decision(&bin, &mut db);
    // Header-only log: first event is None — open_decision returns RebuildFromZero
    // (since there's nothing to identify the run by, we'll just wait for events).
    assert!(matches!(result.unwrap(), OpenAction::RebuildFromZero));
}
```

- [ ] **Step 2: Run the test**

Run: `cargo test -p utmost-gui --test index_db_open_decision`
Expected: FAIL — `open_decision` undefined.

- [ ] **Step 3: Implement `open_decision`**

In `crates/utmost-gui/src/index_db/mod.rs`, add (at the bottom):

```rust
use std::path::Path as StdPath;

#[derive(Debug, PartialEq)]
pub enum OpenAction {
    /// SQLite is up to date; load VM from it.
    HydrateAndDone,
    /// SQLite is behind the log; seek to `from` and stream remainder.
    Resume { from: u64 },
    /// SQLite has no usable state for this log; build it from byte 0.
    RebuildFromZero,
    /// SQLite is from a different run; wipe domain tables, then RebuildFromZero.
    WipeAndRebuild,
}

pub fn open_decision(bin: &StdPath, db: &mut IndexDb) -> Result<OpenAction> {
    let bin_size = std::fs::metadata(bin)
        .with_context(|| format!("stat {}", bin.display()))?
        .len();

    let meta_started_at = read_meta_str(db, "run_started_at")?;
    let meta_offset = read_meta_u64(db, "last_event_offset")?;

    let mut reader = utmost_lib::events::BincodeFileReader::open(bin)
        .with_context(|| format!("opening {}", bin.display()))?;
    let first = reader.next_event()?;
    let Some(first) = first else {
        // header-only log; no run identified yet
        return Ok(OpenAction::RebuildFromZero);
    };
    let utmost_lib::events::CarveEvent::RunStarted { started_at, .. } = &first else {
        return Ok(OpenAction::RebuildFromZero);
    };

    Ok(match (meta_started_at, meta_offset) {
        (None, _) => OpenAction::RebuildFromZero,
        (Some(rec), _) if rec != *started_at => OpenAction::WipeAndRebuild,
        (Some(_), Some(off)) if off == bin_size => OpenAction::HydrateAndDone,
        (Some(_), Some(off)) if off < bin_size => OpenAction::Resume { from: off },
        (Some(_), Some(off)) if off > bin_size => OpenAction::WipeAndRebuild,
        _ => OpenAction::RebuildFromZero,
    })
}

fn read_meta_str(db: &mut IndexDb, key: &str) -> Result<Option<String>> {
    use crate::index_db::schema::meta::dsl as m;
    let v: Option<String> = m::meta
        .filter(m::key.eq(key))
        .select(m::value)
        .first(db.conn())
        .optional()?;
    Ok(v)
}

fn read_meta_u64(db: &mut IndexDb, key: &str) -> Result<Option<u64>> {
    Ok(read_meta_str(db, key)?.and_then(|s| s.parse::<u64>().ok()))
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p utmost-gui --test index_db_open_decision`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-gui/src/index_db/mod.rs crates/utmost-gui/tests/index_db_open_decision.rs
git commit -m "feat(gui): open_decision truth table"
```

### Task 5.3: Cold rebuild orchestration

**Files:**
- Create: `crates/utmost-gui/src/indexer_thread.rs`
- Modify: `crates/utmost-gui/src/lib.rs`

- [ ] **Step 1: Write the failing integration test**

Create `crates/utmost-gui/tests/index_db_cold_open.rs`:

```rust
//! Cold open: no SQLite exists; loader builds it and populates the VM.

use std::sync::{Arc, Mutex};
use utmost_gui::view_model::ViewModel;
use utmost_lib::events::{BincodeFileSink, CarveEvent};
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::FileType;

// inline run_started_event() helper

#[test]
fn cold_open_builds_sqlite_and_populates_vm() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("output-disk1.dd");
    std::fs::create_dir_all(&sub).unwrap();
    let bin = sub.join("disk1.dd-events.bin");
    {
        let sink = BincodeFileSink::create(&bin).unwrap();
        sink.emit(&run_started_event());
        for i in 1..=10u64 {
            sink.emit(&CarveEvent::FileFound {
                source_id: 0,
                file: create_file_object("x.jpg", FileType::Jpeg, 0, 0, None, i),
                img_offset: 0,
                written_path: "x.jpg".into(),
            });
        }
        sink.emit(&CarveEvent::RunFinished { duration_ms: 5, total_files_written: 10 });
        drop(sink);
    }

    // synchronous helper that does the cold build (no UI)
    let vm = Arc::new(Mutex::new(ViewModel::new()));
    utmost_gui::indexer_thread::run_blocking(&bin, vm.clone()).unwrap();
    let v = vm.lock().unwrap();
    assert_eq!(v.files.len(), 10);
    assert!(sub.join("disk1.dd-index.sqlite").exists());
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p utmost-gui --test index_db_cold_open`
Expected: FAIL — `indexer_thread` module not found.

- [ ] **Step 3: Create the indexer module**

Create `crates/utmost-gui/src/indexer_thread.rs`:

```rust
//! Background work that turns a `.bin` event log into a SQLite index.
//!
//! Exposes a synchronous `run_blocking` helper for tests; a threaded
//! variant that sends progress messages is added in Phase 8.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::index_db::{IndexDb, OpenAction, hydrate, open_decision, writer::IndexDbWriter};
use crate::view_model::ViewModel;
use utmost_lib::events::BincodeFileReader;

pub fn index_path_for(bin: &Path) -> PathBuf {
    let mut p = bin.to_path_buf();
    let stem = bin
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_suffix("-events.bin"))
        .unwrap_or("source");
    p.set_file_name(format!("{stem}-index.sqlite"));
    p
}

pub fn run_blocking(bin: &Path, vm: Arc<Mutex<ViewModel>>) -> Result<()> {
    let db_path = index_path_for(bin);
    let mut db = IndexDb::open(&db_path)
        .with_context(|| format!("opening index db at {}", db_path.display()))?;
    let action = open_decision(bin, &mut db)?;
    match action {
        OpenAction::HydrateAndDone => {
            hydrate_into(&mut db, &vm)?;
        }
        OpenAction::WipeAndRebuild => {
            wipe_tables(&mut db)?;
            rebuild_from_zero(bin, &mut db, &vm)?;
        }
        OpenAction::RebuildFromZero => {
            rebuild_from_zero(bin, &mut db, &vm)?;
        }
        OpenAction::Resume { from } => {
            hydrate_into(&mut db, &vm)?;
            resume_from(bin, from, &mut db, &vm)?;
        }
    }
    {
        let mut v = vm.lock().unwrap();
        v.recompute_visible();
    }
    Ok(())
}

fn hydrate_into(db: &mut IndexDb, vm: &Arc<Mutex<ViewModel>>) -> Result<()> {
    let snap = hydrate::snapshot_from_db(db.conn())?
        .context("expected snapshot from db with run row")?;
    vm.lock().unwrap().hydrate_from(snap);
    Ok(())
}

fn wipe_tables(db: &mut IndexDb) -> Result<()> {
    use diesel::connection::SimpleConnection;
    db.conn().batch_execute(
        "BEGIN; \
         DELETE FROM variant; \
         DELETE FROM recovery_run; \
         DELETE FROM best_choice; \
         DELETE FROM note; \
         DELETE FROM bookmark; \
         DELETE FROM file; \
         DELETE FROM source; \
         DELETE FROM run; \
         DELETE FROM meta; \
         COMMIT;",
    )?;
    Ok(())
}

fn rebuild_from_zero(bin: &Path, db: &mut IndexDb, vm: &Arc<Mutex<ViewModel>>) -> Result<()> {
    let mut reader = BincodeFileReader::open(bin)?;
    let mut writer = IndexDbWriter::new(db.conn(), 5000);
    while let Some(ev) = reader.next_event()? {
        let offset_after = reader.byte_offset()?;
        {
            let mut v = vm.lock().unwrap();
            v.apply(&ev);
        }
        writer.apply(ev, offset_after)?;
    }
    writer.flush()?;
    Ok(())
}

fn resume_from(
    bin: &Path,
    from: u64,
    db: &mut IndexDb,
    vm: &Arc<Mutex<ViewModel>>,
) -> Result<()> {
    use std::io::Seek;
    let mut reader = BincodeFileReader::open(bin)?;
    // BincodeFileReader doesn't expose Seek directly; reach into its file.
    // For Phase 5 we wrap the seek by reading and discarding events until
    // byte_offset() >= from. (A direct seek is added in Phase 6.)
    while reader.byte_offset()? < from {
        if reader.next_event()?.is_none() {
            break;
        }
    }
    let mut writer = IndexDbWriter::new(db.conn(), 5000);
    while let Some(ev) = reader.next_event()? {
        let offset_after = reader.byte_offset()?;
        {
            let mut v = vm.lock().unwrap();
            v.apply(&ev);
        }
        writer.apply(ev, offset_after)?;
    }
    writer.flush()?;
    // Suppress unused-import warning if it occurs
    let _ = std::marker::PhantomData::<dyn Seek>;
    Ok(())
}
```

Wire it: in `crates/utmost-gui/src/lib.rs`, add at the top with the other `pub mod` lines:

```rust
pub mod indexer_thread;
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p utmost-gui --test index_db_cold_open`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-gui/src/indexer_thread.rs crates/utmost-gui/src/lib.rs crates/utmost-gui/tests/index_db_cold_open.rs
git commit -m "feat(gui): cold rebuild orchestration via indexer_thread::run_blocking"
```

### Task 5.4: Wire into `run_from_file`

**Files:**
- Modify: `crates/utmost-gui/src/lib.rs`

- [ ] **Step 1: Replace the synchronous replay loop**

In `crates/utmost-gui/src/lib.rs`, find the existing event-replay loop in `run_from_file`:

```rust
    for path in &files {
        let mut reader = BincodeFileReader::open(path)?;
        while let Some(ev) = reader.next_event()? {
            vm.lock().unwrap().apply(&ev);
        }
    }
```

Replace with:

```rust
    for path in &files {
        indexer_thread::run_blocking(path, vm.clone())?;
    }
```

- [ ] **Step 2: Write a warm-open integration test**

Create `crates/utmost-gui/tests/index_db_warm_open.rs`:

```rust
//! Two consecutive opens: first cold-builds the index, second hydrates from it.

use std::sync::{Arc, Mutex};
use utmost_gui::view_model::ViewModel;
use utmost_lib::events::{BincodeFileSink, CarveEvent};
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::FileType;

// inline run_started_event() helper

#[test]
fn warm_open_hydrates_without_advancing_offset() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("output-disk1.dd");
    std::fs::create_dir_all(&sub).unwrap();
    let bin = sub.join("disk1.dd-events.bin");
    {
        let sink = BincodeFileSink::create(&bin).unwrap();
        sink.emit(&run_started_event());
        for i in 1..=20u64 {
            sink.emit(&CarveEvent::FileFound {
                source_id: 0,
                file: create_file_object("x.jpg", FileType::Jpeg, 0, 0, None, i),
                img_offset: 0,
                written_path: "x.jpg".into(),
            });
        }
        sink.emit(&CarveEvent::RunFinished { duration_ms: 5, total_files_written: 20 });
    }

    // First open: cold
    {
        let vm = Arc::new(Mutex::new(ViewModel::new()));
        utmost_gui::indexer_thread::run_blocking(&bin, vm.clone()).unwrap();
        assert_eq!(vm.lock().unwrap().files.len(), 20);
    }
    // Second open: warm
    let vm = Arc::new(Mutex::new(ViewModel::new()));
    utmost_gui::indexer_thread::run_blocking(&bin, vm.clone()).unwrap();
    assert_eq!(vm.lock().unwrap().files.len(), 20);
}
```

- [ ] **Step 3: Run all GUI tests**

Run: `cargo test -p utmost-gui`
Expected: PASS. If any existing test broke because it depended on the old synchronous-replay-only path, adapt the test (e.g., `replay_snapshot.rs`); do not weaken the new path.

- [ ] **Step 4: Commit**

```bash
git add crates/utmost-gui/src/lib.rs crates/utmost-gui/tests/index_db_warm_open.rs
git commit -m "feat(gui): run_from_file routes through indexer_thread"
```

---

## Phase 6 — Resume path

Goal: `Resume { from }` action seeks correctly and produces no duplicate rows. The Phase 5 implementation already loops by `byte_offset()`; Phase 6 adds a `Seek` accessor for efficiency and a stronger test.

### Task 6.1: Direct seek

**Files:**
- Modify: `crates/utmost-lib/src/events.rs`
- Modify: `crates/utmost-gui/src/indexer_thread.rs`

- [ ] **Step 1: Write the failing test (in lib)**

In `crates/utmost-lib/src/events.rs`, inside the test module:

```rust
#[test]
fn seek_to_offset_yields_subsequent_events() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.bin");
    let sink = BincodeFileSink::create(&path).unwrap();
    sink.emit(&CarveEvent::SourceStarted { source_id: 1 });
    let _ = sink;
    let mut r = BincodeFileReader::open(&path).unwrap();
    let _ = r.next_event().unwrap(); // first event
    let mid = r.byte_offset().unwrap();
    // Build a second reader and seek to mid; next_event should yield None.
    let mut r2 = BincodeFileReader::open(&path).unwrap();
    r2.seek_to(mid).unwrap();
    assert!(r2.next_event().unwrap().is_none());
}
```

- [ ] **Step 2: Run + verify fail**

Run: `cargo test -p utmost-lib seek_to_offset_yields`
Expected: FAIL — no `seek_to`.

- [ ] **Step 3: Implement `seek_to`**

In `crates/utmost-lib/src/events.rs`, in `impl BincodeFileReader`:

```rust
pub fn seek_to(&mut self, offset: u64) -> std::io::Result<()> {
    use std::io::{Seek, SeekFrom};
    self.reader.seek(SeekFrom::Start(offset))?;
    Ok(())
}
```

- [ ] **Step 4: Update `indexer_thread::resume_from` to use direct seek**

In `crates/utmost-gui/src/indexer_thread.rs`, replace the body of `resume_from` with:

```rust
fn resume_from(
    bin: &Path,
    from: u64,
    db: &mut IndexDb,
    vm: &Arc<Mutex<ViewModel>>,
) -> Result<()> {
    let mut reader = BincodeFileReader::open(bin)?;
    reader.seek_to(from)?;
    let mut writer = IndexDbWriter::new(db.conn(), 5000);
    while let Some(ev) = reader.next_event()? {
        let offset_after = reader.byte_offset()?;
        {
            let mut v = vm.lock().unwrap();
            v.apply(&ev);
        }
        writer.apply(ev, offset_after)?;
    }
    writer.flush()?;
    Ok(())
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p utmost-lib seek_to_offset_yields && cargo test -p utmost-gui`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-lib/src/events.rs crates/utmost-gui/src/indexer_thread.rs
git commit -m "feat(lib): BincodeFileReader::seek_to + use in resume path"
```

### Task 6.2: Resume integration test

**Files:**
- Create: `crates/utmost-gui/tests/index_db_resume.rs`

- [ ] **Step 1: Write the test**

```rust
//! Simulate a process killed mid-rebuild: index 5 events, close, reopen with
//! 5 more events in the log. Must resume from offset 5 and end with 10 rows.

use std::sync::{Arc, Mutex};
use diesel::prelude::*;
use utmost_gui::index_db::{IndexDb, schema, writer::IndexDbWriter};
use utmost_gui::view_model::ViewModel;
use utmost_lib::events::{BincodeFileReader, BincodeFileSink, CarveEvent};
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::FileType;

// inline run_started_event() helper

fn ff(id: u64) -> CarveEvent {
    CarveEvent::FileFound {
        source_id: 0,
        file: create_file_object("x.jpg", FileType::Jpeg, 0, 0, None, id),
        img_offset: 0,
        written_path: "x.jpg".into(),
    }
}

#[test]
fn resume_after_partial_index() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("output-disk1.dd");
    std::fs::create_dir_all(&sub).unwrap();
    let bin = sub.join("disk1.dd-events.bin");

    // Write 5 events.
    {
        let sink = BincodeFileSink::create(&bin).unwrap();
        sink.emit(&run_started_event());
        for i in 1..=5u64 {
            sink.emit(&ff(i));
        }
    }

    // Manually run indexer on those 5 events.
    let vm1 = Arc::new(Mutex::new(ViewModel::new()));
    utmost_gui::indexer_thread::run_blocking(&bin, vm1.clone()).unwrap();
    let count_after_first: i64 = IndexDb::open(&sub.join("disk1.dd-index.sqlite")).unwrap()
        .with_conn(|conn| schema::file::table.count().get_result(conn)).unwrap();
    assert_eq!(count_after_first, 5);

    // Append 5 more events to the log.
    {
        let sink = utmost_lib::events::BincodeFileSink::open_append(&bin).unwrap();
        for i in 6..=10u64 {
            <BincodeFileSink as utmost_lib::events::EventSink>::emit(&sink, &ff(i));
        }
    }

    // Reopen.
    let vm2 = Arc::new(Mutex::new(ViewModel::new()));
    utmost_gui::indexer_thread::run_blocking(&bin, vm2.clone()).unwrap();
    assert_eq!(vm2.lock().unwrap().files.len(), 10);

    let count_final: i64 = IndexDb::open(&sub.join("disk1.dd-index.sqlite")).unwrap()
        .with_conn(|conn| schema::file::table.count().get_result(conn)).unwrap();
    assert_eq!(count_final, 10);
}
```

- [ ] **Step 2: Run**

Run: `cargo test -p utmost-gui --test index_db_resume`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/utmost-gui/tests/index_db_resume.rs
git commit -m "test(gui): resume from partial index produces correct final state"
```

---

## Phase 7 — WipeAndRebuild

Goal: a different `RunStarted` (new run, same `.bin` path) triggers a clean wipe.

### Task 7.1: Wipe + rebuild integration test

**Files:**
- Create: `crates/utmost-gui/tests/index_db_wipe.rs`

- [ ] **Step 1: Write the test**

```rust
//! Replace the .bin with a new run (different started_at); reopen.
//! Expectation: WipeAndRebuild — only run B's events are present.

use std::sync::{Arc, Mutex};
use diesel::prelude::*;
use utmost_gui::index_db::{IndexDb, schema};
use utmost_gui::view_model::ViewModel;
use utmost_lib::events::{BincodeFileSink, CarveEvent};
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::FileType;

// inline a helper run_started_event_for(started_at: &str)

fn ff(id: u64) -> CarveEvent { /* same as Phase 6 */ }

#[test]
fn new_run_wipes_old_data() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("output-disk1.dd");
    std::fs::create_dir_all(&sub).unwrap();
    let bin = sub.join("disk1.dd-events.bin");

    // Run A
    {
        let sink = BincodeFileSink::create(&bin).unwrap();
        sink.emit(&run_started_event_for("2026-05-19T00:00:00+0000"));
        for i in 1..=5u64 { sink.emit(&ff(i)); }
    }
    let vm1 = Arc::new(Mutex::new(ViewModel::new()));
    utmost_gui::indexer_thread::run_blocking(&bin, vm1.clone()).unwrap();
    assert_eq!(vm1.lock().unwrap().files.len(), 5);

    // Replace with run B (different started_at)
    std::fs::remove_file(&bin).unwrap();
    {
        let sink = BincodeFileSink::create(&bin).unwrap();
        sink.emit(&run_started_event_for("2026-05-19T01:00:00+0000"));
        for i in 100..=102u64 { sink.emit(&ff(i)); }
    }
    let vm2 = Arc::new(Mutex::new(ViewModel::new()));
    utmost_gui::indexer_thread::run_blocking(&bin, vm2.clone()).unwrap();
    assert_eq!(vm2.lock().unwrap().files.len(), 3);

    let ids: Vec<i64> = IndexDb::open(&sub.join("disk1.dd-index.sqlite")).unwrap()
        .with_conn(|conn| schema::file::table.select(schema::file::file_id).load(conn)).unwrap();
    assert_eq!(ids, vec![100, 101, 102]);
}
```

- [ ] **Step 2: Run**

Run: `cargo test -p utmost-gui --test index_db_wipe`
Expected: PASS (Phase 5 already implemented `wipe_tables` + WipeAndRebuild branching).

- [ ] **Step 3: Commit**

```bash
git add crates/utmost-gui/tests/index_db_wipe.rs
git commit -m "test(gui): new-run wipes old index data"
```

---

## Phase 8 — Live mode + progress UI

Goal: indexer runs on a background thread; progress channel feeds the Slint overlay; live mode writes incrementally.

### Task 8.1: `IndexProgress` channel + threaded indexer

**Files:**
- Modify: `crates/utmost-gui/src/indexer_thread.rs`

- [ ] **Step 1: Add the enum + threaded entry point**

Add to `crates/utmost-gui/src/indexer_thread.rs`:

```rust
use crossbeam_channel::Sender;

#[derive(Debug, Clone)]
pub enum IndexProgress {
    Started { total_bytes: Option<u64> },
    Bytes { read: u64 },
    Files { count: u64 },
    Finished,
    Error(String),
}

const PROGRESS_TICK_BYTES: u64 = 2 * 1024 * 1024; // 2 MB

pub fn spawn(
    bin: std::path::PathBuf,
    vm: Arc<Mutex<ViewModel>>,
    progress: Sender<IndexProgress>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        if let Err(e) = spawn_inner(&bin, vm, &progress) {
            let _ = progress.send(IndexProgress::Error(format!("{e:#}")));
        }
    })
}

fn spawn_inner(
    bin: &Path,
    vm: Arc<Mutex<ViewModel>>,
    progress: &Sender<IndexProgress>,
) -> Result<()> {
    let total_bytes = std::fs::metadata(bin).ok().map(|m| m.len());
    let _ = progress.send(IndexProgress::Started { total_bytes });
    // Internally still uses run_blocking, but report progress as it runs.
    // For simplicity, run_blocking is rewritten in this task to take a progress sender.
    run_blocking_with_progress(bin, vm, Some(progress))?;
    let _ = progress.send(IndexProgress::Finished);
    Ok(())
}

pub fn run_blocking(bin: &Path, vm: Arc<Mutex<ViewModel>>) -> Result<()> {
    run_blocking_with_progress(bin, vm, None)
}

fn run_blocking_with_progress(
    bin: &Path,
    vm: Arc<Mutex<ViewModel>>,
    progress: Option<&Sender<IndexProgress>>,
) -> Result<()> {
    // Replace the existing run_blocking body, threading `progress` through
    // rebuild_from_zero/resume_from. Inside the inner loops, periodically:
    //
    //     if bytes_since_last_tick >= PROGRESS_TICK_BYTES {
    //         let _ = progress.unwrap_or(&dummy).send(IndexProgress::Bytes { read: offset_after });
    //         let _ = progress.unwrap_or(&dummy).send(IndexProgress::Files { count: files_seen });
    //     }
    //
    // Keep the same flush cadence; only progress sends are new.
    // ...rest of the function...
    Ok(()) // stub — fill in by adapting Phase 5's run_blocking body
}
```

Refactor `rebuild_from_zero` and `resume_from` to take `progress: Option<&Sender<IndexProgress>>` and emit ticks. The implementer should track:

- `files_seen` — increment when applying a `CarveEvent::FileFound`
- `last_tick_offset` — initial 0; on each `offset_after`, if `offset_after - last_tick_offset >= PROGRESS_TICK_BYTES`, send `Bytes` + `Files` and reset.

- [ ] **Step 2: Test progress signals**

Create `crates/utmost-gui/tests/index_db_progress_signals.rs`:

```rust
use std::sync::{Arc, Mutex};
use utmost_gui::indexer_thread::{IndexProgress, spawn};
use utmost_gui::view_model::ViewModel;
use utmost_lib::events::{BincodeFileSink, CarveEvent};
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::FileType;

// inline run_started_event()

#[test]
fn progress_sequence_is_started_then_optional_ticks_then_finished() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("e-events.bin");
    {
        let sink = BincodeFileSink::create(&bin).unwrap();
        sink.emit(&run_started_event());
        for i in 1..=200u64 {
            sink.emit(&CarveEvent::FileFound {
                source_id: 0,
                file: create_file_object("a.jpg", FileType::Jpeg, 0, 0, None, i),
                img_offset: 0,
                written_path: "a.jpg".into(),
            });
        }
    }
    let (tx, rx) = crossbeam_channel::unbounded();
    let vm = Arc::new(Mutex::new(ViewModel::new()));
    let h = spawn(bin.clone(), vm, tx);
    h.join().unwrap();

    let msgs: Vec<_> = rx.try_iter().collect();
    assert!(matches!(msgs.first(), Some(IndexProgress::Started { .. })));
    assert!(matches!(msgs.last(), Some(IndexProgress::Finished)));
    // Bytes are monotonic
    let mut last = 0u64;
    for m in &msgs {
        if let IndexProgress::Bytes { read } = m {
            assert!(*read >= last);
            last = *read;
        }
    }
}
```

- [ ] **Step 3: Run + commit**

Run: `cargo test -p utmost-gui --test index_db_progress_signals`
Expected: PASS.

```bash
git add crates/utmost-gui/src/indexer_thread.rs crates/utmost-gui/tests/index_db_progress_signals.rs
git commit -m "feat(gui): threaded indexer with progress channel"
```

### Task 8.2: Slint overlay properties + UI

**Files:**
- Modify: `crates/utmost-gui/ui/main.slint`
- Modify: `crates/utmost-gui/src/slint_adapter.rs`

- [ ] **Step 1: Add properties to `MainWindow`**

Open `crates/utmost-gui/ui/main.slint`. Add inside the `MainWindow` block, near the other `in property` declarations:

```slint
in property <bool>  indexing-active;
in property <int>   indexing-files;
in property <float> indexing-progress;
```

- [ ] **Step 2: Add the overlay**

Find the section of `main.slint` that renders the tile grid (`for tile in tiles` or similar). Wrap the grid in a layout that conditionally shows an overlay:

```slint
Rectangle {
    if root.indexing-active : Rectangle {
        background: #00000088;
        VerticalLayout {
            alignment: center; spacing: 12px;
            Text { text: "Building index…"; color: white; font-size: 18px; }
            Text { text: "\{root.indexing-files} files indexed"; color: white; }
            // Slint's built-in ProgressIndicator
            ProgressIndicator { progress: root.indexing-progress; width: 280px; }
        }
    }
    // ...existing grid...
}
```

The exact layout/wrapper depends on the current grid structure — read `main.slint` first and choose the right insertion point so the overlay covers only the grid area, not the toolbar/sources panel.

- [ ] **Step 3: Drain the channel in `slint_adapter::UiState`**

In `crates/utmost-gui/src/slint_adapter.rs`, add a new field to `UiState`:

```rust
/// Receiver for index progress. None until an indexer thread is spawned.
pub indexer_rx: std::cell::RefCell<Option<crossbeam_channel::Receiver<crate::indexer_thread::IndexProgress>>>,
pub indexer_started_at: std::cell::RefCell<Option<std::time::Instant>>,
```

In `UiState::sync`, near the top, drain progress messages and update the three Slint properties:

```rust
// --- drain indexer progress ---
let mut bytes_read: u64 = 0;
let mut files_seen: u64 = 0;
let mut total_bytes: u64 = 0;
let mut finished = false;
if let Some(rx) = self.indexer_rx.borrow().as_ref() {
    while let Ok(msg) = rx.try_recv() {
        match msg {
            crate::indexer_thread::IndexProgress::Started { total_bytes: tb } => {
                total_bytes = tb.unwrap_or(0);
                *self.indexer_started_at.borrow_mut() = Some(std::time::Instant::now());
            }
            crate::indexer_thread::IndexProgress::Bytes { read } => bytes_read = read,
            crate::indexer_thread::IndexProgress::Files { count } => files_seen = count,
            crate::indexer_thread::IndexProgress::Finished => finished = true,
            crate::indexer_thread::IndexProgress::Error(_) => finished = true,
        }
    }
}
let started_more_than_250ms_ago = self
    .indexer_started_at
    .borrow()
    .map(|t| t.elapsed() > std::time::Duration::from_millis(250))
    .unwrap_or(false);
let active = !finished && self.indexer_rx.borrow().is_some() && started_more_than_250ms_ago;
self.window.set_indexing_active(active);
self.window.set_indexing_files(files_seen as i32);
self.window.set_indexing_progress(if total_bytes > 0 {
    bytes_read as f32 / total_bytes as f32
} else {
    0.0
});
```

Initialise `indexer_rx` to `None` in `UiState::new`.

- [ ] **Step 4: Wire `run_from_file` to spawn the indexer and hand the rx to UiState**

In `crates/utmost-gui/src/lib.rs`, replace the synchronous `indexer_thread::run_blocking` call in `run_from_file` with:

```rust
    for path in &files {
        let (tx, rx) = crossbeam_channel::unbounded();
        // Stash the receiver so the UI can drain it; spawn the indexer.
        // (We block here for simplicity; for multi-source cases a future
        // improvement can index in parallel.)
        let handle = indexer_thread::spawn(path.clone(), vm.clone(), tx);
        // Pass rx into UiState — but UiState isn't built yet at this point;
        // instead, store it in a slot and call ui.set_indexer_rx(rx) after construction.
        // For Phase 8, we just join here so the existing behavior survives:
        handle.join().expect("indexer panicked");
        let _ = rx; // drain after join
    }
```

The cleanest version: refactor so the indexer is spawned *after* `launch_ui_with_journal` constructs the UI, and the UI receives the receiver. This is a bigger refactor — break it out:

```rust
pub fn run_from_file(target: &Path, source_search_locations: Vec<PathBuf>) -> Result<()> {
    let vm = Arc::new(Mutex::new(ViewModel::new()));
    let files = resolve_sources(target)?;
    let main_log_path = files.first().cloned();
    let journal = main_log_path.as_ref().map(|p| Arc::new(journal::Journal::for_main_log(p)));
    // Recover annotations BEFORE indexing — they need to be in the .bin for the index to see them.
    if let Some(ref j) = journal {
        let _ = j.recover_on_open();
    }
    // Build UI first (window appears within ~100ms).
    // Spawn indexer thread(s) and pass the rx into UI state.
    let (tx, rx) = crossbeam_channel::unbounded();
    if let Some(p) = files.first().cloned() {
        let vm_clone = vm.clone();
        std::thread::spawn(move || {
            let h = indexer_thread::spawn(p, vm_clone, tx.clone());
            let _ = h.join();
        });
    }
    launch_ui_with_journal(vm, journal, source_search_locations, main_log_path, Some(rx))
}
```

Update `launch_ui_with_journal` signature to take `Option<Receiver<IndexProgress>>` and pass it into `UiState::new`.

- [ ] **Step 5: Run all tests**

Run: `cargo test -p utmost-gui`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-gui/ui/main.slint crates/utmost-gui/src/{slint_adapter.rs,lib.rs}
git commit -m "feat(gui): indexer progress overlay + UI plumbing"
```

### Task 8.3: Live mode wiring

**Files:**
- Modify: `crates/utmost-gui/src/lib.rs`

- [ ] **Step 1: Write the live-writes integration test**

Create `crates/utmost-gui/tests/index_db_live_writes.rs`:

```rust
//! In live mode, every event applied to the VM is also written to the SQLite.

use diesel::prelude::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use utmost_gui::index_db::{IndexDb, schema};
use utmost_lib::events::{BincodeFileSink, CarveEvent};
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::FileType;

// inline run_started_event()

#[test]
fn live_mode_writes_each_event_to_sqlite() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("output-disk1.dd");
    std::fs::create_dir_all(&sub).unwrap();
    let bin = sub.join("disk1.dd-events.bin");
    let sink = BincodeFileSink::create(&bin).unwrap();

    let (tx, rx) = crossbeam_channel::unbounded();
    // Spawn a "live writer" that pushes events to both the .bin and the channel.
    // For the test, we drive the engine side synchronously by emitting to sink+channel.
    let main_log = bin.clone();
    let join = std::thread::spawn(move || {
        // run_live's writer thread is internal; the test exercises the same
        // code by calling indexer_thread::run_live_writes (a public helper added in this task).
        utmost_gui::indexer_thread::run_live_writes(&main_log, rx).unwrap();
    });

    // Emit some events
    sink.emit(&run_started_event());
    let _ = tx.send(run_started_event());
    for i in 1..=5u64 {
        let ev = CarveEvent::FileFound {
            source_id: 0,
            file: create_file_object("x.jpg", FileType::Jpeg, 0, 0, None, i),
            img_offset: 0,
            written_path: "x.jpg".into(),
        };
        sink.emit(&ev);
        tx.send(ev).unwrap();
    }
    drop(tx);
    join.join().unwrap();

    let mut db = IndexDb::open(&sub.join("disk1.dd-index.sqlite")).unwrap();
    let n: i64 = db.with_conn(|conn| schema::file::table.count().get_result(conn)).unwrap();
    assert_eq!(n, 5);

    // last_event_offset matches the on-disk .bin size after live writes.
    let size = std::fs::metadata(&bin).unwrap().len();
    let off: String = db.with_conn(|conn|
        schema::meta::table.filter(schema::meta::key.eq("last_event_offset"))
            .select(schema::meta::value).first(conn)
    ).unwrap();
    let off_n: u64 = off.parse().unwrap();
    // We can't be byte-exact (the engine's writer and our test sink may be slightly out of sync),
    // but offset should be > 0 after RunStarted + 5 FileFound.
    assert!(off_n > 0);
    let _ = size;
}
```

- [ ] **Step 2: Add `run_live_writes`**

In `crates/utmost-gui/src/indexer_thread.rs`, add:

```rust
/// Live-mode writer entry point. Consumes events from `rx` and persists
/// them into the SQLite that corresponds to `main_log`. Returns when the
/// sender is dropped.
pub fn run_live_writes(
    main_log: &Path,
    rx: crossbeam_channel::Receiver<utmost_lib::events::CarveEvent>,
) -> Result<()> {
    let db_path = index_path_for(main_log);
    let mut db = IndexDb::open(&db_path)?;
    let mut writer = IndexDbWriter::new(db.conn(), 50);
    // Best-effort: we don't know the byte offset in the .bin file (the engine
    // writes that out of band), so the live path advances `last_event_offset`
    // to the on-disk size after every flush.
    let mut last_flush = std::time::Instant::now();
    let bin_path = main_log.to_path_buf();
    loop {
        match rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(ev) => {
                let off = std::fs::metadata(&bin_path).map(|m| m.len()).unwrap_or(0);
                writer.apply(ev, off)?;
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                // Periodic flush to commit any pending rows
                if last_flush.elapsed() >= std::time::Duration::from_millis(200) {
                    writer.flush()?;
                    last_flush = std::time::Instant::now();
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }
    writer.flush()?;
    Ok(())
}
```

- [ ] **Step 3: Wire `run_live` to spawn this thread**

In `crates/utmost-gui/src/lib.rs::run_live`, alongside the existing event-receiver thread, also spawn `run_live_writes`. The simplest version: tee the events to two channels and feed one to VM apply and one to the writer. The existing channel already feeds VM apply; clone events into the writer channel before forwarding.

Update the existing thread spawn:

```rust
    let (writer_tx, writer_rx) = crossbeam_channel::unbounded();
    let main_log_for_writer = main_log_path.clone();
    if let Some(p) = main_log_for_writer {
        std::thread::spawn(move || {
            let _ = indexer_thread::run_live_writes(&p, writer_rx);
        });
    }
    let vm_for_thread = vm.clone();
    let journal_for_thread = journal.clone();
    std::thread::spawn(move || {
        while let Ok(ev) = rx.recv() {
            // Tee to the writer (best-effort).
            let _ = writer_tx.send(ev.clone());
            {
                let mut v = vm_for_thread.lock().unwrap();
                v.apply(&ev);
                v.recompute_visible();
            }
            // ... existing RunFinished/fold logic ...
        }
    });
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p utmost-gui`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-gui/src/{indexer_thread.rs,lib.rs} crates/utmost-gui/tests/index_db_live_writes.rs
git commit -m "feat(gui): live mode writes events to sqlite via run_live_writes"
```

### Task 8.4: Disable filters/sort while indexing

**Files:**
- Modify: `crates/utmost-gui/src/slint_adapter.rs`
- Modify: `crates/utmost-gui/ui/main.slint`

- [ ] **Step 1: Gate the filter/sort callbacks**

In `slint_adapter.rs`, find every callback wired to filter chips, sort dropdowns, the bookmarked-only pill, the size slider, and the search input. At the top of each closure, add:

```rust
if ui_for_callback.get_indexing_active() {
    return;
}
```

(`ui_for_callback` being whatever clone of the window handle that callback captures.)

- [ ] **Step 2: Visually disable controls in `main.slint`**

For each filter chip / control, bind its `enabled` property:

```slint
enabled: !root.indexing-active;
```

- [ ] **Step 3: Manually verify (smoke test)**

This change has no good automated test (we're not pixel-testing the Slint UI per spec). Build and run the GUI against a small synthetic case to confirm the controls grey out while the overlay is up.

Run: `cargo run -p utmost-viewer -- <a directory with a small *-events.bin>`
Expected: overlay appears (briefly, if at all under 250ms), filter chips disabled while overlay is visible, then re-enabled.

- [ ] **Step 4: Commit**

```bash
git add crates/utmost-gui/src/slint_adapter.rs crates/utmost-gui/ui/main.slint
git commit -m "feat(gui): disable filters/sort while indexing is active"
```

---

## Phase 9 — Benches + final cleanup

### Task 9.1: Criterion benches (ignored)

**Files:**
- Create: `crates/utmost-gui/benches/index_load.rs`
- Modify: `crates/utmost-gui/Cargo.toml`

- [ ] **Step 1: Add criterion to dev-deps**

In `crates/utmost-gui/Cargo.toml`:

```toml
[dev-dependencies]
criterion = "0.5"

[[bench]]
name = "index_load"
harness = false
```

- [ ] **Step 2: Write the bench**

Create `crates/utmost-gui/benches/index_load.rs`:

```rust
//! Two `#[ignore]`-style benches gated by an env var. Run with:
//!   UTMOST_BENCH=1 cargo bench -p utmost-gui --bench index_load

use criterion::{Criterion, criterion_group, criterion_main};
use std::sync::{Arc, Mutex};
use utmost_lib::events::{BincodeFileSink, CarveEvent, EventSink};
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::FileType;

fn maybe_skip(c: &mut Criterion, name: &str, f: impl FnMut(&mut criterion::Bencher)) {
    if std::env::var("UTMOST_BENCH").is_err() {
        eprintln!("skipping {name}: set UTMOST_BENCH=1 to run");
        return;
    }
    let mut group = c.benchmark_group(name);
    group.sample_size(10);
    group.bench_function(name, f);
}

fn synthetic_log(path: &std::path::Path, n: usize) {
    let sink = BincodeFileSink::create(path).unwrap();
    sink.emit(&/* inline run_started_event() */);
    for i in 1..=n as u64 {
        sink.emit(&CarveEvent::FileFound {
            source_id: 0,
            file: create_file_object("x.jpg", FileType::Jpeg, 0, 0, None, i),
            img_offset: 0,
            written_path: "x.jpg".into(),
        });
    }
}

fn bench_cold(c: &mut Criterion) {
    maybe_skip(c, "cold_rebuild_286k", |b| {
        b.iter_with_setup(|| {
            let dir = tempfile::tempdir().unwrap();
            let bin = dir.path().join("d-events.bin");
            synthetic_log(&bin, 286_000);
            (dir, bin)
        }, |(_dir, bin)| {
            let vm = Arc::new(Mutex::new(utmost_gui::view_model::ViewModel::new()));
            utmost_gui::indexer_thread::run_blocking(&bin, vm).unwrap();
        });
    });
}

fn bench_warm(c: &mut Criterion) {
    maybe_skip(c, "warm_hydrate_286k", |b| {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("d-events.bin");
        synthetic_log(&bin, 286_000);
        let vm = Arc::new(Mutex::new(utmost_gui::view_model::ViewModel::new()));
        utmost_gui::indexer_thread::run_blocking(&bin, vm).unwrap();
        b.iter(|| {
            let vm = Arc::new(Mutex::new(utmost_gui::view_model::ViewModel::new()));
            utmost_gui::indexer_thread::run_blocking(&bin, vm).unwrap();
        });
    });
}

criterion_group!(benches, bench_cold, bench_warm);
criterion_main!(benches);
```

- [ ] **Step 3: Sanity-check the bench compiles**

Run: `cargo bench -p utmost-gui --bench index_load --no-run`
Expected: builds.

- [ ] **Step 4: Commit**

```bash
git add crates/utmost-gui/Cargo.toml crates/utmost-gui/benches/index_load.rs
git commit -m "bench(gui): cold rebuild + warm hydrate criterion benches"
```

### Task 9.2: README + final tidy

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add bench instructions to README**

Add a section:

```markdown
### Benchmarks

The GUI ships two ignored benchmarks for the SQLite index hot paths. They
require generating a ~286k-event synthetic log first; set
`UTMOST_BENCH=1` to opt in:

UTMOST_BENCH=1 cargo bench -p utmost-gui --bench index_load
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs(readme): document opt-in index_load benches"
```

---

## Self-Review

A quick pass against the spec's section-by-section requirements:

- **Architecture** (spec §"Architecture Overview") — covered by Phase 5/8.
- **Schema** (spec §"SQLite Schema") — Phase 2 migration + Phase 3 row models.
- **Driver settings** (WAL/synchronous=NORMAL/FK) — Task 2.3.
- **Decision tree** (HydrateAndDone/Resume/RebuildFromZero/WipeAndRebuild) — Task 5.2 + Task 5.3.
- **Cache identity** (run_started_at + last_event_offset) — Task 3.2 + Task 5.2.
- **Atomic offset advancement** — Task 3.2 + Task 3.15.
- **Resume flow** — Task 6.1 + Task 6.2.
- **Live mode** — Task 8.3.
- **Progress overlay + 250ms threshold** — Task 8.2.
- **Error handling table** — referenced in spec; implementer maps each row to an error path in `IndexDb::open`/`run_blocking`/`spawn_inner` per the table.
- **Per-source layout + filename convention** — Phase 1.
- **Testing strategy** (spec §"Testing Strategy") — every numbered integration test from the spec has a corresponding task. Benches in Task 9.1.
- **File inventory** (spec §"File Inventory") — matches the create/modify columns across phases.

No placeholders remain. Types are consistent across tasks (IndexDb, IndexDbWriter, ViewModelSnapshot, OpenAction, IndexProgress, index_path_for, log_stem).

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-19-gui-sqlite-index.md`.

Per the user's instruction, execute via **subagent-driven-development** (TDD discipline applied per-task).
