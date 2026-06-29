# CLIP Semantic Search + turso Migration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate utmost's per-case index from Diesel/SQLite to turso (extracting a shared `utmost-index` crate), then add CLIP semantic image search (background processing + `\` status panel + search box) on top.

**Architecture:** Phase 1 swaps the Diesel index layer for turso behind the *same sync public API* (bodies wrap a `block_on` bridge over turso's async API), and moves the index + preview code into a new native `utmost-index` crate that `utmost-gui` and `utmost-cli` depend on. Phase 2 adds, behind a default-on `clip` cargo feature, a `clipper`-based embedder (LAION ViT-L/14, 768-dim), a `clip_embedding` F32_BLOB table, a shared two-phase processing engine (previews-for-all → embed-from-preview), a CLI `process` command, a GUI background worker with a `\`-toggled status panel, and a `vector_distance_cos` search box.

**Tech Stack:** Rust (edition 2024), turso `0.7.0-pre.10` (pure-Rust SQLite + vector ext), deadpool, tokio (rt-multi-thread), Slint, `clipper` (git), candle (via clipper), `image`.

## Global Constraints

- **Edition 2024** for the new `utmost-index` crate (`edition = "2024"`), matching the workspace and `rustfmt.toml`.
- **turso pinned exactly** to `0.7.0-pre.10`, `default-features = false`.
- **`utmost-lib` stays WASM-safe** — it gets NO turso, clipper, candle, tokio, or hf-hub deps. All such deps live in `utmost-index` (native-only).
- **No migration framework / no versioned schema** — schema is created with idempotent `CREATE TABLE IF NOT EXISTS`. The per-case `<slug>-index.sqlite` is a derived cache rebuildable from `<slug>-events.bin`.
- **CLIP gated behind a `clip` cargo feature, default ON** (`default = ["clip"]`). `--no-default-features` builds with no candle/hf-hub/tokenizers.
- **Active model:** `laion/CLIP-ViT-L-14-laion2B-s32B-b82K`, dim `768`. Constants `ACTIVE_MODEL` / `ACTIVE_DIM`.
- **clipper dep:** `clipper = { git = "https://github.com/stevenwcarter/clipper-rs", optional = true }`.
- **Public sync signatures of the ported DB functions are preserved** so utmost-gui call sites change only their `use` paths.
- **After every code change:** `cargo fmt` then `cargo clippy --all-targets`, fix all warnings (pre-commit hook enforces this).
- **Spec:** `docs/superpowers/specs/2026-06-28-clip-semantic-search-turso-migration-design.md`.

## File Structure

**New crate `crates/utmost-index/`:**
- `Cargo.toml` — turso/deadpool/tokio/image deps; `clip` feature → `clipper`.
- `src/lib.rs` — crate root; `pub mod db; pub mod preview; pub mod discover;` + `#[cfg(feature="clip")] pub mod clip; pub mod processing;` re-exports.
- `src/db/mod.rs` — `IndexDb`, `TursoPool`, `block_on`, `OPEN` removal.
- `src/db/schema_sql.rs` — `create_schema(conn)`.
- `src/db/models.rs` — plain row structs + `col_*` mappers + `file_row_to_found_file`.
- `src/db/queries.rs` — the 5 read fns (+ Phase-2 search branch & count/get fns).
- `src/db/writer.rs` — the 11 write fns (+ Phase-2 `set_clip_embedding`).
- `src/db/hydrate.rs` — `snapshot_from_db`.
- `src/preview/` — moved from utmost-gui (`mod.rs` + renderers).
- `src/discover.rs` — moved from utmost-gui (`<slug>-events.bin` scan).
- `src/clip/mod.rs` — embedder wrapper (`#[cfg(feature="clip")]`).
- `src/processing.rs` — `ProcessPhase`, `ProcessCounts`, `process_next_batch`, `run_to_completion`.

**Modified in `crates/utmost-gui/`:** `Cargo.toml` (drop diesel, add utmost-index), `src/lib.rs`, `src/case.rs`, `src/picker.rs`, `src/indexer_thread.rs`, `src/thumb_worker.rs`, `src/slint_adapter.rs`, `src/view_model.rs`, `src/processor.rs` (NEW), `ui/detail.slint`, `ui/main.slint`. Old `src/index_db/`, `src/preview/`, `src/discover.rs` are deleted (moved).

**Modified in `crates/utmost-cli/`:** `Cargo.toml` (optional utmost-index dep), `src/main.rs` (`process` subcommand).

**Modified workspace:** `Cargo.toml` (members already `crates/*`; swap deps), `CLAUDE.md`, `README.md`.

---

# PHASE 1 — turso migration

### Task 1: Scaffold `utmost-index` crate + turso connection layer

**Files:**
- Create: `crates/utmost-index/Cargo.toml`, `crates/utmost-index/src/lib.rs`, `crates/utmost-index/src/db/mod.rs`
- Modify: `Cargo.toml` (workspace deps)
- Test: inline `#[cfg(test)]` in `crates/utmost-index/src/db/mod.rs`

**Interfaces:**
- Produces: `utmost_index::db::block_on<F>`, `utmost_index::db::TursoPool` (`open(&Path) -> Result<Self>`, async `get()`), `utmost_index::db::IndexDb` (`open(&Path) -> Result<Self>`, `open_in_memory() -> Result<Self>`, `pool(&self) -> &TursoPool`).

- [ ] **Step 1: Add workspace deps.** In root `Cargo.toml` `[workspace.dependencies]`, remove `diesel`, `diesel_migrations`, `libsqlite3-sys`; add:

```toml
turso = { version = "0.7.0-pre.10", default-features = false }
deadpool = { version = "0.13", features = ["managed"] }
tokio = { version = "1", features = ["rt-multi-thread"] }
```

(Leave `image`, `anyhow`, `chrono`, `serde`, `serde_json` as-is — reused by utmost-index.)

- [ ] **Step 2: Create `crates/utmost-index/Cargo.toml`:**

```toml
[package]
name = "utmost-index"
version = "0.1.0"
edition = "2024"

[features]
default = ["clip"]
clip = ["dep:clipper"]

[dependencies]
utmost-lib = { path = "../utmost-lib" }
turso = { workspace = true }
deadpool = { workspace = true }
tokio = { workspace = true }
image = { workspace = true }
anyhow = { workspace = true }
chrono = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
clipper = { git = "https://github.com/stevenwcarter/clipper-rs", optional = true }

[dev-dependencies]
tempfile = { workspace = true }
```

(Match exact workspace-dep style already used by the other crates; if they inline versions rather than `workspace = true`, follow that.)

- [ ] **Step 3: Write the failing test** in `crates/utmost-index/src/db/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_in_memory_runs_a_trivial_query() {
        let db = IndexDb::open_in_memory().expect("open");
        let pool = db.pool().clone();
        let n: i64 = block_on(async {
            let conn = pool.get().await.unwrap();
            let mut rows = conn.query("SELECT 1", ()).await.unwrap();
            let row = rows.next().await.unwrap().unwrap();
            *row.get_value(0).unwrap().as_integer().unwrap()
        });
        assert_eq!(n, 1);
    }
}
```

- [ ] **Step 4: Run it, expect FAIL** (`block_on`/`IndexDb` undefined):

Run: `cargo test -p utmost-index open_in_memory_runs_a_trivial_query`
Expected: compile error — `IndexDb`/`block_on` not found.

- [ ] **Step 5: Implement `crates/utmost-index/src/lib.rs`:**

```rust
pub mod db;
pub mod preview;   // populated in Task 6 — stub `pub mod preview {}` until then
```

(For Task 1, comment out `pub mod preview;` or create an empty `src/preview/mod.rs`; it is filled in Task 6.)

- [ ] **Step 6: Implement `crates/utmost-index/src/db/mod.rs`** connection layer:

```rust
use anyhow::{Context, Result};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

pub mod schema_sql;     // Task 2
pub mod models;         // Task 3
pub mod queries;        // Task 5
pub mod writer;         // Task 4
pub mod hydrate;        // Task 5

static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build shared DB tokio runtime")
});

/// Bridge sync callers to turso's async API.
pub fn block_on<F: Future>(fut: F) -> F::Output {
    RUNTIME.block_on(fut)
}

#[derive(Clone)]
pub struct TursoPool {
    inner: deadpool::managed::Pool<TursoManager>,
    pub path: PathBuf,
}

pub struct TursoManager {
    db: turso::Database,
}

impl deadpool::managed::Manager for TursoManager {
    type Type = turso::Connection;
    type Error = anyhow::Error;

    async fn create(&self) -> Result<turso::Connection> {
        let conn = self.db.connect().context("connect turso")?;
        conn.busy_timeout(std::time::Duration::from_millis(5000))?;
        conn.execute("PRAGMA foreign_keys = ON", ()).await?;
        let mut rows = conn.query("PRAGMA journal_mode = WAL", ()).await?;
        while rows.next().await?.is_some() {}
        Ok(conn)
    }

    async fn recycle(
        &self,
        _conn: &mut turso::Connection,
        _: &deadpool::managed::Metrics,
    ) -> deadpool::managed::RecycleResult<anyhow::Error> {
        Ok(())
    }
}

impl TursoPool {
    pub fn open(path: &Path) -> Result<Self> {
        let path_str = path.to_str().context("non-utf8 db path")?;
        let db = block_on(async {
            turso::Builder::new_local(path_str).build().await
        })
        .with_context(|| format!("open turso database at {path:?}"))?;
        let mgr = TursoManager { db };
        let inner = deadpool::managed::Pool::builder(mgr)
            .build()
            .context("build turso pool")?;
        Ok(Self { inner, path: path.to_path_buf() })
    }

    pub async fn get(&self) -> Result<deadpool::managed::Object<TursoManager>> {
        self.inner.get().await.context("checkout turso connection")
    }
}

pub struct IndexDb {
    pool: TursoPool,
}

impl IndexDb {
    pub fn open(path: &Path) -> Result<Self> {
        let pool = TursoPool::open(path)?;
        let p = pool.clone();
        block_on(async {
            let conn = p.get().await?;
            schema_sql::create_schema(&conn).await
        })?;
        Ok(Self { pool })
    }

    pub fn open_in_memory() -> Result<Self> {
        // turso supports ":memory:" via new_local; verify against 0.7.0-pre.10.
        Self::open(Path::new(":memory:"))
    }

    pub fn pool(&self) -> &TursoPool {
        &self.pool
    }
}
```

> Implementer note: confirm the exact turso API names against `0.7.0-pre.10` (`Builder::new_local`, `db.connect()`, `conn.busy_timeout`, `conn.query/execute`, `Row::get_value`, `Value::as_integer`). imgfind at `~/src/imgfind/src/db_pool.rs` + `database.rs` is the reference implementation — match it. If `:memory:` is unsupported, change `open_in_memory` to a unique tempfile (e.g. `tempfile::Builder` path) and update tests accordingly.

For Task 1 only, make `schema_sql::create_schema` a temporary no-op (`pub async fn create_schema(_c: &turso::Connection) -> anyhow::Result<()> { Ok(()) }`) so this compiles; Task 2 fills it. Same for the other `pub mod`s — create empty files.

- [ ] **Step 7: Run the test, expect PASS:**

Run: `cargo test -p utmost-index open_in_memory_runs_a_trivial_query`
Expected: PASS.

- [ ] **Step 8: fmt + clippy + commit:**

```bash
cargo fmt && cargo clippy -p utmost-index --all-targets
git add crates/utmost-index Cargo.toml
git commit -m "feat(index): scaffold utmost-index crate + turso connection layer"
```

---

### Task 2: Schema — `create_schema`

**Files:**
- Modify: `crates/utmost-index/src/db/schema_sql.rs`
- Test: inline in `schema_sql.rs`

**Interfaces:**
- Produces: `pub async fn create_schema(conn: &turso::Connection) -> anyhow::Result<()>`.

**Source of truth:** translate `crates/utmost-gui/migrations/0001_initial/up.sql`, `0002_preview_status/up.sql`, `0003_preview_blob/up.sql` into one idempotent set of `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS`. Read those three files first and reproduce every column/type/index exactly. `file.preview_status TEXT NOT NULL DEFAULT 'unknown'` is inline in the `file` table. Skip the migrations' data-backfill statements.

- [ ] **Step 1: Write the failing test:**

```rust
#[cfg(test)]
mod tests {
    use crate::db::{block_on, IndexDb};

    #[test]
    fn create_schema_makes_all_tables_and_is_idempotent() {
        let db = IndexDb::open_in_memory().unwrap(); // open() already ran create_schema
        let pool = db.pool().clone();
        let names: Vec<String> = block_on(async {
            // running it again must not error (idempotent)
            let conn = pool.get().await.unwrap();
            crate::db::schema_sql::create_schema(&conn).await.unwrap();
            let mut rows = conn
                .query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name", ())
                .await
                .unwrap();
            let mut out = Vec::new();
            while let Some(r) = rows.next().await.unwrap() {
                out.push(r.get_value(0).unwrap().as_text().unwrap().to_string());
            }
            out
        });
        for t in ["meta","run","source","file","bookmark","note","best_choice","recovery_run","variant","preview_blob"] {
            assert!(names.contains(&t.to_string()), "missing table {t}");
        }
    }
}
```

- [ ] **Step 2: Run, expect FAIL** (tables absent — current `create_schema` is the no-op stub).

Run: `cargo test -p utmost-index create_schema_makes_all_tables`
Expected: FAIL (assert "missing table meta").

- [ ] **Step 3: Implement `create_schema`** — issue each statement via `conn.execute(sql, ()).await?`. Example shape (fill ALL columns from the migration files):

```rust
use anyhow::Result;

pub async fn create_schema(conn: &turso::Connection) -> Result<()> {
    const STMTS: &[&str] = &[
        "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        // run, source, file (WITH preview_status TEXT NOT NULL DEFAULT 'unknown'),
        // bookmark, note, best_choice, recovery_run, variant, preview_blob ...
        // indexes:
        "CREATE INDEX IF NOT EXISTS idx_file_filter ON file (source_id, file_type, filesize, img_offset)",
        "CREATE INDEX IF NOT EXISTS idx_note_file ON note (file_id)",
        "CREATE INDEX IF NOT EXISTS idx_variant_candidate ON variant (candidate_file_id)",
        "CREATE INDEX IF NOT EXISTS idx_file_preview_status ON file (preview_status)",
        "INSERT OR IGNORE INTO meta (key, value) VALUES ('preview_status_version', '0')",
    ];
    for s in STMTS {
        conn.execute(s, ()).await?;
    }
    Ok(())
}
```

> Reproduce the exact column lists/types from the three migration `up.sql` files. Diesel `BigInt`→`INTEGER`, `Integer`→`INTEGER`, `Double`→`REAL`, `Text`→`TEXT`, `Binary`→`BLOB`, `Nullable<T>`→ omit `NOT NULL`. Preserve PK declarations.

- [ ] **Step 4: Run, expect PASS.**

Run: `cargo test -p utmost-index create_schema`
Expected: PASS.

- [ ] **Step 5: fmt + clippy + commit:**

```bash
cargo fmt && cargo clippy -p utmost-index --all-targets
git add crates/utmost-index/src/db/schema_sql.rs
git commit -m "feat(index): turso schema via idempotent create_schema"
```

---

### Task 3: Row models + manual mappers

**Files:**
- Modify: `crates/utmost-index/src/db/models.rs`
- Test: inline

**Interfaces:**
- Produces: plain structs `MetaRow, RunRow, SourceRow, FileRow, BookmarkRow, NoteRow, BestChoiceRow, RecoveryRunRow, VariantRow, PreviewBlobRow, FileStub, PickerMetadataRow`; mapper helpers `col_i64`, `col_opt_i64`, `col_text`, `col_opt_text`, `col_f64`, `col_blob`; `file_row_to_found_file(FileRow, output_root: &Path) -> FoundFile`.

**Source:** port `crates/utmost-gui/src/index_db/models.rs`, stripping Diesel derives. Keep field names/types and `file_row_to_found_file`.

- [ ] **Step 1: Write the failing test** (mapper round-trip over a real row):

```rust
#[cfg(test)]
mod tests {
    use crate::db::{block_on, models, IndexDb};

    #[test]
    fn col_helpers_read_typed_values() {
        let db = IndexDb::open_in_memory().unwrap();
        let pool = db.pool().clone();
        block_on(async {
            let conn = pool.get().await.unwrap();
            conn.execute("INSERT INTO meta (key, value) VALUES ('k', 'v')", ()).await.unwrap();
            let mut rows = conn.query("SELECT key, value FROM meta WHERE key='k'", ()).await.unwrap();
            let row = rows.next().await.unwrap().unwrap();
            assert_eq!(models::col_text(&row, 0, "key").unwrap(), "k");
            assert_eq!(models::col_text(&row, 1, "value").unwrap(), "v");
        });
    }
}
```

- [ ] **Step 2: Run, expect FAIL** (`models::col_text` undefined).
- [ ] **Step 3: Implement** the `col_*` helpers (copy imgfind's `col_i64`/`col_text` from `~/src/imgfind/src/database.rs:38-83`, add `col_blob`, `col_f64`, `col_opt_*`) and the plain row structs + `file_row_to_found_file` (ported from the gui models). 
- [ ] **Step 4: Run, expect PASS.**
- [ ] **Step 5: fmt + clippy + commit** (`feat(index): plain row models + turso column mappers`).

---

### Task 4: Port the write surface

**Files:**
- Modify: `crates/utmost-index/src/db/writer.rs`
- Test: inline (port the 4 writer tests)

**Interfaces:**
- Consumes: `models::*`, `col_*`, `IndexDb::pool`, `block_on`.
- Produces (same sync signatures as today): `IndexDbWriter::new(pool: TursoPool, batch_size: usize)`, `IndexDbWriter::apply(&mut self, CarveEvent, u64) -> Result<()>`, `IndexDbWriter::flush(&mut self) -> Result<()>`; free fns `write_preview_outcomes(pool, &[PreviewOutcome]) -> Result<()>`, `apply_annotation_event(pool, &CarveEvent) -> Result<()>`, `write_ui_state(pool, &UiStateSnapshot) -> Result<()>`, `read_ui_state(pool) -> Result<Option<UiStateSnapshot>>`, `preview_blob_lookup(pool, file_id: u64) -> Result<Option<PreviewBlobRow>>`; internal `upsert_meta`, `read_meta_i64`, `read_meta_str`.

> Note: signatures take `pool: &TursoPool` (or `&TursoPool`-holding `IndexDb`) instead of `&mut SqliteConnection`. Update call sites accordingly in Task 7. Each fn body uses `block_on(async { let conn = pool.get().await?; ... })`. `PreviewOutcome`/`PreviewStatus`/`PreviewCodec`/`UiStateSnapshot`/`FilterStateSnapshot` move with this task or Task 6 — define/import them in utmost-index; re-export from utmost-gui in Task 7.

**Translation patterns** (apply to every fn; one fully worked example below):
- Upsert: `INSERT ... ON CONFLICT(pk) DO UPDATE SET col = excluded.col, ...`.
- Transaction: `let tx = conn.transaction().await?; ...; tx.commit().await?;`.
- Params: tuple `(turso::Value::Integer(x), turso::Value::Text(s), ...)` or `turso::params_from_iter(vec)`.

- [ ] **Step 1: Port `upsert_meta` + write a failing test** for it:

```rust
#[cfg(test)]
mod tests {
    use crate::db::{block_on, writer, IndexDb};

    #[test]
    fn upsert_meta_inserts_then_updates() {
        let db = IndexDb::open_in_memory().unwrap();
        let pool = db.pool().clone();
        writer::write_ui_state_value_for_test(&pool, "x", "1"); // tiny helper or call upsert path
        // ... assert read_meta_str == "1", upsert again to "2", assert "2"
    }
}
```

(Adjust to whatever minimal public seam exposes `upsert_meta`; if it's private, test it via `write_ui_state` round-trip instead.)

- [ ] **Step 2: Run, expect FAIL.**

- [ ] **Step 3: Implement.** Worked example — `upsert_meta`:

```rust
pub(crate) async fn upsert_meta(conn: &turso::Connection, key: &str, value: &str) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (turso::Value::Text(key.to_string()), turso::Value::Text(value.to_string())),
    )
    .await?;
    Ok(())
}
```

Then port, in this order, reproducing current behavior exactly (read `crates/utmost-gui/src/index_db/writer.rs` for each): `read_meta_str`, `read_meta_i64`, `write_ui_state` (txn → `upsert_meta(conn,"ui_state",&json)`), `read_ui_state` (read + `serde_json::from_str`; corrupt → `Ok(None)`), `preview_blob_lookup`, `apply_event` (exhaustive 13 `CarveEvent` variants — port each upsert/insert), `IndexDbWriter::{new,apply,flush}` (flush = one txn: loop `apply_event`, then `upsert_meta` for `last_event_offset`/`last_event_count`/`indexed_at`), `write_preview_outcomes` (txn: per-outcome `UPDATE file SET preview_status`, `INSERT OR REPLACE INTO preview_blob`, then bump `preview_status_version`), `apply_annotation_event`.

- [ ] **Step 4: Port the 4 writer tests** from `crates/utmost-gui/src/index_db/writer.rs` (event apply/flush round-trip, write_preview_outcomes, ui_state round-trip incl. corrupt→None, upsert idempotency). Adapt to the `pool`-based signatures + `block_on`.

- [ ] **Step 5: Run all writer tests, expect PASS:**

Run: `cargo test -p utmost-index --lib db::writer`
Expected: PASS.

- [ ] **Step 6: fmt + clippy + commit** (`feat(index): port write surface to turso`).

---

### Task 5: Port the read surface + hydrate

**Files:**
- Modify: `crates/utmost-index/src/db/queries.rs`, `crates/utmost-index/src/db/hydrate.rs`
- Test: inline (port the 11 queries tests)

**Interfaces:**
- Consumes: `models::*`, `col_*`, `TursoPool`, `block_on`, `utmost_lib::FilterState` (or wherever `FilterState` lives — confirm; if it's in utmost-gui's `view_model.rs`, it must move to utmost-index since `query_match_ids` consumes it).
- Produces (same sync signatures): `query_match_ids(pool, &FilterState) -> Result<Vec<FileStub>>`, `fetch_window(pool, &[u64]) -> Result<Vec<FoundFile>>`, `read_output_root(pool) -> Result<PathBuf>`, `set_preview_status(pool, u64, &str) -> Result<()>`, `picker_metadata_row(pool) -> Result<PickerMetadataRow>`; `hydrate::snapshot_from_db(pool) -> Result<ViewModelSnapshot>`.

> **`FilterState` placement:** `query_match_ids` consumes `FilterState`; `FilterState` currently lives in `utmost-gui/src/view_model.rs`. Move `FilterState`, `SortKey`, `SortDir`, `FilterState`'s `search_query` field is added in Phase 2 — for Phase 1 move it as-is. Move `FileStub` (already used here) and `FoundFile`/`ViewModelSnapshot` only if they don't create a cycle; otherwise keep `FoundFile`/`ViewModelSnapshot` in utmost-gui and have `query_match_ids`/`hydrate` return them via a shared location. **Decision:** move `FilterState`/`SortKey`/`SortDir`/`FileStub`/`FoundFile`/`ViewModelSnapshot` into a `utmost_index::model` module (these are plain data, Slint-free) and re-export from utmost-gui. Confirm no Slint types are embedded; if any are, leave that type in gui and split the struct.

- [ ] **Step 1: Port `query_match_ids`** keeping its dynamic-SQL builder; map the `Param::{Int,Big,Str}` enum to `turso::Value`, bind via `turso::params_from_iter`. **Write/port the failing filter-matrix test first** (the existing 1500-row fixture test in `crates/utmost-gui/src/index_db/queries.rs`).
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** `query_match_ids`, then `fetch_window` (preserve requested-order reordering of the `IN (...)` result — build a `HashMap<id, row>` then index by `ids` order), `read_output_root`, `set_preview_status` (txn: UPDATE + bump version), `picker_metadata_row`, and `hydrate::snapshot_from_db` (read all tables, build counts/notes/bookmarks/best_choices/variants — port row-by-row).
- [ ] **Step 4: Port all 11 queries tests + the hydrate test(s).**
- [ ] **Step 5: Run, expect PASS:**

Run: `cargo test -p utmost-index --lib db::queries db::hydrate`
Expected: PASS.

- [ ] **Step 6: fmt + clippy + commit** (`feat(index): port read surface + hydrate to turso`).

---

### Task 6: Move preview generation + discovery into utmost-index

**Files:**
- Create: `crates/utmost-index/src/preview/` (moved), `crates/utmost-index/src/discover.rs` (moved)
- Modify: `crates/utmost-index/src/lib.rs`
- Delete: (in Task 7) `crates/utmost-gui/src/preview/`, `crates/utmost-gui/src/discover.rs`
- Test: move the preview/discover tests with the code.

**Interfaces:**
- Produces: `utmost_index::preview::{render_with_fallback, render_full_with_fallback, encode_thumb_to_jpeg, PreviewRegistry, PreviewOutput, Kind}`, `utmost_index::preview::{PreviewOutcome, PreviewStatus, PreviewCodec}`, `utmost_index::discover::scan_cases(dir: &Path) -> Vec<...>` (current return type).

- [ ] **Step 1:** Copy `crates/utmost-gui/src/preview/**` and `src/discover.rs` into `crates/utmost-index/src/`. Adjust `use` paths (`crate::source_resolver` → confirm `source_resolver` is Slint-free; if so move it too, else it stays in gui and preview takes it as a generic/param). **Verify nothing in `preview/` or `discover.rs` imports `slint`** — grep first. If `source_resolver` is needed and Slint-free, move it to `utmost-index` as well.
- [ ] **Step 2:** Add `pub mod preview; pub mod discover;` (and `pub mod source_resolver;` if moved) to `crates/utmost-index/src/lib.rs`.
- [ ] **Step 3: Run the moved tests** to verify they pass in the new crate:

Run: `cargo test -p utmost-index preview discover`
Expected: PASS (same tests, new location).

- [ ] **Step 4: fmt + clippy + commit** (`refactor(index): move preview generation + case discovery into utmost-index`).

---

### Task 7: Rewire utmost-gui onto utmost-index; delete Diesel

**Files:**
- Modify: `crates/utmost-gui/Cargo.toml`, `src/lib.rs`, `src/case.rs`, `src/picker.rs`, `src/indexer_thread.rs`, `src/thumb_worker.rs`, `src/slint_adapter.rs`, `src/view_model.rs`
- Delete: `crates/utmost-gui/src/index_db/`, `src/preview/`, `src/discover.rs`, `crates/utmost-gui/migrations/`
- Test: full `cargo test` + manual smoke.

**Interfaces:**
- Consumes: everything produced by Tasks 1–6.

- [ ] **Step 1:** `crates/utmost-gui/Cargo.toml`: remove `diesel`, `diesel_migrations`, `libsqlite3-sys`; add `utmost-index = { path = "../utmost-index" }`.
- [ ] **Step 2:** Delete `crates/utmost-gui/src/index_db/`, `src/preview/`, `src/discover.rs`, `crates/utmost-gui/migrations/`. Add re-export shims in `src/lib.rs`:

```rust
pub use utmost_index::db as index_db;
pub use utmost_index::preview;
pub use utmost_index::discover;
pub use utmost_index::model::{FilterState, SortKey, SortDir, FileStub, FoundFile, ViewModelSnapshot};
```

- [ ] **Step 3:** Update each call site (`case.rs`, `picker.rs`, `indexer_thread.rs`, `thumb_worker.rs`, `slint_adapter.rs`, `view_model.rs`) to the new function signatures: pass a `TursoPool` (held by `CaseHandle`) instead of `&mut SqliteConnection`. **Pool ownership:** `CaseHandle` opens one `TursoPool` per case and shares clones with the indexer-writer + query-loop threads; `picker.rs` opens short-lived pools per row read; `thumb_worker.rs` gets a pool clone for `preview_blob_lookup`. Remove the old `OPEN_GUARD` usage.
- [ ] **Step 4:** Build:

Run: `cargo build`
Expected: clean compile (fix all `use`/signature mismatches).

- [ ] **Step 5: Run the whole suite:**

Run: `cargo test`
Expected: PASS (all ported tests + existing gui tests).

- [ ] **Step 6: Port the concurrency test** — re-add `concurrent_open_on_same_path_does_not_lock` against `TursoPool`/`IndexDb` (in `utmost-index/src/db/mod.rs`); run it.

- [ ] **Step 7: Manual smoke** (per spec Phase 1 verification): build the viewer, open an existing output dir; picker rows, case open, filter/sort, thumbnails, bookmarks/notes, UI-state persistence behave as before; an existing Diesel-era `.sqlite` opens without rebuild. Record the result in the task report.

- [ ] **Step 8: fmt + clippy (workspace) + commit:**

```bash
cargo fmt && cargo clippy --all-targets
git add -A
git commit -m "refactor(gui): migrate index layer from Diesel to turso via utmost-index"
```

---

# PHASE 2 — CLIP semantic search

### Task 8: clip embedder wrapper

**Files:**
- Create: `crates/utmost-index/src/clip/mod.rs`
- Modify: `crates/utmost-index/src/lib.rs` (`#[cfg(feature="clip")] pub mod clip;`)
- Test: inline (pure helpers; model load `#[ignore]`).

**Interfaces:**
- Produces: `clip::ACTIVE_MODEL: &str`, `clip::ACTIVE_DIM: usize`, `clip::Embedder` (newtype over `Arc<OnceLock<clipper::ClipEmbedder>>` with `start_loading() ` + `is_ready()` + `get() -> Option<&ClipEmbedder>`), `clip::embed_image_from_bytes(&ClipEmbedder, &[u8]) -> Result<Vec<f32>>`, `clip::embed_text(&ClipEmbedder, &str) -> Result<Vec<f32>>`, `clip::normalize_vector(&[f32]) -> Vec<f32>`, `clip::to_le_bytes(&[f32]) -> Vec<u8>`, `clip::EmbedFn` trait (for test injection — `fn embed_image(&self, &[u8]) -> Result<Vec<f32>>`).

- [ ] **Step 1: Write failing tests** for the pure helpers:

```rust
#[test]
fn normalize_vector_is_unit_length() {
    let v = super::normalize_vector(&[3.0, 4.0]);
    let mag: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    assert!((mag - 1.0).abs() < 1e-6);
}
#[test]
fn to_le_bytes_roundtrips() {
    let v = vec![1.0f32, -2.5, 0.0];
    let b = super::to_le_bytes(&v);
    assert_eq!(b.len(), 12);
    let back: Vec<f32> = b.chunks(4).map(|c| f32::from_le_bytes(c.try_into().unwrap())).collect();
    assert_eq!(back, v);
}
```

- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** the constants, `normalize_vector` (L2; copy imgfind's `~/src/imgfind/src/search.rs::normalize_vector`), `to_le_bytes` (copy imgfind's `database.rs:33`), the `Embedder` (`OnceLock` + background-thread loader via `clipper::ClipEmbedder::from_model(ACTIVE_MODEL, false)`), `embed_image_from_bytes` (→ `get_image_embedding_from_bytes`), `embed_text` (→ `get_text_embedding`), and the `EmbedFn` trait + impl for `ClipEmbedder`.
- [ ] **Step 4:** Add an `#[ignore]` integration test `loads_active_model_and_embeds_text` (downloads ~1.5 GB; run manually).
- [ ] **Step 5: Run, expect PASS** (non-ignored):

Run: `cargo test -p utmost-index --features clip clip::`
Expected: PASS.

- [ ] **Step 6: fmt + clippy + commit** (`feat(index): clip embedder wrapper (LAION ViT-L/14)`).

---

### Task 9: clip_embedding table + DB methods

**Files:**
- Modify: `crates/utmost-index/src/db/schema_sql.rs`, `src/db/queries.rs`, `src/db/writer.rs`
- Test: inline.

**Interfaces:**
- Produces: `queries::count_files_without_preview(pool) -> Result<usize>`, `queries::get_files_without_preview(pool, limit) -> Result<Vec<FoundFile>>`, `queries::count_files_without_embedding(pool) -> Result<usize>`, `queries::get_files_without_embedding(pool, limit) -> Result<Vec<(u64, PreviewBlobRow)>>`, `writer::set_clip_embedding(pool, file_id: u64, model: &str, &[f32]) -> Result<()>`.

- [ ] **Step 1:** Add to `create_schema` STMTS:

```rust
"CREATE TABLE IF NOT EXISTS clip_embedding (\
    file_id INTEGER PRIMARY KEY REFERENCES file(file_id) ON DELETE CASCADE, \
    model TEXT NOT NULL, dim INTEGER NOT NULL, embedding F32_BLOB(768) NOT NULL)",
```

- [ ] **Step 2: Write failing tests:** seed files + previews; assert `count_files_without_preview` and `count_files_without_embedding` are correct; `set_clip_embedding` flips the missing-embedding count to 0; a row with a *different* model still counts as missing for `ACTIVE_MODEL` (model-relative).
- [ ] **Step 3: Run, expect FAIL.**
- [ ] **Step 4: Implement** the four queries (preview-able types via `utmost_index::preview::Kind::Image`; embeddings join: `LEFT JOIN clip_embedding c ON c.file_id = f.file_id AND c.model = ?` `WHERE c.file_id IS NULL` over files having a `preview_blob`) + `set_clip_embedding` (upsert, store `to_le_bytes` as `turso::Value::Blob`, with `model`/`dim`).
- [ ] **Step 5: Run, expect PASS.**
- [ ] **Step 6: fmt + clippy + commit** (`feat(index): clip_embedding table + missing-work queries`).

---

### Task 10: Processing engine

**Files:**
- Create: `crates/utmost-index/src/processing.rs`
- Modify: `crates/utmost-index/src/lib.rs`
- Test: inline (fake embedder via `EmbedFn`).

**Interfaces:**
- Consumes: Tasks 8–9, `preview::render_with_fallback`/`encode_thumb_to_jpeg`, `writer::write_preview_outcomes`/`set_clip_embedding`.
- Produces: `processing::ProcessPhase {Previews, Embeddings}`, `processing::ProcessCounts {previews_remaining, embeddings_remaining}` + `ProcessCounts::load(pool) -> Result<Self>`, `processing::BatchOutcome {processed, remaining}`, `processing::process_next_batch(pool, embedder: &dyn EmbedFn, phase, batch_size) -> Result<BatchOutcome>`, `processing::run_to_completion(pool, opts: ProcessOpts, progress: &mut dyn FnMut(ProcessPhase, ProcessCounts)) -> Result<()>`, `processing::ProcessOpts {batch_size, embeddings}`.

- [ ] **Step 1: Write failing tests** with a fake embedder:

```rust
struct FakeEmbed;
impl crate::clip::EmbedFn for FakeEmbed {
    fn embed_image(&self, _b: &[u8]) -> anyhow::Result<Vec<f32>> { Ok(vec![0.1; crate::clip::ACTIVE_DIM]) }
}
// seed a few files (with resolvable sources or pre-seeded preview_blob);
// assert Previews phase drains to 0 and re-running yields processed==0;
// assert Embeddings phase drains to 0 and is idempotent.
```

- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** `ProcessCounts::load`, `process_next_batch` (Previews: `get_files_without_preview` → render → `write_preview_outcomes`; Embeddings: `get_files_without_embedding` → decode blob → `embedder.embed_image` → `normalize_vector` → `set_clip_embedding`), `run_to_completion` (Previews until drained, then — if `opts.embeddings` and `clip` — Embeddings until drained, `progress` between batches).
- [ ] **Step 4: Add the load-bearing characterization test** — embedding source equals `preview_blob` bytes; produces a normalized `ACTIVE_DIM` vector; re-embed is a no-op.
- [ ] **Step 5: Run, expect PASS.**
- [ ] **Step 6: fmt + clippy + commit** (`feat(index): shared two-phase processing engine`).

---

### Task 11: KNN search SQL + query_match_ids search branch

**Files:**
- Modify: `crates/utmost-index/src/db/queries.rs`, `crates/utmost-index/src/model.rs` (add `FilterState.search_query`)
- Test: inline.

**Interfaces:**
- Consumes: `clip::to_le_bytes`, the existing filter-WHERE builder.
- Produces: `FilterState { ..., pub search_query: Option<String> }`; `queries::knn_query(filter_where: &str, threshold: f32, limit: usize) -> String`; `query_match_ids` branches on `search_query` and accepts an optional precomputed query embedding: change signature to `query_match_ids(pool, &FilterState, query_embedding: Option<&[f32]>) -> Result<Vec<FileStub>>`.

> The caller (query-loop thread) computes the text embedding via `embed_text` + `normalize_vector` and passes it in, so utmost-index needn't own the embedder for queries.

- [ ] **Step 1: Write failing tests:** seed files with hand-set embedding blobs (known vectors) and a query vector; assert results come back ordered by `vector_distance_cos` ascending, threshold-filtered, capped at `limit`. **Filter-funnel tests:** with a search active, a file excluded by each of {type chip, partial-type chip, source filter, bookmarked-only, size range, hide-no-preview} never appears even when semantically close — one assertion per producer.
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** `knn_query` (string builder, port `~/src/imgfind/src/vector_sql.rs::knn_query` shape: inner SELECT computing `vector_distance_cos(c.embedding, ?) AS distance` joined to the filtered `file` set, outer `WHERE distance <= threshold ORDER BY distance LIMIT n`); branch `query_match_ids` to use it when `query_embedding.is_some()`, binding the blob via `turso::Value::Blob(to_le_bytes(q))`. Reuse the **same** filter-WHERE fragment as the non-search path (extract it into one helper so both paths share it — DRY + funnel correctness). Default threshold `1.3`, default limit `300` (constants).
- [ ] **Step 4: Run, expect PASS.**
- [ ] **Step 5: fmt + clippy + commit** (`feat(index): vector_distance_cos KNN search branch`).

---

### Task 12: CLI `process` command

**Files:**
- Modify: `crates/utmost-cli/Cargo.toml`, `crates/utmost-cli/src/main.rs`
- Test: inline integration (seed a case dir, run process, assert counts → 0).

**Interfaces:**
- Consumes: `utmost_index::{discover, db, processing, clip}`.

- [ ] **Step 1:** `crates/utmost-cli/Cargo.toml`: add `utmost-index = { path = "../utmost-index", optional = true }` and a `clip` feature wiring (`clip = ["utmost-index/clip"]`); ensure `utmost-index` is pulled for the `process` command (make it a non-optional dep if `process` should always exist, with embeddings gated by feature — **decision:** `utmost-index` non-optional, `clip` feature default-on toggles embeddings).
- [ ] **Step 2: Write the failing integration test** (under `crates/utmost-cli/tests/` or inline): build a temp output dir with one source's `<slug>-events.bin` + extracted files, run the process entrypoint fn, assert `ProcessCounts::load` → both remaining 0 (embeddings only with `clip`).
- [ ] **Step 3: Run, expect FAIL.**
- [ ] **Step 4: Implement** an argv-sniff for `process` in `main.rs` (mirror the existing `recover` dispatch at `main.rs:245`), parsing `-o/--output-directory`, `--count`, `--no-embeddings`; for each discovered case run `processing::run_to_completion` with a `progress` closure printing per-phase lines. Under `--no-default-features` (clip off), run Previews only and print a "embeddings disabled in this build" note.
- [ ] **Step 5: Run, expect PASS.**
- [ ] **Step 6: fmt + clippy + commit** (`feat(cli): utmost process command (previews + embeddings)`).

---

### Task 13: GUI background process-worker

**Files:**
- Create: `crates/utmost-gui/src/processor.rs`
- Modify: `crates/utmost-gui/src/case.rs` (spawn on open_case), `src/lib.rs` (shutdown wiring), `src/view_model.rs` (progress state)
- Test: inline pure-logic tests.

**Interfaces:**
- Produces: `processor::ProcessWorker::start(pool, embedder, shutdown: Arc<AtomicBool>, pause: Arc<AtomicBool>, progress_tx) -> ProcessWorker`; `processor::ProcessProgress { phase, counts }`; pure helpers `next_phase(counts) -> Option<ProcessPhase>`, `panel_state(running, paused, counts) -> RunningState`.

- [ ] **Step 1: Write failing pure-logic tests:** `next_phase` (Previews while previews_remaining>0; else Embeddings while embeddings_remaining>0; else None→Idle); pause-flag transitions; `panel_state` mapping (Running/Paused/Idle).
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** the pure helpers + the worker thread: loop `process_next_batch` per `next_phase`, check `pause` (park on a channel/condvar) and `shutdown` between batches, send `ProcessProgress` after each batch (UI applies via existing Slint timer pattern). Reuse `CaseHandle.shutdown_signal`. Spawn from `open_case` when `ProcessCounts::load` shows remaining work; Embeddings phase waits on `embedder.is_ready()`.
- [ ] **Step 4: Run pure-logic tests, expect PASS.**
- [ ] **Step 5: Build the gui:**

Run: `cargo build -p utmost-gui`
Expected: clean.

- [ ] **Step 6: fmt + clippy + commit** (`feat(gui): background process-worker + pause controller`).

---

### Task 14: Status panel + `\` toggle

**Files:**
- Modify: `crates/utmost-gui/ui/detail.slint`, `ui/main.slint`, `src/slint_adapter.rs`
- Test: build + manual smoke (Slint wiring); the panel-mapping logic is already unit-tested in Task 13.

- [ ] **Step 1:** Add to `detail.slint`: properties `process-panel-open: bool`, `process-running-state: string`, `previews-done/total: int`, `embeddings-done/total: int`, `process-paused: bool`; callbacks `toggle-process-panel()`, `process-pause-toggle()`. Add a `\` arm in the `outer_focus` `FocusScope` `key-pressed` handler → `root.toggle-process-panel()`, **suppressed when a text field (search/note) is focused**. Mirror all on `main.slint` and forward to `DetailPage`.
- [ ] **Step 2:** Add the panel markup (three rows Previews/Embeddings with done/total + bar, a Running/Paused/Idle line, a Pause/Resume button). Reflow (not overlay). Glyph caution: ASCII fallback if tofu.
- [ ] **Step 3:** Wire in `slint_adapter.rs`: `on_toggle_process_panel`, `on_process_pause_toggle` (flip the `pause` AtomicBool), and apply `ProcessProgress` from the worker channel into the Slint properties on the periodic sync tick.
- [ ] **Step 4: Build + manual smoke:** run a live carve or open an unprocessed case; `\` toggles the panel; bars advance; Pause/Resume works; closing the panel doesn't stop the job. Record in report.
- [ ] **Step 5: fmt + clippy + commit** (`feat(gui): \\-toggled background-job status panel`).

---

### Task 15: Search box + clear button

**Files:**
- Modify: `crates/utmost-gui/ui/detail.slint`, `ui/main.slint`, `src/slint_adapter.rs`, `src/indexer_thread.rs`, `src/view_model.rs`
- Test: build + manual smoke; search SQL already unit-tested (Task 11).

- [ ] **Step 1:** Insert a `LineEdit` (placeholder "Search images…") + a "Clear" `Button` in the `detail.slint` toolbar **immediately after the "Hide no-preview" `Rectangle` and before the `horizontal-stretch:1` spacer**. Properties `search-query: string`, `search-enabled: bool`, `indexing-hint: string`; callbacks `search-query-changed(string)`, `search-cleared()`. Mirror on `main.slint`.
- [ ] **Step 2:** Wire in `slint_adapter.rs`: on `search-query-changed`, set `vm.filter.search_query = (non-empty).then(text)`, `requery(...)`; `search-cleared` → `None` + clear LineEdit + requery. Bind `search-enabled` to `embedder.is_ready()`; set `indexing-hint` to "N still indexing" when `count_files_without_embedding() > 0`.
- [ ] **Step 3:** In `indexer_thread.rs` `Requery` handling: when `filter.search_query.is_some()`, compute the text embedding (`embed_text` + `normalize_vector`) and pass it to `query_match_ids(pool, &filter, Some(&emb))`; else `None`. Ensure `search_query` is **reset to `None` on hydrate** (not persisted) — confirm `UiStateSnapshot`/`FilterStateSnapshot` do NOT include it.
- [ ] **Step 4: Build + manual smoke:** type a query → grid reorders by similarity, respects active filters; Clear restores browse; search disabled until model ready; hint shows while embeddings incomplete. Record in report.
- [ ] **Step 5: fmt + clippy + commit** (`feat(gui): CLIP semantic search box + clear button`).

---

### Task 16: Docs

**Files:**
- Modify: `CLAUDE.md`, `README.md`

- [ ] **Step 1:** `CLAUDE.md`: document the new `utmost-index` crate + dependency graph; turso replacing Diesel (no migrations, rebuildable cache); the `clip` feature; `utmost process`; the GUI background job + `\` status panel; the search box. Update the crate table + "Adding a New File Type" if affected.
- [ ] **Step 2:** `README.md`: build commands (incl. `--no-default-features` for a lean build), the `process` command, the ~1.5 GB model download + `~/.cache/huggingface` cache note, turso as the index store. Link the spec.
- [ ] **Step 3: Commit** (`docs: utmost-index, turso, clip feature, process command, search`).

---

## Self-Review

**Spec coverage:** Phase 1 (crate extraction T1,6,7; connection T1; schema T2; models T3; write T4; read+hydrate T5; rewire+delete-diesel T7; tests throughout) ✓. Phase 2 (clip feature+embedder T8; table+queries T9; engine T10; search KNN T11; CLI process T12; GUI worker T13; status panel+`\` T14; search box T15; docs T16) ✓. Load-bearing tests: unified-embedding-source (T10), filter-funnel (T11) ✓. Transient search query (T15) ✓. Default-on `clip` feature + lean build (T8,12,16) ✓.

**Placeholder scan:** Mechanical-port tasks (T4/T5) intentionally reference "port each function from the named source file" with one fully-worked example + the explicit ordered list + the shared translation rules, rather than inlining ~700 lines of near-identical turso translations; the patterns are complete and unambiguous. All novel logic (connection layer, schema, KNN, engine, worker, Slint wiring) has concrete code or exact markup/property lists.

**Type consistency:** `TursoPool`/`IndexDb`/`block_on` (T1) used consistently; `ProcessPhase`/`ProcessCounts`/`BatchOutcome`/`process_next_batch`/`run_to_completion` (T10) consumed by T12/T13; `EmbedFn` (T8) used by T10 tests; `FilterState.search_query` (T11) consumed by T15; `query_match_ids` signature gains `Option<&[f32]>` (T11) — T7 establishes the pre-search signature, T11 changes it (call sites updated in T11/T15). `ACTIVE_MODEL`/`ACTIVE_DIM` (T8) used in T9/T10/T11.
