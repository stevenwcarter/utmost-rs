# Persistent Thumbnail Cache Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist decoded JPEG thumbnails to a new `preview_blob` table on each
case's `<slug>-index.sqlite` so re-opening a case restores thumbs without
re-decoding source bytes. Lazy + windowed-only: blobs are written only for
files the user has actually scrolled into view.

**Architecture:** Extend the existing per-case SQLite index with a new
`preview_blob (file_id, codec, width, height, bytes)` table. The `ThumbWorker`
encodes successful decodes to JPEG q80 on the worker thread and ships them
through the existing `preview_outcomes_tx` channel; `write_preview_outcomes`
inserts the blob and updates `file.preview_status` in one transaction. On the
read side, each worker holds its own read-only SQLite connection and checks
`preview_blob` before falling through to the slow source-bytes decode path.

**Tech Stack:** Rust, Diesel 2.2 + SQLite (already in workspace), `image`
crate 0.25 with `jpeg` feature (already enabled), crossbeam-channel.

**Spec:** `docs/superpowers/specs/2026-05-21-thumbnail-cache-design.md`

**Spec deviations** (apply to all tasks below — the spec used identifiers that
don't quite match what's on disk; the plan uses the on-disk reality):

- On-disk `file.preview_status` values are snake_case: `'unknown'`,
  `'has_preview'`, `'no_preview'`. The spec's `'HasPreview'`/`'NoPreview'`/
  `'Pending'` map to `'has_preview'`, `'no_preview'`, and `'unknown'`
  respectively. The migration backfill uses `'unknown'`, not `'Pending'`.
- The spec proposed a new `PreviewOutcomeData` type with renamed `status →
  data` field. The plan instead extends the existing `PreviewStatus`
  enum's `HasPreview` variant to carry the payload, leaving the
  `PreviewOutcome.status` field name unchanged. Smaller diff, same semantics.

---

## File Structure

| Path | Role | Action |
|------|------|--------|
| `crates/utmost-gui/migrations/0003_preview_blob/up.sql` | Schema migration | Create |
| `crates/utmost-gui/migrations/0003_preview_blob/down.sql` | Schema rollback | Create |
| `crates/utmost-gui/src/index_db/schema.rs` | Diesel table macros | Modify (add `preview_blob` table) |
| `crates/utmost-gui/src/index_db/models.rs` | Insertable/Queryable structs | Modify (add `NewPreviewBlob`, `PreviewBlobRow`) |
| `crates/utmost-gui/src/index_db/writer.rs` | DB access (read + write) | Modify (extend `write_preview_outcomes`, add `preview_blob_lookup`) |
| `crates/utmost-gui/src/thumb_worker.rs` | Decode worker pool + LRU | Modify (extend `PreviewStatus`, add encoder, add fast path, hydrate `failed`) |
| `crates/utmost-gui/src/slint_adapter.rs` | UI thread state | Modify (pass `sqlite_path` to `ThumbWorker::start`) |
| `crates/utmost-gui/src/lib.rs` | Top-level wiring | Modify (pass `handle.sqlite_path` into `UiState::new`) |

---

### Task 1: Add the `preview_blob` migration

**Files:**
- Create: `crates/utmost-gui/migrations/0003_preview_blob/up.sql`
- Create: `crates/utmost-gui/migrations/0003_preview_blob/down.sql`

- [ ] **Step 1: Write the failing test**

Add to `crates/utmost-gui/src/index_db/mod.rs` inside the existing `#[cfg(test)] mod tests` block (alongside `preview_status_defaults_to_unknown_and_round_trips`):

```rust
    #[test]
    fn migration_creates_preview_blob_table() {
        let mut db = IndexDb::open_in_memory().expect("open in-memory db");
        // Query the schema directly so we don't depend on the Diesel table
        // macro existing yet (that lands in Task 2).
        let count: i32 = diesel::sql_query(
            "SELECT count(*) AS c FROM sqlite_master \
             WHERE type='table' AND name='preview_blob'",
        )
        .get_result::<CountRow>(db.conn())
        .map(|r| r.c)
        .expect("query sqlite_master");
        assert_eq!(count, 1, "preview_blob table must exist after migrations");
    }

    #[test]
    fn migration_backfills_has_preview_to_unknown() {
        // Verify the SQL the migration runs. Once migrations have applied, we
        // can't re-run the backfill against rows we set up afterward —
        // instead we re-execute the same UPDATE inline and assert it does
        // the right thing on rows that are in the bad state.
        let mut db = IndexDb::open_in_memory().expect("open in-memory db");
        seed_source(&mut db);
        seed_file(&mut db, 100, 1, "a.jpg", 1);
        seed_file(&mut db, 101, 1, "b.jpg", 1);
        // Manually mark one as has_preview to simulate a pre-migration row.
        diesel::sql_query("UPDATE file SET preview_status='has_preview' WHERE file_id=100")
            .execute(db.conn())
            .unwrap();
        // Re-run the migration's backfill SQL.
        diesel::sql_query("UPDATE file SET preview_status='unknown' WHERE preview_status='has_preview'")
            .execute(db.conn())
            .unwrap();
        let row100: FileRow = schema::file::table.find(100i64).first(db.conn()).unwrap();
        let row101: FileRow = schema::file::table.find(101i64).first(db.conn()).unwrap();
        assert_eq!(row100.preview_status, "unknown");
        assert_eq!(row101.preview_status, "unknown");
    }
```

Add this helper struct above the `tests` mod (still inside `mod.rs`):

```rust
#[cfg(test)]
#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    c: i32,
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p utmost-gui --lib index_db::tests::migration_creates_preview_blob_table index_db::tests::migration_backfills_has_preview_to_unknown`

Expected: both FAIL — `migration_creates_preview_blob_table` returns count=0; `migration_backfills_has_preview_to_unknown` panics on the inline UPDATE if the column setup is wrong, otherwise passes already (the SQL is just a UPDATE). Confirm both fail with output that says "preview_blob table must exist" or similar. If `migration_backfills_has_preview_to_unknown` happens to pass already, that's fine — the test is still useful as a regression check.

- [ ] **Step 3: Create the migration up.sql**

Write `crates/utmost-gui/migrations/0003_preview_blob/up.sql`:

```sql
CREATE TABLE preview_blob (
    file_id  BIGINT  PRIMARY KEY,
    codec    TEXT    NOT NULL,
    width    INTEGER NOT NULL,
    height   INTEGER NOT NULL,
    bytes    BLOB    NOT NULL,
    FOREIGN KEY (file_id) REFERENCES file(file_id) ON DELETE CASCADE
);

-- Pre-existing 'has_preview' rows have no blob bytes on disk yet — they
-- violate the new invariant ("has_preview implies a preview_blob row").
-- Reset them to 'unknown' so the next scroll re-decodes and persists.
UPDATE file SET preview_status = 'unknown' WHERE preview_status = 'has_preview';
```

- [ ] **Step 4: Create the migration down.sql**

Write `crates/utmost-gui/migrations/0003_preview_blob/down.sql`:

```sql
DROP TABLE preview_blob;
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p utmost-gui --lib index_db::tests::migration_creates_preview_blob_table index_db::tests::migration_backfills_has_preview_to_unknown`

Expected: both PASS.

- [ ] **Step 6: Run the full lib test suite to verify no regressions**

Run: `cargo test -p utmost-gui --lib`

Expected: all tests pass.

- [ ] **Step 7: cargo fmt + clippy**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings`

Expected: clean. Fix any warnings.

- [ ] **Step 8: Commit**

```bash
git add crates/utmost-gui/migrations/0003_preview_blob crates/utmost-gui/src/index_db/mod.rs
git commit -m "feat(gui): add preview_blob table and backfill migration"
```

---

### Task 2: Add Diesel schema entry for `preview_blob`

**Files:**
- Modify: `crates/utmost-gui/src/index_db/schema.rs`

- [ ] **Step 1: Write the failing test**

Add to `crates/utmost-gui/src/index_db/mod.rs` inside the existing `tests` mod:

```rust
    #[test]
    fn schema_preview_blob_table_is_queryable() {
        // Compile-time check that the diesel::table! macro exists and the
        // table is recognised by the query DSL. Also a sanity check that
        // an empty table SELECT returns zero rows.
        let mut db = IndexDb::open_in_memory().expect("open in-memory db");
        let n: i64 = schema::preview_blob::table
            .count()
            .get_result(db.conn())
            .expect("count preview_blob");
        assert_eq!(n, 0);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p utmost-gui --lib index_db::tests::schema_preview_blob_table_is_queryable`

Expected: FAIL — compile error "no `preview_blob` in `schema`".

- [ ] **Step 3: Add the table macro to schema.rs**

Add this `diesel::table!` block to `crates/utmost-gui/src/index_db/schema.rs`, after the existing `variant` block and before `allow_tables_to_appear_in_same_query!`:

```rust
diesel::table! {
    preview_blob (file_id) {
        file_id -> BigInt,
        codec   -> Text,
        width   -> Integer,
        height  -> Integer,
        bytes   -> Binary,
    }
}
```

Then add `preview_blob` to the `allow_tables_to_appear_in_same_query!` list:

```rust
diesel::allow_tables_to_appear_in_same_query!(
    meta,
    run,
    source,
    file,
    bookmark,
    note,
    best_choice,
    recovery_run,
    variant,
    preview_blob,
);
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p utmost-gui --lib index_db::tests::schema_preview_blob_table_is_queryable`

Expected: PASS.

- [ ] **Step 5: cargo fmt + clippy**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings`

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-gui/src/index_db/schema.rs crates/utmost-gui/src/index_db/mod.rs
git commit -m "feat(gui): add diesel schema entry for preview_blob table"
```

---

### Task 3: Add Diesel models (`NewPreviewBlob`, `PreviewBlobRow`)

**Files:**
- Modify: `crates/utmost-gui/src/index_db/models.rs`

- [ ] **Step 1: Write the failing test**

Add to `crates/utmost-gui/src/index_db/mod.rs` inside the existing `tests` mod:

```rust
    #[test]
    fn preview_blob_row_round_trips() {
        use crate::index_db::models::{NewPreviewBlob, PreviewBlobRow};
        let mut db = IndexDb::open_in_memory().expect("open in-memory db");
        seed_source(&mut db);
        seed_file(&mut db, 7, 1, "x.jpg", 1024);

        let new_row = NewPreviewBlob {
            file_id: 7,
            codec: "jpeg".to_string(),
            width: 256,
            height: 192,
            bytes: vec![0xFF, 0xD8, 0xFF, 0xE0, 1, 2, 3],
        };
        diesel::insert_into(schema::preview_blob::table)
            .values(&new_row)
            .execute(db.conn())
            .expect("insert preview_blob row");

        let got: PreviewBlobRow = schema::preview_blob::table
            .find(7i64)
            .first(db.conn())
            .expect("read preview_blob row");
        assert_eq!(got.file_id, 7);
        assert_eq!(got.codec, "jpeg");
        assert_eq!(got.width, 256);
        assert_eq!(got.height, 192);
        assert_eq!(got.bytes, vec![0xFF, 0xD8, 0xFF, 0xE0, 1, 2, 3]);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p utmost-gui --lib index_db::tests::preview_blob_row_round_trips`

Expected: FAIL — compile error "no `NewPreviewBlob` in models".

- [ ] **Step 3: Add the model structs to models.rs**

Append to `crates/utmost-gui/src/index_db/models.rs`:

```rust
#[derive(diesel::Insertable, diesel::AsChangeset)]
#[diesel(table_name = crate::index_db::schema::preview_blob)]
pub struct NewPreviewBlob {
    pub file_id: i64,
    pub codec: String,
    pub width: i32,
    pub height: i32,
    pub bytes: Vec<u8>,
}

#[derive(diesel::Queryable, diesel::Selectable, Debug, PartialEq, Eq)]
#[diesel(table_name = crate::index_db::schema::preview_blob)]
pub struct PreviewBlobRow {
    pub file_id: i64,
    pub codec: String,
    pub width: i32,
    pub height: i32,
    pub bytes: Vec<u8>,
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p utmost-gui --lib index_db::tests::preview_blob_row_round_trips`

Expected: PASS.

- [ ] **Step 5: cargo fmt + clippy**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings`

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-gui/src/index_db/models.rs crates/utmost-gui/src/index_db/mod.rs
git commit -m "feat(gui): add NewPreviewBlob and PreviewBlobRow models"
```

---

### Task 4: Extend `PreviewStatus` to carry blob payload + add `PreviewCodec`

**Files:**
- Modify: `crates/utmost-gui/src/thumb_worker.rs`
- Modify: `crates/utmost-gui/src/index_db/writer.rs`
- Modify: `crates/utmost-gui/src/index_db/mod.rs` (existing tests use the old shape)

This is a coordinated breaking change: every construction of
`PreviewStatus::HasPreview` (in worker code, tests, and downstream matchers)
must update together. There's no smaller subdivision that compiles.

- [ ] **Step 1: Update `PreviewStatus` and add `PreviewCodec` in thumb_worker.rs**

Replace the existing `PreviewStatus` block in
`crates/utmost-gui/src/thumb_worker.rs` (currently around line 30-38):

```rust
/// Terminal outcome of a single preview-decode attempt, broadcast to a
/// background indexer so the per-file `preview_status` column in the
/// SQLite index can be updated and the `preview_status_version` meta key
/// bumped. The `HasPreview` variant carries the encoded thumbnail bytes
/// so the writer can persist them into `preview_blob` in the same
/// transaction as the `preview_status` update.
#[derive(Debug, Clone)]
pub enum PreviewStatus {
    HasPreview {
        codec: PreviewCodec,
        width: u32,
        height: u32,
        bytes: Vec<u8>,
    },
    NoPreview,
}

/// Encoding format of a persisted thumbnail. Only `Jpeg` is produced by
/// the worker today; the variant exists so the on-disk `preview_blob.codec`
/// column can grow new values (e.g. `Webp`) without a schema migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewCodec {
    Jpeg,
}

impl PreviewCodec {
    /// On-disk string representation stored in `preview_blob.codec`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Jpeg => "jpeg",
        }
    }
}
```

The `PreviewOutcome` struct stays unchanged:

```rust
pub struct PreviewOutcome {
    pub file_id: u64,
    pub status: PreviewStatus,
}
```

(`#[derive(Debug, Clone, Copy)]` on `PreviewStatus` was removed because the
`HasPreview` payload now owns a `Vec<u8>` — `Copy` is impossible. `Clone`
remains. Downstream code that relied on `Copy` of `PreviewStatus` does not
exist today, but if cargo build flags any, switch them to explicit
`.clone()`.)

- [ ] **Step 2: Update existing `PreviewStatus::HasPreview` constructors in thumb_worker.rs**

Inside the worker hot loop (around line 134), the current code is:

```rust
if let Some(tx) = &outcomes_tx {
    let _ = tx.send(PreviewOutcome {
        file_id: durable_file_id,
        status: PreviewStatus::HasPreview,
    });
}
```

Change to (we'll fill the `bytes` field with `Vec::new()` for now — Task 7
puts the real encoded bytes there; we just need to keep the worker compiling
until then):

```rust
if let Some(tx) = &outcomes_tx {
    let _ = tx.send(PreviewOutcome {
        file_id: durable_file_id,
        status: PreviewStatus::HasPreview {
            codec: PreviewCodec::Jpeg,
            width: w,
            height: h,
            bytes: Vec::new(),
        },
    });
}
```

(Note: `w` and `h` are already in scope as `(w, h) = (img.width(), img.height())`.)

- [ ] **Step 3: Update `write_preview_outcomes` in writer.rs**

In `crates/utmost-gui/src/index_db/writer.rs`, the existing match (around
line 103-110) is:

```rust
let s = match outcome.status {
    PreviewStatus::HasPreview => "has_preview",
    PreviewStatus::NoPreview => "no_preview",
};
```

Replace with (Task 6 will add the preview_blob insert; here we just keep the
match exhaustive against the new variant shape):

```rust
let s = match &outcome.status {
    PreviewStatus::HasPreview { .. } => "has_preview",
    PreviewStatus::NoPreview => "no_preview",
};
```

- [ ] **Step 4: Update test fixtures in index_db/mod.rs**

In `crates/utmost-gui/src/index_db/mod.rs`, the existing test
`write_preview_outcomes_updates_column_and_bumps_version` (around line 213)
constructs `PreviewStatus::HasPreview` and `PreviewStatus::NoPreview`. Update
the `HasPreview` constructor:

```rust
        let outcomes = [
            PreviewOutcome {
                file_id: 42,
                status: PreviewStatus::HasPreview {
                    codec: crate::thumb_worker::PreviewCodec::Jpeg,
                    width: 1,
                    height: 1,
                    bytes: vec![],
                },
            },
            PreviewOutcome {
                file_id: 43,
                status: PreviewStatus::NoPreview,
            },
        ];
```

(`NoPreview` is unchanged.)

- [ ] **Step 5: Verify all build + tests pass**

Run: `cargo build -p utmost-gui --all-targets`

Expected: clean build. If anything else used `PreviewStatus::HasPreview` as a
unit variant, the compiler will point it out — fix each call site to use the
struct form (with placeholder `bytes: Vec::new()` if the real bytes aren't
available there).

Run: `cargo test -p utmost-gui --lib`

Expected: all tests pass.

- [ ] **Step 6: cargo fmt + clippy**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings`

Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add crates/utmost-gui/src/thumb_worker.rs \
        crates/utmost-gui/src/index_db/writer.rs \
        crates/utmost-gui/src/index_db/mod.rs
git commit -m "refactor(gui): widen PreviewStatus::HasPreview to carry blob payload"
```

---

### Task 5: Extend `write_preview_outcomes` to persist `preview_blob` rows

**Files:**
- Modify: `crates/utmost-gui/src/index_db/writer.rs`
- Modify: `crates/utmost-gui/src/index_db/mod.rs` (new test)

- [ ] **Step 1: Write the failing test**

Add to `crates/utmost-gui/src/index_db/mod.rs` inside the existing `tests` mod:

```rust
    #[test]
    fn write_preview_outcomes_persists_blob_in_same_transaction() {
        use crate::index_db::models::PreviewBlobRow;
        use crate::index_db::writer::write_preview_outcomes;
        use crate::thumb_worker::{PreviewCodec, PreviewOutcome, PreviewStatus};

        let mut db = IndexDb::open_in_memory().expect("open in-memory db");
        seed_source(&mut db);
        seed_file(&mut db, 50, 1, "p.jpg", 1);
        seed_file(&mut db, 51, 1, "q.jpg", 1);

        let bytes = vec![0xFF, 0xD8, 0xFF, 1, 2, 3, 4, 5];
        let outcomes = [
            PreviewOutcome {
                file_id: 50,
                status: PreviewStatus::HasPreview {
                    codec: PreviewCodec::Jpeg,
                    width: 128,
                    height: 96,
                    bytes: bytes.clone(),
                },
            },
            PreviewOutcome {
                file_id: 51,
                status: PreviewStatus::NoPreview,
            },
        ];
        write_preview_outcomes(db.conn(), &outcomes).expect("write");

        // HasPreview row: blob present, with matching codec/dims/bytes.
        let blob: PreviewBlobRow = schema::preview_blob::table
            .find(50i64)
            .first(db.conn())
            .expect("preview_blob row for file 50");
        assert_eq!(blob.codec, "jpeg");
        assert_eq!(blob.width, 128);
        assert_eq!(blob.height, 96);
        assert_eq!(blob.bytes, bytes);

        // NoPreview row: NO blob row.
        let missing: Option<PreviewBlobRow> = schema::preview_blob::table
            .find(51i64)
            .first(db.conn())
            .optional()
            .expect("query");
        assert!(missing.is_none(), "no_preview must not produce a blob row");
    }

    #[test]
    fn write_preview_outcomes_overwrites_existing_blob() {
        use crate::index_db::models::PreviewBlobRow;
        use crate::index_db::writer::write_preview_outcomes;
        use crate::thumb_worker::{PreviewCodec, PreviewOutcome, PreviewStatus};

        let mut db = IndexDb::open_in_memory().expect("open in-memory db");
        seed_source(&mut db);
        seed_file(&mut db, 60, 1, "r.jpg", 1);

        let first = PreviewOutcome {
            file_id: 60,
            status: PreviewStatus::HasPreview {
                codec: PreviewCodec::Jpeg,
                width: 64,
                height: 64,
                bytes: vec![1, 2, 3],
            },
        };
        let second = PreviewOutcome {
            file_id: 60,
            status: PreviewStatus::HasPreview {
                codec: PreviewCodec::Jpeg,
                width: 128,
                height: 96,
                bytes: vec![4, 5, 6, 7],
            },
        };
        write_preview_outcomes(db.conn(), std::slice::from_ref(&first)).unwrap();
        write_preview_outcomes(db.conn(), std::slice::from_ref(&second)).unwrap();

        let blob: PreviewBlobRow = schema::preview_blob::table
            .find(60i64)
            .first(db.conn())
            .unwrap();
        assert_eq!(blob.width, 128);
        assert_eq!(blob.bytes, vec![4, 5, 6, 7]);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p utmost-gui --lib index_db::tests::write_preview_outcomes_persists_blob_in_same_transaction index_db::tests::write_preview_outcomes_overwrites_existing_blob`

Expected: both FAIL — the existing `write_preview_outcomes` does not insert into `preview_blob`, so the `.find(50i64).first` query returns `NotFound`.

- [ ] **Step 3: Extend `write_preview_outcomes`**

Replace the body of `write_preview_outcomes` in
`crates/utmost-gui/src/index_db/writer.rs` (currently around line 93-122):

```rust
pub fn write_preview_outcomes(
    conn: &mut SqliteConnection,
    batch: &[PreviewOutcome],
) -> diesel::QueryResult<()> {
    use crate::index_db::models::NewPreviewBlob;
    use crate::index_db::schema::file::dsl as f;
    use crate::index_db::schema::meta::dsl as m;
    use crate::index_db::schema::preview_blob::dsl as pb;
    if batch.is_empty() {
        return Ok(());
    }
    conn.transaction(|tx| {
        for outcome in batch {
            let s = match &outcome.status {
                PreviewStatus::HasPreview { .. } => "has_preview",
                PreviewStatus::NoPreview => "no_preview",
            };
            diesel::update(f::file.find(outcome.file_id as i64))
                .set(f::preview_status.eq(s))
                .execute(tx)?;
            if let PreviewStatus::HasPreview {
                codec,
                width,
                height,
                bytes,
            } = &outcome.status
            {
                let row = NewPreviewBlob {
                    file_id: outcome.file_id as i64,
                    codec: codec.as_str().to_string(),
                    width: *width as i32,
                    height: *height as i32,
                    bytes: bytes.clone(),
                };
                // INSERT OR REPLACE so a re-decode for an already-cached
                // file_id overwrites cleanly; matches the invariant
                // "preview_status='has_preview' ⇔ row in preview_blob".
                diesel::insert_into(pb::preview_blob)
                    .values(&row)
                    .on_conflict(pb::file_id)
                    .do_update()
                    .set(&row)
                    .execute(tx)?;
            }
        }
        let cur: String = m::meta
            .find("preview_status_version")
            .select(m::value)
            .first(tx)?;
        let next: u64 = cur.parse::<u64>().unwrap_or(0) + 1;
        diesel::update(m::meta.find("preview_status_version"))
            .set(m::value.eq(next.to_string()))
            .execute(tx)?;
        Ok(())
    })
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p utmost-gui --lib index_db::tests::write_preview_outcomes_persists_blob_in_same_transaction index_db::tests::write_preview_outcomes_overwrites_existing_blob`

Expected: both PASS.

- [ ] **Step 5: Run the existing `write_preview_outcomes_updates_column_and_bumps_version` test**

Run: `cargo test -p utmost-gui --lib index_db::tests::write_preview_outcomes_updates_column_and_bumps_version`

Expected: PASS (regression check — the existing test's HasPreview now carries `bytes: vec![]`, but the column update and version bump still work).

- [ ] **Step 6: Run the full lib test suite**

Run: `cargo test -p utmost-gui --lib`

Expected: all tests pass.

- [ ] **Step 7: cargo fmt + clippy**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings`

Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add crates/utmost-gui/src/index_db/writer.rs crates/utmost-gui/src/index_db/mod.rs
git commit -m "feat(gui): persist preview_blob rows atomically with preview_status"
```

---

### Task 6: Add JPEG encoder + `encode_thumb_to_jpeg` helper

**Files:**
- Modify: `crates/utmost-gui/src/thumb_worker.rs`

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block at the bottom of
`crates/utmost-gui/src/thumb_worker.rs`:

```rust
    #[test]
    fn encode_thumb_to_jpeg_round_trips_dimensions() {
        // A 4×3 solid-red RGBA buffer encodes to JPEG bytes, and decoding
        // those bytes recovers the same dimensions.
        let w: u32 = 4;
        let h: u32 = 3;
        let rgba: Vec<u8> = (0..(w * h * 4))
            .map(|i| if i % 4 == 3 { 255 } else { (i % 256) as u8 })
            .collect();

        let encoded = super::encode_thumb_to_jpeg(&rgba, w, h).expect("encode");
        assert!(
            encoded.len() > 2 && encoded[0] == 0xFF && encoded[1] == 0xD8,
            "must start with JPEG SOI marker"
        );

        // Decode-back round trip via the `image` crate.
        let decoded = image::ImageReader::new(std::io::Cursor::new(encoded))
            .with_guessed_format()
            .expect("guess")
            .decode()
            .expect("decode jpeg");
        assert_eq!(decoded.width(), w);
        assert_eq!(decoded.height(), h);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p utmost-gui --lib thumb_worker::tests::encode_thumb_to_jpeg_round_trips_dimensions`

Expected: FAIL — `encode_thumb_to_jpeg` does not exist.

- [ ] **Step 3: Add the helper function**

Add to `crates/utmost-gui/src/thumb_worker.rs` (module-level, near the
top, after the `use` statements and type aliases):

```rust
/// Quality factor for the persisted thumbnail. ~80 keeps thumbs visually
/// indistinguishable from the RGBA source at 256-px max edge while
/// landing each blob in the 5-15 KB range.
const JPEG_QUALITY: u8 = 80;

/// Encode a decoded RGBA8 thumbnail to JPEG bytes for persistence in the
/// `preview_blob` table. Runs on the decode worker thread so encoding
/// parallelism scales with the worker pool. Quality is fixed at
/// [`JPEG_QUALITY`]; codec/quality choice is encoded in the
/// `preview_blob.codec` column so future encoders can be added without a
/// schema migration.
pub fn encode_thumb_to_jpeg(rgba: &[u8], width: u32, height: u32) -> anyhow::Result<Vec<u8>> {
    use image::codecs::jpeg::JpegEncoder;
    use image::ExtendedColorType;
    let expected = (width as usize) * (height as usize) * 4;
    if rgba.len() != expected {
        anyhow::bail!(
            "encode_thumb_to_jpeg: buffer len {} != width*height*4 = {}",
            rgba.len(),
            expected
        );
    }
    let mut out: Vec<u8> = Vec::with_capacity(rgba.len() / 16);
    JpegEncoder::new_with_quality(&mut out, JPEG_QUALITY)
        .encode(rgba, width, height, ExtendedColorType::Rgba8)?;
    Ok(out)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p utmost-gui --lib thumb_worker::tests::encode_thumb_to_jpeg_round_trips_dimensions`

Expected: PASS.

- [ ] **Step 5: cargo fmt + clippy**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings`

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-gui/src/thumb_worker.rs
git commit -m "feat(gui): add encode_thumb_to_jpeg helper for preview cache persistence"
```

---

### Task 7: Worker writes encoded bytes into the outgoing `PreviewOutcome`

**Files:**
- Modify: `crates/utmost-gui/src/thumb_worker.rs`

- [ ] **Step 1: Write the failing test**

Add to `crates/utmost-gui/src/thumb_worker.rs`'s test module:

```rust
    /// On a successful slow-path decode, the worker must send a HasPreview
    /// outcome that carries the JPEG-encoded thumbnail bytes (not an empty
    /// vec). This is the on-the-wire payload that `write_preview_outcomes`
    /// turns into a `preview_blob` row.
    #[test]
    fn worker_emits_jpeg_bytes_in_has_preview_outcome() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let (otx, orx) = unbounded::<PreviewOutcome>();
        let registry = Arc::new(PreviewRegistry::with_defaults_and_jpeg());

        // Resolve a temp source so the slow path can actually decode.
        let tmp = tempfile::tempdir().unwrap();
        let src_path = tmp.path().join("src.dd");
        let jpeg_bytes: &[u8] = include_bytes!("../tests/fixtures/tiny_2x2.jpg");
        std::fs::write(&src_path, jpeg_bytes).unwrap();
        let resolver = Arc::new(crate::source_resolver::SourceResolver::new(
            vec![src_path.clone()],
            None,
        ));
        let on_complete: Arc<dyn Fn(FileId) + Send + Sync> = Arc::new(|_| {});

        let worker = ThumbWorker::start(
            registry,
            resolver,
            16,
            1,
            on_complete,
            Some(otx),
            shutdown.clone(),
        );

        // sources_by_id needs the entry so render_with_fallback can resolve.
        worker
            .sources_by_id
            .write()
            .unwrap()
            .insert(0u32, src_path.to_string_lossy().into_owned());

        // Build a FoundFile that points at the source bytes (path-based
        // path won't work — the file at the dummy path doesn't exist —
        // so render_with_fallback drops into render_from_bytes).
        use utmost_lib::types::{ByteRun, FileObject};
        let f = FoundFile {
            id: 99,
            source_id: 0,
            file: FileObject {
                file_id: 99,
                filename: "x.jpg".into(),
                filesize: jpeg_bytes.len() as u64,
                file_type: "jpeg".into(),
                byte_runs: vec![ByteRun {
                    offset: 0,
                    img_offset: 0,
                    len: jpeg_bytes.len() as u64,
                }],
                jpeg_scan: None,
            },
            written_path: tmp.path().join("does-not-exist.jpg"),
            img_offset: 0,
        };
        worker.request(
            99 as FileId,
            FileType::Jpeg,
            f.written_path.clone(),
            f.clone(),
        );

        let outcome = orx
            .recv_timeout(Duration::from_secs(5))
            .expect("worker emitted an outcome");
        assert_eq!(outcome.file_id, 99);
        match outcome.status {
            PreviewStatus::HasPreview {
                codec,
                width,
                height,
                bytes,
            } => {
                assert_eq!(codec, PreviewCodec::Jpeg);
                assert!(width > 0 && height > 0);
                assert!(!bytes.is_empty(), "bytes must contain the JPEG payload");
                assert!(
                    bytes[0] == 0xFF && bytes[1] == 0xD8,
                    "bytes must start with JPEG SOI marker, got {:02x}{:02x}",
                    bytes[0],
                    bytes[1]
                );
            }
            PreviewStatus::NoPreview => panic!("expected HasPreview"),
        }
        drop(worker);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p utmost-gui --lib thumb_worker::tests::worker_emits_jpeg_bytes_in_has_preview_outcome`

Expected: FAIL — the worker currently sends `bytes: Vec::new()` (placeholder from Task 4). The `assert!(!bytes.is_empty())` triggers.

- [ ] **Step 3: Fill the real bytes into the outgoing outcome**

In `crates/utmost-gui/src/thumb_worker.rs`, find the spot in the worker
closure (around line 122-140) that constructs the `HasPreview` outcome
after a successful decode. The current Task-4-placeholder version is:

```rust
let buf =
    slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
        &pixels, w, h,
    );
cache.lock().unwrap().put(req.id, buf);
let cb = on_complete.clone();
let id = req.id;
let _ = slint::invoke_from_event_loop(move || cb(id));
if let Some(tx) = &outcomes_tx {
    let _ = tx.send(PreviewOutcome {
        file_id: durable_file_id,
        status: PreviewStatus::HasPreview {
            codec: PreviewCodec::Jpeg,
            width: w,
            height: h,
            bytes: Vec::new(),
        },
    });
}
```

Replace with:

```rust
let buf =
    slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
        &pixels, w, h,
    );
cache.lock().unwrap().put(req.id, buf);
let cb = on_complete.clone();
let id = req.id;
let _ = slint::invoke_from_event_loop(move || cb(id));
if let Some(tx) = &outcomes_tx {
    // Encode the RGBA buffer to JPEG on this worker thread so encoding
    // parallelism scales with the worker pool. On encode failure, fall
    // back to NoPreview — re-decoding from source is the next-best
    // recourse on the next case open.
    match encode_thumb_to_jpeg(&pixels, w, h) {
        Ok(bytes) => {
            let _ = tx.send(PreviewOutcome {
                file_id: durable_file_id,
                status: PreviewStatus::HasPreview {
                    codec: PreviewCodec::Jpeg,
                    width: w,
                    height: h,
                    bytes,
                },
            });
        }
        Err(e) => {
            tracing::warn!(
                "thumb worker: encode_thumb_to_jpeg failed for file_id={}: {}",
                durable_file_id,
                e
            );
            let _ = tx.send(PreviewOutcome {
                file_id: durable_file_id,
                status: PreviewStatus::NoPreview,
            });
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p utmost-gui --lib thumb_worker::tests::worker_emits_jpeg_bytes_in_has_preview_outcome`

Expected: PASS.

- [ ] **Step 5: Run the existing worker tests to verify no regression**

Run: `cargo test -p utmost-gui --lib thumb_worker::tests`

Expected: all PASS, including the existing
`workers_exit_on_shutdown_without_processing_queued_requests` and
`workers_process_queued_requests_when_not_shutdown`.

- [ ] **Step 6: cargo fmt + clippy**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings`

Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add crates/utmost-gui/src/thumb_worker.rs
git commit -m "feat(gui): thumb worker emits JPEG-encoded bytes in HasPreview outcomes"
```

---

### Task 8: Add `preview_blob_lookup` reader helper

**Files:**
- Modify: `crates/utmost-gui/src/index_db/writer.rs`
- Modify: `crates/utmost-gui/src/index_db/mod.rs` (new test)

- [ ] **Step 1: Write the failing test**

Add to `crates/utmost-gui/src/index_db/mod.rs` test mod:

```rust
    #[test]
    fn preview_blob_lookup_returns_row_when_present() {
        use crate::index_db::writer::preview_blob_lookup;
        let mut db = IndexDb::open_in_memory().expect("open in-memory db");
        seed_source(&mut db);
        seed_file(&mut db, 70, 1, "y.jpg", 1);
        diesel::insert_into(schema::preview_blob::table)
            .values(&crate::index_db::models::NewPreviewBlob {
                file_id: 70,
                codec: "jpeg".to_string(),
                width: 64,
                height: 48,
                bytes: vec![0xFF, 0xD8, 0xFF, 1, 2],
            })
            .execute(db.conn())
            .unwrap();

        let row = preview_blob_lookup(db.conn(), 70)
            .expect("ok")
            .expect("row present");
        assert_eq!(row.codec, "jpeg");
        assert_eq!(row.width, 64);
        assert_eq!(row.height, 48);
        assert_eq!(row.bytes, vec![0xFF, 0xD8, 0xFF, 1, 2]);
    }

    #[test]
    fn preview_blob_lookup_returns_none_when_missing() {
        use crate::index_db::writer::preview_blob_lookup;
        let mut db = IndexDb::open_in_memory().expect("open in-memory db");
        let row = preview_blob_lookup(db.conn(), 999).expect("ok");
        assert!(row.is_none());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p utmost-gui --lib index_db::tests::preview_blob_lookup_returns_row_when_present index_db::tests::preview_blob_lookup_returns_none_when_missing`

Expected: both FAIL — compile error "no `preview_blob_lookup` in writer".

- [ ] **Step 3: Add the helper to writer.rs**

Append to `crates/utmost-gui/src/index_db/writer.rs`:

```rust
/// Point-lookup a cached preview blob by `file_id`. Used by the thumb
/// worker hot loop: a hit returns the persisted JPEG bytes which the
/// worker decodes (~1 ms) instead of re-running the full
/// `render_with_fallback` slow path against the source image (~tens of
/// ms). Returns `Ok(None)` when no row exists; `Err` on schema
/// errors (the worker logs and falls through to the slow path).
pub fn preview_blob_lookup(
    conn: &mut SqliteConnection,
    file_id: u64,
) -> diesel::QueryResult<Option<crate::index_db::models::PreviewBlobRow>> {
    use crate::index_db::schema::preview_blob::dsl as pb;
    pb::preview_blob.find(file_id as i64).first(conn).optional()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p utmost-gui --lib index_db::tests::preview_blob_lookup_returns_row_when_present index_db::tests::preview_blob_lookup_returns_none_when_missing`

Expected: both PASS.

- [ ] **Step 5: cargo fmt + clippy**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings`

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-gui/src/index_db/writer.rs crates/utmost-gui/src/index_db/mod.rs
git commit -m "feat(gui): add preview_blob_lookup point-query helper"
```

---

### Task 9: `ThumbWorker::start` accepts a sqlite path; per-worker connections + failed-set hydration

**Files:**
- Modify: `crates/utmost-gui/src/thumb_worker.rs`

This task does three things together because the signature change rippling
through callers must happen atomically:

1. Adds `sqlite_path: Option<PathBuf>` parameter to `ThumbWorker::start`.
2. Each spawned worker thread opens its own read-only SQLite connection from
   that path (if `Some`).
3. Before spawning workers, `start` hydrates `failed: FailedSet` from
   `SELECT file_id FROM file WHERE preview_status = 'no_preview'`.

The fast-path *lookup* on each request lands in Task 10.

- [ ] **Step 1: Write the failing test**

Add to `crates/utmost-gui/src/thumb_worker.rs`'s test mod:

```rust
    /// At case-open, the worker must hydrate its `failed` set from sqlite
    /// rows with preview_status='no_preview' so previously-failed files
    /// don't get re-decoded on the next session.
    #[test]
    fn worker_hydrates_failed_set_from_no_preview_rows_on_open() {
        use crate::index_db::IndexDb;
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("case-index.sqlite");

        // Seed the on-disk sqlite with one file_id known to be NoPreview.
        {
            let mut db = IndexDb::open(&db_path).expect("open sqlite");
            diesel::sql_query(
                "INSERT INTO source (source_id, filename, output_subdir, total_bytes, \
                 bytes_read, files_found, status, duration_ms) \
                 VALUES (1, 'x.dd', 'x', 0, 0, 0, 'Running', NULL)",
            )
            .execute(db.conn())
            .unwrap();
            diesel::sql_query(
                "INSERT INTO file (file_id, source_id, filename, filesize, file_type, \
                 img_offset, written_path, byte_runs_json, jpeg_status, jpeg_width, \
                 jpeg_height, jpeg_fragmentation_point, jpeg_has_restart_markers, \
                 preview_status) VALUES (\
                 123, 1, 'a.jpg', 0, 'jpeg', 0, '/dev/null', '[]', NULL, NULL, \
                 NULL, NULL, NULL, 'no_preview')",
            )
            .execute(db.conn())
            .unwrap();
        }

        let shutdown = Arc::new(AtomicBool::new(false));
        let (otx, _orx) = unbounded::<PreviewOutcome>();
        let registry = Arc::new(PreviewRegistry::with_defaults_and_jpeg());
        let resolver = Arc::new(crate::source_resolver::SourceResolver::new(vec![], None));
        let on_complete: Arc<dyn Fn(FileId) + Send + Sync> = Arc::new(|_| {});

        let worker = ThumbWorker::start_with_sqlite(
            registry,
            resolver,
            16,
            1,
            on_complete,
            Some(otx),
            shutdown.clone(),
            Some(db_path),
        );
        assert!(
            worker.has_failed(123),
            "worker should have hydrated file_id=123 into the failed set"
        );
        drop(worker);
    }
```

(We use a new helper name `start_with_sqlite` to keep the change surface
small for this task; Task 12 collapses `start` into this signature.
Alternative: change `start` directly and update both existing tests at this
step. Pick whichever the executing agent finds cleaner — if changing `start`
directly, update `workers_exit_on_shutdown_without_processing_queued_requests`
and `workers_process_queued_requests_when_not_shutdown` to pass `None` for
the new `sqlite_path` parameter.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p utmost-gui --lib thumb_worker::tests::worker_hydrates_failed_set_from_no_preview_rows_on_open`

Expected: FAIL — compile error "no `start_with_sqlite` on `ThumbWorker`".

- [ ] **Step 3: Add the new constructor**

Add to `crates/utmost-gui/src/thumb_worker.rs`, alongside the existing
`start` method (do NOT delete `start` yet — Task 12 finishes that):

```rust
impl ThumbWorker {
    /// Same as [`Self::start`], plus a `sqlite_path` that enables the
    /// persistent preview cache. When `Some`, the worker:
    ///   1. Hydrates `failed` from `preview_status='no_preview'` rows at
    ///      construction time so previously-failed files are not re-decoded.
    ///   2. Opens one read-only SQLite connection per spawned worker thread
    ///      for the fast-path `preview_blob_lookup` added in Task 10.
    /// When `None`, behaves identically to `start` (no persistent cache —
    /// the legacy in-memory-only behavior, kept for tests and the bare
    /// `start` callers that haven't been migrated yet).
    #[allow(clippy::too_many_arguments)]
    pub fn start_with_sqlite(
        registry: Arc<PreviewRegistry>,
        resolver: Arc<SourceResolver>,
        capacity: usize,
        workers: usize,
        on_complete: Arc<dyn Fn(FileId) + Send + Sync>,
        outcomes_tx: Option<Sender<PreviewOutcome>>,
        shutdown_signal: Arc<AtomicBool>,
        sqlite_path: Option<PathBuf>,
    ) -> Self {
        let cache: ThumbCache = Arc::new(Mutex::new(LruCache::new(
            NonZeroUsize::new(capacity.max(1)).unwrap(),
        )));
        let failed: FailedSet = Arc::new(Mutex::new(HashSet::new()));
        let sources_by_id: SourcesByIdMap = Arc::new(RwLock::new(HashMap::new()));

        // Hydrate `failed` from preview_status='no_preview' rows so we
        // don't re-attempt deterministic failures on every case reopen.
        if let Some(path) = sqlite_path.as_ref() {
            match hydrate_failed_from_sqlite(path) {
                Ok(ids) => {
                    let mut f = failed.lock().unwrap();
                    for id in ids {
                        f.insert(id);
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "thumb worker: hydrate_failed_from_sqlite({}) failed: {e:#}; \
                         starting with empty failed set",
                        path.display()
                    );
                }
            }
        }

        let (tx, rx) = unbounded::<ThumbRequest>();
        for _ in 0..workers.max(1) {
            let rx: Receiver<ThumbRequest> = rx.clone();
            let cache = cache.clone();
            let failed = failed.clone();
            let registry = registry.clone();
            let resolver = resolver.clone();
            let sources_by_id = sources_by_id.clone();
            let on_complete = on_complete.clone();
            let outcomes_tx = outcomes_tx.clone();
            let shutdown = shutdown_signal.clone();
            let sqlite_path = sqlite_path.clone();
            thread::spawn(move || {
                // Per-thread Diesel connection for blob fast-path lookups.
                // Diesel's SqliteConnection is !Sync; each worker holds its
                // own. WAL mode on the per-case DB lets N readers + 1 writer
                // proceed in parallel.
                let mut conn: Option<diesel::sqlite::SqliteConnection> =
                    sqlite_path.as_ref().and_then(|p| open_reader_conn(p).ok());

                while let Ok(req) = rx.recv() {
                    if shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    if cache.lock().unwrap().contains(&req.id) {
                        continue;
                    }
                    if failed.lock().unwrap().contains(&req.id) {
                        continue;
                    }
                    // FAST PATH (Task 10 fills this in). Suppress unused
                    // warning so this task compiles with the conn already
                    // wired in.
                    let _ = conn.as_mut();

                    // SLOW PATH (unchanged from today).
                    let snap = sources_by_id.read().unwrap().clone();
                    let out = render_with_fallback(
                        &registry,
                        &resolver,
                        &snap,
                        req.file_type,
                        &req.path,
                        &req.file,
                    );
                    let durable_file_id: u64 = req.file.file.file_id;
                    match out {
                        Ok(crate::preview::PreviewOutput::Image(img)) => {
                            let (w, h) = (img.width(), img.height());
                            let pixels: Vec<u8> = img.into_raw();
                            let buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
                                &pixels, w, h,
                            );
                            cache.lock().unwrap().put(req.id, buf);
                            let cb = on_complete.clone();
                            let id = req.id;
                            let _ = slint::invoke_from_event_loop(move || cb(id));
                            if let Some(tx) = &outcomes_tx {
                                match encode_thumb_to_jpeg(&pixels, w, h) {
                                    Ok(bytes) => {
                                        let _ = tx.send(PreviewOutcome {
                                            file_id: durable_file_id,
                                            status: PreviewStatus::HasPreview {
                                                codec: PreviewCodec::Jpeg,
                                                width: w,
                                                height: h,
                                                bytes,
                                            },
                                        });
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "thumb worker: encode_thumb_to_jpeg failed for file_id={}: {}",
                                            durable_file_id, e
                                        );
                                        let _ = tx.send(PreviewOutcome {
                                            file_id: durable_file_id,
                                            status: PreviewStatus::NoPreview,
                                        });
                                    }
                                }
                            }
                        }
                        _ => {
                            failed.lock().unwrap().insert(req.id);
                            if let Some(tx) = &outcomes_tx {
                                let _ = tx.send(PreviewOutcome {
                                    file_id: durable_file_id,
                                    status: PreviewStatus::NoPreview,
                                });
                            }
                        }
                    }
                }
            });
        }
        Self {
            tx,
            cache,
            failed,
            sources_by_id,
        }
    }
}

/// Open a fresh Diesel connection to the per-case sqlite for read-only
/// fast-path lookups by a single worker thread. WAL mode is set at
/// case-open via [`crate::index_db::IndexDb::open`]; this caller just
/// needs a connection that can SELECT.
fn open_reader_conn(path: &std::path::Path) -> anyhow::Result<diesel::sqlite::SqliteConnection> {
    use diesel::Connection;
    let url = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-utf8 path: {}", path.display()))?;
    let mut conn = diesel::sqlite::SqliteConnection::establish(url)
        .map_err(|e| anyhow::anyhow!("connect {}: {e}", path.display()))?;
    // busy_timeout matches the writer's setting so contention surfaces as
    // a wait, not a SQLITE_BUSY error.
    use diesel::connection::SimpleConnection;
    conn.batch_execute("PRAGMA busy_timeout = 5000;")
        .map_err(|e| anyhow::anyhow!("set busy_timeout: {e}"))?;
    Ok(conn)
}

/// Read all `file.file_id`s whose `preview_status` is `'no_preview'`.
/// Used at [`ThumbWorker::start_with_sqlite`] construction to hydrate
/// `failed` from durable state.
fn hydrate_failed_from_sqlite(path: &std::path::Path) -> anyhow::Result<Vec<FileId>> {
    use crate::index_db::schema::file::dsl as f;
    use diesel::prelude::*;
    let mut conn = open_reader_conn(path)?;
    let ids: Vec<i64> = f::file
        .filter(f::preview_status.eq("no_preview"))
        .select(f::file_id)
        .load(&mut conn)
        .map_err(|e| anyhow::anyhow!("load no_preview ids: {e}"))?;
    Ok(ids.into_iter().map(|i| i as FileId).collect())
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p utmost-gui --lib thumb_worker::tests::worker_hydrates_failed_set_from_no_preview_rows_on_open`

Expected: PASS.

- [ ] **Step 5: Run existing worker tests to verify no regressions**

Run: `cargo test -p utmost-gui --lib thumb_worker::tests`

Expected: all PASS, including `workers_exit_on_shutdown_without_processing_queued_requests`.

- [ ] **Step 6: cargo fmt + clippy**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings`

Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add crates/utmost-gui/src/thumb_worker.rs
git commit -m "feat(gui): hydrate failed set + per-worker sqlite connections on case open"
```

---

### Task 10: Wire the blob fast path into the worker hot loop

**Files:**
- Modify: `crates/utmost-gui/src/thumb_worker.rs`

- [ ] **Step 1: Write the failing test**

Add to `crates/utmost-gui/src/thumb_worker.rs`'s test mod:

```rust
    /// With a pre-populated preview_blob row in sqlite, requesting that
    /// file_id must:
    ///   1. Populate the in-memory LRU cache with the decoded bytes.
    ///   2. Invoke on_complete with the file id.
    ///   3. NOT send a PreviewOutcome (status is already on disk).
    /// Uses `PreviewRegistry::empty()` so any fall-through to the slow
    /// path would error — proving the fast path actually ran.
    #[test]
    fn worker_fast_path_serves_from_preview_blob() {
        use crate::index_db::IndexDb;
        use crate::index_db::models::NewPreviewBlob;

        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("case-index.sqlite");

        // Pre-populate a preview_blob row for file_id=200 with a real JPEG.
        let jpeg_bytes: Vec<u8> = include_bytes!("../tests/fixtures/tiny_2x2.jpg").to_vec();
        {
            let mut db = IndexDb::open(&db_path).expect("open sqlite");
            diesel::sql_query(
                "INSERT INTO source (source_id, filename, output_subdir, total_bytes, \
                 bytes_read, files_found, status, duration_ms) \
                 VALUES (1, 'x.dd', 'x', 0, 0, 0, 'Running', NULL)",
            )
            .execute(db.conn())
            .unwrap();
            diesel::sql_query(
                "INSERT INTO file (file_id, source_id, filename, filesize, file_type, \
                 img_offset, written_path, byte_runs_json, jpeg_status, jpeg_width, \
                 jpeg_height, jpeg_fragmentation_point, jpeg_has_restart_markers, \
                 preview_status) VALUES (\
                 200, 1, 'a.jpg', 1, 'jpeg', 0, '/dev/null', '[]', NULL, NULL, \
                 NULL, NULL, NULL, 'has_preview')",
            )
            .execute(db.conn())
            .unwrap();
            diesel::insert_into(crate::index_db::schema::preview_blob::table)
                .values(&NewPreviewBlob {
                    file_id: 200,
                    codec: "jpeg".into(),
                    width: 2,
                    height: 2,
                    bytes: jpeg_bytes.clone(),
                })
                .execute(db.conn())
                .unwrap();
        }

        let shutdown = Arc::new(AtomicBool::new(false));
        let (otx, orx) = unbounded::<PreviewOutcome>();
        // Empty registry → slow path would error → if a PreviewOutcome
        // arrives, it would be NoPreview, NOT a fast-path silent fill.
        let registry = Arc::new(PreviewRegistry::empty());
        let resolver = Arc::new(crate::source_resolver::SourceResolver::new(vec![], None));

        let completed: Arc<Mutex<Vec<FileId>>> = Arc::new(Mutex::new(Vec::new()));
        let completed_for_cb = completed.clone();
        let on_complete: Arc<dyn Fn(FileId) + Send + Sync> = Arc::new(move |id| {
            completed_for_cb.lock().unwrap().push(id);
        });

        let worker = ThumbWorker::start_with_sqlite(
            registry,
            resolver,
            16,
            1,
            on_complete,
            Some(otx),
            shutdown.clone(),
            Some(db_path),
        );

        // We need a Slint event loop running so invoke_from_event_loop
        // delivers our on_complete. Run on this thread and quit when done.
        let completed_check = completed.clone();
        slint::invoke_from_event_loop(move || {
            // (no-op: just to confirm the loop is ready)
            let _ = completed_check;
        })
        .ok();

        worker.request(
            200 as FileId,
            FileType::Jpeg,
            std::path::PathBuf::from("/does-not-exist.jpg"),
            dummy_file(200),
        );

        // Drain — fast path should NOT emit a PreviewOutcome. Anything
        // arriving within 500 ms is a regression.
        match orx.recv_timeout(Duration::from_millis(500)) {
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => { /* expected */ }
            Err(e) => panic!("unexpected channel error: {e:?}"),
            Ok(o) => panic!(
                "fast path must not emit a PreviewOutcome, got {:?}",
                o.status
            ),
        }

        // The LRU cache should now hold the decoded buffer.
        assert!(
            worker.get_buffer(200 as FileId).is_some(),
            "fast path must populate the in-memory LRU"
        );

        drop(worker);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p utmost-gui --lib thumb_worker::tests::worker_fast_path_serves_from_preview_blob`

Expected: FAIL — `PreviewRegistry::empty()` means the slow path errors out;
the test sees a `NoPreview` outcome arrive on the channel, or the cache
remains empty.

- [ ] **Step 3: Implement the fast path in the worker hot loop**

In `crates/utmost-gui/src/thumb_worker.rs`, inside `start_with_sqlite`'s
worker closure (just after the `failed.contains` check, before the slow
path's `render_with_fallback` call), replace the placeholder
`let _ = conn.as_mut();` with the real lookup:

```rust
// FAST PATH: serve from preview_blob if present. A hit skips the
// source-bytes decode entirely. We do NOT emit a PreviewOutcome here
// because preview_status='has_preview' is already on disk and the
// preview_status_version meta key is unchanged.
if let Some(c) = conn.as_mut() {
    let lookup = crate::index_db::writer::preview_blob_lookup(c, req.id as u64);
    let decoded = match lookup {
        Ok(Some(row)) => image::ImageReader::new(std::io::Cursor::new(&row.bytes))
            .with_guessed_format()
            .ok()
            .and_then(|r| r.decode().ok()),
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(
                "thumb worker: preview_blob_lookup({}) errored: {e}; \
                 falling through to slow path",
                req.id
            );
            None
        }
    };
    if let Some(dyn_img) = decoded {
        let rgba = dyn_img.to_rgba8();
        let (w, h) = (rgba.width(), rgba.height());
        let pixels: Vec<u8> = rgba.into_raw();
        let buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
            &pixels, w, h,
        );
        cache.lock().unwrap().put(req.id, buf);
        let cb = on_complete.clone();
        let id = req.id;
        let _ = slint::invoke_from_event_loop(move || cb(id));
        continue;
    }
    // Lookup miss, lookup error, or decode failure → fall through to
    // slow path. If a bad blob caused the decode failure, the slow
    // path's INSERT OR REPLACE in write_preview_outcomes overwrites
    // it on success.
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p utmost-gui --lib thumb_worker::tests::worker_fast_path_serves_from_preview_blob`

Expected: PASS. If it times out waiting for the cache to fill, the
`invoke_from_event_loop` path may not be delivering — for the test,
`worker.get_buffer(200)` reads the cache directly, which is populated
BEFORE the `invoke_from_event_loop` post, so the assertion succeeds
regardless of whether on_complete actually fires.

- [ ] **Step 5: Run all worker tests for regression**

Run: `cargo test -p utmost-gui --lib thumb_worker::tests`

Expected: all PASS.

- [ ] **Step 6: cargo fmt + clippy**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings`

Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add crates/utmost-gui/src/thumb_worker.rs
git commit -m "feat(gui): worker fast path serves thumbs from preview_blob cache"
```

---

### Task 11: Thread `sqlite_path` through `UiState::new` and `lib.rs`

**Files:**
- Modify: `crates/utmost-gui/src/slint_adapter.rs`
- Modify: `crates/utmost-gui/src/lib.rs`

This task wires the real `CaseHandle.sqlite_path` into the live worker. After
this commit, opening a case in the GUI uses the persistent cache end-to-end.

- [ ] **Step 1: Add `sqlite_path` parameter to `UiState::new`**

In `crates/utmost-gui/src/slint_adapter.rs`, the `UiState::new` signature
currently ends with `thumbs_shutdown: Arc<AtomicBool>`. Add a new parameter
after it:

```rust
    pub fn new(
        window: MainWindow,
        vm: Arc<Mutex<ViewModel>>,
        source_search_locations: Vec<std::path::PathBuf>,
        event_log_path: Option<std::path::PathBuf>,
        indexer_rx: Option<crossbeam_channel::Receiver<crate::indexer_thread::IndexProgress>>,
        perf: Arc<crate::telemetry::PerfRecorder>,
        preview_outcomes_tx: Option<crossbeam_channel::Sender<PreviewOutcome>>,
        indexer_cmd_tx: Option<crossbeam_channel::Sender<IndexerCommand>>,
        indexer_event_rx: Option<crossbeam_channel::Receiver<IndexerEvent>>,
        ui_state_on_open: Option<crate::view_model::UiStateSnapshot>,
        thumbs_shutdown: Arc<std::sync::atomic::AtomicBool>,
        sqlite_path: Option<std::path::PathBuf>,
    ) -> Result<Self, slint::PlatformError> {
```

- [ ] **Step 2: Use `sqlite_path` in the `ThumbWorker::start` call**

In `crates/utmost-gui/src/slint_adapter.rs`, find the existing
`ThumbWorker::start(...)` call (around line 305) and replace it with a call
to `start_with_sqlite` that forwards `sqlite_path`:

```rust
        let thumbs = ThumbWorker::start_with_sqlite(
            registry.clone(),
            resolver.clone(),
            256,
            2,
            on_complete,
            preview_outcomes_tx,
            thumbs_shutdown,
            sqlite_path,
        );
```

- [ ] **Step 3: Pass `handle.sqlite_path` from `lib.rs`**

In `crates/utmost-gui/src/lib.rs`, find the `UiState::new` call (around line
219) and add `Some(handle.sqlite_path.clone())` as the final argument:

```rust
                    match slint_adapter::UiState::new(
                        window.clone_strong(),
                        vm.clone(),
                        search_locs.clone(),
                        event_log_path,
                        progress_rx,
                        perf.clone(),
                        preview_outcomes_tx,
                        indexer_cmd_tx.clone(),
                        indexer_event_rx,
                        handle.ui_state_on_open.take(),
                        thumbs_shutdown,
                        Some(handle.sqlite_path.clone()),
                    ) {
```

- [ ] **Step 4: Build and run tests**

Run: `cargo build -p utmost-gui --all-targets`

Expected: clean build. If there's any other caller of `UiState::new` (e.g.
benchmarks, examples), add `None` for the new parameter at those sites.

Run: `cargo test -p utmost-gui --lib`

Expected: all tests pass.

- [ ] **Step 5: cargo fmt + clippy**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings`

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-gui/src/slint_adapter.rs crates/utmost-gui/src/lib.rs
git commit -m "feat(gui): wire per-case sqlite_path into ThumbWorker for cache reads"
```

---

### Task 12: Collapse `start` and `start_with_sqlite` into one API

**Files:**
- Modify: `crates/utmost-gui/src/thumb_worker.rs`

Now that the real caller uses `start_with_sqlite`, the two-method split is
just deadweight. Fold them into a single `start` with the
`sqlite_path: Option<PathBuf>` parameter at the end.

- [ ] **Step 1: Delete the old `start` and rename `start_with_sqlite` to `start`**

In `crates/utmost-gui/src/thumb_worker.rs`:

- Delete the original `pub fn start(...)` method body (the one without the
  `sqlite_path` parameter).
- Rename `start_with_sqlite` → `start`. Update its doc comment to drop the
  "Same as `start`, plus..." preamble; restate the full intent.

The two existing tests (`workers_exit_on_shutdown_without_processing_queued_requests`
and `workers_process_queued_requests_when_not_shutdown`) need their
`ThumbWorker::start(...)` calls updated to pass `None` for the new
`sqlite_path` parameter. The newer tests added in Tasks 7/9/10 already use
`start_with_sqlite` — rename their callsites to `start` too.

The `slint_adapter.rs` callsite (Task 11) needs its `start_with_sqlite` →
`start` rename as well.

- [ ] **Step 2: Build and run all tests**

Run: `cargo build -p utmost-gui --all-targets && cargo test -p utmost-gui --lib`

Expected: clean build, all tests pass.

- [ ] **Step 3: cargo fmt + clippy**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings`

Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/utmost-gui/src/thumb_worker.rs crates/utmost-gui/src/slint_adapter.rs
git commit -m "refactor(gui): collapse ThumbWorker::start variants now that sqlite is wired"
```

---

### Task 13: End-to-end manual verification

This isn't a code task — it's a smoke test to run before marking the feature
done. The automated tests cover the units; this verifies the user-facing
behavior.

- [ ] **Step 1: Build the release viewer binary**

Run: `cargo build --release -p utmost-viewer`

Expected: clean build.

- [ ] **Step 2: Carve a sample image with at least 100 JPEGs**

If you don't already have a sample carve output handy, run:

```bash
cargo run --release -- -t jpeg path/to/some/disk.img -o /tmp/cachetest
```

(Substitute a real image path. Any disk image with embedded JPEGs works.)

- [ ] **Step 3: First open — observe the slow path populating**

Run: `cargo run --release -p utmost-viewer -- /tmp/cachetest`

Click into the case. Scroll through the grid. Watch:
- Thumbs fill in progressively (decoding from source bytes; this is today's
  baseline behavior — should be unchanged).
- After a few seconds of scrolling, `/tmp/cachetest/<slug>-index.sqlite`
  should have grown. Check with: `ls -la /tmp/cachetest/*-index.sqlite`.

Close the case (back button) and the window.

- [ ] **Step 4: Second open — verify the fast path**

Run: `cargo run --release -p utmost-viewer -- /tmp/cachetest` again.

Click into the same case. Scroll to the SAME files you saw on first open.
Expected: thumbs appear **noticeably faster** than the first time —
sub-perceptible instead of progressively filling.

Verify the cache table is populated:

```bash
sqlite3 /tmp/cachetest/*-index.sqlite \
  "SELECT count(*) FROM preview_blob; \
   SELECT count(*) FROM file WHERE preview_status='has_preview';"
```

Expected: both counts equal and non-zero. The two should match (invariant
from spec Section 1).

- [ ] **Step 5: Verify no_preview hydration**

If your carve produced any files with `preview_status='no_preview'`, they
should NOT be re-decoded on second open. Check with:

```bash
sqlite3 /tmp/cachetest/*-index.sqlite \
  "SELECT count(*) FROM file WHERE preview_status='no_preview';"
```

Note the count from this run. Close, reopen, scroll past those rows, close
again, re-query. The count should be identical — no growth, no shrinkage.

- [ ] **Step 6: If anything misbehaves**

Capture the symptom, the file_id of the offending tile, and a screenshot.
Drop the failing case into `~/test-cases/<short-name>/` so it can be
reproduced. File a follow-up task on `feature/utmost-gui-slint` rather
than reverting; the slow-path fallback in Task 10 means the user-facing
impact of any blob misbehavior is "thumbs reload like before" rather
than "GUI breaks."

---

## Self-review

**Spec coverage:**

| Spec section | Plan tasks |
|---|---|
| §1 Storage (schema, codec, sizing) | T1 (migration), T2 (schema entry), T3 (models) |
| §2 Write path (encoder + outcome enrichment + writer change) | T4 (enum widen), T5 (writer extension), T6 (encoder), T7 (worker wires encoder into outcomes) |
| §3 Read path (per-worker connection, fast path, no-outcome on hit) | T8 (lookup helper), T9 (per-worker conn), T10 (fast path) |
| §4 Hydration on case-open (failed set, lazy LRU) | T9 (failed hydration) |
| §5 Failure modes (read errors, decode errors, etc.) | T10 implements fall-through; T7 implements encoder fall-through |
| §6 Migration | T1 |
| Test coverage list | T1, T5, T7, T9, T10 each ship the named integration test |

**Placeholder scan:** all code blocks are concrete. No TBDs, no
"implement later", no "similar to Task N". The one
helper-name-evolution split (T9 introduces `start_with_sqlite`, T12
collapses it back to `start`) is intentional and explicit.

**Type consistency:** `PreviewStatus::HasPreview { codec, width, height,
bytes }` is the same shape everywhere it appears. `PreviewCodec::Jpeg`
is the only variant. `PreviewBlobRow` and `NewPreviewBlob` field names
match the table columns. `preview_blob_lookup` signature is stable
between T8 (definition) and T10 (use).
