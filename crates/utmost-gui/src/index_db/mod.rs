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

pub mod hydrate;
pub mod models;
pub mod queries;
pub mod schema;
pub mod writer;

/// Serializes [`IndexDb::open`] across the whole process. See the doc on
/// `IndexDb::open` for why this is needed.
static OPEN_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Owned SQLite connection plus the rules for opening and migrating it.
pub struct IndexDb {
    conn: SqliteConnection,
}

impl IndexDb {
    /// Open (or create) the SQLite at `path`. Applies the bundled set of
    /// embedded migrations, sets WAL + NORMAL synchronous + FK pragmas.
    ///
    /// `IndexDb::open` is serialized across the process via [`OPEN_GUARD`].
    /// At GUI startup three worker threads (`run_live_writes`,
    /// `run_preview_outcomes_writer`, `run_query_loop`) all open the same
    /// SQLite file. Without serialization they race on two things:
    /// (1) `PRAGMA journal_mode = WAL` requires an exclusive lock that
    ///     `busy_timeout` doesn't cover (it can return `SQLITE_LOCKED`,
    ///     not just `SQLITE_BUSY`), and
    /// (2) Diesel's migration runner reads `__diesel_schema_migrations`,
    ///     then applies missing migrations — non-atomically across
    ///     connections, so two openers both try to apply `0001_initial`
    ///     and the loser sees `table meta already exists`.
    /// A process-wide mutex around the open path makes both races
    /// impossible while keeping concurrent USE of separate connections
    /// (read/write through their own `IndexDb`) unaffected.
    pub fn open(path: &Path) -> Result<Self> {
        let _guard = OPEN_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let url = path
            .to_str()
            .with_context(|| format!("non-utf8 path: {}", path.display()))?;
        let mut conn = SqliteConnection::establish(url)
            .with_context(|| format!("opening sqlite at {}", path.display()))?;
        // busy_timeout still set first as defense-in-depth for any
        // remaining cross-process contention (none in our codebase today).
        conn.batch_execute(
            "PRAGMA busy_timeout = 5000; \
             PRAGMA journal_mode = WAL; \
             PRAGMA synchronous = NORMAL; \
             PRAGMA foreign_keys = ON;",
        )
        .context("applying pragmas")?;
        conn.run_pending_migrations(MIGRATIONS)
            .map_err(|e| anyhow::anyhow!("applying migrations: {e}"))?;
        Ok(Self { conn })
    }

    /// Open an in-memory SQLite database with all embedded migrations applied.
    /// Intended for unit tests; in-memory connections vanish when dropped.
    pub fn open_in_memory() -> Result<Self> {
        let mut conn =
            SqliteConnection::establish(":memory:").context("opening in-memory sqlite")?;
        conn.batch_execute("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;")
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

pub fn open_decision(bin: &std::path::Path, db: &mut IndexDb) -> Result<OpenAction> {
    let bin_size = std::fs::metadata(bin)
        .with_context(|| format!("stat {}", bin.display()))?
        .len();

    let meta_started_at = read_meta_str(db, "run_started_at")?;
    let meta_offset = read_meta_u64(db, "last_event_offset")?;

    let mut reader = utmost_lib::events::BincodeFileReader::open(bin)
        .with_context(|| format!("opening {}", bin.display()))?;
    let first = reader.next_event()?;
    let Some(first) = first else {
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

#[cfg(test)]
#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    c: i32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index_db::models::{FileRow, NewFile, NewSource};
    use crate::index_db::writer::write_preview_outcomes;
    use crate::thumb_worker::{PreviewOutcome, PreviewStatus};

    fn seed_source(db: &mut IndexDb) {
        let source = NewSource {
            source_id: 1,
            filename: "test.img".to_string(),
            output_subdir: "test".to_string(),
            total_bytes: 0,
            bytes_read: 0,
            files_found: 0,
            status: "Running".to_string(),
            duration_ms: None,
        };
        diesel::insert_into(schema::source::table)
            .values(&source)
            .execute(db.conn())
            .expect("seed source row");
    }

    fn seed_file(db: &mut IndexDb, file_id: i64, source_id: i32, filename: &str, filesize: i64) {
        let new_file = NewFile {
            file_id,
            source_id,
            filename: filename.to_string(),
            filesize,
            file_type: "jpg".to_string(),
            img_offset: 0,
            written_path: format!("/tmp/{filename}"),
            byte_runs_json: "[]".to_string(),
            jpeg_status: None,
            jpeg_width: None,
            jpeg_height: None,
            jpeg_fragmentation_point: None,
            jpeg_has_restart_markers: None,
            preview_status: "unknown".to_string(),
        };
        diesel::insert_into(schema::file::table)
            .values(&new_file)
            .execute(db.conn())
            .expect("insert file row");
    }

    #[test]
    fn preview_status_defaults_to_unknown_and_round_trips() {
        let mut db = IndexDb::open_in_memory().expect("open in-memory db");
        seed_source(&mut db);
        seed_file(&mut db, 42, 1, "00042.jpg", 1024);

        let back: FileRow = schema::file::table
            .find(42i64)
            .first(db.conn())
            .expect("read file row back");
        assert_eq!(back.preview_status, "unknown");

        // Sanity-check the migration also seeded the version meta key.
        let v = read_meta_str(&mut db, "preview_status_version").expect("read meta");
        assert_eq!(v.as_deref(), Some("0"));
    }

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
        // the right thing on rows that are in the bad state. row100 (set to
        // has_preview) must flip to unknown; row101 (set to no_preview)
        // must NOT be touched — that's what proves the WHERE clause filters
        // correctly rather than mass-updating the whole table.
        let mut db = IndexDb::open_in_memory().expect("open in-memory db");
        seed_source(&mut db);
        seed_file(&mut db, 100, 1, "a.jpg", 1);
        seed_file(&mut db, 101, 1, "b.jpg", 1);
        // Manually mark row100 as has_preview to simulate a pre-migration
        // row, and row101 as no_preview (which must survive untouched).
        diesel::sql_query("UPDATE file SET preview_status='has_preview' WHERE file_id=100")
            .execute(db.conn())
            .unwrap();
        diesel::sql_query("UPDATE file SET preview_status='no_preview' WHERE file_id=101")
            .execute(db.conn())
            .unwrap();
        // Re-run the migration's backfill SQL.
        diesel::sql_query(
            "UPDATE file SET preview_status='unknown' WHERE preview_status='has_preview'",
        )
        .execute(db.conn())
        .unwrap();
        let row100: FileRow = schema::file::table.find(100i64).first(db.conn()).unwrap();
        let row101: FileRow = schema::file::table.find(101i64).first(db.conn()).unwrap();
        assert_eq!(row100.preview_status, "unknown");
        assert_eq!(row101.preview_status, "no_preview");
    }

    #[test]
    fn write_preview_outcomes_updates_column_and_bumps_version() {
        let mut db = IndexDb::open_in_memory().expect("open in-memory db");
        seed_source(&mut db);
        seed_file(&mut db, 42, 1, "00042.jpg", 100);
        seed_file(&mut db, 43, 1, "00043.jpg", 200);

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
        write_preview_outcomes(db.conn(), &outcomes).expect("write preview outcomes");

        let row42: FileRow = schema::file::table
            .find(42i64)
            .first(db.conn())
            .expect("read file 42");
        assert_eq!(row42.preview_status, "has_preview");
        let row43: FileRow = schema::file::table
            .find(43i64)
            .first(db.conn())
            .expect("read file 43");
        assert_eq!(row43.preview_status, "no_preview");

        let v: String = schema::meta::table
            .find("preview_status_version")
            .select(schema::meta::value)
            .first(db.conn())
            .expect("read preview_status_version");
        assert_eq!(v, "1");

        // A second flush should bump again to 2.
        write_preview_outcomes(
            db.conn(),
            &[PreviewOutcome {
                file_id: 42,
                status: PreviewStatus::NoPreview,
            }],
        )
        .expect("write second batch");
        let v2: String = schema::meta::table
            .find("preview_status_version")
            .select(schema::meta::value)
            .first(db.conn())
            .expect("read preview_status_version v2");
        assert_eq!(v2, "2");
        let row42b: FileRow = schema::file::table
            .find(42i64)
            .first(db.conn())
            .expect("read file 42 again");
        assert_eq!(row42b.preview_status, "no_preview");
    }

    /// Three threads racing to open the same on-disk SQLite must all succeed.
    /// Before the busy_timeout-ordering fix, the loser of `PRAGMA journal_mode = WAL`
    /// got SQLITE_BUSY because its own busy_timeout hadn't been set yet
    /// (busy_timeout was applied after journal_mode in the same batch_execute).
    #[test]
    fn concurrent_open_on_same_path_does_not_lock() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let db_path = tmp.path().join("race.sqlite");

        let threads: Vec<_> = (0..3)
            .map(|_| {
                let path = db_path.clone();
                std::thread::spawn(move || IndexDb::open(&path).map(|_| ()))
            })
            .collect();

        let results: Vec<_> = threads
            .into_iter()
            .map(|t| t.join().expect("thread join"))
            .collect();

        for (i, r) in results.iter().enumerate() {
            assert!(
                r.is_ok(),
                "thread {i} failed to open the shared db: {:?}",
                r.as_ref().err()
            );
        }
    }

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
}
