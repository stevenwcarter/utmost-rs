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
             PRAGMA foreign_keys = ON; \
             PRAGMA busy_timeout = 5000;",
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
    fn write_preview_outcomes_updates_column_and_bumps_version() {
        let mut db = IndexDb::open_in_memory().expect("open in-memory db");
        seed_source(&mut db);
        seed_file(&mut db, 42, 1, "00042.jpg", 100);
        seed_file(&mut db, 43, 1, "00043.jpg", 200);

        let outcomes = [
            PreviewOutcome {
                file_id: 42,
                status: PreviewStatus::HasPreview,
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
}
