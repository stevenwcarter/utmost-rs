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

pub mod models;
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
