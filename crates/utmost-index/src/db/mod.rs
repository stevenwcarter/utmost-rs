//! Async Turso connection pool + synchronous bridge for GUI/CLI callers.
//!
//! The `block_on` helper bridges sync call-sites (GUI worker threads, CLI) to
//! the turso async API without each caller managing its own runtime.  The
//! single `RUNTIME` is shared across all DB operations in this crate.
use anyhow::{Context, Result};
use deadpool::managed::{Manager, Metrics, Pool, RecycleResult};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

pub mod hydrate; // Task 5
pub mod models; // Task 3
pub mod queries; // Task 5
pub mod schema_sql; // Task 2
pub mod writer; // Task 4

static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build shared DB tokio runtime")
});

/// Run `fut` to completion on the shared multi-thread runtime.
///
/// For **sync callers only** (CLI, GUI worker threads).  Panics if called
/// from inside an existing tokio runtime — async callers must `.await`
/// directly instead of going through this bridge.
pub fn block_on<F: Future>(fut: F) -> F::Output {
    RUNTIME.block_on(fut)
}

// ── Manager ─────────────────────────────────────────────────────────────────

/// [`deadpool`] manager that creates and recycles [`turso::Connection`]s.
///
/// Each new connection gets a 5 s busy timeout plus `foreign_keys = ON` and
/// `journal_mode = WAL` applied before it is handed to a caller.
pub struct TursoManager {
    db: turso::Database,
}

impl Manager for TursoManager {
    type Type = turso::Connection;
    type Error = turso::Error;

    async fn create(&self) -> std::result::Result<turso::Connection, turso::Error> {
        let conn = self.db.connect()?;
        // Without a busy timeout, a second concurrent writer under WAL's
        // single-writer lock fails immediately with SQLITE_BUSY instead of
        // waiting and retrying.  5000 ms matches turso's own sync default.
        conn.busy_timeout(std::time::Duration::from_millis(5_000))?;
        conn.execute("PRAGMA foreign_keys = ON", ()).await?;
        // `PRAGMA journal_mode = WAL` returns a result row ("wal"); use
        // `query` and drain it so turso doesn't treat the row as unexpected.
        let mut rows = conn.query("PRAGMA journal_mode = WAL", ()).await?;
        while rows.next().await?.is_some() {}
        Ok(conn)
    }

    async fn recycle(
        &self,
        _conn: &mut turso::Connection,
        _metrics: &Metrics,
    ) -> RecycleResult<turso::Error> {
        Ok(())
    }
}

// ── Pool ────────────────────────────────────────────────────────────────────

/// A cloneable, sync-friendly Turso connection pool.
///
/// Open with [`TursoPool::open`]; check out a connection with
/// [`TursoPool::get`].
#[derive(Clone)]
pub struct TursoPool {
    inner: Pool<TursoManager>,
    /// The path the database was opened from.
    pub path: PathBuf,
}

impl TursoPool {
    /// Open (or create) the Turso database at `path` and build a connection
    /// pool.  Blocks the calling thread on the shared runtime.
    pub fn open(path: &Path) -> Result<Self> {
        let path_str = path.to_str().context("non-UTF-8 database path")?;
        let db = block_on(async { turso::Builder::new_local(path_str).build().await })
            .with_context(|| format!("open turso database at {path:?}"))?;
        let inner = Pool::builder(TursoManager { db })
            .build()
            .context("build turso connection pool")?;
        Ok(Self {
            inner,
            path: path.to_path_buf(),
        })
    }

    /// Check out a connection from the pool.
    pub async fn get(&self) -> Result<deadpool::managed::Object<TursoManager>> {
        self.inner.get().await.context("checkout turso connection")
    }
}

// ── IndexDb ─────────────────────────────────────────────────────────────────

/// Handle to an open per-case index database.
///
/// Created via [`IndexDb::open`] (file-backed) or
/// [`IndexDb::open_in_memory`] (in-process `:memory:` — tests only).
pub struct IndexDb {
    pool: TursoPool,
}

impl IndexDb {
    /// Open the index database at `path`, running any pending schema
    /// migrations before returning.
    pub fn open(path: &Path) -> Result<Self> {
        let pool = TursoPool::open(path)?;
        let p = pool.clone();
        block_on(async {
            let conn = p.get().await?;
            schema_sql::create_schema(&conn).await
        })?;
        Ok(Self { pool })
    }

    /// Open an in-memory database.  Intended for tests only.
    pub fn open_in_memory() -> Result<Self> {
        Self::open(Path::new(":memory:"))
    }

    /// Return a reference to the underlying connection pool.
    pub fn pool(&self) -> &TursoPool {
        &self.pool
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

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

    /// Several threads opening the same on-disk DB concurrently must all
    /// succeed. WAL mode + the 5 s busy timeout applied per connection in
    /// [`TursoManager::create`] make the schema-creation race a wait, not a
    /// `SQLITE_BUSY`/`SQLITE_LOCKED` failure — replacing the old Diesel-era
    /// process-wide `OPEN_GUARD`.
    #[test]
    fn concurrent_open_on_same_path_does_not_lock() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let db_path = tmp.path().join("race.sqlite");

        let threads: Vec<_> = (0..4)
            .map(|_| {
                let path = db_path.clone();
                std::thread::spawn(move || -> Result<()> {
                    let db = IndexDb::open(&path)?;
                    let pool = db.pool().clone();
                    block_on(async {
                        let conn = pool.get().await?;
                        let mut rows = conn.query("SELECT COUNT(*) FROM meta", ()).await?;
                        let _ = rows.next().await?;
                        anyhow::Ok(())
                    })
                })
            })
            .collect();

        for (i, t) in threads.into_iter().enumerate() {
            let r = t.join().expect("thread join");
            assert!(
                r.is_ok(),
                "thread {i} failed to open shared db: {:?}",
                r.err()
            );
        }
    }
}
