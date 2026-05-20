//! Background work that turns a `.bin` event log into a SQLite index.
//!
//! `run_blocking` is the synchronous entry point used by tests; `spawn`
//! runs the same work on a background thread and emits `IndexProgress`
//! over a `crossbeam_channel::Sender`. Both share
//! `run_blocking_with_progress` as the implementation.

use anyhow::{Context, Result};
use crossbeam_channel::{Receiver, Sender};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::index_db::{
    IndexDb, OpenAction, hydrate, open_decision,
    queries::{self, FileStub},
    writer::{IndexDbWriter, write_preview_outcomes},
};
use crate::thumb_worker::PreviewOutcome;
use crate::view_model::{FilterState, FoundFile, ViewModel};
use utmost_lib::events::BincodeFileReader;

/// Progress signals emitted by [`spawn`] over a `crossbeam_channel::Sender`.
///
/// The window thread drives a Slint overlay from this stream: it shows
/// `Started`'s `total_bytes` as a denominator, increments a numerator on
/// `Bytes`, updates a file counter on `Files`, and hides the overlay on
/// `Finished` / `Error`.
#[derive(Debug, Clone)]
pub enum IndexProgress {
    /// First message of every run. `total_bytes` is the size of the
    /// `.bin` event log when the indexer started, or `None` if the
    /// metadata read failed.
    Started { total_bytes: Option<u64> },
    /// Periodic byte-progress tick. `read` is the absolute byte offset
    /// into the event log just processed; values are monotonic
    /// non-decreasing within a single run.
    Bytes { read: u64 },
    /// Periodic file-count tick. `count` is the cumulative number of
    /// `CarveEvent::FileFound` events observed during the current run.
    Files { count: u64 },
    /// Successful completion. No further messages will be sent.
    Finished,
    /// Terminal error. `String` is a formatted `anyhow` chain. No
    /// further messages will be sent.
    Error(String),
}

/// How many bytes the indexer must advance between progress ticks.
const PROGRESS_TICK_BYTES: u64 = 2 * 1024 * 1024;

/// Compute the SQLite path for the index that corresponds to an event log
/// at `bin`. Convention: `<stem>-events.bin` → `<stem>-index.sqlite` in the
/// same directory.
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

/// Spawn the indexer on a background thread and stream progress over
/// `progress`. The thread always emits `Started` first; on success it
/// emits `Finished`, on failure it emits `Error` and returns.
pub fn spawn(
    bin: PathBuf,
    vm: Arc<Mutex<ViewModel>>,
    progress: Sender<IndexProgress>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let total_bytes = std::fs::metadata(&bin).ok().map(|m| m.len());
        let _ = progress.send(IndexProgress::Started { total_bytes });
        if let Err(e) = run_blocking_with_progress(&bin, vm, Some(&progress)) {
            let _ = progress.send(IndexProgress::Error(format!("{e:#}")));
            return;
        }
        let _ = progress.send(IndexProgress::Finished);
    })
}

/// Synchronous index build / hydrate without progress signalling. Used
/// by tests and by call-sites that don't need a `crossbeam_channel`.
pub fn run_blocking(bin: &Path, vm: Arc<Mutex<ViewModel>>) -> Result<()> {
    run_blocking_with_progress(bin, vm, None)
}

/// Shared implementation behind [`run_blocking`] and [`spawn`]. When
/// `progress` is `Some`, the inner loops emit a `Bytes` / `Files` tick
/// every ~2 MB of event-log bytes processed.
fn run_blocking_with_progress(
    bin: &Path,
    vm: Arc<Mutex<ViewModel>>,
    progress: Option<&Sender<IndexProgress>>,
) -> Result<()> {
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
            rebuild_from_zero(bin, &mut db, &vm, progress)?;
        }
        OpenAction::RebuildFromZero => {
            rebuild_from_zero(bin, &mut db, &vm, progress)?;
        }
        OpenAction::Resume { from } => {
            hydrate_into(&mut db, &vm)?;
            resume_from(bin, from, &mut db, &vm, progress)?;
        }
    }
    {
        let mut v = vm.lock().unwrap();
        v.recompute_visible();
    }
    Ok(())
}

fn hydrate_into(db: &mut IndexDb, vm: &Arc<Mutex<ViewModel>>) -> Result<()> {
    let snap =
        hydrate::snapshot_from_db(db.conn())?.context("expected snapshot from db with run row")?;
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

fn rebuild_from_zero(
    bin: &Path,
    db: &mut IndexDb,
    vm: &Arc<Mutex<ViewModel>>,
    progress: Option<&Sender<IndexProgress>>,
) -> Result<()> {
    let mut reader = BincodeFileReader::open(bin)?;
    let mut writer = IndexDbWriter::new(db.conn(), 5000);
    let mut files_seen: u64 = 0;
    let mut last_tick_offset: u64 = 0;
    while let Some(ev) = reader.next_event()? {
        let offset_after = reader.byte_offset()?;
        if matches!(ev, utmost_lib::events::CarveEvent::FileFound { .. }) {
            files_seen += 1;
        }
        {
            let mut v = vm.lock().unwrap();
            v.apply(&ev);
        }
        writer.apply(ev, offset_after)?;
        if let Some(tx) = progress
            && offset_after.saturating_sub(last_tick_offset) >= PROGRESS_TICK_BYTES
        {
            let _ = tx.send(IndexProgress::Bytes { read: offset_after });
            let _ = tx.send(IndexProgress::Files { count: files_seen });
            last_tick_offset = offset_after;
        }
    }
    writer.flush()?;
    Ok(())
}

/// Live-mode writer loop. Reads `CarveEvent`s off `rx` and folds each into
/// the SQLite index sitting next to `main_log`. The batching cadence is
/// "every 50 events or every 200 ms," whichever comes first; this keeps the
/// SQLite write amplification low while still surfacing rows to readers
/// (and to a future hot-hydrate path) within ~5 batches per second.
///
/// The loop terminates cleanly when every sender for `rx` has been
/// dropped. A final `flush()` runs on exit so the meta keys
/// (`last_event_offset`, `last_event_count`, `indexed_at`) reflect the
/// final batch.
///
/// `offset_after` is tracked as a synthetic, precise byte position into
/// the bincode log. The `FileHeader` was already written by
/// `BincodeFileSink::create` before this loop starts, so we seed the
/// synthetic offset from the current `.bin` size. Each persistable event
/// the engine appends is one length-prefixed bincoded frame
/// (4-byte u32 LE + payload), so we mirror that growth by re-serializing
/// the event and adding `4 + bytes.len()`. Non-persistable events
/// (e.g. progress ticks) don't grow the log and don't bump the offset.
///
/// This makes `last_event_offset` exact: on a crash, the open-decision
/// path can safely `Resume { from: last_event_offset }` and the reader
/// will pick up the next unindexed event without skipping or
/// double-applying.
pub fn run_live_writes(
    main_log: &Path,
    rx: crossbeam_channel::Receiver<utmost_lib::events::CarveEvent>,
) -> Result<()> {
    // Seed the synthetic offset from the current `.bin` size (the
    // FileHeader has already been written by `BincodeFileSink::create`
    // by the time this function is called in production).
    let initial_offset = std::fs::metadata(main_log).map(|m| m.len()).unwrap_or(0);
    run_live_writes_with_initial_offset(main_log, rx, initial_offset)
}

/// Same as [`run_live_writes`] but with an explicit seed for the
/// synthetic offset. Exposed for tests that need a deterministic
/// starting point (the metadata-based seed used in production has a
/// brief race window with the engine's first frame writes that's
/// awkward to synchronize from a test).
pub fn run_live_writes_with_initial_offset(
    main_log: &Path,
    rx: crossbeam_channel::Receiver<utmost_lib::events::CarveEvent>,
    initial_offset: u64,
) -> Result<()> {
    let db_path = index_path_for(main_log);
    let mut db = IndexDb::open(&db_path)
        .with_context(|| format!("opening index db at {}", db_path.display()))?;
    let mut writer = IndexDbWriter::new(db.conn(), 50);
    let mut last_flush = std::time::Instant::now();

    // Each persistable event we receive corresponds to one length-prefixed
    // bincoded frame the engine has appended to the `.bin`.
    let mut synthetic_offset: u64 = initial_offset;

    loop {
        match rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(ev) => {
                if ev.persistable() {
                    let bytes = bincode::serialize(&ev)
                        .map_err(|e| anyhow::anyhow!("bincode serialize live event: {e}"))?;
                    synthetic_offset += 4 + bytes.len() as u64;
                }
                writer.apply(ev, synthetic_offset)?;
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
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

/// Drain `outcomes_rx` and persist `PreviewOutcome`s into the SQLite
/// index sitting next to `main_log`. Outcomes are batched: a flush is
/// issued every 100 outcomes or every 500 ms, whichever comes first.
///
/// Each flush is one transaction — the per-row `preview_status` updates
/// and the `preview_status_version` meta bump succeed or fail together,
/// so readers polling the version key always see a consistent snapshot.
/// After each successful flush, if `event_tx` is `Some`, the new
/// `preview_status_version` is broadcast as `IndexerEvent::PreviewStatusVersion`
/// so the UI's debounced observer can refresh `hide_no_preview` results.
///
/// The loop terminates cleanly when every sender for `outcomes_rx` has
/// been dropped. A final flush runs on exit so any straggling outcomes
/// are persisted before the process tears down.
pub fn run_preview_outcomes_writer(
    main_log: &Path,
    outcomes_rx: crossbeam_channel::Receiver<PreviewOutcome>,
    event_tx: Option<crossbeam_channel::Sender<IndexerEvent>>,
) -> Result<()> {
    const BATCH_CAP: usize = 100;
    const FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

    let db_path = index_path_for(main_log);
    let mut db = IndexDb::open(&db_path)
        .with_context(|| format!("opening index db at {}", db_path.display()))?;

    let flush_and_notify = |db: &mut IndexDb,
                            batch: &mut Vec<PreviewOutcome>,
                            event_tx: &Option<crossbeam_channel::Sender<IndexerEvent>>|
     -> Result<()> {
        write_preview_outcomes(db.conn(), batch)?;
        batch.clear();
        if let Some(tx) = event_tx
            && let Ok(v) = read_preview_status_version(db.conn())
        {
            let _ = tx.send(IndexerEvent::PreviewStatusVersion(v));
        }
        Ok(())
    };

    let mut batch: Vec<PreviewOutcome> = Vec::with_capacity(BATCH_CAP);
    let mut last_flush = std::time::Instant::now();

    loop {
        // Use a tight timeout so the periodic flush still fires while the
        // upstream worker is producing outcomes faster than the timer.
        let timeout = FLUSH_INTERVAL
            .checked_sub(last_flush.elapsed())
            .unwrap_or(std::time::Duration::from_millis(0));
        match outcomes_rx.recv_timeout(timeout) {
            Ok(o) => {
                batch.push(o);
                if batch.len() >= BATCH_CAP {
                    flush_and_notify(&mut db, &mut batch, &event_tx)?;
                    last_flush = std::time::Instant::now();
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                if !batch.is_empty() {
                    flush_and_notify(&mut db, &mut batch, &event_tx)?;
                }
                last_flush = std::time::Instant::now();
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }
    if !batch.is_empty() {
        flush_and_notify(&mut db, &mut batch, &event_tx)?;
    }
    Ok(())
}

fn resume_from(
    bin: &Path,
    from: u64,
    db: &mut IndexDb,
    vm: &Arc<Mutex<ViewModel>>,
    progress: Option<&Sender<IndexProgress>>,
) -> Result<()> {
    let mut reader = BincodeFileReader::open(bin)?;
    reader.seek_to(from)?;
    let mut writer = IndexDbWriter::new(db.conn(), 5000);
    let mut files_seen: u64 = 0;
    let mut last_tick_offset: u64 = from;
    while let Some(ev) = reader.next_event()? {
        let offset_after = reader.byte_offset()?;
        if matches!(ev, utmost_lib::events::CarveEvent::FileFound { .. }) {
            files_seen += 1;
        }
        {
            let mut v = vm.lock().unwrap();
            v.apply(&ev);
        }
        writer.apply(ev, offset_after)?;
        if let Some(tx) = progress
            && offset_after.saturating_sub(last_tick_offset) >= PROGRESS_TICK_BYTES
        {
            let _ = tx.send(IndexProgress::Bytes { read: offset_after });
            let _ = tx.send(IndexProgress::Files { count: files_seen });
            last_tick_offset = offset_after;
        }
    }
    writer.flush()?;
    Ok(())
}

/// Command messages accepted by [`run_query_loop`].
///
/// The query thread is long-running and owns its own [`IndexDb`] connection.
/// `Requery` / `FetchWindow` carry an `epoch` so the UI can issue work and
/// then move on (e.g. the user toggles another filter chip) without
/// receiving stale responses: any command whose `epoch` is older than the
/// thread's `current_epoch` is silently dropped at ingest. `WritePreviewStatus`
/// carries no epoch because its only observable effect (a `preview_status_version`
/// meta-key bump) is fire-and-forget — the UI polls the version key to detect
/// the commit.
#[derive(Debug, Clone)]
pub enum IndexerCommand {
    /// Re-run the visible-ids query with `filter`. The thread updates its
    /// `current_epoch` to `epoch` (when not stale) and emits a single
    /// [`IndexerEvent::MatchIds`] with the same `epoch`.
    Requery { filter: FilterState, epoch: u64 },
    /// Hydrate `ids` (the requested window slice) into full [`FoundFile`]s.
    /// `range_start` is echoed back on the response so the UI can plug the
    /// rows into the correct position in its match-id list.
    FetchWindow {
        ids: Vec<u64>,
        range_start: usize,
        epoch: u64,
    },
    /// Persist a batch of [`PreviewOutcome`]s through this thread's
    /// connection. Acknowledged via [`IndexerEvent::PreviewStatusVersion`]
    /// carrying the new `preview_status_version` value.
    WritePreviewStatus { outcomes: Vec<PreviewOutcome> },
    /// Periodic poll from the UI's sync timer used to drive live-mode
    /// auto-requery. On `Tick`, the loop checks the SQLite `file` row
    /// count against the count it cached after the last `Requery`. When
    /// the count has grown, the loop re-runs the most recent filter and
    /// emits a fresh [`IndexerEvent::MatchIds`] so the grid extends to
    /// include the newly-appended files.
    ///
    /// The check is throttled to once every ~500 ms — successive `Tick`s
    /// arriving inside that window are no-ops. This keeps the cost of
    /// firing a `Tick` from the UI's 100 ms timer to a single integer
    /// compare in the common (no new files) case.
    Tick,
    /// Tear-down marker. The loop breaks out of `recv()` and the thread exits.
    Shutdown,
}

/// Response messages emitted by [`run_query_loop`] over its `event_tx` channel.
#[derive(Debug, Clone)]
pub enum IndexerEvent {
    /// Result of a [`IndexerCommand::Requery`]. `epoch` is echoed verbatim.
    MatchIds { stubs: Vec<FileStub>, epoch: u64 },
    /// Result of a [`IndexerCommand::FetchWindow`]. `range_start` is echoed
    /// from the request so the UI can splice the rows in at the right offset.
    WindowFilled {
        rows: Vec<FoundFile>,
        range_start: usize,
        epoch: u64,
    },
    /// Result of a [`IndexerCommand::WritePreviewStatus`]: the new
    /// `preview_status_version` value after the commit. The UI polls this
    /// key on a timer; receiving the event lets it short-circuit the next
    /// poll cycle and refresh sooner.
    PreviewStatusVersion(u64),
    /// Either a per-command failure (`epoch = Some(_)`) or a general error
    /// not tied to a specific request (`epoch = None`).
    Error { epoch: Option<u64>, message: String },
}

/// Long-running query/write loop. Opens its own [`IndexDb`] against the
/// SQLite index sitting next to `main_log` and keeps that connection alive
/// for the thread's lifetime.
///
/// The thread tracks the highest `epoch` it has seen on a `Requery` /
/// `FetchWindow` command; any later command whose `epoch` is strictly less
/// than that high-water mark is silently dropped before it touches the DB,
/// so the UI never has to disambiguate stale responses from fresh ones.
/// The loop exits cleanly when a [`IndexerCommand::Shutdown`] is received,
/// or when every sender for `cmd_rx` has been dropped.
pub fn run_query_loop(
    main_log: PathBuf,
    cmd_rx: Receiver<IndexerCommand>,
    event_tx: Sender<IndexerEvent>,
) -> Result<()> {
    let db_path = index_path_for(&main_log);
    let mut db = IndexDb::open(&db_path)
        .with_context(|| format!("opening index db at {}", db_path.display()))?;
    let mut current_epoch: u64 = 0;
    // Live-mode auto-requery state. The most recent `Requery` filter is
    // cached so the loop can re-run it from a `Tick` without the UI having
    // to re-send the full filter; `last_match_count` is the row count from
    // that requery, used to skip the re-run when nothing has changed in
    // SQLite since.
    let mut last_filter: Option<FilterState> = None;
    let mut last_match_count: usize = 0;
    let mut last_live_requery_at: Option<std::time::Instant> = None;
    // Throttle the row-count probe so a busy 10 Hz `Tick` stream doesn't
    // hammer SQLite. ~500 ms matches the spec's debounce target.
    const LIVE_REQUERY_THROTTLE: std::time::Duration = std::time::Duration::from_millis(500);

    // Local PerfRecorder targeting the indexer thread. Activation mirrors
    // the UI-side init: `UTMOST_PERF_TRACE=1` (case-insensitive `1`/`true`)
    // or `RUST_LOG` containing `utmost_gui::perf=<level>` flips it on. When
    // disabled, `phase()` and `tick()` are effectively no-ops.
    let perf_enabled = crate::telemetry::perf_activated_from(
        std::env::var("UTMOST_PERF_TRACE").ok().as_deref(),
        std::env::var("RUST_LOG").ok().as_deref(),
    );
    let tick_interval: u64 = std::env::var("UTMOST_PERF_TICKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let perf = crate::telemetry::PerfRecorder::new(
        crate::telemetry::PerfTarget::Indexer,
        perf_enabled,
        tick_interval,
    );

    while let Ok(cmd) = cmd_rx.recv() {
        match cmd {
            IndexerCommand::Requery { filter, epoch } => {
                if epoch < current_epoch {
                    continue;
                }
                current_epoch = epoch;
                let res = {
                    let _g = perf.phase("query_match_ids");
                    queries::query_match_ids(db.conn(), &filter)
                };
                match res {
                    Ok(stubs) => {
                        last_match_count = stubs.len();
                        last_filter = Some(filter);
                        last_live_requery_at = Some(std::time::Instant::now());
                        let _ = event_tx.send(IndexerEvent::MatchIds { stubs, epoch });
                    }
                    Err(e) => {
                        let _ = event_tx.send(IndexerEvent::Error {
                            epoch: Some(epoch),
                            message: format!("query_match_ids: {e}"),
                        });
                    }
                }
                perf.tick();
            }
            IndexerCommand::FetchWindow {
                ids,
                range_start,
                epoch,
            } => {
                if epoch < current_epoch {
                    continue;
                }
                current_epoch = epoch;
                let res = {
                    let _g = perf.phase("fetch_window");
                    queries::fetch_window(db.conn(), &ids)
                };
                match res {
                    Ok(rows) => {
                        let _ = event_tx.send(IndexerEvent::WindowFilled {
                            rows,
                            range_start,
                            epoch,
                        });
                    }
                    Err(e) => {
                        let _ = event_tx.send(IndexerEvent::Error {
                            epoch: Some(epoch),
                            message: format!("fetch_window: {e}"),
                        });
                    }
                }
                perf.tick();
            }
            IndexerCommand::WritePreviewStatus { outcomes } => {
                let res = {
                    let _g = perf.phase("preview_status_write");
                    write_preview_outcomes(db.conn(), &outcomes)
                };
                match res {
                    Ok(()) => match read_preview_status_version(db.conn()) {
                        Ok(v) => {
                            let _ = event_tx.send(IndexerEvent::PreviewStatusVersion(v));
                        }
                        Err(e) => {
                            let _ = event_tx.send(IndexerEvent::Error {
                                epoch: None,
                                message: format!("read preview_status_version: {e}"),
                            });
                        }
                    },
                    Err(e) => {
                        let _ = event_tx.send(IndexerEvent::Error {
                            epoch: None,
                            message: format!("write_preview_outcomes: {e}"),
                        });
                    }
                }
                perf.tick();
            }
            IndexerCommand::Tick => {
                // Skip Tick work entirely until the UI has issued at least
                // one Requery — we have no filter to re-run otherwise.
                let Some(filter) = last_filter.as_ref() else {
                    continue;
                };
                // Throttle: at most one row-count probe + auto-requery per
                // LIVE_REQUERY_THROTTLE window.
                if let Some(prev) = last_live_requery_at
                    && prev.elapsed() < LIVE_REQUERY_THROTTLE
                {
                    continue;
                }
                let count_res = {
                    let _g = perf.phase("file_count_check");
                    count_file_rows(db.conn())
                };
                let count_now = match count_res {
                    Ok(n) => n,
                    Err(e) => {
                        let _ = event_tx.send(IndexerEvent::Error {
                            epoch: None,
                            message: format!("count_file_rows: {e}"),
                        });
                        perf.tick();
                        continue;
                    }
                };
                last_live_requery_at = Some(std::time::Instant::now());
                if count_now <= last_match_count {
                    perf.tick();
                    continue;
                }
                // New rows since the last requery — re-run the cached filter
                // under a fresh epoch so the UI's match_id list extends. The
                // UI's `current_epoch` lags this bump until it receives the
                // MatchIds and applies it; that's fine because subsequent
                // UI-issued commands always send `current_epoch + 1` from
                // the UI's perspective and our `current_epoch` only moves
                // forward, so a UI-initiated command with a stale epoch is
                // already handled by the existing drop-stale guard.
                current_epoch += 1;
                let epoch = current_epoch;
                let res = {
                    let _g = perf.phase("query_match_ids");
                    queries::query_match_ids(db.conn(), filter)
                };
                match res {
                    Ok(stubs) => {
                        last_match_count = stubs.len();
                        let _ = event_tx.send(IndexerEvent::MatchIds { stubs, epoch });
                    }
                    Err(e) => {
                        let _ = event_tx.send(IndexerEvent::Error {
                            epoch: Some(epoch),
                            message: format!("auto-requery query_match_ids: {e}"),
                        });
                    }
                }
                perf.tick();
            }
            IndexerCommand::Shutdown => break,
        }
    }
    Ok(())
}

/// Count the rows in the `file` table. Used by the live-mode auto-requery
/// path in [`run_query_loop`] to cheaply detect whether the engine writer
/// has appended new files since the most recent `Requery`.
fn count_file_rows(conn: &mut diesel::sqlite::SqliteConnection) -> diesel::QueryResult<usize> {
    use crate::index_db::schema::file::dsl as f;
    use diesel::prelude::*;
    let n: i64 = f::file.count().get_result(conn)?;
    Ok(n.max(0) as usize)
}

/// Read the current `preview_status_version` meta value. Used by
/// [`run_query_loop`] to acknowledge `WritePreviewStatus` commits.
fn read_preview_status_version(
    conn: &mut diesel::sqlite::SqliteConnection,
) -> diesel::QueryResult<u64> {
    use crate::index_db::schema::meta::dsl as m;
    use diesel::prelude::*;
    let s: String = m::meta
        .find("preview_status_version")
        .select(m::value)
        .first(conn)?;
    Ok(s.parse::<u64>().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index_db::models::{NewFile, NewSource};
    use crate::index_db::schema;
    use diesel::prelude::*;
    use std::time::Duration;

    /// Seed an empty DB on disk with `count` files distributed across
    /// `num_sources`. Mirrors the fixture style used in `queries.rs` tests,
    /// but writes to a real on-disk SQLite so we can hand the path to the
    /// query-loop thread (`IndexDb` is `!Send` and so the thread must open
    /// its own connection).
    fn seed_db_on_disk(db_path: &Path, count: i64, num_sources: i32) {
        let mut db = IndexDb::open(db_path).expect("open db on disk");
        for s in 1..=num_sources {
            let row = NewSource {
                source_id: s,
                filename: format!("img{s}.bin"),
                output_subdir: format!("img{s}"),
                total_bytes: 0,
                bytes_read: 0,
                files_found: 0,
                status: "Finished".into(),
                duration_ms: None,
            };
            diesel::insert_into(schema::source::table)
                .values(&row)
                .execute(db.conn())
                .expect("insert source");
        }
        db.with_conn::<(), diesel::result::Error, _>(|conn| {
            conn.transaction(|tx| {
                for i in 0..count {
                    let source_id = ((i as i32) % num_sources) + 1;
                    let row = NewFile {
                        file_id: i + 1,
                        source_id,
                        filename: format!("{:08}.jpeg", i + 1),
                        filesize: 1_000 + i * 17,
                        file_type: "jpeg".into(),
                        img_offset: i * 4096,
                        written_path: format!("img{source_id}/{:08}.jpeg", i + 1),
                        byte_runs_json: "[]".into(),
                        jpeg_status: None,
                        jpeg_width: None,
                        jpeg_height: None,
                        jpeg_fragmentation_point: None,
                        jpeg_has_restart_markers: None,
                        preview_status: "unknown".into(),
                    };
                    diesel::insert_into(schema::file::table)
                        .values(&row)
                        .execute(tx)?;
                }
                Ok(())
            })
        })
        .expect("seed files");
    }

    /// Make a fake `<stem>-events.bin` next to the SQLite index so the
    /// `index_path_for(main_log)` convention picks up our seeded DB. The
    /// file's contents don't matter — `run_query_loop` never reads it; it
    /// only uses the path to derive the DB location.
    fn fixture_paths(dir: &Path) -> (PathBuf, PathBuf) {
        let main_log = dir.join("source-events.bin");
        std::fs::write(&main_log, b"placeholder").expect("write placeholder log");
        let db_path = index_path_for(&main_log);
        (main_log, db_path)
    }

    #[test]
    fn requery_returns_matchids() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (main_log, db_path) = fixture_paths(dir.path());
        seed_db_on_disk(&db_path, 25, 2);

        let (ctx, crx) = crossbeam_channel::unbounded::<IndexerCommand>();
        let (etx, erx) = crossbeam_channel::unbounded::<IndexerEvent>();
        let handle = std::thread::spawn(move || {
            run_query_loop(main_log, crx, etx).expect("query loop");
        });

        ctx.send(IndexerCommand::Requery {
            filter: FilterState::default(),
            epoch: 1,
        })
        .expect("send requery");

        let ev = erx
            .recv_timeout(Duration::from_secs(2))
            .expect("recv MatchIds");
        match ev {
            IndexerEvent::MatchIds { stubs, epoch } => {
                assert_eq!(epoch, 1, "echoed epoch must match request");
                assert_eq!(stubs.len(), 25, "all seeded rows should come back");
            }
            other => panic!("expected MatchIds, got {other:?}"),
        }

        ctx.send(IndexerCommand::Shutdown).expect("send shutdown");
        drop(ctx);
        handle.join().expect("join query thread");
    }

    #[test]
    fn stale_epoch_requery_is_dropped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (main_log, db_path) = fixture_paths(dir.path());
        seed_db_on_disk(&db_path, 10, 1);

        let (ctx, crx) = crossbeam_channel::unbounded::<IndexerCommand>();
        let (etx, erx) = crossbeam_channel::unbounded::<IndexerEvent>();
        let handle = std::thread::spawn(move || {
            run_query_loop(main_log, crx, etx).expect("query loop");
        });

        // First Requery at epoch=1 ⇒ current_epoch becomes 1.
        ctx.send(IndexerCommand::Requery {
            filter: FilterState::default(),
            epoch: 1,
        })
        .expect("send requery 1");
        let ev = erx
            .recv_timeout(Duration::from_secs(2))
            .expect("recv MatchIds for epoch=1");
        assert!(
            matches!(ev, IndexerEvent::MatchIds { epoch: 1, .. }),
            "expected MatchIds for epoch=1, got {ev:?}"
        );

        // Second Requery at epoch=2 ⇒ current_epoch becomes 2.
        ctx.send(IndexerCommand::Requery {
            filter: FilterState::default(),
            epoch: 2,
        })
        .expect("send requery 2");
        let ev = erx
            .recv_timeout(Duration::from_secs(2))
            .expect("recv MatchIds for epoch=2");
        assert!(
            matches!(ev, IndexerEvent::MatchIds { epoch: 2, .. }),
            "expected MatchIds for epoch=2, got {ev:?}"
        );

        // Third Requery at the stale epoch=1 ⇒ MUST be dropped silently.
        ctx.send(IndexerCommand::Requery {
            filter: FilterState::default(),
            epoch: 1,
        })
        .expect("send stale requery 1");
        match erx.recv_timeout(Duration::from_millis(200)) {
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
            Ok(ev) => panic!("expected no event for stale epoch, got {ev:?}"),
            Err(e) => panic!("unexpected channel error: {e:?}"),
        }

        ctx.send(IndexerCommand::Shutdown).expect("send shutdown");
        drop(ctx);
        handle.join().expect("join query thread");
    }

    #[test]
    fn fetch_window_returns_window_filled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (main_log, db_path) = fixture_paths(dir.path());
        seed_db_on_disk(&db_path, 5, 1);

        let (ctx, crx) = crossbeam_channel::unbounded::<IndexerCommand>();
        let (etx, erx) = crossbeam_channel::unbounded::<IndexerEvent>();
        let handle = std::thread::spawn(move || {
            run_query_loop(main_log, crx, etx).expect("query loop");
        });

        let ids = vec![3u64, 1, 4];
        ctx.send(IndexerCommand::FetchWindow {
            ids: ids.clone(),
            range_start: 7,
            epoch: 1,
        })
        .expect("send fetch_window");

        let ev = erx
            .recv_timeout(Duration::from_secs(2))
            .expect("recv WindowFilled");
        match ev {
            IndexerEvent::WindowFilled {
                rows,
                range_start,
                epoch,
            } => {
                assert_eq!(epoch, 1, "echoed epoch must match request");
                assert_eq!(range_start, 7, "range_start must be echoed verbatim");
                assert_eq!(
                    rows.iter().map(|r| r.id).collect::<Vec<_>>(),
                    ids,
                    "rows must preserve the requested input order"
                );
            }
            other => panic!("expected WindowFilled, got {other:?}"),
        }

        ctx.send(IndexerCommand::Shutdown).expect("send shutdown");
        drop(ctx);
        handle.join().expect("join query thread");
    }
}
