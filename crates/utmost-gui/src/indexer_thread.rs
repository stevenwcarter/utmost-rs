//! Background work that turns a `.bin` event log into a SQLite index.
//!
//! `run_blocking` is the synchronous entry point used by tests; `spawn`
//! runs the same work on a background thread and emits `IndexProgress`
//! over a `crossbeam_channel::Sender`. Both share
//! `run_blocking_with_progress` as the implementation.

use anyhow::{Context, Result};
use crossbeam_channel::{Receiver, Sender};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::index_db::models::FileStub;
use crate::index_db::{
    IndexDb, TursoPool, block_on, hydrate, queries,
    writer::{IndexDbWriter, apply_annotation_event, write_preview_outcomes},
};
use crate::thumb_worker::PreviewOutcome;
use crate::view_model::{FilterState, FoundFile, ViewModel};
use turso::Value;
use utmost_lib::events::BincodeFileReader;

/// Decision about how to reconcile the on-disk index against the event log,
/// computed by [`open_decision`].
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

/// Read a single `meta.value` string by key through the turso pool.
fn read_meta_str(pool: &TursoPool, key: &str) -> Result<Option<String>> {
    let pool = pool.clone();
    let key = key.to_owned();
    block_on(async move {
        let conn = pool.get().await?;
        let mut rows = conn
            .query(
                "SELECT value FROM meta WHERE key = ?1",
                (Value::Text(key),),
            )
            .await?;
        match rows.next().await? {
            Some(row) => Ok(Some(
                row.get_value(0)?
                    .as_text()
                    .context("meta.value is not text")?
                    .to_owned(),
            )),
            None => Ok(None),
        }
    })
}

/// Decide how to reconcile the index DB against the event log at `bin`.
///
/// Mirrors the pre-turso logic: compares the recorded `run_started_at` /
/// `last_event_offset` meta keys against the log's first `RunStarted` event
/// and current size.
pub fn open_decision(bin: &Path, pool: &TursoPool) -> Result<OpenAction> {
    let bin_size = std::fs::metadata(bin)
        .with_context(|| format!("stat {}", bin.display()))?
        .len();

    let meta_started_at = read_meta_str(pool, "run_started_at")?;
    let meta_offset = read_meta_str(pool, "last_event_offset")?.and_then(|s| s.parse::<u64>().ok());

    let mut reader = BincodeFileReader::open(bin)
        .with_context(|| format!("opening {}", bin.display()))?;
    let Some(first) = reader.next_event()? else {
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
    /// One-shot "tail loop has processed every event currently in the
    /// events.bin and is now waiting for more data" signal. Emitted on
    /// the first `Ok(None)` inside `tail_loop`. The UI uses this to drop
    /// the modal "Building index…" overlay so the user can interact with
    /// files already folded into the index while new events continue to
    /// trickle in via the per-tick requery path.
    ///
    /// Fires at most once per writer-thread lifecycle.
    CaughtUp,
    /// Terminal "indexer is done" signal. **No longer emitted by `spawn()`
    /// after the tail-mode refactor** — the tail loop runs until
    /// `shutdown_signal` is set or the error cap is hit, both of which
    /// exit via plain `Ok` without sending `Finished`. The variant is
    /// retained for backwards compatibility with handlers in
    /// `slint_adapter.rs`; live "carve done" detection moves to the
    /// picker's per-row tailer observing `RunFinished` in the events.bin.
    Finished,
    /// Terminal error. `String` is a formatted `anyhow` chain. No
    /// further messages will be sent.
    Error(String),
}

/// How many bytes the indexer must advance between progress ticks.
const PROGRESS_TICK_BYTES: u64 = 2 * 1024 * 1024;
/// How long the tail loop sleeps after a clean EOF before retrying.
const TAIL_POLL_INTERVAL_MS: u64 = 500;
/// Maximum number of consecutive decode errors before the tail loop gives up.
const MAX_CONSECUTIVE_ERRORS: u32 = 10;

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
/// `progress`. The thread always emits `Started` first. With the tail-mode
/// loop, the thread runs until `shutdown` is set (caller-driven
/// termination via close_case) or `MAX_CONSECUTIVE_ERRORS`
/// consecutive read errors are observed (gives up cleanly).
/// On unrecoverable errors during the initial setup, an
/// `Error` progress message is emitted before the thread exits.
/// `Finished` is no longer emitted — callers that need to detect
/// "carve done" should observe `RunFinished` in the events.bin
/// via the per-case picker tailer or read the case's sqlite.
pub fn spawn(
    bin: PathBuf,
    vm: Arc<Mutex<ViewModel>>,
    progress: Sender<IndexProgress>,
    shutdown: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let total_bytes = std::fs::metadata(&bin).ok().map(|m| m.len());
        let _ = progress.send(IndexProgress::Started { total_bytes });
        if let Err(e) = run_blocking_with_progress(&bin, vm, Some(&progress), Some(&shutdown)) {
            let _ = progress.send(IndexProgress::Error(format!("{e:#}")));
        }
        // No Finished signal: the tail loop exits only via shutdown or
        // MAX_CONSECUTIVE_ERRORS, not at a clean EOF, so Finished is
        // never the right terminal event in tail mode.
    })
}

/// Synchronous index build / hydrate without progress signalling. Used
/// by tests and by call-sites that don't need a `crossbeam_channel`.
pub fn run_blocking(bin: &Path, vm: Arc<Mutex<ViewModel>>) -> Result<()> {
    run_blocking_with_progress(bin, vm, None, None)
}

/// Shared implementation behind [`run_blocking`] and [`spawn`]. When
/// `progress` is `Some`, the inner loops emit a `Bytes` / `Files` tick
/// every ~2 MB of event-log bytes processed. When `shutdown` is `Some`
/// and observed `true` (Relaxed) between events, the loop flushes any
/// pending batch and returns `Ok` early — `last_event_offset` is
/// advanced so a subsequent [`Resume`](OpenAction::Resume) picks up
/// where we stopped.
fn run_blocking_with_progress(
    bin: &Path,
    vm: Arc<Mutex<ViewModel>>,
    progress: Option<&Sender<IndexProgress>>,
    shutdown: Option<&Arc<AtomicBool>>,
) -> Result<()> {
    let db_path = index_path_for(bin);
    let pool = IndexDb::open(&db_path)
        .with_context(|| format!("opening index db at {}", db_path.display()))?
        .pool()
        .clone();
    let action = open_decision(bin, &pool)?;
    match action {
        OpenAction::HydrateAndDone => {
            hydrate_into(&pool, &vm)?;
        }
        OpenAction::WipeAndRebuild => {
            wipe_tables(&pool)?;
            rebuild_from_zero(bin, &pool, &vm, progress, shutdown)?;
        }
        OpenAction::RebuildFromZero => {
            rebuild_from_zero(bin, &pool, &vm, progress, shutdown)?;
        }
        OpenAction::Resume { from } => {
            hydrate_into(&pool, &vm)?;
            resume_from(bin, from, &pool, &vm, progress, shutdown)?;
        }
    }
    {
        let mut v = vm.lock().unwrap();
        v.recompute_visible();
    }
    Ok(())
}

fn hydrate_into(pool: &TursoPool, vm: &Arc<Mutex<ViewModel>>) -> Result<()> {
    let snap =
        hydrate::snapshot_from_db(pool)?.context("expected snapshot from db with run row")?;
    vm.lock().unwrap().hydrate_from(snap);
    Ok(())
}

fn wipe_tables(pool: &TursoPool) -> Result<()> {
    let pool = pool.clone();
    block_on(async move {
        let mut conn = pool.get().await?;
        let tx = conn.transaction().await?;
        for stmt in [
            "DELETE FROM preview_blob",
            "DELETE FROM variant",
            "DELETE FROM recovery_run",
            "DELETE FROM best_choice",
            "DELETE FROM note",
            "DELETE FROM bookmark",
            "DELETE FROM file",
            "DELETE FROM source",
            "DELETE FROM run",
            "DELETE FROM meta",
        ] {
            tx.execute(stmt, ()).await?;
        }
        tx.execute(
            "INSERT INTO meta(key, value) VALUES ('preview_status_version', '0')",
            (),
        )
        .await?;
        tx.commit().await?;
        anyhow::Ok(())
    })
}

/// Shared event-fold loop used by both `rebuild_from_zero` and `resume_from`
/// after their initial reader setup. Reads events from `reader`, applies
/// them to `vm`, writes via `writer`, emits progress ticks every
/// `PROGRESS_TICK_BYTES`, retries up to `MAX_CONSECUTIVE_ERRORS` on read
/// errors before giving up.
///
/// **EOF behavior depends on `shutdown`:**
/// - `Some(_)` — tail mode: on EOF, flush + sleep + retry. Exits only when
///   `shutdown` is set (or the error cap is hit). Used by `spawn()` for
///   live-carve cases (an `open_case` indexer-writer thread).
/// - `None` — bounded mode: on EOF, flush + return Ok. Used by tests and
///   by synchronous `run_blocking` for cold-build scenarios.
///
/// On exit (clean or via error cap), the writer is flushed to commit any
/// pending batch and advance `last_event_offset`.
fn tail_loop(
    reader: &mut BincodeFileReader,
    writer: &mut IndexDbWriter,
    vm: &Arc<Mutex<ViewModel>>,
    progress: Option<&Sender<IndexProgress>>,
    shutdown: Option<&Arc<AtomicBool>>,
    mut last_tick_offset: u64,
) -> Result<()> {
    let mut files_seen: u64 = 0;
    let mut consecutive_errors: u32 = 0;
    // CaughtUp must fire on the *first* EOF the loop observes, after which
    // the writer is in "tail" mode for the rest of its lifetime. The UI
    // uses this to drop the modal overlay; further Bytes/Files ticks
    // during tail mode are informational and don't re-engage it.
    let mut caught_up_emitted = false;

    loop {
        if let Some(s) = shutdown
            && s.load(Ordering::Relaxed)
        {
            writer.flush()?;
            return Ok(());
        }
        match reader.next_event() {
            Ok(Some(ev)) => {
                consecutive_errors = 0;
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
            Ok(None) => {
                consecutive_errors = 0;
                writer.flush()?;
                // Signal "caught up to the events.bin's current EOF" once,
                // before potentially napping in tail mode. The UI drops
                // its "Building index…" overlay on this so the user can
                // interact with everything already folded. Skipped in
                // bounded mode — there's no tail to caught-up-from; the
                // caller's loop exit / channel disconnect is its own
                // terminal signal.
                if let Some(tx) = progress
                    && shutdown.is_some()
                    && !caught_up_emitted
                {
                    let _ = tx.send(IndexProgress::Files { count: files_seen });
                    let _ = tx.send(IndexProgress::CaughtUp);
                    caught_up_emitted = true;
                }
                // Bounded mode (no shutdown signal): exit at EOF for tests
                // and synchronous run_blocking callers. Tail mode (Some
                // shutdown): sleep and retry; the spawn-based caller will
                // set the signal to exit.
                if shutdown.is_none() {
                    return Ok(());
                }
                std::thread::sleep(std::time::Duration::from_millis(TAIL_POLL_INTERVAL_MS));
            }
            Err(e) => {
                consecutive_errors += 1;
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                    tracing::warn!(
                        "indexer giving up after {consecutive_errors} consecutive errors: {e:#}"
                    );
                    writer.flush()?;
                    return Ok(());
                }
                tracing::debug!(
                    "indexer tail retry {consecutive_errors}/{MAX_CONSECUTIVE_ERRORS} after: {e:#}"
                );
                writer.flush()?;
                std::thread::sleep(std::time::Duration::from_millis(TAIL_POLL_INTERVAL_MS));
            }
        }
    }
}

fn rebuild_from_zero(
    bin: &Path,
    pool: &TursoPool,
    vm: &Arc<Mutex<ViewModel>>,
    progress: Option<&Sender<IndexProgress>>,
    shutdown: Option<&Arc<AtomicBool>>,
) -> Result<()> {
    let mut reader = BincodeFileReader::open(bin)?;
    let mut writer = IndexDbWriter::new(pool.clone(), 5000);
    tail_loop(&mut reader, &mut writer, vm, progress, shutdown, 0)
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
    let pool = IndexDb::open(&db_path)
        .with_context(|| format!("opening index db at {}", db_path.display()))?
        .pool()
        .clone();
    let mut writer = IndexDbWriter::new(pool, 50);
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
    let pool = IndexDb::open(&db_path)
        .with_context(|| format!("opening index db at {}", db_path.display()))?
        .pool()
        .clone();

    let flush_and_notify = |pool: &TursoPool,
                            batch: &mut Vec<PreviewOutcome>,
                            event_tx: &Option<crossbeam_channel::Sender<IndexerEvent>>|
     -> Result<()> {
        write_preview_outcomes(pool, batch)?;
        batch.clear();
        if let Some(tx) = event_tx
            && let Ok(v) = read_preview_status_version(pool)
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
                    flush_and_notify(&pool, &mut batch, &event_tx)?;
                    last_flush = std::time::Instant::now();
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                if !batch.is_empty() {
                    flush_and_notify(&pool, &mut batch, &event_tx)?;
                }
                last_flush = std::time::Instant::now();
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }
    if !batch.is_empty() {
        flush_and_notify(&pool, &mut batch, &event_tx)?;
    }
    Ok(())
}

fn resume_from(
    bin: &Path,
    from: u64,
    pool: &TursoPool,
    vm: &Arc<Mutex<ViewModel>>,
    progress: Option<&Sender<IndexProgress>>,
    shutdown: Option<&Arc<AtomicBool>>,
) -> Result<()> {
    let mut reader = BincodeFileReader::open(bin)?;
    reader.seek_to(from)?;
    let mut writer = IndexDbWriter::new(pool.clone(), 5000);
    tail_loop(&mut reader, &mut writer, vm, progress, shutdown, from)
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
    /// Apply a UI-originated annotation event (`Bookmark`, `Note`,
    /// `MarkAsBest`) to SQLite immediately so the next `Requery` sees it.
    /// The journal continues to persist the same event to `.pending` for
    /// crash recovery; the next-session `resume_from` re-applies via
    /// idempotent `on_conflict` upserts, so dropping or duplicating this
    /// command is safe. Fire-and-forget — failures are logged but do not
    /// emit an event.
    ///
    /// `CarveEvent` is large (~500 bytes via its `RunStarted` variant) so
    /// the payload is boxed to keep the enum's overall size aligned with
    /// the other variants.
    ApplyAnnotation(Box<utmost_lib::events::CarveEvent>),
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
    /// Write the supplied [`UiStateSnapshot`] to `meta.ui_state` on this
    /// case's sqlite. Fire-and-forget — the UI thread does not wait for
    /// acknowledgement. Errors are logged on the query-loop thread.
    PersistUiState(crate::view_model::UiStateSnapshot),
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
    let pool = IndexDb::open(&db_path)
        .with_context(|| format!("opening index db at {}", db_path.display()))?
        .pool()
        .clone();
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
                    // Task 15 will pass a real query embedding when search is
                    // active; for now always pass None (normal filter+sort path).
                    queries::query_match_ids(&pool, &filter, None)
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
                    queries::fetch_window(&pool, &ids)
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
            IndexerCommand::ApplyAnnotation(event) => {
                let res = {
                    let _g = perf.phase("apply_annotation");
                    apply_annotation_event(&pool, event.as_ref())
                };
                if let Err(e) = res {
                    // No epoch tied to annotations; surface as a generic
                    // error so the UI can log it. The in-memory VM state
                    // already reflects the change, so the user sees the
                    // bookmark star / note in the side panel even if the
                    // SQLite write fails — only the filter chip is affected.
                    let _ = event_tx.send(IndexerEvent::Error {
                        epoch: None,
                        message: format!("apply_annotation_event: {e}"),
                    });
                }
                perf.tick();
            }
            IndexerCommand::WritePreviewStatus { outcomes } => {
                let res = {
                    let _g = perf.phase("preview_status_write");
                    write_preview_outcomes(&pool, &outcomes)
                };
                match res {
                    Ok(()) => match read_preview_status_version(&pool) {
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
                    count_file_rows(&pool)
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
                    // Task 15 will pass a real query embedding when search is
                    // active; for now always pass None (normal filter+sort path).
                    queries::query_match_ids(&pool, filter, None)
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
            IndexerCommand::PersistUiState(snap) => {
                if let Err(e) = crate::index_db::writer::write_ui_state(&pool, &snap) {
                    tracing::warn!("write_ui_state on PersistUiState failed: {e:#}");
                }
            }
            IndexerCommand::Shutdown => break,
        }
    }
    Ok(())
}

/// Count the rows in the `file` table. Used by the live-mode auto-requery
/// path in [`run_query_loop`] to cheaply detect whether the engine writer
/// has appended new files since the most recent `Requery`.
fn count_file_rows(pool: &TursoPool) -> Result<usize> {
    let pool = pool.clone();
    block_on(async move {
        let conn = pool.get().await?;
        let mut rows = conn.query("SELECT COUNT(*) FROM file", ()).await?;
        let row = rows.next().await?.context("COUNT(*) returned no row")?;
        let n = row.get_value(0)?.as_integer().copied().unwrap_or(0);
        anyhow::Ok(n.max(0) as usize)
    })
}

/// Read the current `preview_status_version` meta value. Used by
/// [`run_query_loop`] to acknowledge `WritePreviewStatus` commits.
fn read_preview_status_version(pool: &TursoPool) -> Result<u64> {
    Ok(read_meta_str(pool, "preview_status_version")?
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_run_started_for_tests() -> utmost_lib::events::CarveEvent {
        use utmost_lib::events::{CarveEvent, CliConfigSnapshot, SourceDescriptor};
        use utmost_lib::types::{ExecutionEnvironment, FileType};
        CarveEvent::RunStarted {
            utmost_version: "test".into(),
            format_version: 1,
            started_at: "2026-05-20T00:00:00Z".into(),
            command_line: vec![],
            working_directory: "/".into(),
            execution_environment: ExecutionEnvironment {
                os_sysname: "linux".into(),
                os_release: "6.0".into(),
                os_version: "1".into(),
                host: "h".into(),
                arch: "x86_64".into(),
                uid: 0,
                start_time: "2026-05-20T00:00:00Z".into(),
            },
            cli_config: CliConfigSnapshot {
                output_directory: "/out".into(),
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
            case: None,
            configured_types: vec![FileType::Jpeg],
            sources: vec![SourceDescriptor {
                source_id: 0,
                filename: "/in/x.img".into(),
                total_bytes: 0,
                output_subdir: "a".into(),
            }],
            output_root: "/out".into(),
        }
    }

    /// Seed an empty DB on disk with `count` files distributed across
    /// `num_sources`. Mirrors the fixture style used in `queries.rs` tests,
    /// but writes to a real on-disk SQLite so we can hand the path to the
    /// query-loop thread (`IndexDb` is `!Send` and so the thread must open
    /// its own connection).
    fn seed_db_on_disk(db_path: &Path, count: i64, num_sources: i32) {
        let pool = IndexDb::open(db_path)
            .expect("open db on disk")
            .pool()
            .clone();
        block_on(async {
            let mut conn = pool.get().await.unwrap();
            let tx = conn.transaction().await.unwrap();
            for s in 1..=num_sources {
                tx.execute(
                    "INSERT INTO source (source_id, filename, output_subdir, total_bytes, \
                     bytes_read, files_found, status) VALUES (?1, ?2, ?3, 0, 0, 0, 'Finished')",
                    turso::params_from_iter(vec![
                        Value::Integer(s as i64),
                        Value::Text(format!("img{s}.bin")),
                        Value::Text(format!("img{s}")),
                    ]),
                )
                .await
                .unwrap();
            }
            for i in 0..count {
                let source_id = ((i as i32) % num_sources) + 1;
                tx.execute(
                    "INSERT INTO file (file_id, source_id, filename, filesize, file_type, \
                     img_offset, written_path, byte_runs_json, preview_status) \
                     VALUES (?1, ?2, ?3, ?4, 'jpeg', ?5, ?6, '[]', 'unknown')",
                    turso::params_from_iter(vec![
                        Value::Integer(i + 1),
                        Value::Integer(source_id as i64),
                        Value::Text(format!("{:08}.jpeg", i + 1)),
                        Value::Integer(1_000 + i * 17),
                        Value::Integer(i * 4096),
                        Value::Text(format!("img{source_id}/{:08}.jpeg", i + 1)),
                    ]),
                )
                .await
                .unwrap();
            }
            tx.commit().await.unwrap();
        });
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

    /// In live mode, the engine never emits Bookmark events — only the UI
    /// does, via `vm.toggle_bookmark` → `journal.append`. Until the journal
    /// is folded into the main `.bin` (at `RunFinished` or next-session
    /// open), the SQLite `bookmark` table stays empty, so a `Requery` with
    /// `bookmarked_only=true` returns nothing even though `vm.bookmarks`
    /// has the entry. Routing the UI's annotation event through
    /// `IndexerCommand::ApplyAnnotation` writes the row to SQLite
    /// immediately so the filter chip works during the run.
    #[test]
    fn apply_annotation_bookmark_makes_filter_chip_visible() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (main_log, db_path) = fixture_paths(dir.path());
        seed_db_on_disk(&db_path, 5, 1); // file_ids 1..=5, no bookmarks

        let (ctx, crx) = crossbeam_channel::unbounded::<IndexerCommand>();
        let (etx, erx) = crossbeam_channel::unbounded::<IndexerEvent>();
        let handle = std::thread::spawn(move || {
            run_query_loop(main_log, crx, etx).expect("query loop");
        });

        // Simulate the UI toggling a bookmark on file_id=3 during a live run.
        ctx.send(IndexerCommand::ApplyAnnotation(Box::new(
            utmost_lib::events::CarveEvent::Bookmark {
                file_id: 3,
                bookmarked: true,
                at: "t".into(),
            },
        )))
        .expect("send apply_annotation");

        // Then the user toggles the "Bookmarked" filter chip.
        let filter = FilterState {
            bookmarked_only: true,
            ..FilterState::default()
        };
        ctx.send(IndexerCommand::Requery { filter, epoch: 1 })
            .expect("send requery");

        let ev = erx
            .recv_timeout(Duration::from_secs(2))
            .expect("recv MatchIds");
        match ev {
            IndexerEvent::MatchIds { stubs, epoch } => {
                assert_eq!(epoch, 1);
                let ids: Vec<u64> = stubs.iter().map(|s| s.file_id).collect();
                assert_eq!(
                    ids,
                    vec![3u64],
                    "Bookmarked filter must return the bookmark the UI just added"
                );
            }
            other => panic!("expected MatchIds, got {other:?}"),
        }

        // Untoggle the bookmark — chip must now return zero rows.
        ctx.send(IndexerCommand::ApplyAnnotation(Box::new(
            utmost_lib::events::CarveEvent::Bookmark {
                file_id: 3,
                bookmarked: false,
                at: "t2".into(),
            },
        )))
        .expect("send apply_annotation untoggle");
        let filter = FilterState {
            bookmarked_only: true,
            ..FilterState::default()
        };
        ctx.send(IndexerCommand::Requery { filter, epoch: 2 })
            .expect("send requery 2");
        let ev = erx
            .recv_timeout(Duration::from_secs(2))
            .expect("recv MatchIds 2");
        match ev {
            IndexerEvent::MatchIds { stubs, epoch: 2 } => {
                assert!(
                    stubs.is_empty(),
                    "Untoggling the bookmark must clear the bookmark table row"
                );
            }
            other => panic!("expected MatchIds epoch=2, got {other:?}"),
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

    #[test]
    fn query_loop_handles_persist_ui_state() {
        use crate::view_model::{FilterStateSnapshot, UiStateSnapshot};
        use utmost_lib::EventSink;
        use utmost_lib::events::BincodeFileSink;

        let tmp = tempfile::TempDir::new().unwrap();
        let bin = tmp.path().join("t-events.bin");
        {
            let sink = BincodeFileSink::create(&bin).unwrap();
            sink.emit(&make_run_started_for_tests());
        }

        let (cmd_tx, cmd_rx) = crossbeam_channel::unbounded::<IndexerCommand>();
        let (event_tx, _event_rx) = crossbeam_channel::unbounded::<IndexerEvent>();
        let bin_clone = bin.clone();
        let join = std::thread::spawn(move || {
            let _ = run_query_loop(bin_clone, cmd_rx, event_tx);
        });

        let snap = UiStateSnapshot {
            v: 1,
            filter: FilterStateSnapshot {
                enabled_types: vec!["jpeg".into()],
                enabled_partial_types: vec![],
                bookmarked_only: true,
                source_filter: None,
                sort_key: "Filename".into(),
                sort_dir: "Asc".into(),
                bookmarked_first: false,
                hide_no_preview: false,
                size_range: None,
            },
            filters_visible: false,
            selected_group: None,
            selection_file_id: Some(99),
        };
        cmd_tx
            .send(IndexerCommand::PersistUiState(snap.clone()))
            .expect("send PersistUiState");
        cmd_tx
            .send(IndexerCommand::Shutdown)
            .expect("send shutdown");
        join.join().expect("query loop thread join");

        let sqlite_path = crate::picker::sqlite_path_for(&bin);
        let pool = IndexDb::open(&sqlite_path).expect("reopen").pool().clone();
        let got = crate::index_db::writer::read_ui_state(&pool)
            .expect("read")
            .expect("snapshot present");
        assert_eq!(got, snap);
    }

    #[test]
    fn tail_loop_picks_up_events_appended_after_initial_eof() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;
        use tempfile::TempDir;
        use utmost_lib::events::{BincodeFileSink, CarveEvent, EventSink};
        use utmost_lib::reporting::create_file_object;
        use utmost_lib::types::FileType;

        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("tail-events.bin");

        {
            let sink = BincodeFileSink::create(&bin).expect("create");
            sink.emit(&make_run_started_for_tests());
        }

        let (tx, rx) = crossbeam_channel::unbounded();
        let vm = std::sync::Arc::new(std::sync::Mutex::new(crate::view_model::ViewModel::new()));
        let shutdown = std::sync::Arc::new(AtomicBool::new(false));
        let h = spawn(bin.clone(), vm.clone(), tx, shutdown.clone());

        std::thread::sleep(Duration::from_millis(700));
        {
            let sink = BincodeFileSink::open_append(&bin).expect("append");
            for i in 1..=50u64 {
                sink.emit(&CarveEvent::FileFound {
                    source_id: 0,
                    file: create_file_object("a.jpg", FileType::Jpeg, 0, 0, None, i),
                    img_offset: 0,
                    written_path: "a.jpg".into(),
                });
            }
        }

        std::thread::sleep(Duration::from_millis(1500));

        shutdown.store(true, Ordering::Relaxed);
        h.join().expect("indexer join");

        let sqlite_path = crate::picker::sqlite_path_for(&bin);
        let pool = crate::index_db::IndexDb::open(&sqlite_path)
            .expect("reopen")
            .pool()
            .clone();
        let count = count_file_rows(&pool).unwrap();
        assert_eq!(count, 50, "tail loop must have folded the appended events");

        let msgs: Vec<_> = rx.try_iter().collect();
        assert!(matches!(msgs.first(), Some(IndexProgress::Started { .. })));
    }

    #[test]
    fn tail_loop_recovers_from_partial_frame_at_tail() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;
        use tempfile::TempDir;
        use utmost_lib::events::{BincodeFileSink, EventSink};

        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("partial-events.bin");

        {
            let sink = BincodeFileSink::create(&bin).expect("create");
            sink.emit(&make_run_started_for_tests());
        }

        let (tx, _rx) = crossbeam_channel::unbounded();
        let vm = std::sync::Arc::new(std::sync::Mutex::new(crate::view_model::ViewModel::new()));
        let shutdown = std::sync::Arc::new(AtomicBool::new(false));
        let h = spawn(bin.clone(), vm.clone(), tx, shutdown.clone());

        std::thread::sleep(Duration::from_millis(700));

        use std::io::Write;
        {
            let mut f = std::fs::OpenOptions::new().append(true).open(&bin).unwrap();
            f.write_all(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
            f.flush().unwrap();
        }
        std::thread::sleep(Duration::from_millis(700));

        assert!(
            !h.is_finished(),
            "indexer must still be tailing despite corrupt tail bytes"
        );

        shutdown.store(true, Ordering::Relaxed);
        h.join().expect("indexer join");
    }

    /// Regression: while the writer thread is in tail mode during a live
    /// carve, the UI must be able to drop its "Building index…" overlay
    /// as soon as the writer has caught up to the events.bin's initial
    /// EOF. Without a `CaughtUp` signal the overlay sits up forever
    /// (the channel only disconnects on `shutdown_signal`), blocking
    /// every interaction.
    #[test]
    fn tail_loop_emits_caught_up_once_after_initial_eof() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, Instant};
        use tempfile::TempDir;
        use utmost_lib::events::{BincodeFileSink, CarveEvent, EventSink};
        use utmost_lib::reporting::create_file_object;
        use utmost_lib::types::FileType;

        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("caughtup-events.bin");

        // Small events.bin: well under PROGRESS_TICK_BYTES, so without
        // CaughtUp the UI would never see a terminal signal here.
        {
            let sink = BincodeFileSink::create(&bin).expect("create");
            sink.emit(&make_run_started_for_tests());
            for i in 1..=3u64 {
                sink.emit(&CarveEvent::FileFound {
                    source_id: 0,
                    file: create_file_object("a.jpg", FileType::Jpeg, 0, 0, None, i),
                    img_offset: 0,
                    written_path: "a.jpg".into(),
                });
            }
        }

        let (tx, rx) = crossbeam_channel::unbounded();
        let vm = std::sync::Arc::new(std::sync::Mutex::new(crate::view_model::ViewModel::new()));
        let shutdown = std::sync::Arc::new(AtomicBool::new(false));
        let h = spawn(bin.clone(), vm.clone(), tx, shutdown.clone());

        // Poll for CaughtUp. Must arrive without us touching shutdown —
        // that's the whole point: the UI drops the overlay while the
        // writer keeps tailing in the background.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut saw_caught_up = false;
        while Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(IndexProgress::CaughtUp) => {
                    saw_caught_up = true;
                    break;
                }
                Ok(_) => continue,
                Err(_) => continue,
            }
        }
        assert!(
            saw_caught_up,
            "tail_loop must emit CaughtUp once it processes every event currently in the bin"
        );

        // After CaughtUp the writer must still be tailing: appending more
        // events should be picked up and folded into the index.
        {
            let sink = BincodeFileSink::open_append(&bin).expect("append");
            for i in 4..=6u64 {
                sink.emit(&CarveEvent::FileFound {
                    source_id: 0,
                    file: create_file_object("b.jpg", FileType::Jpeg, 0, 0, None, i),
                    img_offset: 0,
                    written_path: "b.jpg".into(),
                });
            }
        }
        std::thread::sleep(Duration::from_millis(1200));
        assert!(
            !h.is_finished(),
            "writer must keep tailing after CaughtUp, not exit"
        );

        // CaughtUp must be a one-shot: drain any further progress and
        // confirm we never see a second CaughtUp.
        let extra: Vec<_> = rx.try_iter().collect();
        let extra_caught_up = extra
            .iter()
            .filter(|m| matches!(m, IndexProgress::CaughtUp))
            .count();
        assert_eq!(
            extra_caught_up, 0,
            "CaughtUp must fire at most once per writer lifecycle"
        );

        shutdown.store(true, Ordering::Relaxed);
        h.join().expect("indexer join");

        // Verify the post-CaughtUp appended rows actually landed in the
        // index — proves the writer kept doing its job after the signal.
        let sqlite_path = crate::picker::sqlite_path_for(&bin);
        let pool = crate::index_db::IndexDb::open(&sqlite_path)
            .expect("reopen")
            .pool()
            .clone();
        let count = count_file_rows(&pool).unwrap();
        assert_eq!(
            count, 6,
            "writer must fold both pre- and post-CaughtUp file events"
        );
    }

    #[test]
    fn tail_loop_gives_up_after_max_consecutive_errors() {
        use std::sync::atomic::AtomicBool;
        use std::time::Duration;
        use tempfile::TempDir;

        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("corrupt-events.bin");

        {
            use utmost_lib::events::{BincodeFileSink, EventSink};
            let sink = BincodeFileSink::create(&bin).expect("create");
            sink.emit(&make_run_started_for_tests());
        }
        {
            // Write MAX_CONSECUTIVE_ERRORS properly-framed records whose
            // bincode payloads are invalid. Each record is:
            //   [4, 0, 0, 0]          ← length prefix (4 bytes)
            //   [0xAA, 0xBB, 0xCC, 0xDD] ← 4 bytes of undecodable garbage
            // read_frame succeeds (frame length is valid and all bytes are
            // present), but bincode::deserialize fails → consecutive Err
            // from next_event() → counter reaches MAX_CONSECUTIVE_ERRORS.
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().append(true).open(&bin).unwrap();
            for _ in 0..15 {
                f.write_all(&[4, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
            }
            f.flush().unwrap();
        }

        let (tx, _rx) = crossbeam_channel::unbounded();
        let vm = std::sync::Arc::new(std::sync::Mutex::new(crate::view_model::ViewModel::new()));
        let shutdown = std::sync::Arc::new(AtomicBool::new(false));

        let h = spawn(bin.clone(), vm.clone(), tx, shutdown);

        let start = std::time::Instant::now();
        while !h.is_finished() && start.elapsed() < Duration::from_secs(8) {
            std::thread::sleep(Duration::from_millis(200));
        }

        assert!(
            h.is_finished(),
            "indexer must exit on its own after MAX_CONSECUTIVE_ERRORS"
        );
        h.join().expect("indexer join");
    }
}
