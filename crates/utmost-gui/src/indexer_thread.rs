//! Background work that turns a `.bin` event log into a SQLite index.
//!
//! `run_blocking` is the synchronous entry point used by tests; `spawn`
//! runs the same work on a background thread and emits `IndexProgress`
//! over a `crossbeam_channel::Sender`. Both share
//! `run_blocking_with_progress` as the implementation.

use anyhow::{Context, Result};
use crossbeam_channel::Sender;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::index_db::{IndexDb, OpenAction, hydrate, open_decision, writer::IndexDbWriter};
use crate::view_model::ViewModel;
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
/// Each `apply()` records `offset_after` derived from the current size of
/// the bincode log on disk. This is a coarse approximation — the actual
/// per-event byte offset would require a synchronous reader — but it
/// satisfies the open-decision contract: after RunFinished the meta
/// offset matches the final log size, so a re-open after the live run
/// short-circuits straight to `HydrateAndDone`.
pub fn run_live_writes(
    main_log: &Path,
    rx: crossbeam_channel::Receiver<utmost_lib::events::CarveEvent>,
) -> Result<()> {
    let db_path = index_path_for(main_log);
    let mut db = IndexDb::open(&db_path)
        .with_context(|| format!("opening index db at {}", db_path.display()))?;
    let mut writer = IndexDbWriter::new(db.conn(), 50);
    let mut last_flush = std::time::Instant::now();
    let bin_path = main_log.to_path_buf();
    loop {
        match rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(ev) => {
                let off = std::fs::metadata(&bin_path).map(|m| m.len()).unwrap_or(0);
                writer.apply(ev, off)?;
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
