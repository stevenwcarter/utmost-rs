//! Background processing worker: runs preview rendering and CLIP embedding as
//! a pausable background job while the user browses the case detail view.
//!
//! ## Pure helpers
//!
//! [`next_phase`] and [`panel_state`] are side-effect-free functions that can
//! be tested without spinning up a database or thread.
//!
//! ## Worker
//!
//! [`ProcessWorker::start`] spawns a single thread that drives
//! [`process_next_batch`] in a loop, honouring the `shutdown` and `pause`
//! [`AtomicBool`]s between every batch.  The worker parks when all work is
//! done and re-polls every 500 ms so newly-carved files are picked up
//! automatically without requiring a case-reopen.
//!
//! ## Shutdown discipline
//!
//! The `shutdown` [`AtomicBool`] is shared with the rest of the case's worker
//! threads (thumb worker, indexer writer).  `close_case` sets it to `true`
//! before joining any thread, so the process worker exits on its next poll
//! without blocking the close path.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossbeam_channel::Sender;

use utmost_index::db::TursoPool;
use utmost_index::processing::{PreviewContext, ProcessCounts, ProcessPhase, process_next_batch};

/// How long to sleep between polls when idle, paused, or after an error.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Files processed per batch.  Small enough to keep each batch sub-second so
/// the pause and shutdown signals are checked frequently; large enough to
/// amortise per-batch DB overhead.
const BATCH_SIZE: usize = 8;

// ── Pure helpers ──────────────────────────────────────────────────────────────

/// Return the next processing phase that has remaining work, or `None` when
/// both queues are drained.
///
/// Phase ordering: Previews before Embeddings so that embedding always
/// operates on the persisted `preview_blob` bytes (the load-bearing ordering
/// guarantee documented in `utmost_index::processing`).
pub fn next_phase(counts: &ProcessCounts) -> Option<ProcessPhase> {
    if counts.previews_remaining > 0 {
        Some(ProcessPhase::Previews)
    } else if counts.embeddings_remaining > 0 {
        Some(ProcessPhase::Embeddings)
    } else {
        None
    }
}

/// Coarse runtime state of the background worker, used by the status panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunningState {
    /// A batch is in progress: not paused and work remains.
    Running,
    /// The user has paused the worker.
    Paused,
    /// Both queues are empty; the worker is polling for new work.
    Idle,
}

/// Derive the UI-facing running state from the pause flag and current counts.
///
/// Pause takes priority over work-remaining: a paused worker that still has
/// files pending reports `Paused`, not `Running`.
pub fn panel_state(paused: bool, counts: &ProcessCounts) -> RunningState {
    if paused {
        RunningState::Paused
    } else if next_phase(counts).is_none() {
        RunningState::Idle
    } else {
        RunningState::Running
    }
}

// ── Progress type ─────────────────────────────────────────────────────────────

/// Snapshot of processing progress sent to the UI after each batch completes.
///
/// `counts` reflects the state immediately after the batch so that any
/// parallel CLI `process` invocation is visible in the next UI refresh.
pub struct ProcessProgress {
    /// Which phase just completed a batch.
    pub phase: ProcessPhase,
    /// Remaining work counts as of the end of that batch.
    pub counts: ProcessCounts,
}

// ── Worker ────────────────────────────────────────────────────────────────────

/// Handle to the background processing thread.
///
/// Created by [`ProcessWorker::start`]; stopped by [`ProcessWorker::join`] (or
/// on `Drop`).  The `shutdown` signal shared with the rest of the case's threads
/// is the primary stop mechanism.
pub struct ProcessWorker {
    thread: Option<JoinHandle<()>>,
}

impl ProcessWorker {
    /// Spawn the background processing thread.
    ///
    /// # Parameters
    /// - `pool`: Turso connection pool for the case's index database.
    /// - `shutdown`: case-wide stop signal; the thread exits on its next poll.
    /// - `pause`: UI-controlled pause toggle.
    /// - `progress_tx`: channel for progress updates consumed by the status panel.
    /// - `embedder` (`clip` feature only): handle to the lazily-loaded CLIP model.
    pub fn start(
        pool: TursoPool,
        shutdown: Arc<AtomicBool>,
        pause: Arc<AtomicBool>,
        progress_tx: Sender<ProcessProgress>,
        #[cfg(feature = "clip")] embedder: utmost_index::clip::Embedder,
    ) -> Self {
        let handle = thread::spawn(move || {
            worker_loop(
                pool,
                shutdown,
                pause,
                progress_tx,
                #[cfg(feature = "clip")]
                embedder,
            );
        });
        Self {
            thread: Some(handle),
        }
    }

    /// Wait for the worker thread to exit.
    ///
    /// Idempotent: calling after a previous `join` (or after `Drop`) is a
    /// no-op.  Callers should set the `shutdown` signal before calling `join`
    /// so the thread exits promptly rather than waiting out `POLL_INTERVAL`.
    pub fn join(&mut self) {
        if let Some(t) = self.thread.take()
            && let Err(e) = t.join()
        {
            tracing::warn!("ProcessWorker thread panicked: {e:?}");
        }
    }
}

impl Drop for ProcessWorker {
    fn drop(&mut self) {
        self.join();
    }
}

// ── Worker loop (private) ─────────────────────────────────────────────────────

fn worker_loop(
    pool: TursoPool,
    shutdown: Arc<AtomicBool>,
    pause: Arc<AtomicBool>,
    progress_tx: Sender<ProcessProgress>,
    #[cfg(feature = "clip")] embedder: utmost_index::clip::Embedder,
) {
    // Model string forwarded to `ProcessCounts::load` and the clip batch
    // function.  In non-clip builds the SQL still executes (counting rows) but
    // the worker never actually runs the Embeddings phase.
    #[cfg(feature = "clip")]
    let model = utmost_index::clip::ACTIVE_MODEL;
    #[cfg(not(feature = "clip"))]
    let model = "";

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Pause: sleep briefly then loop back so shutdown is re-checked at the
        // top.  This avoids holding the worker in a tight spin while paused.
        if pause.load(Ordering::Relaxed) {
            thread::sleep(POLL_INTERVAL);
            continue;
        }

        // Load current remaining counts.
        let counts = match ProcessCounts::load(&pool, model) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("ProcessWorker: ProcessCounts::load failed: {e:#}");
                thread::sleep(POLL_INTERVAL);
                continue;
            }
        };

        let Some(phase) = next_phase(&counts) else {
            // Both queues are empty: idle-poll in case the live carve adds
            // more files.  This keeps the thread alive at negligible CPU cost
            // so newly-carved images are processed without a case-reopen.
            thread::sleep(POLL_INTERVAL);
            continue;
        };

        // Non-clip builds cannot compute embeddings: skip the phase rather
        // than looping forever on a count we can never reduce.
        #[cfg(not(feature = "clip"))]
        if matches!(phase, ProcessPhase::Embeddings) {
            thread::sleep(POLL_INTERVAL);
            continue;
        }

        // Embeddings phase: wait for the CLIP model to finish loading before
        // starting.  During the wait the worker keeps checking shutdown/pause.
        #[cfg(feature = "clip")]
        if matches!(phase, ProcessPhase::Embeddings) && !embedder.is_ready() {
            thread::sleep(POLL_INTERVAL);
            continue;
        }

        // Previews phase: build (or refresh) the PreviewContext.  Rebuilding
        // each iteration is cheap (a single `SELECT source_id, filename FROM
        // source` round-trip) and ensures sources indexed by the concurrent
        // indexer writer are visible on the next pass.
        let ctx = if matches!(phase, ProcessPhase::Previews) {
            match PreviewContext::from_case(&pool) {
                Ok(c) => Some(c),
                Err(e) => {
                    tracing::warn!("ProcessWorker: PreviewContext::from_case failed: {e:#}");
                    thread::sleep(POLL_INTERVAL);
                    continue;
                }
            }
        } else {
            None
        };

        // Run one batch for the chosen phase.
        let result = process_next_batch(
            &pool,
            ctx.as_ref(),
            #[cfg(feature = "clip")]
            embedder
                .get()
                .map(|e| e as &dyn utmost_index::clip::EmbedFn),
            #[cfg(feature = "clip")]
            model,
            phase,
            BATCH_SIZE,
        );

        match result {
            Ok(_outcome) => {
                // Re-read counts so any parallel CLI `process` run is
                // reflected in the progress snapshot.
                match ProcessCounts::load(&pool, model) {
                    Ok(fresh) => {
                        // A send error means the case is being torn down;
                        // shutdown will be observed on the next loop iteration.
                        let _ = progress_tx.send(ProcessProgress {
                            phase,
                            counts: fresh,
                        });
                    }
                    Err(e) => {
                        tracing::debug!(
                            "ProcessWorker: post-batch ProcessCounts::load failed: {e:#}"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!("ProcessWorker: process_next_batch({phase:?}) failed: {e:#}");
                thread::sleep(POLL_INTERVAL);
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(previews_remaining: usize, embeddings_remaining: usize) -> ProcessCounts {
        ProcessCounts {
            previews_remaining,
            embeddings_remaining,
        }
    }

    // ── next_phase ────────────────────────────────────────────────────────────

    /// Previews are scheduled when previews remain, even with no embeddings.
    #[test]
    fn next_phase_previews_only() {
        assert_eq!(next_phase(&counts(3, 0)), Some(ProcessPhase::Previews));
    }

    /// Previews are scheduled before Embeddings when both remain (ordering
    /// guarantee: embeddings require persisted preview_blob bytes).
    #[test]
    fn next_phase_previews_before_embeddings_when_both_remain() {
        assert_eq!(
            next_phase(&counts(2, 5)),
            Some(ProcessPhase::Previews),
            "Previews must be prioritised over Embeddings"
        );
    }

    /// Embeddings are scheduled only after all previews are done.
    #[test]
    fn next_phase_embeddings_when_only_embeddings_remain() {
        assert_eq!(next_phase(&counts(0, 4)), Some(ProcessPhase::Embeddings));
    }

    /// None is returned when both queues are empty.
    #[test]
    fn next_phase_none_when_queues_empty() {
        assert_eq!(next_phase(&counts(0, 0)), None);
    }

    // ── panel_state ───────────────────────────────────────────────────────────

    /// Running when not paused and work remains.
    #[test]
    fn panel_state_running_not_paused_with_work() {
        assert_eq!(panel_state(false, &counts(1, 0)), RunningState::Running);
    }

    /// Running when only embeddings remain and not paused.
    #[test]
    fn panel_state_running_embeddings_outstanding() {
        assert_eq!(panel_state(false, &counts(0, 7)), RunningState::Running);
    }

    /// Paused when paused and work remains — pause takes priority.
    #[test]
    fn panel_state_paused_overrides_work_remaining() {
        assert_eq!(panel_state(true, &counts(3, 5)), RunningState::Paused);
    }

    /// Paused even when no work remains — pause takes priority over Idle too.
    #[test]
    fn panel_state_paused_overrides_idle() {
        assert_eq!(panel_state(true, &counts(0, 0)), RunningState::Paused);
    }

    /// Idle when not paused and both queues are empty.
    #[test]
    fn panel_state_idle_when_not_paused_and_no_work() {
        assert_eq!(panel_state(false, &counts(0, 0)), RunningState::Idle);
    }
}
