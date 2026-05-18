//! Background runner that drives the recovery pipeline from the GUI.
//!
//! The "Run recovery" button calls `start_recovery_request`, which spawns a
//! worker thread that runs `recover_fragmented_jpegs_with_event_log_sink`
//! against the source image and an existing `carve_events.bin`. Events
//! emitted by the library land in both the bincode log (durable) and an
//! in-process `ChannelSink` consumed by the view-model.

use std::path::PathBuf;
use std::sync::Arc;

use crossbeam_channel::{Receiver, Sender, unbounded};
use utmost_lib::events::{CarveEvent, ChannelSink, EventSink};
use utmost_lib::jpeg_recover::{RecoveryConfig, recover_fragmented_jpegs_with_event_log_sink};

pub const KEEP_CANDIDATES_DEFAULT: usize = 5;
pub const KEEP_CANDIDATES_MAX: usize = 10;

#[derive(Debug, Clone)]
pub struct RecoveryRequest {
    pub image_path: String,
    pub report_path: String,
    pub output_dir: String,
    pub event_log: PathBuf,
    pub keep_candidates: usize,
}

pub fn clamp_keep_candidates(n: usize) -> usize {
    n.clamp(1, KEEP_CANDIDATES_MAX)
}

/// Run recovery synchronously. Returns Ok with the bincode events the
/// pipeline emitted (also persisted to `req.event_log`).
pub fn run_recovery_blocking(req: RecoveryRequest, tx: Sender<CarveEvent>) -> anyhow::Result<()> {
    let channel_sink = Arc::new(ChannelSink::new(tx)) as Arc<dyn EventSink>;
    let cfg = RecoveryConfig {
        keep_candidates: req.keep_candidates,
        ..RecoveryConfig::default()
    };
    recover_fragmented_jpegs_with_event_log_sink(
        &req.image_path,
        &req.report_path,
        &req.output_dir,
        &cfg,
        Some(channel_sink),
        Some(&req.event_log),
    )?;
    Ok(())
}

/// Spawn `run_recovery_blocking` on a worker thread. Returns the receiver
/// half; UI code drains it on the Slint timer.
pub fn start_background(req: RecoveryRequest) -> Receiver<CarveEvent> {
    let (tx, rx) = unbounded();
    std::thread::spawn(move || {
        if let Err(e) = run_recovery_blocking(req, tx) {
            tracing::warn!("recovery worker failed: {e}");
        }
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keep_candidates_clamps_to_bounds() {
        assert_eq!(clamp_keep_candidates(0), 1);
        assert_eq!(clamp_keep_candidates(5), 5);
        assert_eq!(clamp_keep_candidates(100), KEEP_CANDIDATES_MAX);
    }

    // NOTE: a full end-to-end recovery test through run_recovery_blocking
    // belongs in Task 22 (recovery_pipeline_e2e.rs) which has access to the
    // partial-JPEG fixture builders. Skipping it here keeps this task small.
}
