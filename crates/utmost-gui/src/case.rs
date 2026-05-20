//! Per-case runtime state. One CaseHandle for the case currently open
//! in the picker; created by [`open_case`], destroyed by [`close_case`].

use anyhow::Result;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crossbeam_channel::{Receiver, Sender};
use utmost_lib::events::CarveEvent;

use crate::indexer_thread::{IndexerCommand, IndexerEvent};
use crate::journal::Journal;
use crate::thumb_worker::PreviewOutcome;
use crate::view_model::ViewModel;

/// Where a case's events come from. Today only `Historical` is built;
/// `Live` is here for Plan 2 (live-carve multi-source) and intentionally
/// unused in Plan 1.
pub enum CaseSource {
    Historical(PathBuf),
    #[allow(dead_code)]
    Live {
        events_bin: PathBuf,
        event_rx: Receiver<CarveEvent>,
    },
}

impl CaseSource {
    pub fn events_bin(&self) -> &PathBuf {
        match self {
            Self::Historical(p) => p,
            Self::Live { events_bin, .. } => events_bin,
        }
    }
}

/// Per-case lifetime bundle. Created by [`open_case`]; on [`close_case`]
/// all threads are joined and channels dropped in order.
pub struct CaseHandle {
    pub events_bin: PathBuf,
    pub sqlite_path: PathBuf,
    pub vm: Arc<Mutex<ViewModel>>,
    pub indexer_cmd_tx: Sender<IndexerCommand>,
    pub indexer_event_rx: Receiver<IndexerEvent>,
    pub indexer_thread: Option<JoinHandle<()>>,
    pub preview_writer_thread: Option<JoinHandle<()>>,
    pub preview_outcomes_tx: Option<Sender<PreviewOutcome>>,
    pub journal: Option<Arc<Journal>>,
    pub vm_event_tx: Option<Sender<CarveEvent>>,
    pub shutdown_signal: Arc<AtomicBool>,
}

/// Stub: real implementation lands in Task 7. Defined here so callers
/// can compile against the signature.
pub fn open_case(_source: CaseSource, _source_search_locations: &[PathBuf]) -> Result<CaseHandle> {
    anyhow::bail!("open_case is not implemented yet (see Task 7)");
}

/// Stub: real implementation lands in Task 7.
pub fn close_case(_handle: CaseHandle) -> Result<()> {
    Ok(())
}
