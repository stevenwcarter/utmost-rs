//! Slint GUI for utmost.
//!
//! Two entry points:
//! - `run_live(rx, run_meta)` — channel-driven for in-process `--gui` mode
//! - `run_from_file(target)` — replay one or more `carve_events.bin`

pub mod preview;
pub mod slint_adapter;
pub mod thumb_worker;
pub mod view_model;

use anyhow::Result;
use std::path::Path;

pub fn run_live(_rx: crossbeam_channel::Receiver<utmost_lib::events::CarveEvent>) -> Result<()> {
    // Filled in by later tasks.
    unimplemented!("run_live is wired in a later task")
}

pub fn run_from_file(_target: &Path) -> Result<()> {
    unimplemented!("run_from_file is wired in a later task")
}
