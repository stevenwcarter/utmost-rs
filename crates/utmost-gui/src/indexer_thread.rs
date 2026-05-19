//! Background work that turns a `.bin` event log into a SQLite index.
//!
//! `run_blocking` is the synchronous entry point used by tests and by the
//! initial wiring in `run_from_file`. A threaded variant with progress
//! signalling is added in Phase 8.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::index_db::{IndexDb, OpenAction, hydrate, open_decision, writer::IndexDbWriter};
use crate::view_model::ViewModel;
use utmost_lib::events::BincodeFileReader;

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

/// Synchronous index build / hydrate. The window thread is responsible for
/// spawning this on a worker; see Phase 8 for the threaded variant.
pub fn run_blocking(bin: &Path, vm: Arc<Mutex<ViewModel>>) -> Result<()> {
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
            rebuild_from_zero(bin, &mut db, &vm)?;
        }
        OpenAction::RebuildFromZero => {
            rebuild_from_zero(bin, &mut db, &vm)?;
        }
        OpenAction::Resume { from } => {
            hydrate_into(&mut db, &vm)?;
            resume_from(bin, from, &mut db, &vm)?;
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

fn rebuild_from_zero(bin: &Path, db: &mut IndexDb, vm: &Arc<Mutex<ViewModel>>) -> Result<()> {
    let mut reader = BincodeFileReader::open(bin)?;
    let mut writer = IndexDbWriter::new(db.conn(), 5000);
    while let Some(ev) = reader.next_event()? {
        let offset_after = reader.byte_offset()?;
        {
            let mut v = vm.lock().unwrap();
            v.apply(&ev);
        }
        writer.apply(ev, offset_after)?;
    }
    writer.flush()?;
    Ok(())
}

fn resume_from(bin: &Path, from: u64, db: &mut IndexDb, vm: &Arc<Mutex<ViewModel>>) -> Result<()> {
    // For Phase 5 we walk events from byte 0 until we're past `from`, then apply
    // the remainder. Phase 6's Task 6.1 adds `BincodeFileReader::seek_to` for a
    // direct seek, replacing this fallback.
    let mut reader = BincodeFileReader::open(bin)?;
    while reader.byte_offset()? < from {
        if reader.next_event()?.is_none() {
            return Ok(());
        }
    }
    let mut writer = IndexDbWriter::new(db.conn(), 5000);
    while let Some(ev) = reader.next_event()? {
        let offset_after = reader.byte_offset()?;
        {
            let mut v = vm.lock().unwrap();
            v.apply(&ev);
        }
        writer.apply(ev, offset_after)?;
    }
    writer.flush()?;
    Ok(())
}
