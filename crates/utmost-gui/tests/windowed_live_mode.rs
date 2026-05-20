//! Task 16: live-mode auto-requery integration test.
//!
//! Seeds an on-disk SQLite index, drives `run_query_loop` through an
//! initial `Requery`, then writes additional `file` rows directly via
//! diesel (mirroring what the engine's live-mode writer thread does) and
//! sends an `IndexerCommand::Tick`. The query loop's Tick handler must
//! notice the row-count delta, re-run the cached filter, and emit a
//! fresh `MatchIds` event covering the new rows.
//!
//! This test deliberately bypasses the bincode event log and the
//! `IndexDbWriter`: the contract under test is "the indexer loop's Tick
//! handler re-runs the last filter when the `file` table has grown," not
//! the writer's batching cadence (which has dedicated coverage in
//! `index_db_live_writes.rs` and friends).

use crossbeam_channel::unbounded;
use std::path::{Path, PathBuf};
use std::time::Duration;

use diesel::prelude::*;
use utmost_gui::index_db::IndexDb;
use utmost_gui::index_db::models::{NewFile, NewSource};
use utmost_gui::index_db::schema;
use utmost_gui::indexer_thread::{IndexerCommand, IndexerEvent, index_path_for, run_query_loop};
use utmost_gui::view_model::FilterState;

/// Insert `count` rows starting at `start_id` into the `file` table.
/// Source row 1 must already exist (created by `seed_initial`).
fn append_rows(db_path: &Path, start_id: i64, count: i64) {
    let mut db = IndexDb::open(db_path).expect("open db for append");
    db.with_conn::<(), diesel::result::Error, _>(|conn| {
        conn.transaction(|tx| {
            for i in 0..count {
                let id = start_id + i;
                let row = NewFile {
                    file_id: id,
                    source_id: 1,
                    filename: format!("{id:08}.jpeg"),
                    filesize: 1_000 + id,
                    file_type: "jpeg".into(),
                    img_offset: id * 4096,
                    written_path: format!("img1/{id:08}.jpeg"),
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
    .expect("append rows");
}

fn seed_initial(db_path: &Path, count: i64) {
    let mut db = IndexDb::open(db_path).expect("open db for seed");
    let src = NewSource {
        source_id: 1,
        filename: "img1.bin".into(),
        output_subdir: "img1".into(),
        total_bytes: 0,
        bytes_read: 0,
        files_found: 0,
        status: "Finished".into(),
        duration_ms: None,
    };
    diesel::insert_into(schema::source::table)
        .values(&src)
        .execute(db.conn())
        .expect("insert source");
    drop(db);
    append_rows(db_path, 1, count);
}

fn fixture_paths(dir: &Path) -> (PathBuf, PathBuf) {
    let main_log = dir.join("img1-events.bin");
    std::fs::write(&main_log, b"placeholder").expect("write placeholder log");
    let db_path = index_path_for(&main_log);
    (main_log, db_path)
}

#[test]
fn appending_files_via_writer_extends_match_ids_via_tick() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (main_log, db_path) = fixture_paths(dir.path());
    seed_initial(&db_path, 100);

    let (cmd_tx, cmd_rx) = unbounded::<IndexerCommand>();
    let (evt_tx, evt_rx) = unbounded::<IndexerEvent>();
    let main_log_for_thread = main_log.clone();
    let handle = std::thread::spawn(move || {
        run_query_loop(main_log_for_thread, cmd_rx, evt_tx).expect("query loop");
    });

    // Step 1: initial Requery — expect 100 rows.
    cmd_tx
        .send(IndexerCommand::Requery {
            filter: FilterState::default(),
            epoch: 1,
        })
        .expect("send initial requery");

    match evt_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("recv initial MatchIds")
    {
        IndexerEvent::MatchIds { stubs, epoch } => {
            assert_eq!(epoch, 1, "echoed epoch must match");
            assert_eq!(stubs.len(), 100, "initial requery sees all 100 rows");
        }
        other => panic!("expected MatchIds, got {other:?}"),
    }

    // Step 2: append 50 more rows directly (simulates the live-mode writer).
    append_rows(&db_path, 101, 50);

    // Step 3: send Tick — the indexer loop should observe the row-count
    // delta and emit a fresh MatchIds covering all 150 rows.
    //
    // The indexer's Tick handler is throttled to ~500 ms between probes,
    // and the initial Requery counted as a recent "live probe" so the
    // first Tick may be a no-op. Sleep slightly past the throttle window
    // before sending the Tick so the probe runs.
    std::thread::sleep(Duration::from_millis(600));
    cmd_tx.send(IndexerCommand::Tick).expect("send tick");

    match evt_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("recv post-tick MatchIds")
    {
        IndexerEvent::MatchIds { stubs, epoch } => {
            assert!(
                epoch > 1,
                "auto-requery should advance the epoch beyond the UI's last value"
            );
            assert_eq!(
                stubs.len(),
                150,
                "post-tick requery must include the 50 newly-appended rows"
            );
        }
        other => panic!("expected post-tick MatchIds, got {other:?}"),
    }

    // Step 4: a second Tick with no new rows must NOT produce another
    // MatchIds — the row-count check short-circuits when nothing changed.
    std::thread::sleep(Duration::from_millis(600));
    cmd_tx.send(IndexerCommand::Tick).expect("send second tick");
    match evt_rx.recv_timeout(Duration::from_millis(300)) {
        Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
        Ok(ev) => panic!("expected no event for no-op tick, got {ev:?}"),
        Err(e) => panic!("unexpected channel error: {e:?}"),
    }

    cmd_tx
        .send(IndexerCommand::Shutdown)
        .expect("send shutdown");
    drop(cmd_tx);
    handle.join().expect("join query thread");
}
