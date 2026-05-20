//! Task 15: cold-load integration test for the windowed-files pipeline.
//!
//! Seeds a fresh on-disk SQLite index with 50k files, drives the
//! `run_query_loop` thread end-to-end through one `Requery` + one
//! `FetchWindow`, and asserts that the resulting `ViewModel` state matches
//! the plan's invariants:
//!
//! * `match_ids.len() == 50_000` after the `MatchIds` event lands.
//! * `window.len() == 1_000` after the `WindowFilled` event lands.
//!
//! `IndexDb` is `!Send`, so the test seeds the DB on the test thread (one
//! connection), then hands `run_query_loop` a `main_log: PathBuf` whose
//! `index_path_for` resolution points at the same on-disk file. The query
//! loop opens its own connection. The `main_log` itself is a placeholder
//! byte sequence — `run_query_loop` never reads it.

use crossbeam_channel::unbounded;
use std::path::{Path, PathBuf};
use std::time::Duration;

use diesel::prelude::*;
use utmost_gui::index_db::IndexDb;
use utmost_gui::index_db::models::{NewFile, NewSource};
use utmost_gui::index_db::schema;
use utmost_gui::indexer_thread::{IndexerCommand, IndexerEvent, index_path_for, run_query_loop};
use utmost_gui::view_model::{FilterState, ViewModel};

/// Seed `count` jpeg rows across a single source into a fresh on-disk DB.
/// Inserts are batched into 1k-row transactions to keep the test runtime
/// reasonable (50k single-row commits would take many seconds).
fn seed_db_on_disk(db_path: &Path, count: i64) {
    let mut db = IndexDb::open(db_path).expect("open db on disk");
    let src = NewSource {
        source_id: 1,
        filename: "disk1.bin".into(),
        output_subdir: "disk1".into(),
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

    const CHUNK: i64 = 1_000;
    db.with_conn::<(), diesel::result::Error, _>(|conn| {
        let mut next = 1i64;
        while next <= count {
            let end = (next + CHUNK - 1).min(count);
            conn.transaction(|tx| {
                let mut rows: Vec<NewFile> = Vec::with_capacity((end - next + 1) as usize);
                for i in next..=end {
                    rows.push(NewFile {
                        file_id: i,
                        source_id: 1,
                        filename: format!("{i:08}.jpeg"),
                        filesize: 1_000 + i,
                        file_type: "jpeg".into(),
                        img_offset: i * 4096,
                        written_path: format!("disk1/{i:08}.jpeg"),
                        byte_runs_json: "[]".into(),
                        jpeg_status: None,
                        jpeg_width: None,
                        jpeg_height: None,
                        jpeg_fragmentation_point: None,
                        jpeg_has_restart_markers: None,
                        preview_status: "unknown".into(),
                    });
                }
                diesel::insert_into(schema::file::table)
                    .values(&rows)
                    .execute(tx)?;
                Ok::<(), diesel::result::Error>(())
            })?;
            next = end + 1;
        }
        Ok(())
    })
    .expect("seed files");
}

/// Build a placeholder `<stem>-events.bin` next to the SQLite index so the
/// `index_path_for(main_log)` convention picks up the seeded DB. The query
/// loop never reads this file — only the derived DB path matters.
fn fixture_paths(dir: &Path) -> (PathBuf, PathBuf) {
    let main_log = dir.join("disk1-events.bin");
    std::fs::write(&main_log, b"placeholder").expect("write placeholder log");
    let db_path = index_path_for(&main_log);
    (main_log, db_path)
}

#[test]
fn cold_open_materializes_only_window_size_rows() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (main_log, db_path) = fixture_paths(dir.path());
    seed_db_on_disk(&db_path, 50_000);

    let (cmd_tx, cmd_rx) = unbounded::<IndexerCommand>();
    let (evt_tx, evt_rx) = unbounded::<IndexerEvent>();
    let main_log_for_thread = main_log.clone();
    let handle = std::thread::spawn(move || {
        run_query_loop(main_log_for_thread, cmd_rx, evt_tx).expect("query loop");
    });

    let mut vm = ViewModel::new();

    // Step 1: Requery with the default filter at epoch 1; expect 50k stubs.
    cmd_tx
        .send(IndexerCommand::Requery {
            filter: FilterState::default(),
            epoch: 1,
        })
        .expect("send requery");

    let stubs = match evt_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("recv MatchIds")
    {
        IndexerEvent::MatchIds { stubs, epoch } => {
            assert_eq!(epoch, 1, "echoed epoch must match request");
            assert_eq!(stubs.len(), 50_000, "all seeded rows should be returned");
            stubs
        }
        other => panic!("expected MatchIds, got {other:?}"),
    };

    vm.current_epoch = 1;
    vm.apply_match_ids(stubs, 1);
    assert_eq!(
        vm.match_ids.len(),
        50_000,
        "vm.match_ids should hold all 50k stubs"
    );

    // Step 2: FetchWindow on the first 1000 ids; expect 1000 hydrated rows.
    let ids: Vec<u64> = vm.match_ids[0..1_000].iter().map(|s| s.file_id).collect();
    cmd_tx
        .send(IndexerCommand::FetchWindow {
            ids: ids.clone(),
            range_start: 0,
            epoch: 1,
        })
        .expect("send fetch_window");

    let (rows, range_start) = match evt_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("recv WindowFilled")
    {
        IndexerEvent::WindowFilled {
            rows,
            range_start,
            epoch,
        } => {
            assert_eq!(epoch, 1, "echoed epoch must match request");
            assert_eq!(rows.len(), 1_000, "window fetch should hydrate 1000 rows");
            (rows, range_start)
        }
        other => panic!("expected WindowFilled, got {other:?}"),
    };

    vm.apply_window_filled(rows, range_start, 1);
    assert_eq!(vm.window.len(), 1_000, "vm.window should hold 1000 rows");
    assert_eq!(
        vm.match_ids.len(),
        50_000,
        "match_ids must still hold all 50k stubs after the window fetch"
    );

    cmd_tx
        .send(IndexerCommand::Shutdown)
        .expect("send shutdown");
    drop(cmd_tx);
    handle.join().expect("join query thread");
}
