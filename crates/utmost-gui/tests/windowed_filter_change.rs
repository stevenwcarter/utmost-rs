//! Task 15: filter-change integration test for the windowed-files pipeline.
//!
//! Seeds 5_000 jpeg + 5_000 png rows into a fresh on-disk SQLite index,
//! then drives `run_query_loop` through two consecutive `Requery` commands:
//!
//! 1. Default filter at epoch 1 — expect MatchIds with all 10_000 rows.
//! 2. Jpeg-only filter at epoch 2 — expect MatchIds with exactly 5_000 rows.
//!
//! This exercises the live wiring between a chip toggle (which the UI
//! models as bumping the epoch and posting a new `Requery`) and the SQL
//! `WHERE f.file_type IN (...)` projection.

use crossbeam_channel::unbounded;
use std::path::{Path, PathBuf};
use std::time::Duration;

use turso::Value;
use utmost_gui::index_db::{IndexDb, block_on};
use utmost_gui::indexer_thread::{IndexerCommand, IndexerEvent, index_path_for, run_query_loop};
use utmost_gui::view_model::FilterState;
use utmost_lib::types::FileType;

/// Seed `jpeg_count` jpeg rows and `png_count` png rows into a fresh
/// on-disk DB. File ids are unique across types.
fn seed_db_mixed(db_path: &Path, jpeg_count: i64, png_count: i64) {
    let pool = IndexDb::open(db_path).expect("open db on disk").pool().clone();
    block_on(async move {
        let mut conn = pool.get().await.unwrap();
        conn.execute(
            "INSERT INTO source \
             (source_id, filename, output_subdir, total_bytes, bytes_read, files_found, status) \
             VALUES (1, 'disk1.bin', 'disk1', 0, 0, 0, 'Finished')",
            (),
        )
        .await
        .unwrap();

        const CHUNK: i64 = 1_000;
        let total = jpeg_count + png_count;
        let mut next = 1i64;
        while next <= total {
            let end = (next + CHUNK - 1).min(total);
            let tx = conn.transaction().await.unwrap();
            for i in next..=end {
                let (ext, ftype) = if i <= jpeg_count {
                    ("jpeg", "jpeg")
                } else {
                    ("png", "png")
                };
                tx.execute(
                    "INSERT INTO file \
                     (file_id, source_id, filename, filesize, file_type, img_offset, \
                      written_path, byte_runs_json, preview_status) \
                     VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, '[]', 'unknown')",
                    turso::params_from_iter(vec![
                        Value::Integer(i),
                        Value::Text(format!("{i:08}.{ext}")),
                        Value::Integer(1_000 + i),
                        Value::Text(ftype.to_owned()),
                        Value::Integer(i * 4096),
                        Value::Text(format!("disk1/{i:08}.{ext}")),
                    ]),
                )
                .await
                .unwrap();
            }
            tx.commit().await.unwrap();
            next = end + 1;
        }
    });
}

fn fixture_paths(dir: &Path) -> (PathBuf, PathBuf) {
    let main_log = dir.join("disk1-events.bin");
    std::fs::write(&main_log, b"placeholder").expect("write placeholder log");
    let db_path = index_path_for(&main_log);
    (main_log, db_path)
}

#[test]
fn toggling_type_chip_emits_one_new_matchids_event() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (main_log, db_path) = fixture_paths(dir.path());
    seed_db_mixed(&db_path, 5_000, 5_000);

    let (cmd_tx, cmd_rx) = unbounded::<IndexerCommand>();
    let (evt_tx, evt_rx) = unbounded::<IndexerEvent>();
    let main_log_for_thread = main_log.clone();
    let handle = std::thread::spawn(move || {
        run_query_loop(main_log_for_thread, cmd_rx, evt_tx).expect("query loop");
    });

    // Step 1: default filter at epoch 1 — all 10k rows.
    cmd_tx
        .send(IndexerCommand::Requery {
            filter: FilterState::default(),
            epoch: 1,
        })
        .expect("send requery 1");

    match evt_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("recv MatchIds for epoch=1")
    {
        IndexerEvent::MatchIds { stubs, epoch } => {
            assert_eq!(epoch, 1, "echoed epoch must match request");
            assert_eq!(stubs.len(), 10_000, "default filter should see all rows");
        }
        other => panic!("expected MatchIds for epoch=1, got {other:?}"),
    }

    // Step 2: jpeg-only filter at epoch 2 — exactly 5k rows.
    let mut jpeg_only = FilterState::default();
    jpeg_only.enabled_types.insert(FileType::Jpeg);
    cmd_tx
        .send(IndexerCommand::Requery {
            filter: jpeg_only,
            epoch: 2,
        })
        .expect("send requery 2");

    match evt_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("recv MatchIds for epoch=2")
    {
        IndexerEvent::MatchIds { stubs, epoch } => {
            assert_eq!(epoch, 2, "echoed epoch must match request");
            assert_eq!(
                stubs.len(),
                5_000,
                "jpeg-only filter should drop the png half"
            );
            assert!(
                stubs.iter().all(|s| s.file_type == FileType::Jpeg),
                "all returned stubs should be jpeg"
            );
        }
        other => panic!("expected MatchIds for epoch=2, got {other:?}"),
    }

    cmd_tx
        .send(IndexerCommand::Shutdown)
        .expect("send shutdown");
    drop(cmd_tx);
    handle.join().expect("join query thread");
}
