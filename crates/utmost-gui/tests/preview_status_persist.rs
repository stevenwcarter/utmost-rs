//! Task 16: preview-status persistence + `hide_no_preview` filter
//! integration test.
//!
//! First session: open a fresh on-disk SQLite index seeded with 200
//! files, then drive `run_query_loop` to persist `NoPreview` outcomes for
//! file_ids 1..=50 via `IndexerCommand::WritePreviewStatus`. The loop
//! commits the rows + bumps `preview_status_version` inside one
//! transaction (`write_preview_outcomes`), then we shut the thread down.
//!
//! Second session: reopen the SAME on-disk DB, drive a fresh
//! `run_query_loop` with `hide_no_preview = true`. The returned
//! `MatchIds` must contain 150 stubs (200 minus the 50 we tagged as
//! NoPreview in session one), proving that:
//!   1. the `preview_status` column survives a connection close + reopen,
//!   2. `query_match_ids` correctly excludes `no_preview` rows when the
//!      filter is engaged.

use crossbeam_channel::unbounded;
use std::path::{Path, PathBuf};
use std::time::Duration;

use turso::Value;
use utmost_gui::index_db::{IndexDb, block_on};
use utmost_gui::indexer_thread::{IndexerCommand, IndexerEvent, index_path_for, run_query_loop};
use utmost_gui::thumb_worker::{PreviewOutcome, PreviewStatus};
use utmost_gui::view_model::FilterState;

fn seed_db(db_path: &Path, count: i64) {
    let pool = IndexDb::open(db_path).expect("open db").pool().clone();
    block_on(async move {
        let mut conn = pool.get().await.unwrap();
        conn.execute(
            "INSERT INTO source \
             (source_id, filename, output_subdir, total_bytes, bytes_read, files_found, status) \
             VALUES (1, 'img1.bin', 'img1', 0, 0, 0, 'Finished')",
            (),
        )
        .await
        .unwrap();
        let tx = conn.transaction().await.unwrap();
        for i in 1..=count {
            tx.execute(
                "INSERT INTO file \
                 (file_id, source_id, filename, filesize, file_type, img_offset, \
                  written_path, byte_runs_json, preview_status) \
                 VALUES (?1, 1, ?2, ?3, 'jpeg', ?4, ?5, '[]', 'unknown')",
                turso::params_from_iter(vec![
                    Value::Integer(i),
                    Value::Text(format!("{i:08}.jpeg")),
                    Value::Integer(1_000 + i),
                    Value::Integer(i * 4096),
                    Value::Text(format!("img1/{i:08}.jpeg")),
                ]),
            )
            .await
            .unwrap();
        }
        tx.commit().await.unwrap();
    });
}

fn fixture_paths(dir: &Path) -> (PathBuf, PathBuf) {
    let main_log = dir.join("img1-events.bin");
    std::fs::write(&main_log, b"placeholder").expect("write placeholder log");
    let db_path = index_path_for(&main_log);
    (main_log, db_path)
}

#[test]
fn preview_status_persists_and_filters_no_preview_on_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (main_log, db_path) = fixture_paths(dir.path());
    seed_db(&db_path, 200);

    // ---- First session: tag file_ids 1..=50 as NoPreview ----
    {
        let (cmd_tx, cmd_rx) = unbounded::<IndexerCommand>();
        let (evt_tx, evt_rx) = unbounded::<IndexerEvent>();
        let main_log_t = main_log.clone();
        let handle = std::thread::spawn(move || {
            run_query_loop(
                main_log_t,
                cmd_rx,
                evt_tx,
                #[cfg(feature = "clip")]
                utmost_gui::clip::Embedder::new(),
            )
            .expect("query loop s1");
        });

        let outcomes: Vec<PreviewOutcome> = (1..=50)
            .map(|id| PreviewOutcome {
                file_id: id as u64,
                status: PreviewStatus::NoPreview,
            })
            .collect();

        cmd_tx
            .send(IndexerCommand::WritePreviewStatus { outcomes })
            .expect("send WritePreviewStatus");

        // Drain the ack so we know the commit landed before tearing the
        // thread down.
        match evt_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("recv PreviewStatusVersion")
        {
            IndexerEvent::PreviewStatusVersion(v) => {
                assert!(v >= 1, "version must advance past the seeded zero");
            }
            other => panic!("expected PreviewStatusVersion, got {other:?}"),
        }

        cmd_tx
            .send(IndexerCommand::Shutdown)
            .expect("send shutdown s1");
        drop(cmd_tx);
        handle.join().expect("join query thread s1");
    }

    // ---- Second session: reopen the same DB, requery with hide_no_preview ----
    {
        let (cmd_tx, cmd_rx) = unbounded::<IndexerCommand>();
        let (evt_tx, evt_rx) = unbounded::<IndexerEvent>();
        let main_log_t = main_log.clone();
        let handle = std::thread::spawn(move || {
            run_query_loop(
                main_log_t,
                cmd_rx,
                evt_tx,
                #[cfg(feature = "clip")]
                utmost_gui::clip::Embedder::new(),
            )
            .expect("query loop s2");
        });

        let filter = FilterState {
            hide_no_preview: true,
            ..Default::default()
        };
        cmd_tx
            .send(IndexerCommand::Requery { filter, epoch: 1 })
            .expect("send hide-no-preview requery");

        match evt_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("recv MatchIds s2")
        {
            IndexerEvent::MatchIds { stubs, epoch } => {
                assert_eq!(epoch, 1, "echoed epoch must match");
                assert_eq!(
                    stubs.len(),
                    150,
                    "200 seeded minus 50 NoPreview = 150 visible"
                );
                assert!(
                    stubs.iter().all(|s| s.file_id > 50),
                    "the 50 NoPreview ids (1..=50) must be filtered out"
                );
            }
            other => panic!("expected MatchIds, got {other:?}"),
        }

        cmd_tx
            .send(IndexerCommand::Shutdown)
            .expect("send shutdown s2");
        drop(cmd_tx);
        handle.join().expect("join query thread s2");
    }
}
