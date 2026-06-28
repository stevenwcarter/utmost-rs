mod common;

use common::run_started_event;
use utmost_gui::index_db::writer::IndexDbWriter;
use utmost_lib::events::CarveEvent;

#[test]
fn apply_recovery_started_writes_recovery_run_row() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("idx.sqlite");
    let pool = common::open_pool(&path);
    {
        let mut w = IndexDbWriter::new(pool.clone(), 100);
        w.apply(run_started_event(), 10).unwrap();
        w.apply(
            CarveEvent::RecoveryStarted {
                started_at: "2026-05-19T01:00:00+0000".into(),
                keep_candidates: 5,
                search_window: 1024 * 1024,
                block_size: 512,
                min_entropy_score: 7.0,
                huffman_validation: true,
            },
            20,
        )
        .unwrap();
        w.flush().unwrap();
    }
    assert_eq!(common::count(&pool, "recovery_run"), 1);
    assert_eq!(
        common::scalar_i64(&pool, "SELECT keep_candidates FROM recovery_run WHERE id = 1"),
        5
    );
    assert_eq!(
        common::scalar_i64(
            &pool,
            "SELECT huffman_validation FROM recovery_run WHERE id = 1"
        ),
        1
    );
}
