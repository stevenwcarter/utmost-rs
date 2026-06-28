mod common;

use common::run_started_event;
use utmost_gui::index_db::writer::IndexDbWriter;
use utmost_lib::events::{CarveEvent, RecoveryMethod};

#[test]
fn apply_recovery_candidate_writes_variant_row() {
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
        w.apply(
            CarveEvent::RecoveryCandidate {
                original_file_id: 1,
                candidate_file_id: 2,
                rank: 1,
                method: RecoveryMethod::DirectContinuation,
                entropy_score: 7.5,
                ff_validity_score: Some(0.95),
                huffman_mcu_count: Some(100),
                continuation_img_offset: 4096,
            },
            30,
        )
        .unwrap();
        w.flush().unwrap();
    }
    assert_eq!(common::count(&pool, "variant"), 1);
    assert_eq!(
        common::scalar_text(
            &pool,
            "SELECT method FROM variant WHERE original_file_id = 1 AND candidate_file_id = 2"
        ),
        Some("direct_continuation".to_owned())
    );
}
