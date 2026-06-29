mod common;

use common::run_started_event;
use utmost_gui::index_db::writer::IndexDbWriter;
use utmost_lib::events::CarveEvent;

#[test]
fn apply_mark_as_best_upserts_best_choice() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("idx.sqlite");
    let pool = common::open_pool(&path);
    {
        let mut w = IndexDbWriter::new(pool.clone(), 100);
        w.apply(run_started_event(), 10).unwrap();
        w.apply(
            CarveEvent::MarkAsBest {
                original_file_id: 1,
                chosen_file_id: 2,
                at: "t".into(),
            },
            20,
        )
        .unwrap();
        w.flush().unwrap();
    }
    assert_eq!(common::count(&pool, "best_choice"), 1);
    assert_eq!(
        common::scalar_i64(
            &pool,
            "SELECT chosen_file_id FROM best_choice WHERE original_file_id = 1"
        ),
        2
    );

    {
        let mut w = IndexDbWriter::new(pool.clone(), 100);
        w.apply(
            CarveEvent::MarkAsBest {
                original_file_id: 1,
                chosen_file_id: 3,
                at: "t2".into(),
            },
            30,
        )
        .unwrap();
        w.flush().unwrap();
    }
    assert_eq!(common::count(&pool, "best_choice"), 1);
    assert_eq!(
        common::scalar_i64(
            &pool,
            "SELECT chosen_file_id FROM best_choice WHERE original_file_id = 1"
        ),
        3
    );
}
