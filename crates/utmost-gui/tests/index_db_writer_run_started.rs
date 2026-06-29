mod common;

use common::run_started_event;
use utmost_gui::index_db::writer::IndexDbWriter;

#[test]
fn apply_run_started_writes_run_and_source_rows_and_advances_offset() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("idx.sqlite");
    let pool = common::open_pool(&path);
    {
        let mut w = IndexDbWriter::new(pool.clone(), 100);
        w.apply(run_started_event(), 1234).unwrap();
        w.flush().unwrap();
    }

    assert_eq!(
        common::scalar_i64(&pool, "SELECT id FROM run WHERE id = 1"),
        1
    );
    assert_eq!(
        common::scalar_text(&pool, "SELECT started_at FROM run WHERE id = 1").as_deref(),
        Some("2026-05-19T00:00:00+0000")
    );
    assert_eq!(
        common::scalar_text(&pool, "SELECT output_root FROM run WHERE id = 1").as_deref(),
        Some("out")
    );
    assert_eq!(
        common::scalar_text(&pool, "SELECT case_id FROM run WHERE id = 1").as_deref(),
        Some("C-1")
    );

    let n_sources = common::count(&pool, "source");
    assert_eq!(n_sources, 1);

    // last_event_offset advanced to 1234
    assert_eq!(
        common::meta_value(&pool, "last_event_offset").as_deref(),
        Some("1234")
    );

    // run_started_at recorded
    assert_eq!(
        common::meta_value(&pool, "run_started_at").as_deref(),
        Some("2026-05-19T00:00:00+0000")
    );
}
