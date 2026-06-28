mod common;

use common::run_started_event;
use utmost_gui::index_db::writer::IndexDbWriter;
use utmost_lib::events::CarveEvent;

#[test]
fn apply_bookmark_add_then_remove() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("idx.sqlite");
    let pool = common::open_pool(&path);
    {
        let mut w = IndexDbWriter::new(pool.clone(), 100);
        w.apply(run_started_event(), 10).unwrap();
        w.apply(
            CarveEvent::Bookmark {
                file_id: 1,
                bookmarked: true,
                at: "t".into(),
            },
            20,
        )
        .unwrap();
        w.flush().unwrap();
    }
    assert_eq!(common::count(&pool, "bookmark"), 1);
    assert_eq!(common::scalar_i64(&pool, "SELECT file_id FROM bookmark"), 1);

    {
        let mut w = IndexDbWriter::new(pool.clone(), 100);
        w.apply(
            CarveEvent::Bookmark {
                file_id: 1,
                bookmarked: false,
                at: "t".into(),
            },
            30,
        )
        .unwrap();
        w.flush().unwrap();
    }
    assert_eq!(common::count(&pool, "bookmark"), 0);
}
