mod common;

use common::run_started_event;
use utmost_gui::index_db::writer::IndexDbWriter;
use utmost_lib::events::CarveEvent;

#[test]
fn apply_note_inserts_note_row() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("idx.sqlite");
    let pool = common::open_pool(&path);
    {
        let mut w = IndexDbWriter::new(pool.clone(), 100);
        w.apply(run_started_event(), 10).unwrap();
        w.apply(
            CarveEvent::Note {
                note_id: 1,
                file_id: 1,
                text: "hello".into(),
                at: "t".into(),
            },
            20,
        )
        .unwrap();
        w.flush().unwrap();
    }
    assert_eq!(common::count(&pool, "note"), 1);
    assert_eq!(common::scalar_i64(&pool, "SELECT note_id FROM note"), 1);
    assert_eq!(common::scalar_i64(&pool, "SELECT file_id FROM note"), 1);
    assert_eq!(
        common::scalar_text(&pool, "SELECT text FROM note"),
        Some("hello".to_owned())
    );
    assert_eq!(
        common::scalar_text(&pool, "SELECT at FROM note"),
        Some("t".to_owned())
    );
}
