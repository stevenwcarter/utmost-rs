mod common;

use common::run_started_event;
use diesel::prelude::*;
use utmost_gui::index_db::{IndexDb, schema, writer::IndexDbWriter};
use utmost_lib::events::CarveEvent;

#[test]
fn apply_note_inserts_note_row() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = IndexDb::open(&dir.path().join("idx.sqlite")).unwrap();
    {
        let mut w = IndexDbWriter::new(db.conn(), 100);
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
    db.with_conn(|conn| {
        let n: i64 = schema::note::table.count().get_result(conn).unwrap();
        assert_eq!(n, 1);
        let note_id: i64 = schema::note::table
            .select(schema::note::note_id)
            .first(conn)
            .unwrap();
        assert_eq!(note_id, 1);
        let file_id: i64 = schema::note::table
            .select(schema::note::file_id)
            .first(conn)
            .unwrap();
        assert_eq!(file_id, 1);
        let text: String = schema::note::table
            .select(schema::note::text)
            .first(conn)
            .unwrap();
        assert_eq!(text, "hello");
        let at: String = schema::note::table
            .select(schema::note::at)
            .first(conn)
            .unwrap();
        assert_eq!(at, "t");
        Ok::<_, diesel::result::Error>(())
    })
    .unwrap();
}
