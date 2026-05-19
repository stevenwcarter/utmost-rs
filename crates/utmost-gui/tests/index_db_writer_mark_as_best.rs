mod common;

use common::run_started_event;
use diesel::prelude::*;
use utmost_gui::index_db::{IndexDb, schema, writer::IndexDbWriter};
use utmost_lib::events::CarveEvent;

#[test]
fn apply_mark_as_best_upserts_best_choice() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = IndexDb::open(&dir.path().join("idx.sqlite")).unwrap();
    {
        let mut w = IndexDbWriter::new(db.conn(), 100);
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
    db.with_conn(|conn| {
        let n: i64 = schema::best_choice::table.count().get_result(conn).unwrap();
        assert_eq!(n, 1);
        let chosen: i64 = schema::best_choice::table
            .filter(schema::best_choice::original_file_id.eq(1i64))
            .select(schema::best_choice::chosen_file_id)
            .first(conn)
            .unwrap();
        assert_eq!(chosen, 2);
        Ok::<_, diesel::result::Error>(())
    })
    .unwrap();

    {
        let mut w = IndexDbWriter::new(db.conn(), 100);
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
    db.with_conn(|conn| {
        let n: i64 = schema::best_choice::table.count().get_result(conn).unwrap();
        assert_eq!(n, 1);
        let chosen: i64 = schema::best_choice::table
            .filter(schema::best_choice::original_file_id.eq(1i64))
            .select(schema::best_choice::chosen_file_id)
            .first(conn)
            .unwrap();
        assert_eq!(chosen, 3);
        Ok::<_, diesel::result::Error>(())
    })
    .unwrap();
}
