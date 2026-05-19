mod common;

use common::run_started_event;
use diesel::prelude::*;
use utmost_gui::index_db::{IndexDb, schema, writer::IndexDbWriter};
use utmost_lib::events::CarveEvent;

#[test]
fn apply_bookmark_add_then_remove() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = IndexDb::open(&dir.path().join("idx.sqlite")).unwrap();
    {
        let mut w = IndexDbWriter::new(db.conn(), 100);
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
    db.with_conn(|conn| {
        let n: i64 = schema::bookmark::table.count().get_result(conn).unwrap();
        assert_eq!(n, 1);
        let fid: i64 = schema::bookmark::table
            .select(schema::bookmark::file_id)
            .first(conn)
            .unwrap();
        assert_eq!(fid, 1);
        Ok::<_, diesel::result::Error>(())
    })
    .unwrap();

    {
        let mut w = IndexDbWriter::new(db.conn(), 100);
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
    db.with_conn(|conn| {
        let n: i64 = schema::bookmark::table.count().get_result(conn).unwrap();
        assert_eq!(n, 0);
        Ok::<_, diesel::result::Error>(())
    })
    .unwrap();
}
