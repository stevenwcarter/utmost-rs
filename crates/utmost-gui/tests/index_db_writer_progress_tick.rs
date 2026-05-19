mod common;

use common::run_started_event;
use diesel::prelude::*;
use utmost_gui::index_db::{IndexDb, schema, writer::IndexDbWriter};
use utmost_lib::events::CarveEvent;

#[test]
fn apply_progress_tick_updates_source_bytes_read() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = IndexDb::open(&dir.path().join("idx.sqlite")).unwrap();
    {
        let mut w = IndexDbWriter::new(db.conn(), 100);
        w.apply(run_started_event(), 10).unwrap();
        w.apply(
            CarveEvent::ProgressTick {
                source_id: 0,
                bytes_read: 1234,
            },
            20,
        )
        .unwrap();
        w.flush().unwrap();
    }
    db.with_conn(|conn| {
        let bytes_read: i64 = schema::source::table
            .filter(schema::source::source_id.eq(0i32))
            .select(schema::source::bytes_read)
            .first(conn)
            .unwrap();
        assert_eq!(bytes_read, 1234);
        Ok::<_, diesel::result::Error>(())
    })
    .unwrap();
}
