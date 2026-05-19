mod common;

use common::run_started_event;
use diesel::prelude::*;
use utmost_gui::index_db::{IndexDb, schema, writer::IndexDbWriter};
use utmost_lib::events::CarveEvent;

#[test]
fn apply_source_finished_updates_source_status_and_duration() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = IndexDb::open(&dir.path().join("idx.sqlite")).unwrap();
    {
        let mut w = IndexDbWriter::new(db.conn(), 100);
        w.apply(run_started_event(), 10).unwrap();
        w.apply(
            CarveEvent::SourceFinished {
                source_id: 0,
                bytes_read: 4096,
                duration_ms: 5,
            },
            30,
        )
        .unwrap();
        w.flush().unwrap();
    }
    db.with_conn(|conn| {
        let (status, bytes_read, duration_ms): (String, i64, Option<i64>) = schema::source::table
            .filter(schema::source::source_id.eq(0i32))
            .select((
                schema::source::status,
                schema::source::bytes_read,
                schema::source::duration_ms,
            ))
            .first(conn)
            .unwrap();
        assert_eq!(status, "Finished");
        assert_eq!(bytes_read, 4096);
        assert_eq!(duration_ms, Some(5));
        Ok::<_, diesel::result::Error>(())
    })
    .unwrap();
}
