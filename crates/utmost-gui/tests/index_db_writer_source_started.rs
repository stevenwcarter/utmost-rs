mod common;

use common::run_started_event;
use diesel::prelude::*;
use utmost_gui::index_db::{IndexDb, schema, writer::IndexDbWriter};
use utmost_lib::events::CarveEvent;

#[test]
fn apply_source_started_sets_source_status_running() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = IndexDb::open(&dir.path().join("idx.sqlite")).unwrap();
    {
        let mut w = IndexDbWriter::new(db.conn(), 100);
        w.apply(run_started_event(), 10).unwrap();
        w.apply(CarveEvent::SourceStarted { source_id: 0 }, 20)
            .unwrap();
        w.flush().unwrap();
    }
    db.with_conn(|conn| {
        let status: String = schema::source::table
            .filter(schema::source::source_id.eq(0i32))
            .select(schema::source::status)
            .first(conn)
            .unwrap();
        assert_eq!(status, "Running");
        Ok::<_, diesel::result::Error>(())
    })
    .unwrap();
}
