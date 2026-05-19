mod common;

use common::run_started_event;
use diesel::prelude::*;
use utmost_gui::index_db::{IndexDb, schema, writer::IndexDbWriter};
use utmost_lib::events::CarveEvent;

#[test]
fn apply_run_finished_updates_run_status_and_elapsed_ms() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = IndexDb::open(&dir.path().join("idx.sqlite")).unwrap();
    {
        let mut w = IndexDbWriter::new(db.conn(), 100);
        w.apply(run_started_event(), 10).unwrap();
        w.apply(
            CarveEvent::RunFinished {
                duration_ms: 1234,
                total_files_written: 0,
            },
            40,
        )
        .unwrap();
        w.flush().unwrap();
    }
    db.with_conn(|conn| {
        let (status, elapsed_ms): (String, i64) = schema::run::table
            .filter(schema::run::id.eq(1i32))
            .select((schema::run::status, schema::run::elapsed_ms))
            .first(conn)
            .unwrap();
        assert_eq!(status, "Finished");
        assert_eq!(elapsed_ms, 1234);
        Ok::<_, diesel::result::Error>(())
    })
    .unwrap();
}
