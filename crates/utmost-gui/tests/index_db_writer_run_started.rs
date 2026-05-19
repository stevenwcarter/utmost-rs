mod common;

use common::run_started_event;
use diesel::prelude::*;
use utmost_gui::index_db::{IndexDb, models::RunRow, schema, writer::IndexDbWriter};

#[test]
fn apply_run_started_writes_run_and_source_rows_and_advances_offset() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = IndexDb::open(&dir.path().join("idx.sqlite")).unwrap();
    {
        let mut w = IndexDbWriter::new(db.conn(), 100);
        w.apply(run_started_event(), 1234).unwrap();
        w.flush().unwrap();
    }

    db.with_conn(|conn| {
        let row: RunRow = schema::run::table.first(conn).unwrap();
        assert_eq!(row.id, 1);
        assert_eq!(row.started_at, "2026-05-19T00:00:00+0000");
        assert_eq!(row.output_root, "out");
        assert_eq!(row.case_id.as_deref(), Some("C-1"));

        let n_sources: i64 = schema::source::table.count().get_result(conn).unwrap();
        assert_eq!(n_sources, 1);

        // last_event_offset advanced to 1234
        let off: String = schema::meta::table
            .filter(schema::meta::key.eq("last_event_offset"))
            .select(schema::meta::value)
            .first(conn)
            .unwrap();
        assert_eq!(off, "1234");

        // run_started_at recorded
        let rs: String = schema::meta::table
            .filter(schema::meta::key.eq("run_started_at"))
            .select(schema::meta::value)
            .first(conn)
            .unwrap();
        assert_eq!(rs, "2026-05-19T00:00:00+0000");

        Ok::<_, diesel::result::Error>(())
    })
    .unwrap();
}
