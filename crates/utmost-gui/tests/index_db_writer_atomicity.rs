mod common;

use common::run_started_event;
use diesel::prelude::*;
use utmost_gui::index_db::{IndexDb, schema, writer::IndexDbWriter};
use utmost_lib::events::CarveEvent;
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::FileType;

fn ff(id: u64) -> CarveEvent {
    CarveEvent::FileFound {
        source_id: 0,
        file: create_file_object("x.jpg", FileType::Jpeg, 1, 0, None, id),
        img_offset: 0,
        written_path: "x.jpg".into(),
    }
}

#[test]
fn duplicate_file_id_aborts_batch_with_no_partial_writes() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = IndexDb::open(&dir.path().join("idx.sqlite")).unwrap();

    // Seed run + source.
    {
        let mut w = IndexDbWriter::new(db.conn(), 10);
        w.apply(run_started_event(), 0).unwrap();
        w.flush().unwrap();
    }

    // First batch: insert file 1 successfully.
    {
        let mut w = IndexDbWriter::new(db.conn(), 10);
        w.apply(ff(1), 100).unwrap();
        w.flush().unwrap();
    }

    let count_before: i64 = db
        .with_conn(|conn| schema::file::table.count().get_result::<i64>(conn))
        .unwrap();
    let offset_before: String = db
        .with_conn(|conn| {
            schema::meta::table
                .filter(schema::meta::key.eq("last_event_offset"))
                .select(schema::meta::value)
                .first(conn)
        })
        .unwrap();

    // Second batch: file 2, then duplicate file 1. Flush must fail and rollback.
    let result = {
        let mut w = IndexDbWriter::new(db.conn(), 10);
        w.apply(ff(2), 200).unwrap();
        w.apply(ff(1), 300).unwrap(); // duplicate PK on flush
        w.flush()
    };
    assert!(result.is_err(), "duplicate file_id should fail the batch");

    let count_after: i64 = db
        .with_conn(|conn| schema::file::table.count().get_result::<i64>(conn))
        .unwrap();
    let offset_after: String = db
        .with_conn(|conn| {
            schema::meta::table
                .filter(schema::meta::key.eq("last_event_offset"))
                .select(schema::meta::value)
                .first(conn)
        })
        .unwrap();

    assert_eq!(count_after, count_before, "rows must not have advanced");
    assert_eq!(offset_after, offset_before, "offset must not have advanced");
}
