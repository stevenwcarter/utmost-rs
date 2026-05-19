mod common;

use common::run_started_event;
use diesel::prelude::*;
use utmost_gui::index_db::{IndexDb, schema, writer::IndexDbWriter};
use utmost_lib::events::CarveEvent;
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::FileType;

#[test]
fn apply_file_found_inserts_file_row_and_advances_counters() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = IndexDb::open(&dir.path().join("idx.sqlite")).unwrap();
    {
        let mut w = IndexDbWriter::new(db.conn(), 100);
        w.apply(run_started_event(), 10).unwrap();
        let fo = create_file_object("a.jpg", FileType::Jpeg, 1024, 512, None, 42);
        w.apply(
            CarveEvent::FileFound {
                source_id: 0,
                file: fo,
                img_offset: 512,
                written_path: "a.jpg".into(),
            },
            100,
        )
        .unwrap();
        w.flush().unwrap();
    }
    db.with_conn(|conn| {
        let n: i64 = schema::file::table.count().get_result(conn).unwrap();
        assert_eq!(n, 1);
        let row_filesize: i64 = schema::file::table
            .filter(schema::file::file_id.eq(42i64))
            .select(schema::file::filesize)
            .first(conn)
            .unwrap();
        assert_eq!(row_filesize, 1024);
        // source.files_found incremented
        let files_found: i64 = schema::source::table
            .filter(schema::source::source_id.eq(0i32))
            .select(schema::source::files_found)
            .first(conn)
            .unwrap();
        assert_eq!(files_found, 1);
        // run.total_files incremented
        let total_files: i64 = schema::run::table
            .filter(schema::run::id.eq(1i32))
            .select(schema::run::total_files)
            .first(conn)
            .unwrap();
        assert_eq!(total_files, 1);
        Ok::<_, diesel::result::Error>(())
    })
    .unwrap();
}
