mod common;

use common::run_started_event;
use utmost_gui::index_db::writer::IndexDbWriter;
use utmost_lib::events::CarveEvent;
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::FileType;

#[test]
fn apply_file_found_inserts_file_row_and_advances_counters() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("idx.sqlite");
    let pool = common::open_pool(&path);
    {
        let mut w = IndexDbWriter::new(pool.clone(), 100);
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
    assert_eq!(common::count(&pool, "file"), 1);
    assert_eq!(
        common::scalar_i64(&pool, "SELECT filesize FROM file WHERE file_id = 42"),
        1024
    );
    // source.files_found incremented
    assert_eq!(
        common::scalar_i64(&pool, "SELECT files_found FROM source WHERE source_id = 0"),
        1
    );
    // run.total_files incremented
    assert_eq!(
        common::scalar_i64(&pool, "SELECT total_files FROM run WHERE id = 1"),
        1
    );
}
