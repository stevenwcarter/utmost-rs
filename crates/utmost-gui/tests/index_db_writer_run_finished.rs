mod common;

use common::run_started_event;
use utmost_gui::index_db::writer::IndexDbWriter;
use utmost_lib::events::CarveEvent;

#[test]
fn apply_run_finished_updates_run_status_and_elapsed_ms() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("idx.sqlite");
    let pool = common::open_pool(&path);
    {
        let mut w = IndexDbWriter::new(pool.clone(), 100);
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
    assert_eq!(
        common::scalar_text(&pool, "SELECT status FROM run WHERE id = 1").as_deref(),
        Some("Finished")
    );
    assert_eq!(
        common::scalar_i64(&pool, "SELECT elapsed_ms FROM run WHERE id = 1"),
        1234
    );
}
