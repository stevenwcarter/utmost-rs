mod common;

use common::run_started_event;
use utmost_gui::index_db::writer::IndexDbWriter;
use utmost_lib::events::CarveEvent;

#[test]
fn apply_progress_tick_updates_source_bytes_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("idx.sqlite");
    let pool = common::open_pool(&path);
    {
        let mut w = IndexDbWriter::new(pool.clone(), 100);
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
    assert_eq!(
        common::scalar_i64(&pool, "SELECT bytes_read FROM source WHERE source_id = 0"),
        1234
    );
}
