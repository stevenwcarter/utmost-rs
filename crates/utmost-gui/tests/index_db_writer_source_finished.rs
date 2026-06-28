mod common;

use common::run_started_event;
use utmost_gui::index_db::writer::IndexDbWriter;
use utmost_lib::events::CarveEvent;

#[test]
fn apply_source_finished_updates_source_status_and_duration() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("idx.sqlite");
    let pool = common::open_pool(&path);
    {
        let mut w = IndexDbWriter::new(pool.clone(), 100);
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
    assert_eq!(
        common::scalar_text(&pool, "SELECT status FROM source WHERE source_id = 0").as_deref(),
        Some("Finished")
    );
    assert_eq!(
        common::scalar_i64(&pool, "SELECT bytes_read FROM source WHERE source_id = 0"),
        4096
    );
    assert_eq!(
        common::scalar_opt_i64(&pool, "SELECT duration_ms FROM source WHERE source_id = 0"),
        Some(5)
    );
}
