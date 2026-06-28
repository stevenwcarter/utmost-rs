mod common;

use common::run_started_event;
use utmost_gui::index_db::writer::IndexDbWriter;
use utmost_lib::events::CarveEvent;

#[test]
fn apply_source_started_sets_source_status_running() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("idx.sqlite");
    let pool = common::open_pool(&path);
    {
        let mut w = IndexDbWriter::new(pool.clone(), 100);
        w.apply(run_started_event(), 10).unwrap();
        w.apply(CarveEvent::SourceStarted { source_id: 0 }, 20)
            .unwrap();
        w.flush().unwrap();
    }
    assert_eq!(
        common::scalar_text(&pool, "SELECT status FROM source WHERE source_id = 0").as_deref(),
        Some("Running")
    );
}
