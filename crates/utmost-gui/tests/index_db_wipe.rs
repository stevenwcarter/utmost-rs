mod common;

use common::run_started_event_at;
use std::sync::{Arc, Mutex};
use utmost_gui::index_db::block_on;
use utmost_gui::view_model::ViewModel;
use utmost_lib::events::{BincodeFileSink, CarveEvent, EventSink};
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::FileType;

fn ff(id: u64) -> CarveEvent {
    CarveEvent::FileFound {
        source_id: 0,
        file: create_file_object("x.jpg", FileType::Jpeg, 0, 0, None, id),
        img_offset: 0,
        written_path: "x.jpg".into(),
    }
}

#[test]
fn new_run_wipes_old_data() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("output-disk1_dd");
    std::fs::create_dir_all(&sub).unwrap();
    let bin = sub.join("disk1_dd-events.bin");

    // Run A: 5 files with file_ids 1..=5.
    {
        let sink = BincodeFileSink::create(&bin).unwrap();
        sink.emit(&run_started_event_at("2026-05-19T00:00:00+0000"));
        for i in 1..=5u64 {
            sink.emit(&ff(i));
        }
    }
    let vm1 = Arc::new(Mutex::new(ViewModel::new()));
    utmost_gui::indexer_thread::run_blocking(&bin, vm1.clone()).unwrap();
    // Task 12: vm.files is gone; the per-run SQLite count below covers
    // the expected row count after each run.

    // Replace with Run B (different started_at), file_ids 100..=102.
    std::fs::remove_file(&bin).unwrap();
    {
        let sink = BincodeFileSink::create(&bin).unwrap();
        sink.emit(&run_started_event_at("2026-05-19T01:00:00+0000"));
        for i in 100..=102u64 {
            sink.emit(&ff(i));
        }
    }
    let vm2 = Arc::new(Mutex::new(ViewModel::new()));
    utmost_gui::indexer_thread::run_blocking(&bin, vm2.clone()).unwrap();
    // Task 12: see note above.

    // Confirm only Run B's file_ids are present in the SQLite.
    let pool = common::open_pool(&sub.join("disk1_dd-index.sqlite"));
    let mut ids: Vec<i64> = block_on(async move {
        let conn = pool.get().await.unwrap();
        let mut rows = conn.query("SELECT file_id FROM file", ()).await.unwrap();
        let mut out = Vec::new();
        while let Some(row) = rows.next().await.unwrap() {
            out.push(*row.get_value(0).unwrap().as_integer().unwrap());
        }
        out
    });
    ids.sort();
    assert_eq!(ids, vec![100, 101, 102]);
}
