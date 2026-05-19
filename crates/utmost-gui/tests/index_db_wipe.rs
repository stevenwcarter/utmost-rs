mod common;

use common::run_started_event_at;
use diesel::prelude::*;
use std::sync::{Arc, Mutex};
use utmost_gui::index_db::{IndexDb, schema};
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
    assert_eq!(vm1.lock().unwrap().files.len(), 5);

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
    assert_eq!(vm2.lock().unwrap().files.len(), 3);

    // Confirm only Run B's file_ids are present in the SQLite.
    let mut db = IndexDb::open(&sub.join("disk1_dd-index.sqlite")).unwrap();
    let mut ids: Vec<i64> = db
        .with_conn(|conn| {
            schema::file::table
                .select(schema::file::file_id)
                .load::<i64>(conn)
        })
        .unwrap();
    ids.sort();
    assert_eq!(ids, vec![100, 101, 102]);
}
