mod common;

use common::run_started_event;
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
fn resume_after_partial_index() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("output-disk1_dd");
    std::fs::create_dir_all(&sub).unwrap();
    let bin = sub.join("disk1_dd-events.bin");

    // First chunk: RunStarted + 5 FileFound, drop sink so file syncs.
    {
        let sink = BincodeFileSink::create(&bin).unwrap();
        sink.emit(&run_started_event());
        for i in 1..=5u64 {
            sink.emit(&ff(i));
        }
    }

    // Index the first chunk.
    let vm1 = Arc::new(Mutex::new(ViewModel::new()));
    utmost_gui::indexer_thread::run_blocking(&bin, vm1.clone()).unwrap();
    {
        let mut db = IndexDb::open(&sub.join("disk1_dd-index.sqlite")).unwrap();
        let count_after_first: i64 = db
            .with_conn(|conn| schema::file::table.count().get_result::<i64>(conn))
            .unwrap();
        assert_eq!(count_after_first, 5);
    }

    // Append 5 more events to the same .bin.
    {
        let sink = BincodeFileSink::open_append(&bin).unwrap();
        for i in 6..=10u64 {
            <BincodeFileSink as utmost_lib::events::EventSink>::emit(&sink, &ff(i));
        }
    }

    // Reopen — should hit Resume.
    let vm2 = Arc::new(Mutex::new(ViewModel::new()));
    utmost_gui::indexer_thread::run_blocking(&bin, vm2.clone()).unwrap();
    assert_eq!(vm2.lock().unwrap().files.len(), 10);

    let mut db = IndexDb::open(&sub.join("disk1_dd-index.sqlite")).unwrap();
    let count_final: i64 = db
        .with_conn(|conn| schema::file::table.count().get_result::<i64>(conn))
        .unwrap();
    assert_eq!(count_final, 10);
}
