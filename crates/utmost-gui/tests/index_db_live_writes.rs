mod common;

use common::run_started_event;
use diesel::prelude::*;
use utmost_gui::index_db::{IndexDb, schema};
use utmost_lib::events::{BincodeFileSink, CarveEvent, EventSink};
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::FileType;

/// Drive `run_live_writes` directly (no Slint event loop) and verify that
/// each `FileFound` shows up as a row in the SQLite index after the writer
/// thread joins. This exercises the live-mode fan-out path used by
/// `lib.rs::run_live`.
#[test]
fn live_writes_persist_each_event_to_sqlite() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("output-disk1_dd");
    std::fs::create_dir_all(&sub).unwrap();
    let bin = sub.join("disk1_dd-events.bin");
    let sink = BincodeFileSink::create(&bin).unwrap();

    let (tx, rx) = crossbeam_channel::unbounded();
    let main_log = bin.clone();
    let join = std::thread::spawn(move || {
        utmost_gui::indexer_thread::run_live_writes(&main_log, rx).unwrap();
    });

    sink.emit(&run_started_event());
    tx.send(run_started_event()).unwrap();
    for i in 1..=5u64 {
        let ev = CarveEvent::FileFound {
            source_id: 0,
            file: create_file_object("x.jpg", FileType::Jpeg, 0, 0, None, i),
            img_offset: 0,
            written_path: "x.jpg".into(),
        };
        sink.emit(&ev);
        tx.send(ev).unwrap();
    }
    drop(tx);
    join.join().unwrap();

    let mut db = IndexDb::open(&sub.join("disk1_dd-index.sqlite")).unwrap();
    let n: i64 = db
        .with_conn(|conn| schema::file::table.count().get_result::<i64>(conn))
        .unwrap();
    assert_eq!(n, 5);
}
