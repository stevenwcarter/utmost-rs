mod common;

use common::run_started_event;
use std::sync::{Arc, Mutex};
use utmost_gui::view_model::ViewModel;
use utmost_lib::events::{BincodeFileSink, CarveEvent, EventSink};
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::FileType;

#[test]
fn warm_open_hydrates_without_advancing_offset() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("output-disk1_dd");
    std::fs::create_dir_all(&sub).unwrap();
    let bin = sub.join("disk1_dd-events.bin");
    {
        let sink = BincodeFileSink::create(&bin).unwrap();
        sink.emit(&run_started_event());
        for i in 1..=20u64 {
            sink.emit(&CarveEvent::FileFound {
                source_id: 0,
                file: create_file_object("x.jpg", FileType::Jpeg, 0, 0, None, i),
                img_offset: 0,
                written_path: "x.jpg".into(),
            });
        }
        sink.emit(&CarveEvent::RunFinished {
            duration_ms: 5,
            total_files_written: 20,
        });
    }

    // First open: cold
    {
        let vm = Arc::new(Mutex::new(ViewModel::new()));
        utmost_gui::indexer_thread::run_blocking(&bin, vm.clone()).unwrap();
        assert_eq!(vm.lock().unwrap().files.len(), 20);
    }
    // Second open: warm
    let vm = Arc::new(Mutex::new(ViewModel::new()));
    utmost_gui::indexer_thread::run_blocking(&bin, vm.clone()).unwrap();
    assert_eq!(vm.lock().unwrap().files.len(), 20);
}
