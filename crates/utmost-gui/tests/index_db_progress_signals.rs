mod common;

use common::run_started_event;
use std::sync::{Arc, Mutex};
use utmost_gui::indexer_thread::{IndexProgress, spawn};
use utmost_gui::view_model::ViewModel;
use utmost_lib::events::{BincodeFileSink, CarveEvent, EventSink};
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::FileType;

#[test]
fn progress_sequence_started_optional_ticks_finished() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("output-disk1_dd");
    std::fs::create_dir_all(&sub).unwrap();
    let bin = sub.join("disk1_dd-events.bin");
    {
        let sink = BincodeFileSink::create(&bin).unwrap();
        sink.emit(&run_started_event());
        for i in 1..=200u64 {
            sink.emit(&CarveEvent::FileFound {
                source_id: 0,
                file: create_file_object("a.jpg", FileType::Jpeg, 0, 0, None, i),
                img_offset: 0,
                written_path: "a.jpg".into(),
            });
        }
    }
    let (tx, rx) = crossbeam_channel::unbounded();
    let vm = Arc::new(Mutex::new(ViewModel::new()));
    let h = spawn(bin.clone(), vm, tx);
    h.join().unwrap();

    let msgs: Vec<_> = rx.try_iter().collect();
    assert!(!msgs.is_empty());
    assert!(matches!(msgs.first(), Some(IndexProgress::Started { .. })));
    assert!(matches!(msgs.last(), Some(IndexProgress::Finished)));

    // Bytes ticks (if any) must be monotonic non-decreasing.
    let mut last_bytes: u64 = 0;
    for m in &msgs {
        if let IndexProgress::Bytes { read } = m {
            assert!(*read >= last_bytes, "bytes regressed");
            last_bytes = *read;
        }
    }

    // Files ticks (if any) must be monotonic non-decreasing.
    let mut last_files: u64 = 0;
    for m in &msgs {
        if let IndexProgress::Files { count } = m {
            assert!(*count >= last_files, "files regressed");
            last_files = *count;
        }
    }
}
