mod common;

use common::run_started_event;
use std::sync::atomic::AtomicBool;
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
    let shutdown = Arc::new(AtomicBool::new(false));
    let h = spawn(bin.clone(), vm, tx, shutdown.clone());

    // Give the indexer time to consume the 200 fixture events and reach EOF.
    std::thread::sleep(std::time::Duration::from_millis(500));
    shutdown.store(true, std::sync::atomic::Ordering::Relaxed);

    h.join().unwrap();

    let msgs: Vec<_> = rx.try_iter().collect();
    assert!(!msgs.is_empty());
    // Started must be the first message; Finished is no longer emitted
    // in tail mode (the loop exits via shutdown_signal, not clean EOF).
    assert!(matches!(msgs.first(), Some(IndexProgress::Started { .. })));

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

/// Setting the shutdown signal *before* spawn() runs makes the writer
/// thread exit on the very first iteration of its event loop —
/// proving the cancellation hook is wired all the way through to
/// rebuild_from_zero / resume_from. Without the hook, the writer would
/// process all 200 events; with it, it sees the flag and bails after
/// flushing the (empty) batch.
#[test]
fn pre_set_shutdown_short_circuits_indexer() {
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
    let shutdown = Arc::new(AtomicBool::new(true));

    let h = spawn(bin.clone(), vm.clone(), tx, shutdown);

    // With shutdown pre-set, the writer must finish within a generous
    // timeout — far shorter than reading 200 events would take if the
    // hook weren't wired. We bound the wait explicitly (no sleep loop):
    // spawn returns a JoinHandle, and join() blocks. To assert "fast,"
    // we just observe that join completes and that the VM ends up at
    // its initial state (no FileFound was applied).
    h.join().unwrap();

    // Started was emitted (always); Finished may or may not be emitted
    // depending on whether the loop entered before the check, but the
    // bookkeeping invariant is that no FileFound rows leaked into the
    // VM via apply().
    let _msgs: Vec<_> = rx.try_iter().collect();
    let v = vm.lock().unwrap();
    // The VM's `bookmarks` etc. stay empty; what we really want to check
    // is that the bulk of the 200 FileFound events were NOT applied.
    // `v.run.total_files` is bumped per FileFound (via apply()).
    // Without cancellation: 200; with cancellation: 0 or a small number.
    assert!(
        v.run.total_files <= 1,
        "expected cancellation to short-circuit; got total_files={}",
        v.run.total_files,
    );
}
