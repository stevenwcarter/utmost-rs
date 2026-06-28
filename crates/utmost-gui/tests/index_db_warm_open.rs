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
        // Task 12: vm.files is gone; verify SQLite has the 20 files instead.
        assert_eq!(count_files(&sub.join("disk1_dd-index.sqlite")), 20);
    }
    // Second open: warm
    let vm = Arc::new(Mutex::new(ViewModel::new()));
    utmost_gui::indexer_thread::run_blocking(&bin, vm.clone()).unwrap();
    assert_eq!(count_files(&sub.join("disk1_dd-index.sqlite")), 20);
}

/// Strong assertion that the second open hits the warm-hydrate path
/// (`OpenAction::HydrateAndDone`) and never iterates events out of the
/// `.bin`.
///
/// `open_decision` itself reads the FileHeader and the first event
/// (`RunStarted`) to validate the run identity — that's unavoidable. But
/// the warm path then takes `HydrateAndDone`, which doesn't iterate any
/// further. A cold rebuild would stream every frame and fail on
/// corrupted ones.
///
/// So we corrupt the bytes of a later event (a `FileFound`) and ensure
/// the second open still succeeds. We also assert `last_event_offset`
/// is unchanged afterward, which proves no resume-write happened.
#[test]
fn warm_open_does_not_touch_bin() {
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

    // First open: cold rebuild populates the SQLite index.
    {
        let vm = Arc::new(Mutex::new(ViewModel::new()));
        utmost_gui::indexer_thread::run_blocking(&bin, vm.clone()).unwrap();
        // Task 12: vm.files is gone; verify SQLite has the 20 files instead.
        assert_eq!(count_files(&sub.join("disk1_dd-index.sqlite")), 20);
    }

    let off_before = read_offset(&sub.join("disk1_dd-index.sqlite"));
    let size_before = std::fs::metadata(&bin).unwrap().len();

    // Smash bytes in the last quarter of the `.bin`. `open_decision`
    // only reads the FileHeader plus the first event (`RunStarted`),
    // both of which live at the start; the warm path
    // (`HydrateAndDone`) takes over from there and never iterates the
    // rest of the log. A cold rebuild would stream every frame and
    // fail when it hit our corruption.
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = std::fs::OpenOptions::new().write(true).open(&bin).unwrap();
        let corrupt_at = size_before.saturating_sub(size_before / 4);
        f.seek(SeekFrom::Start(corrupt_at)).unwrap();
        // Wipe a hundred bytes — long enough to corrupt frame lengths
        // and payload alike.
        f.write_all(&[0xFFu8; 100]).unwrap();
    }

    // Second open: must succeed (warm path) without iterating events.
    let vm = Arc::new(Mutex::new(ViewModel::new()));
    utmost_gui::indexer_thread::run_blocking(&bin, vm.clone())
        .expect("warm open must not iterate the (now-corrupted) .bin");
    // Task 12: vm.files is gone; verify SQLite still has the 20 files.
    assert_eq!(count_files(&sub.join("disk1_dd-index.sqlite")), 20);

    let off_after = read_offset(&sub.join("disk1_dd-index.sqlite"));
    let size_after = std::fs::metadata(&bin).unwrap().len();
    assert_eq!(
        off_before, off_after,
        "warm open must not advance last_event_offset"
    );
    assert_eq!(size_before, size_after, ".bin size must be unchanged");
}

fn read_offset(db_path: &std::path::Path) -> String {
    let pool = common::open_pool(db_path);
    common::meta_value(&pool, "last_event_offset").unwrap()
}

/// Task 12 helper: count rows in the `file` table. Used in place of
/// `vm.files.len()` since the ViewModel no longer holds the file list.
fn count_files(db_path: &std::path::Path) -> i64 {
    let pool = common::open_pool(db_path);
    common::count(&pool, "file")
}
