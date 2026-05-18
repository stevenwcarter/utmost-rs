use std::sync::{Arc, Mutex};
use utmost_gui::journal::Journal;
use utmost_gui::view_model::ViewModel;
use utmost_lib::events::BincodeFileSink;

#[test]
fn annotations_made_during_live_carve_land_in_main_log_after_fold() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("carve_events.bin");
    let _ = BincodeFileSink::create(&bin).unwrap();

    let journal = Journal::for_main_log(&bin);
    let vm = Arc::new(Mutex::new(ViewModel::new()));

    // Simulate: user bookmarks file 7
    let ev = {
        let mut v = vm.lock().unwrap();
        v.toggle_bookmark(7)
    };
    journal.append(&ev).unwrap();
    assert!(journal.pending_path().exists());

    // Engine finishes — fold
    journal.fold().unwrap();
    assert!(!journal.pending_path().exists());

    // Replay main log into a fresh VM
    let mut vm2 = ViewModel::new();
    let mut r = utmost_lib::events::BincodeFileReader::open(&bin).unwrap();
    while let Some(ev) = r.next_event().unwrap() {
        vm2.apply(&ev);
    }
    assert!(vm2.bookmarks.contains(&7));
}
