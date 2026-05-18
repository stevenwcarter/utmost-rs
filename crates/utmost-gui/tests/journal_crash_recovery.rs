use utmost_gui::journal::Journal;
use utmost_gui::view_model::ViewModel;
use utmost_lib::events::{BincodeFileSink, CarveEvent};

#[test]
fn crashed_session_recovers_annotations_on_next_open() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("carve_events.bin");
    let _ = BincodeFileSink::create(&bin).unwrap();

    // Simulate a session that wrote two annotation events to .pending then crashed
    let j1 = Journal::for_main_log(&bin);
    j1.append(&CarveEvent::Bookmark {
        file_id: 1,
        bookmarked: true,
        at: "t".into(),
    })
    .unwrap();
    j1.append(&CarveEvent::Note {
        note_id: 1,
        file_id: 1,
        text: "hi".into(),
        at: "t".into(),
    })
    .unwrap();
    drop(j1);
    let pending = dir.path().join("carve_events.pending");
    assert!(
        pending.exists(),
        "pending file should exist before recovery"
    );

    // New session opens the log
    let j2 = Journal::for_main_log(&bin);
    let recovered = j2.recover_on_open().unwrap();
    assert_eq!(recovered.len(), 2);
    assert!(
        !pending.exists(),
        "pending should be deleted after recover_on_open"
    );

    // Both events are now in main log; replaying yields the same view-model state
    let mut vm = ViewModel::new();
    let mut r = utmost_lib::events::BincodeFileReader::open(&bin).unwrap();
    while let Some(ev) = r.next_event().unwrap() {
        vm.apply(&ev);
    }
    assert!(vm.bookmarks.contains(&1));
    assert_eq!(vm.notes.get(&1).unwrap().len(), 1);
}
