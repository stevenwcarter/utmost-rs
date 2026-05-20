//! Drive a fixed event stream through the writer, then hydrate a fresh VM
//! from the SQLite and compare to a second VM built by direct `apply()`.

mod common;

use common::run_started_event;
use utmost_gui::index_db::{IndexDb, hydrate, writer::IndexDbWriter};
use utmost_gui::view_model::ViewModel;
use utmost_lib::events::CarveEvent;
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::FileType;

fn events() -> Vec<CarveEvent> {
    let mut ev = vec![run_started_event()];
    for i in 1..=5u64 {
        ev.push(CarveEvent::FileFound {
            source_id: 0,
            file: create_file_object("a.jpg", FileType::Jpeg, 1024, 0, None, i),
            img_offset: 0,
            written_path: "a.jpg".into(),
        });
    }
    ev.push(CarveEvent::Bookmark {
        file_id: 2,
        bookmarked: true,
        at: "t".into(),
    });
    ev.push(CarveEvent::Note {
        note_id: 1,
        file_id: 3,
        text: "hello".into(),
        at: "t".into(),
    });
    ev.push(CarveEvent::RunFinished {
        duration_ms: 50,
        total_files_written: 5,
    });
    ev
}

#[test]
fn hydrate_matches_direct_replay() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = IndexDb::open(&dir.path().join("idx.sqlite")).unwrap();
    let events = events();

    // Path A: write to db
    {
        let mut w = IndexDbWriter::new(db.conn(), 1000);
        for (i, e) in events.iter().enumerate() {
            w.apply(e.clone(), (i as u64 + 1) * 10).unwrap();
        }
        w.flush().unwrap();
    }

    // Path B: direct replay into a VM
    let mut vm_b = ViewModel::new();
    for e in &events {
        vm_b.apply(e);
    }
    vm_b.recompute_visible();

    // Hydrate VM from db
    let snap = hydrate::snapshot_from_db(db.conn()).unwrap().unwrap();
    let mut vm_a = ViewModel::new();
    vm_a.hydrate_from(snap);
    vm_a.recompute_visible();

    // Compare relevant fields
    assert_eq!(vm_a.run.total_files, vm_b.run.total_files);
    assert_eq!(
        format!("{:?}", vm_a.run.status),
        format!("{:?}", vm_b.run.status)
    );
    // Task 12: ViewModel no longer holds a file list; the SQLite `file`
    // table is the source of truth. The total_files counter above is the
    // remaining cross-VM file-count assertion.
    assert_eq!(vm_a.bookmarks, vm_b.bookmarks);
    let a_notes: usize = vm_a.notes.values().map(|v| v.len()).sum();
    let b_notes: usize = vm_b.notes.values().map(|v| v.len()).sum();
    assert_eq!(a_notes, b_notes);
}
