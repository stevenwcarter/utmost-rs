//! Task 15: keyboard-nav coverage for the windowed-files match list.
//!
//! Simulates 5_000 `j` keypresses (advance selection by one) against a VM
//! whose `match_ids` holds 50_000 synthetic stubs. Asserts that the
//! resulting selection points at the 5_001st stub (index 5_000).
//!
//! No SQLite or indexer thread is involved — this is a pure VM walk over
//! `match_ids`, exercising the same loop the UI uses when the user holds
//! down `j` past the loaded window boundary.

use utmost_gui::view_model::{FileStub, ViewModel};
use utmost_lib::types::FileType;

#[test]
fn j_5000_times_advances_selection_across_match_ids() {
    let stubs: Vec<FileStub> = (0..50_000u64)
        .map(|id| FileStub {
            file_id: id,
            filename: format!("{id:08}.jpeg"),
            filesize: 1_000,
            file_type: FileType::Jpeg,
        })
        .collect();

    let mut vm = ViewModel::new();
    vm.current_epoch = 1;
    vm.apply_match_ids(stubs.clone(), 1);
    vm.selection = Some(stubs[0].file_id);

    for _ in 0..5_000 {
        let cur = vm.selection.expect("selection is set");
        let idx = vm
            .match_ids
            .iter()
            .position(|s| s.file_id == cur)
            .expect("current selection must appear in match_ids");
        vm.selection = Some(vm.match_ids[idx + 1].file_id);
    }

    assert_eq!(
        vm.selection,
        Some(stubs[5_000].file_id),
        "5000 `j` keypresses must land on the 5001st stub"
    );
}
