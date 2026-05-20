//! Task 15: unit-ish coverage of `ViewModel::need_slide`, the predicate the
//! UI tick uses to decide whether the currently-loaded window needs to
//! slide before the next `FetchWindow`.
//!
//! The plan slots this as an integration test even though `need_slide` is
//! pure — keeping it in `tests/` keeps every "windowed-files" verification
//! discoverable from one file glob.

use utmost_gui::index_db::queries::FileStub;
use utmost_gui::view_model::ViewModel;
use utmost_lib::types::FileType;

/// Build a VM whose `match_ids` holds `n` synthetic stubs and whose loaded
/// window covers `window_range`. The stubs are minimal; only `file_id`
/// matters for `need_slide` (which only consults `match_ids.len()` and
/// `window_range`).
fn vm_with_stubs(n: usize, window_range: std::ops::Range<usize>) -> ViewModel {
    let mut vm = ViewModel::new();
    vm.match_ids = (0..n as u64)
        .map(|id| FileStub {
            file_id: id,
            filename: format!("{id:08}.jpeg"),
            filesize: 1_000,
            file_type: FileType::Jpeg,
        })
        .collect();
    vm.window_range = window_range;
    vm
}

#[test]
fn need_slide_triggers_for_visible_range_outside_window() {
    // Window covers indices 0..1000. `need_slide` requires `slide_trigger`
    // rows of slack on both ends of the visible range, so a visible range
    // touching either window edge will trigger a slide; we pick a visible
    // range with comfortable interior slack for the "no slide" case.
    let vm = vm_with_stubs(20_000, 0..1_000);

    // Case 1: visible rows are well inside the window — no slide needed.
    assert!(
        vm.need_slide(100, 150, 1_000, 4).is_none(),
        "visible rows inside the window must not trigger a slide"
    );

    // Case 2: visible rows are far outside the current window — slide needed,
    // and the new range must contain the visible rows.
    let new_range = vm
        .need_slide(1_500, 1_550, 1_000, 4)
        .expect("visible rows outside the window should trigger a slide");
    assert!(
        new_range.contains(&1_500),
        "new window range {new_range:?} must contain visible row 1500"
    );
    assert!(
        new_range.contains(&1_550),
        "new window range {new_range:?} must also contain visible row 1550"
    );
}
