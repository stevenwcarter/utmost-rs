# GUI Polish Pass Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land seven discrete GUI fixes in `crates/utmost-gui` from manual-testing feedback: filter pill toggle bug, gallery keyboard nav + selection indicator + `n` focus, bookmark chip persistence, selectable text for filenames/notes, and lightbox mouse-wheel zoom.

**Architecture:** All changes are local to the `utmost-gui` crate. Three Slint files (`main.slint`, `detail.slint`, `lightbox.slint`) and two Rust files (`slint_adapter.rs`, `view_model.rs`). No new dependencies. No changes to `utmost-lib`, the event log format, or the journal/recovery code paths.

**Tech Stack:** Slint 1.10 (std-widgets: `LineEdit`, `TextEdit`, `TouchArea`, `FocusScope`, `Flickable`), Rust 1.95, `cargo test`/`clippy`/`fmt`. Slint design reference: `docs/superpowers/specs/2026-05-18-gui-polish-pass-design.md`.

**Pre-flight (do once before Task 1):** Confirm the working tree is clean on branch `feature/utmost-gui-slint`. Run `cargo build -p utmost-gui` to make sure the baseline compiles before any edits.

---

## File Map

- `crates/utmost-gui/src/view_model.rs` — add `NavDirection` enum + `gallery_move` method; new tests for chip parsing, bookmark-chip-when-empty, and gallery navigation.
- `crates/utmost-gui/src/slint_adapter.rs` — lowercase chip `name`, populate new `display_name`, always push bookmark chip, mirror `vm.selection` onto `selected_id` property, wire `on_gallery_nav`.
- `crates/utmost-gui/ui/main.slint` — declare `selected_id` property + `gallery-nav` callback; pass through to `DetailPage` and out to Rust.
- `crates/utmost-gui/ui/detail.slint` — `FilterChipData.display_name` field; tile `border` bindings keyed on `selected-id`; outer `FocusScope` arrow/hjkl handlers; `n` focuses `note_input`; swap `Text` → `LineEdit` (read-only) for filename + metadata values; swap `Text`/`TextInput` → read-only `TextEdit` for saved notes and editable `TextEdit` for the draft; "Add" button.
- `crates/utmost-gui/ui/lightbox.slint` — wheel zoom on `drag_touch`; note input `TextInput` → `TextEdit` with Cmd/Ctrl+Enter submit + "Add" button.

Order of tasks below follows roughly the file order to minimize cross-task conflicts. Each task ends with `cargo fmt && cargo clippy --all-targets && cargo test -p utmost-gui` and a commit.

---

## Task 1: Fix the filter-pill toggle bug (lowercase chip name + display_name)

**Files:**
- Modify: `crates/utmost-gui/ui/detail.slint` (FilterChipData struct + chip rendering)
- Modify: `crates/utmost-gui/src/slint_adapter.rs` (chip populator ~line 542-575)
- Test: `crates/utmost-gui/src/view_model.rs` (new unit test)

### Background

Chip `name` is currently `format!("{ft:?}")` → `"Jpeg"`. `parse_file_type` only accepts lowercase, so clicks no-op. Lowercasing the name breaks the visible label (`detail.slint:165-171` uses `chip.name` directly), so we add a `display_name` field on `FilterChipData` and use that for the visible label.

- [ ] **Step 1: Write the failing test**

Add to `crates/utmost-gui/src/view_model.rs` in the existing test module:

```rust
#[test]
fn parse_file_type_pub_accepts_chip_name_format() {
    // The slint_adapter populates chip name as lowercase of Debug formatter.
    // This test pins that contract.
    use crate::types::FileType;
    let name = format!("{:?}", FileType::Jpeg).to_lowercase();
    assert_eq!(name, "jpeg");
    assert_eq!(parse_file_type_pub(&name), Some(FileType::Jpeg));
}
```

Check whether the test module already has `use crate::types::FileType;` (it does — search for it before adding). If `FileType` is imported via `use super::*;` you can drop the explicit `use`.

- [ ] **Step 2: Run test to verify it fails (or check that the adapter path is broken)**

Run: `cargo test -p utmost-gui parse_file_type_pub_accepts_chip_name_format`
Expected: PASS (the test itself doesn't fail — it documents the contract). The real bug is in `slint_adapter.rs`, not detectable by a pure VM unit test. The test above is a regression guard for the contract.

- [ ] **Step 3: Add a regression test for `chip_toggled` end-to-end behavior**

Add to `crates/utmost-gui/src/view_model.rs` test module:

```rust
#[test]
fn chip_toggled_with_lowercase_name_flips_enabled_types() {
    use crate::types::FileType;
    let mut vm = ViewModel::new();
    vm.filter.enabled_types.insert(FileType::Jpeg);
    // Simulate the handler body from on_chip_toggled (slint_adapter.rs):
    let name = format!("{:?}", FileType::Jpeg).to_lowercase();
    if let Some(ft) = parse_file_type_pub(&name) {
        if vm.filter.enabled_types.contains(&ft) {
            vm.filter.enabled_types.remove(&ft);
        } else {
            vm.filter.enabled_types.insert(ft);
        }
    }
    assert!(!vm.filter.enabled_types.contains(&FileType::Jpeg));
}
```

Run: `cargo test -p utmost-gui chip_toggled_with_lowercase_name_flips_enabled_types`
Expected: PASS.

- [ ] **Step 4: Add `display_name` to `FilterChipData` in `detail.slint`**

In `crates/utmost-gui/ui/detail.slint` around line 3-8:

```slint
export struct FilterChipData {
    name: string,
    display_name: string,
    enabled: bool,
    count: int,
    kind: string,  // "type" | "partial" | "bookmarked"
}
```

- [ ] **Step 5: Use `display_name` for the visible label**

In `detail.slint` around line 164-171 (the chip `Text`), change the binding to prefer `display_name` and fall back to `name` only when empty:

```slint
Text {
    text: chip.kind == "bookmarked"
        ? "Bookmarked (" + chip.count + ")"
        : (chip.kind == "partial" ? "Partial " : "")
            + (chip.display_name == "" ? chip.name : chip.display_name)
            + " (" + chip.count + ")";
    color: white;
    horizontal-alignment: center;
    vertical-alignment: center;
}
```

- [ ] **Step 6: Populate lowercase `name` + PascalCase `display_name` in the adapter**

In `crates/utmost-gui/src/slint_adapter.rs` around line 542-575, change the populator:

```rust
let mut chips: Vec<FilterChipData> = vm
    .type_counts
    .iter()
    .map(|(ft, count)| FilterChipData {
        name: SharedString::from(format!("{ft:?}").to_lowercase()),
        display_name: SharedString::from(format!("{ft:?}")),
        enabled: vm.filter.enabled_types.contains(ft),
        count: *count as i32,
        kind: SharedString::from("type"),
    })
    .collect();

for (ft, count) in &vm.partial_counts {
    let ft_string = format!("{:?}", ft).to_lowercase();
    chips.push(FilterChipData {
        name: SharedString::from(format!("partial:{}", ft_string)),
        display_name: SharedString::from(format!("{ft:?}")),
        enabled: vm.filter.enabled_partial_types.contains(ft),
        count: *count as i32,
        kind: SharedString::from("partial"),
    });
}
```

(Task 2 handles the bookmarked chip's populator.)

- [ ] **Step 7: Build, format, clippy, test**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test -p utmost-gui
```

Expected: all green.

- [ ] **Step 8: Commit**

```bash
git add crates/utmost-gui/ui/detail.slint \
        crates/utmost-gui/src/slint_adapter.rs \
        crates/utmost-gui/src/view_model.rs
git commit -m "$(cat <<'EOF'
fix(gui): filter pill clicks were silently no-op due to case mismatch

Type-chip name was populated as Debug-formatted PascalCase ("Jpeg")
but parse_file_type only matched lowercase, so on_chip_toggled
silently returned None. Adapter now lowercases the wire name and a
new display_name field carries the user-visible PascalCase string.

Regression tests pin both the contract (parse_file_type_pub accepts
the populator output) and the end-to-end toggle behavior.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Bookmark chip always rendered

**Files:**
- Modify: `crates/utmost-gui/src/slint_adapter.rs` (~line 565-573)
- Test: `crates/utmost-gui/src/view_model.rs`

### Background

The bookmark chip currently appears only when `!vm.bookmarks.is_empty()`. Emptying bookmarks while `bookmarked_only` is on strands the user — there's no UI to turn the filter off. Always push the chip.

- [ ] **Step 1: Write the failing-on-current-behavior contract test**

Add to `crates/utmost-gui/src/view_model.rs` test module:

```rust
#[test]
fn bookmark_filter_can_be_toggled_off_when_zero_bookmarks() {
    // Simulates: user has bookmarked_only=true, then removes the last bookmark.
    // The handler should still be able to flip bookmarked_only off via chip.
    let mut vm = ViewModel::new();
    vm.filter.bookmarked_only = true;
    // bookmarks already empty
    // Simulate the handler body from on_chip_toggled (slint_adapter.rs):
    vm.filter.bookmarked_only = !vm.filter.bookmarked_only;
    assert!(!vm.filter.bookmarked_only);
}
```

Run: `cargo test -p utmost-gui bookmark_filter_can_be_toggled_off_when_zero_bookmarks`
Expected: PASS (the VM logic is fine; the gap is purely UI presence).

- [ ] **Step 2: Remove the conditional in the chip populator**

In `crates/utmost-gui/src/slint_adapter.rs` around line 565-573:

```rust
// Bookmarked chip: always present so the filter can be toggled off
// even after the last bookmark is removed.
chips.push(FilterChipData {
    name: SharedString::from("bookmarked"),
    display_name: SharedString::from("Bookmarked"),
    enabled: vm.filter.bookmarked_only,
    count: vm.bookmarks.len() as i32,
    kind: SharedString::from("bookmarked"),
});
```

- [ ] **Step 3: Build, format, clippy, test**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test -p utmost-gui
```

Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add crates/utmost-gui/src/slint_adapter.rs crates/utmost-gui/src/view_model.rs
git commit -m "$(cat <<'EOF'
fix(gui): bookmark chip always visible to avoid filter strand

Previously the chip only appeared when at least one bookmark existed.
Unbookmarking the last item while filtering by bookmarked hid the
chip and left the filter on with no UI to turn it off. The chip now
renders regardless of count.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Selection indicator on the selected gallery tile

**Files:**
- Modify: `crates/utmost-gui/ui/main.slint` (declare `selected_id`)
- Modify: `crates/utmost-gui/ui/detail.slint` (`selected-id` property + tile border binding)
- Modify: `crates/utmost-gui/src/slint_adapter.rs` (mirror `vm.selection` into `selected_id`)

### Background

`vm.selection: Option<FileId>` exists but the UI never reads it back. Add a Slint property and bind the tile border color/width to it.

- [ ] **Step 1: Add `selected-id` property to `DetailPage`**

In `crates/utmost-gui/ui/detail.slint` around line 67-86 (the `in-out property` block), add:

```slint
in-out property <int> selected-id: -1;
```

- [ ] **Step 2: Update tile border bindings**

In `crates/utmost-gui/ui/detail.slint` around line 198-204, replace:

```slint
border-width: 1px;
border-color: tile_touch.has-hover ? #888 : #444;
```

with:

```slint
border-width: tile.id == root.selected-id ? 2px : 1px;
border-color: tile.id == root.selected-id
    ? #3a6
    : (tile_touch.has-hover ? #888 : #444);
```

- [ ] **Step 3: Add `selected-id` property to `MainWindow` and wire it through**

In `crates/utmost-gui/ui/main.slint`:

a. Around line 26-43 add:

```slint
in-out property <int> selected-id: -1;
```

b. Around line 93-110 (the `if root.show-detail: DetailPage { ... }` instantiation), add:

```slint
selected-id: root.selected-id;
```

- [ ] **Step 4: Mirror `vm.selection` from the adapter sync**

In `crates/utmost-gui/src/slint_adapter.rs`, locate the periodic sync function (the one that already calls `set_chips`, `set_tiles`, etc. — search for `replace_model(&self.chips_model, chips);` around line 575). After that block but before `tiles` are computed, add:

```rust
let selected_id = vm.selection.map(|id| id as i32).unwrap_or(-1);
self.window
    .upgrade()
    .map(|w| w.set_selected_id(selected_id));
```

Adjust to whatever pattern that function already uses to access the window (it may be `&self.window` directly, or a weak handle — match the surrounding code). If unsure, `grep` the file for an existing setter call like `set_run_status` or `set_total_files` and follow that exact pattern.

- [ ] **Step 5: Build, format, clippy, test**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test -p utmost-gui
```

Expected: all green. No new tests in this task — visual change verified manually.

- [ ] **Step 6: Manual smoke check**

```bash
cargo run -p utmost-gui --release
```

Click a tile in the gallery view. Expected: a 2px green border (#3a6) on the clicked tile; other tiles unchanged. Click a different tile; the green border moves. Click the grid background; the green border disappears.

- [ ] **Step 7: Commit**

```bash
git add crates/utmost-gui/ui/main.slint \
        crates/utmost-gui/ui/detail.slint \
        crates/utmost-gui/src/slint_adapter.rs
git commit -m "$(cat <<'EOF'
feat(gui): visual selection indicator on the selected gallery tile

Selected tile now gets a 2px #3a6 border, matching the accent color
used elsewhere in the UI. Drives off vm.selection mirrored into a
new selected_id Slint property.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Add `NavDirection` enum and `gallery_move` to ViewModel

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs`
- Test: `crates/utmost-gui/src/view_model.rs` (same module)

### Background

Backend for keyboard navigation. Left/Right wraps across rows (and from last↔first tile). Up/Down clamps at top/bottom rows. No selection + any direction → select first visible tile.

- [ ] **Step 1: Write the failing tests**

Add to `crates/utmost-gui/src/view_model.rs` test module:

```rust
fn vm_with_n_visible(n: usize) -> ViewModel {
    use crate::types::FileType;
    let mut vm = ViewModel::new();
    vm.filter.enabled_types.insert(FileType::Jpeg);
    for i in 0..n {
        add_file(&mut vm, 1, &format!("f{i}.jpg"), FileType::Jpeg, 100);
    }
    vm
}

#[test]
fn gallery_move_with_no_selection_selects_first() {
    let mut vm = vm_with_n_visible(5);
    assert!(vm.selection.is_none());
    vm.gallery_move(NavDirection::Right, 3);
    assert_eq!(vm.selection, Some(vm.visible_files[0]));
}

#[test]
fn gallery_move_left_wraps_across_rows() {
    let mut vm = vm_with_n_visible(6); // cols=3, two rows
    vm.selection = Some(vm.visible_files[3]); // start of row 1
    vm.gallery_move(NavDirection::Left, 3);
    assert_eq!(vm.selection, Some(vm.visible_files[2])); // end of row 0
}

#[test]
fn gallery_move_left_wraps_from_first_to_last() {
    let mut vm = vm_with_n_visible(6);
    vm.selection = Some(vm.visible_files[0]);
    vm.gallery_move(NavDirection::Left, 3);
    assert_eq!(vm.selection, Some(vm.visible_files[5]));
}

#[test]
fn gallery_move_right_wraps_from_last_to_first() {
    let mut vm = vm_with_n_visible(6);
    vm.selection = Some(vm.visible_files[5]);
    vm.gallery_move(NavDirection::Right, 3);
    assert_eq!(vm.selection, Some(vm.visible_files[0]));
}

#[test]
fn gallery_move_up_clamps_at_top_row() {
    let mut vm = vm_with_n_visible(6);
    vm.selection = Some(vm.visible_files[1]); // top row
    vm.gallery_move(NavDirection::Up, 3);
    assert_eq!(vm.selection, Some(vm.visible_files[1])); // unchanged
}

#[test]
fn gallery_move_down_clamps_at_bottom_row() {
    let mut vm = vm_with_n_visible(5); // cols=3 → rows 0..3 has 3 tiles, row 1 has 2 tiles
    vm.selection = Some(vm.visible_files[4]); // bottom row
    vm.gallery_move(NavDirection::Down, 3);
    assert_eq!(vm.selection, Some(vm.visible_files[4])); // clamped
}

#[test]
fn gallery_move_down_into_partial_bottom_row_clamps() {
    let mut vm = vm_with_n_visible(5); // cols=3, row 1 has 2 tiles
    vm.selection = Some(vm.visible_files[2]); // row 0, col 2
    vm.gallery_move(NavDirection::Down, 3);
    // Index 2 + 3 = 5 which is out of bounds, so clamp.
    assert_eq!(vm.selection, Some(vm.visible_files[2]));
}

#[test]
fn gallery_move_on_empty_visible_is_noop() {
    let mut vm = ViewModel::new();
    assert!(vm.visible_files.is_empty());
    vm.gallery_move(NavDirection::Right, 3);
    assert_eq!(vm.selection, None);
}
```

The `add_file` helper already exists in the test module (search for `fn add_file(`). The `vm_with_n_visible` helper is new — add it once in the test module.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p utmost-gui gallery_move`
Expected: compile errors — `NavDirection` and `gallery_move` don't exist yet.

- [ ] **Step 3: Add `NavDirection` enum and `gallery_move` method**

In `crates/utmost-gui/src/view_model.rs`, near the other public types around line 140 (where `ViewModel` is declared):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavDirection {
    Left,
    Right,
    Up,
    Down,
}
```

In the `impl ViewModel` block, add (placement near `deselect`/`close_or_deselect` around line 411 is natural):

```rust
pub fn gallery_move(&mut self, dir: NavDirection, cols: usize) {
    if self.visible_files.is_empty() {
        return;
    }
    let cols = cols.max(1);
    let cur_idx = self
        .selection
        .and_then(|id| self.visible_files.iter().position(|&f| f == id));
    let len = self.visible_files.len();
    let new_idx = match (cur_idx, dir) {
        (None, _) => 0,
        (Some(i), NavDirection::Left) => {
            if i == 0 {
                len - 1
            } else {
                i - 1
            }
        }
        (Some(i), NavDirection::Right) => {
            if i + 1 >= len {
                0
            } else {
                i + 1
            }
        }
        (Some(i), NavDirection::Up) => {
            if i < cols {
                i
            } else {
                i - cols
            }
        }
        (Some(i), NavDirection::Down) => {
            if i + cols >= len {
                i
            } else {
                i + cols
            }
        }
    };
    self.selection = Some(self.visible_files[new_idx]);
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test -p utmost-gui gallery_move
```

Expected: all 8 gallery_move_* tests pass.

- [ ] **Step 5: Build, format, clippy, full test**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test -p utmost-gui
```

Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-gui/src/view_model.rs
git commit -m "$(cat <<'EOF'
feat(gui): NavDirection enum + gallery_move for keyboard navigation

Pure view-model logic: given current selection and column count,
compute the new selection. Left/Right wraps across rows and around
the ends; Up/Down clamps at top/bottom. First arrow press with no
selection picks the first visible tile.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Wire arrow/hjkl keys in Slint to the new `gallery_move` backend

**Files:**
- Modify: `crates/utmost-gui/ui/detail.slint` (new callback + key handlers)
- Modify: `crates/utmost-gui/ui/main.slint` (propagate callback)
- Modify: `crates/utmost-gui/src/slint_adapter.rs` (`on_gallery_nav`)

### Background

Slint side computes `cols` from layout (`grid_pane.cols`) and passes it through the callback. Rust side parses the direction string and calls `gallery_move`.

- [ ] **Step 1: Add `gallery-nav` callback on `DetailPage`**

In `crates/utmost-gui/ui/detail.slint`, in the callbacks block (around line 88-106), add:

```slint
callback gallery-nav(string, int);
```

- [ ] **Step 2: Add key bindings in the outer `FocusScope`**

In `detail.slint` around line 111-132 (the `key-pressed` handler in `outer_focus`), insert the new cases before `return reject;`:

```slint
if (event.text == Key.LeftArrow || event.text == "h" || event.text == "H") {
    root.gallery-nav("left", grid_pane.cols);
    return accept;
}
if (event.text == Key.RightArrow || event.text == "l" || event.text == "L") {
    root.gallery-nav("right", grid_pane.cols);
    return accept;
}
if (event.text == Key.UpArrow || event.text == "k" || event.text == "K") {
    root.gallery-nav("up", grid_pane.cols);
    return accept;
}
if (event.text == Key.DownArrow || event.text == "j" || event.text == "J") {
    root.gallery-nav("down", grid_pane.cols);
    return accept;
}
```

Note: `grid_pane` is declared at `detail.slint:175`. It's in scope from `outer_focus.key-pressed` because both live inside `DetailPage`.

- [ ] **Step 3: Forward the callback in `MainWindow`**

In `crates/utmost-gui/ui/main.slint`:

a. Add to the callbacks block (around line 58-91):

```slint
callback gallery-nav(string, int);
```

b. Inside the `DetailPage { ... }` instantiation (around line 93-163), add a handler:

```slint
gallery-nav(dir, cols) => {
    root.gallery-nav(dir, cols);
}
```

- [ ] **Step 4: Wire `on_gallery_nav` in the adapter**

In `crates/utmost-gui/src/slint_adapter.rs`, near the other `on_*` registrations (search for `on_select_all` around line 142), add:

```rust
{
    let vm_cb = vm.clone();
    window.on_gallery_nav(move |dir, cols| {
        let dir = match dir.as_str() {
            "left" => crate::view_model::NavDirection::Left,
            "right" => crate::view_model::NavDirection::Right,
            "up" => crate::view_model::NavDirection::Up,
            "down" => crate::view_model::NavDirection::Down,
            _ => return,
        };
        let mut v = vm_cb.lock().unwrap();
        v.gallery_move(dir, cols.max(1) as usize);
    });
}
```

If `NavDirection` isn't already in scope at the top of `slint_adapter.rs`, add it to the existing `use crate::view_model::...;` line.

- [ ] **Step 5: Build, format, clippy, test**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test -p utmost-gui
```

Expected: all green. (Unit coverage for the new logic was added in Task 4.)

- [ ] **Step 6: Manual smoke check**

```bash
cargo run -p utmost-gui --release
```

Open the detail view, press an arrow key. Expected: the first tile gains the green selection border. Press Right/L several times: selection moves rightward, wraps from end of row to start of next row, and wraps from last tile back to first. Press Down/J at the bottom row: no movement. Press h/j/k/l: same behavior as arrows.

- [ ] **Step 7: Commit**

```bash
git add crates/utmost-gui/ui/detail.slint \
        crates/utmost-gui/ui/main.slint \
        crates/utmost-gui/src/slint_adapter.rs
git commit -m "$(cat <<'EOF'
feat(gui): arrow / hjkl gallery navigation

Outer FocusScope in DetailPage now handles Left/Right/Up/Down and
h/j/k/l, calling gallery-nav with the current column count. The
adapter routes that to ViewModel::gallery_move. Left/Right wrap;
Up/Down clamp.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: `n` focuses the note input on the detail page

**Files:**
- Modify: `crates/utmost-gui/ui/detail.slint` (around line 124-130)

### Background

Currently `n`/`N` is rejected with a comment claiming sibling `TextInput` focus is hard. It isn't — `note_input` shares an ancestor with `outer_focus` and is reachable by name. Side panel is always open when a tile is selected, so the input is always in the layout tree at that point.

- [ ] **Step 1: Replace the no-op `n` handler**

In `crates/utmost-gui/ui/detail.slint` around line 124-130, replace:

```slint
// 'n' — focusing a TextInput inside a sibling VerticalBox from a
// FocusScope is not straightforward in Slint; the user can click
// the "+ Note" button to reach the input. Tasks 20-21 may extend
// this with a dedicated callback once note_input is named in scope.
if (event.text == "n" || event.text == "N") {
    return accept;
}
```

with:

```slint
if (event.text == "n" || event.text == "N") {
    if (root.side-panel-open) {
        note_input.focus();
    }
    return accept;
}
```

- [ ] **Step 2: Build, format, clippy, test**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test -p utmost-gui
```

Expected: all green.

- [ ] **Step 3: Manual smoke check**

```bash
cargo run -p utmost-gui --release
```

Open detail view, click a tile (side panel opens). Press `n`. Expected: the note input gets a focus ring and keystrokes are captured by the input. Press `Esc` to return focus to outer scope, then press `b` to confirm the bookmark shortcut still works.

If the direct `note_input.focus()` call does not work at runtime (no focus ring, keystrokes still go to the outer scope), STOP and surface this — the spec documents a callback+flag fallback that we'll wire instead. Do not silently revert to the no-op.

- [ ] **Step 4: Commit**

```bash
git add crates/utmost-gui/ui/detail.slint
git commit -m "$(cat <<'EOF'
feat(gui): 'n' focuses the side-panel note input

The TextInput is reachable by name from the outer FocusScope because
both live inside DetailPage. Removes the stale comment from the
previous attempt.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Selectable filename and metadata values (LineEdit, read-only)

**Files:**
- Modify: `crates/utmost-gui/ui/detail.slint` (filename header ~line 259, metadata rows ~line 346-356)

### Background

Replace plain `Text` with read-only `LineEdit` (from `std-widgets`) for single-value displays the user might want to copy.

- [ ] **Step 1: Import `LineEdit`**

At the top of `crates/utmost-gui/ui/detail.slint` (line 1), update the import:

```slint
import { HorizontalBox, VerticalBox, Button, SpinBox, LineEdit } from "std-widgets.slint";
```

- [ ] **Step 2: Replace filename header**

In `detail.slint` around line 258-264 (the filename `Text` inside the side panel HorizontalBox), replace:

```slint
Text {
    text: root.selected-filename;
    font-size: 16px;
    color: white;
    horizontal-stretch: 1;
    overflow: elide;
}
```

with:

```slint
LineEdit {
    text: root.selected-filename;
    read-only: true;
    font-size: 16px;
    horizontal-stretch: 1;
}
```

(`LineEdit` doesn't expose `color` or `overflow` directly; the default theming is acceptable. If the visual diff is too jarring, surface it after the smoke check rather than hand-styling here.)

- [ ] **Step 3: Replace metadata-row values**

In `detail.slint` around line 346-356, replace:

```slint
for row in root.selected-metadata: HorizontalBox {
    Text {
        text: row.key;
        font-weight: 700;
        color: white;
    }
    Text {
        text: row.value;
        color: white;
    }
}
```

with:

```slint
for row in root.selected-metadata: HorizontalBox {
    Text {
        text: row.key;
        font-weight: 700;
        color: white;
    }
    LineEdit {
        text: row.value;
        read-only: true;
        horizontal-stretch: 1;
    }
}
```

- [ ] **Step 4: Build, format, clippy, test**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test -p utmost-gui
```

Expected: all green.

- [ ] **Step 5: Manual smoke check**

```bash
cargo run -p utmost-gui --release
```

Click a tile. In the side panel, click and drag across the filename to highlight a portion of it. Expected: text is selectable. Right-click → Copy (or Cmd+C) should put it on the clipboard. Same for any metadata value.

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-gui/ui/detail.slint
git commit -m "$(cat <<'EOF'
feat(gui): selectable filename + metadata values via read-only LineEdit

Replaces plain Text widgets with read-only LineEdit so the user can
highlight and copy single-value displays in the side panel. Saved
notes remain plain Text until the next commit converts them.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Selectable saved-note bodies (TextEdit, read-only)

**Files:**
- Modify: `crates/utmost-gui/ui/detail.slint` (~line 364-381)

### Background

Saved notes are rendered as plain `Text`, which doesn't support selection. Switch the note body to read-only `TextEdit`. The timestamp stays plain `Text`.

- [ ] **Step 1: Add `TextEdit` to the imports**

In `crates/utmost-gui/ui/detail.slint`, update the line edited in Task 7:

```slint
import { HorizontalBox, VerticalBox, Button, SpinBox, LineEdit, TextEdit } from "std-widgets.slint";
```

- [ ] **Step 2: Replace the note body Text**

In `detail.slint` around line 364-382, replace the inner `VerticalBox`:

```slint
for note in root.selected-notes: Rectangle {
    background: #2a2a2a;
    border-radius: 3px;
    min-height: 32px;
    VerticalBox {
        padding: 4px;
        Text {
            text: note.at;
            color: #777;
            font-size: 9px;
        }
        Text {
            text: note.text;
            color: white;
            font-size: 12px;
            wrap: word-wrap;
        }
    }
}
```

with:

```slint
for note in root.selected-notes: Rectangle {
    background: #2a2a2a;
    border-radius: 3px;
    min-height: 32px;
    VerticalBox {
        padding: 4px;
        Text {
            text: note.at;
            color: #777;
            font-size: 9px;
        }
        TextEdit {
            text: note.text;
            read-only: true;
            wrap: word-wrap;
            font-size: 12px;
        }
    }
}
```

- [ ] **Step 3: Build, format, clippy, test**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test -p utmost-gui
```

Expected: all green.

- [ ] **Step 4: Manual smoke check**

```bash
cargo run -p utmost-gui --release
```

Open a file with at least one saved note. Drag-select across the note body. Expected: highlight appears; Cmd+C / right-click Copy puts the selection on the clipboard.

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-gui/ui/detail.slint
git commit -m "$(cat <<'EOF'
feat(gui): saved-note bodies are selectable via read-only TextEdit

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Multi-line note draft (TextEdit + Cmd/Ctrl+Enter + "Add" button)

**Files:**
- Modify: `crates/utmost-gui/ui/detail.slint` (note input ~line 383-410)

### Background

Switch the single-line `TextInput` for the note draft to multi-line `TextEdit`. Cmd/Ctrl+Enter submits. Add an explicit "Add" button next to (or beneath) the draft area. Plain Enter inserts a newline.

- [ ] **Step 1: Replace the note input block**

In `crates/utmost-gui/ui/detail.slint` around line 383-410, replace:

```slint
Rectangle {
    background: #111;
    border-radius: 3px;
    height: 60px;
    note_input := TextInput {
        width: parent.width - 8px;
        height: parent.height - 8px;
        x: 4px;
        y: 4px;
        color: white;
        font-size: 12px;
        text: root.note-draft;
        edited => { root.note-draft = self.text; }
        accepted => {
            root.add-note(self.text);
            root.note-draft = "";
            self.text = "";
            outer_focus.focus();
        }
        key-pressed(event) => {
            if (event.text == Key.Escape) {
                outer_focus.focus();
                return accept;
            }
            return reject;
        }
    }
}
```

with:

```slint
Rectangle {
    background: #111;
    border-radius: 3px;
    height: 80px;
    note_input := TextEdit {
        width: parent.width - 8px;
        height: parent.height - 8px;
        x: 4px;
        y: 4px;
        font-size: 12px;
        wrap: word-wrap;
        text: root.note-draft;
        edited => { root.note-draft = self.text; }
        key-pressed(event) => {
            if (event.text == Key.Return
                && (event.modifiers.control || event.modifiers.meta)) {
                root.add-note(self.text);
                root.note-draft = "";
                self.text = "";
                outer_focus.focus();
                return accept;
            }
            if (event.text == Key.Escape) {
                outer_focus.focus();
                return accept;
            }
            return reject;
        }
    }
}
HorizontalBox {
    padding: 0px;
    Rectangle { horizontal-stretch: 1; }
    Button {
        text: "Add";
        enabled: root.note-draft != "";
        clicked => {
            root.add-note(root.note-draft);
            root.note-draft = "";
            note_input.text = "";
            outer_focus.focus();
        }
    }
}
```

Notes:
- `TextEdit` doesn't have an `accepted` callback (that's `TextInput`); submit is purely via Ctrl/Cmd+Return or the Add button.
- `event.modifiers.control` and `event.modifiers.meta` are both checked so the binding works on macOS (Cmd) and Linux/Windows (Ctrl).
- `note_input.text = ""` after Add — `TextEdit` exposes `text` as `in-out`, same as the prior `TextInput`.

- [ ] **Step 2: Build, format, clippy, test**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test -p utmost-gui
```

Expected: all green.

- [ ] **Step 3: Manual smoke check**

```bash
cargo run -p utmost-gui --release
```

Click a tile (side panel opens). Type a note across multiple lines (press Enter to add a newline — should add a newline, NOT submit). Press Cmd+Enter (mac) or Ctrl+Enter (linux). Expected: note is added, draft clears, focus returns to outer scope. Type another note. Click "Add". Expected: same behavior. With an empty draft, the Add button is disabled.

- [ ] **Step 4: Commit**

```bash
git add crates/utmost-gui/ui/detail.slint
git commit -m "$(cat <<'EOF'
feat(gui): multi-line note draft with Cmd/Ctrl+Enter + Add button

The detail-page note input becomes a multi-line TextEdit. Plain
Enter inserts a newline; Cmd+Enter (mac) / Ctrl+Enter (linux) and
the new Add button submit. Escape returns focus to the outer
FocusScope as before.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: Same note-input treatment in the lightbox

**Files:**
- Modify: `crates/utmost-gui/ui/lightbox.slint` (~line 294-328 and the bottom action row ~line 273-290)

### Background

Mirror Task 9 in the lightbox so the two note flows stay symmetric. The lightbox `Lightbox` is itself a FocusScope (not a separate `outer_focus`) so the focus-return target is `root` not `outer_focus`.

- [ ] **Step 1: Add `TextEdit` to the lightbox imports**

In `crates/utmost-gui/ui/lightbox.slint` line 1, update the import:

```slint
import { HorizontalBox, VerticalBox, Button, Slider, TextEdit } from "std-widgets.slint";
```

- [ ] **Step 2: Replace the lightbox note input block**

In `lightbox.slint` around line 294-328, replace:

```slint
// Note input overlay — floats above the bottom bar when open.
// Always present in the layout tree (visible: property only) so that
// lightbox_note_input.focus() works immediately when 'n' is pressed.
Rectangle {
    visible: root.lightbox-note-input-open;
    x: 8px;
    y: parent.height - 80px - 68px;
    width: parent.width - 16px;
    height: 60px;
    background: #111;
    border-radius: 3px;
    lightbox_note_input := TextInput {
        x: 4px;
        y: 4px;
        width: parent.width - 8px;
        height: parent.height - 8px;
        color: white;
        text: root.lightbox-note-draft;
        edited => { root.lightbox-note-draft = self.text; }
        accepted => {
            root.lightbox-add-note(self.text);
            root.lightbox-note-draft = "";
            self.text = "";
            root.lightbox-note-input-open = false;
        }
        key-pressed(event) => {
            if (event.text == Key.Escape) {
                root.lightbox-note-input-open = false;
                root.focus();
                return accept;
            }
            return reject;
        }
    }
}
```

with:

```slint
// Note input overlay — floats above the bottom bar when open.
// Always present in the layout tree (visible: property only) so that
// lightbox_note_input.focus() works immediately when 'n' is pressed.
Rectangle {
    visible: root.lightbox-note-input-open;
    x: 8px;
    y: parent.height - 80px - 88px;
    width: parent.width - 16px;
    height: 80px;
    background: #111;
    border-radius: 3px;
    lightbox_note_input := TextEdit {
        x: 4px;
        y: 4px;
        width: parent.width - 8px - 60px;
        height: parent.height - 8px;
        wrap: word-wrap;
        text: root.lightbox-note-draft;
        edited => { root.lightbox-note-draft = self.text; }
        key-pressed(event) => {
            if (event.text == Key.Return
                && (event.modifiers.control || event.modifiers.meta)) {
                root.lightbox-add-note(self.text);
                root.lightbox-note-draft = "";
                self.text = "";
                root.lightbox-note-input-open = false;
                root.focus();
                return accept;
            }
            if (event.text == Key.Escape) {
                root.lightbox-note-input-open = false;
                root.focus();
                return accept;
            }
            return reject;
        }
    }
    Button {
        text: "Add";
        x: parent.width - 56px;
        y: 4px;
        width: 50px;
        height: 28px;
        enabled: root.lightbox-note-draft != "";
        clicked => {
            root.lightbox-add-note(root.lightbox-note-draft);
            root.lightbox-note-draft = "";
            lightbox_note_input.text = "";
            root.lightbox-note-input-open = false;
            root.focus();
        }
    }
}
```

- [ ] **Step 3: Build, format, clippy, test**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test -p utmost-gui
```

Expected: all green.

- [ ] **Step 4: Manual smoke check**

```bash
cargo run -p utmost-gui --release
```

In the gallery, double-click an image to open the lightbox. Press `n` to open the note overlay. Type a note with Enter for newlines. Press Cmd/Ctrl+Enter. Expected: note added, overlay closes, focus returns to lightbox. Press `n` again, type a note, click Add. Same expected result.

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-gui/ui/lightbox.slint
git commit -m "$(cat <<'EOF'
feat(gui): lightbox note input gains multi-line + Cmd/Ctrl+Enter + Add

Mirror of the detail-page change so the two note flows stay
symmetric.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: Mouse-wheel zoom in the lightbox

**Files:**
- Modify: `crates/utmost-gui/ui/lightbox.slint` (drag_touch TouchArea ~line 98-119)
- Optional test: `crates/utmost-gui/src/view_model.rs`

### Background

Slint `TouchArea` exposes `scroll-event(event) -> EventResult`. `event.delta-y` is positive for scroll-up. When in Fit mode, exit Fit first and anchor zoom at `fit-scale`, then apply the wheel delta. Clamp at [0.1, 8.0].

- [ ] **Step 1: Pin the zoom_set behavior with a test**

The spec relies on `zoom_set` clearing `fit`. Add a regression test in `view_model.rs` test module:

```rust
#[test]
fn zoom_set_clears_fit() {
    let mut vm = ViewModel::new();
    vm.lightbox_view.fit = true;
    vm.lightbox_view.zoom = 1.0;
    vm.zoom_set(0.5);
    assert!(!vm.lightbox_view.fit);
    assert!((vm.lightbox_view.zoom - 0.5).abs() < f32::EPSILON);
}

#[test]
fn zoom_set_clamps_within_bounds() {
    let mut vm = ViewModel::new();
    vm.zoom_set(100.0);
    assert!((vm.lightbox_view.zoom - 8.0).abs() < f32::EPSILON);
    vm.zoom_set(-5.0);
    assert!((vm.lightbox_view.zoom - 0.1).abs() < f32::EPSILON);
}
```

Run: `cargo test -p utmost-gui zoom_set`
Expected: PASS (behavior already exists; tests are guards).

- [ ] **Step 2: Add the `scroll-event` handler**

In `crates/utmost-gui/ui/lightbox.slint`, around line 98-119 (the `drag_touch` TouchArea), inside the existing block, add a `scroll-event` callback. The final block becomes:

```slint
drag_touch := TouchArea {
    x: 0;
    y: 0;
    width: parent.width;
    height: parent.height;
    enabled: root.has-image;
    mouse-cursor: drag_touch.pressed ? MouseCursor.grabbing : MouseCursor.grab;

    property <length> start-pan-x;
    property <length> start-pan-y;

    changed pressed => {
        if (self.pressed) {
            self.start-pan-x = root.pan-x;
            self.start-pan-y = root.pan-y;
        }
    }
    moved => {
        if (!root.fit) {
            root.pan-x = drag_touch.start-pan-x + (self.mouse-x - self.pressed-x);
            root.pan-y = drag_touch.start-pan-y + (self.mouse-y - self.pressed-y);
        }
    }
    scroll-event(event) => {
        if (!root.has-image) {
            return reject;
        }
        // If currently in Fit mode, anchor zoom at the displayed fit-scale
        // first so the image doesn't jump in size on the first wheel tick.
        if (root.fit) {
            root.zoom-changed(root.fit-scale);
        }
        // event.delta-y is in length units. ~60px per wheel notch on most
        // platforms; 1.1 base gives smooth perceived steps.
        root.zoom-changed(clamp(
            root.zoom * pow(1.1, event.delta-y / 60px),
            0.1,
            8.0));
        return accept;
    }
}
```

Important changes vs. the prior code:
- `enabled` was `root.has-image && !root.fit`; we expanded to `root.has-image` so that wheel events reach the handler in Fit mode (otherwise scroll-event is never dispatched). To keep drag-to-pan disabled in Fit mode, the `moved` body now guards on `!root.fit`.
- The `scroll-event` block is new.

- [ ] **Step 3: Build, format, clippy, test**

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test -p utmost-gui
```

Expected: all green.

If the Slint compiler rejects `pow(1.1, event.delta-y / 60px)` because of unit mismatches, swap to an integer step:

```slint
root.zoom-changed(clamp(
    root.zoom * (event.delta-y > 0px ? 1.1 : (event.delta-y < 0px ? 0.9 : 1.0)),
    0.1,
    8.0));
```

(Discrete per-event step; less smooth on trackpads but works regardless of unit math.)

- [ ] **Step 4: Manual smoke check**

```bash
cargo run -p utmost-gui --release
```

Open the lightbox on an image. While in Fit mode, scroll the wheel up. Expected: image transitions out of Fit at the displayed size (no jump) and zooms in. Scroll down to zoom back out. Push past zoom limits: the displayed % clamps at ~800% / ~10%. Drag-to-pan works after zooming in. Press "Fit" to return; wheel-scroll again to re-exit Fit smoothly.

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-gui/ui/lightbox.slint crates/utmost-gui/src/view_model.rs
git commit -m "$(cat <<'EOF'
feat(gui): mouse-wheel zoom in the lightbox

Wheel events on the image area now zoom in/out. First wheel tick
exits Fit mode and anchors at fit-scale so the image doesn't jump in
size. Drag-to-pan is gated to !fit so panning behavior is unchanged.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Final verification

After Task 11, run a full pass:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test -p utmost-gui
cargo build -p utmost-gui --release
```

All four must succeed before declaring the feature complete. Then run the GUI once more and walk through the seven original bullets in `docs/superpowers/specs/2026-05-18-gui-polish-pass-design.md` to confirm each symptom is resolved.

## Out-of-scope follow-ups (documented from the spec)

- Selectable text in lightbox top-bar filename (mirror of Task 7 — easy follow-up).
- Selectable text in gallery tile labels (too noisy).
- Auto-scroll the gallery Flickable when keyboard navigation moves the selection out of view (spec Fix 3b notes; defer if the math gets fiddly during Task 5 — none of the smoke checks above require it).
- Pinch-to-zoom on trackpads.
