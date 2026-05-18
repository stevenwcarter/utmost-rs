# GUI Polish Pass — Design

**Date:** 2026-05-18
**Branch:** feature/utmost-gui-slint
**Scope:** Seven GUI fixes discovered during manual testing of the Slint-based UI in `crates/utmost-gui`.

## Goals

Address seven independent issues found during a hands-on session with the GUI:

1. Clicking a type filter pill (e.g. "Jpeg (1962)") does nothing.
2. Gallery view has no arrow-key or h/j/k/l navigation.
3. Pressing `n` while a gallery tile is selected should focus the Notes input.
4. The currently selected gallery tile has no visual indication of selection.
5. Unbookmarking the last bookmarked file while filtering by bookmarked strands the user — the chip disappears and the filter cannot be turned off.
6. Saved-note bodies and the selected file's filename cannot be selected for copy.
7. The lightbox does not support mouse-wheel zoom.

## Non-Goals

- Selectable text in the gallery tile filename/size labels (low value, visually noisy if every label gets the `LineEdit` chrome).
- Selectable text in the lightbox top-bar filename (possible follow-up).
- Drag-to-pan after wheel zoom — already supported by `lightbox.slint`'s `drag_touch.moved` handler.

## Fix 1 — Filter pill toggle (bug)

### Root cause

`crates/utmost-gui/src/slint_adapter.rs:547` populates the `FilterChipData.name` for each type chip as `format!("{ft:?}")` — Rust's `Debug` formatter, which yields PascalCase strings like `"Jpeg"`, `"Pdf"`.

`on_chip_toggled` (`slint_adapter.rs:117`) routes non-`bookmarked` / non-`partial:*` names through `parse_file_type_pub`, which calls `parse_file_type` in `crates/utmost-gui/src/view_model.rs:524`. That function only matches lowercase strings (`"jpeg"`, `"pdf"`, …). Result: `parse_file_type_pub("Jpeg") == None`, so the handler silently no-ops.

`Select all` and `Select none` bypass this path entirely (they take their own callbacks straight to `enabled_types`), which is why they work.

### Fix

Lowercase the chip `name` when populating the type-chip entries in `slint_adapter.rs:547`:

```rust
.map(|(ft, count)| FilterChipData {
    name: SharedString::from(format!("{ft:?}").to_lowercase()),
    enabled: vm.filter.enabled_types.contains(ft),
    count: *count as i32,
    kind: SharedString::from("type"),
})
```

The partial-chip path already lowercases (`slint_adapter.rs:556-558`), so `strip_prefix("partial:")` continues to find them.

Important: the chip's **visible label** is still derived from the (also-`Debug`-formatted) `chip.name` string in `detail.slint:165-167`. Lowercasing the name will now render "jpeg (1962)" instead of "Jpeg (1962)". Two options:

- **Add a `display_name` field to `FilterChipData`** populated with the original `format!("{ft:?}")` (PascalCase), and use it for the on-screen label. The wire/identity `name` stays lowercase. **Recommended.**
- Capitalize the lowercase name in the Slint template via string ops. Slint has no built-in `capitalize`, so this is awkward.

Implementation will add the `display_name` field on `FilterChipData` and update `detail.slint:164-171` to display `display_name` (falling back to `name` for the partial/bookmarked kinds which already format correctly).

### Test

Unit test in `view_model.rs` (or alongside the existing slint_adapter tests):

- `chip_toggled_with_populated_name_flips_enabled_types`: drive `parse_file_type_pub` with the exact `name` string the adapter produces (`"jpeg"`) and assert the matching `FileType` comes back.
- Integration test: drive a full slint sync, simulate a `chip_toggled("jpeg")` callback, and assert `vm.visible_files` updates.

## Fix 2 — Bookmark chip persistence (bug)

### Root cause

`slint_adapter.rs:566` conditions chip presence on `if !vm.bookmarks.is_empty()`. When the user is filtering by `bookmarked_only` and unbookmarks the last file, the chip disappears, leaving `bookmarked_only = true` with no UI affordance to turn it off.

### Fix

Always push the bookmark chip, regardless of count:

```rust
chips.push(FilterChipData {
    name: SharedString::from("bookmarked"),
    enabled: vm.filter.bookmarked_only,
    count: vm.bookmarks.len() as i32,
    kind: SharedString::from("bookmarked"),
});
```

Per the user's preference, the chip always renders — including when the count is 0 — so the visual stays stable across bookmark add/remove cycles and the filter can always be toggled off.

### Test

- `bookmark_chip_present_when_filter_enabled_and_zero_bookmarks`: build a `ViewModel` with `filter.bookmarked_only = true` and no bookmarks, sync, assert the chip model contains a `kind == "bookmarked"` entry.

## Fix 3 — Gallery selection indicator + keyboard navigation (feature)

Three sub-pieces grouped because they all touch the same code paths.

### 3a. Selection indicator

- Add `in-out property <int> selected_id` to `MainWindow` and `DetailPage`.
- In `slint_adapter.rs`'s periodic sync (the same place where chips/tiles are pushed), mirror `vm.selection.map(|id| id as i32).unwrap_or(-1)` onto `window.set_selected_id(...)`.
- In `detail.slint:198-204`, replace the tile `Rectangle`'s `border-width` / `border-color` bindings:

```slint
border-width: tile.id == root.selected-id ? 2px : 1px;
border-color: tile.id == root.selected-id
    ? #3a6
    : (tile_touch.has-hover ? #888 : #444);
```

`#3a6` matches the existing accent green used for the progress bar and active filter pills.

### 3b. Keyboard navigation

Bind Arrow keys and `h/j/k/l` to gallery movement.

**Slint side** (`detail.slint`):

- New callback on `DetailPage`: `gallery-nav(string direction)` — direction is one of `"left"`, `"right"`, `"up"`, `"down"`.
- In `outer_focus.key-pressed`, add cases:
  - `event.text == Key.LeftArrow || event.text == "h"` → `root.gallery-nav("left"); return accept;`
  - `event.text == Key.RightArrow || event.text == "l"` → `gallery-nav("right")`
  - `event.text == Key.UpArrow || event.text == "k"` → `gallery-nav("up")`
  - `event.text == Key.DownArrow || event.text == "j"` → `gallery-nav("down")`
- The callback bubbles up through `main.slint` and is wired in `slint_adapter.rs`.

**Column count**: the navigation needs to know how many tiles per row to compute Up/Down jumps. Two options:

- Pass `grid_pane.cols` as a second arg to `gallery-nav(string, int)`. **Recommended.** Slint already computes it (`detail.slint:180`) and passes it implicitly via property bindings; sending it through the callback is straightforward.
- Have Rust recompute cols from window width and tile width. Brittle (Rust would need to know the layout magic numbers).

**Rust side** (`view_model.rs`):

```rust
pub enum NavDirection { Left, Right, Up, Down }

impl ViewModel {
    pub fn gallery_move(&mut self, dir: NavDirection, cols: usize) {
        if self.visible_files.is_empty() { return; }
        let cols = cols.max(1);
        let cur_idx = self.selection
            .and_then(|id| self.visible_files.iter().position(|&f| f == id));
        let new_idx = match (cur_idx, dir) {
            (None, _) => 0, // first arrow press selects first tile
            (Some(i), NavDirection::Left) => {
                if i == 0 { self.visible_files.len() - 1 }
                else { i - 1 }
            }
            (Some(i), NavDirection::Right) => {
                if i + 1 >= self.visible_files.len() { 0 }
                else { i + 1 }
            }
            (Some(i), NavDirection::Up) => {
                if i < cols { i } // clamp at top row
                else { i - cols }
            }
            (Some(i), NavDirection::Down) => {
                if i + cols >= self.visible_files.len() { i } // clamp at bottom
                else { i + cols }
            }
        };
        self.selection = Some(self.visible_files[new_idx]);
    }
}
```

Behavior summary:
- No selection + any arrow → select first visible tile.
- Left/Right: wrap across rows (end-of-row Right → start of next row; start-of-row Left → end of previous row); wraps from last tile to first and vice versa.
- Up/Down: clamp at the top/bottom row (no-op if would land outside `visible_files`).

`slint_adapter.rs` registers `on_gallery_nav(|dir, cols| { vm.gallery_move(parse(dir), cols as usize) })`.

**Auto-scroll**: when the selected tile moves outside the Flickable viewport, the grid should scroll to keep it visible.

- Slint's `Flickable.viewport-y` is an in-out property. Bind it to `MainWindow`'s in-out property `gallery_viewport_y` mirrored from a `vm.gallery_scroll_y: f32` field.
- When `gallery_move` changes the selection, compute the row of the new selection and adjust `gallery_scroll_y` if the row's `y` is outside `[-viewport_y, -viewport_y + visible_height]`. The visible height isn't trivially known on the Rust side; pass `viewport-height` and `viewport-y` back the same way `cols` is passed (extra args on the callback).
- If the math gets thorny in the implementation phase, defer auto-scroll as a follow-up (noted in the Out-of-Scope below) — selection indicator and key-driven `selection` updates are the essential parts.

### 3c. `n` focuses the note input

Currently `detail.slint:124-130` rejects `n`/`N` with a comment that focusing a sibling TextInput from a FocusScope is "not straightforward in Slint". This is a misdiagnosis: `note_input` (declared at `detail.slint:387`) lives inside the same `DetailPage` component and is reachable by name from `outer_focus`.

Replace the no-op:

```slint
if (event.text == "n" || event.text == "N") {
    if (root.side-panel-open) {
        note_input.focus();
    }
    return accept;
}
```

Side panel auto-opens whenever there's a selection (existing behavior), so when there's a selected tile, the input is in the layout tree and focusable.

**Fallback if direct focus call fails**: expose a `request_focus_note()` callback on `DetailPage`. Wire it from `outer_focus.key-pressed`. In `slint_adapter.rs`, set a `note_focus_requested: AtomicBool` flag. On the next sync, push the flag value onto an in-out property `request_note_focus: bool`; bind that to a tiny `Timer` or `changed` handler near `note_input` that calls `note_input.focus()` and clears the flag. This adds two more state-shuffles per `n` press, but is robust. Document this fallback in the plan; try the direct call first.

### Tests

- `gallery_move_with_no_selection_selects_first`
- `gallery_move_left_wraps_across_rows`
- `gallery_move_right_wraps_at_end`
- `gallery_move_up_clamps_at_top_row`
- `gallery_move_down_clamps_at_bottom_row`
- `gallery_move_left_with_empty_visible_is_noop`

## Fix 4 — Selectable text for filenames and notes (feature)

Slint's `LineEdit` and `TextEdit` (from `std-widgets`) support text selection and copy when `read-only: true`. Plain `Text` does not.

**Single-line displays** (use read-only `LineEdit`):

- Side-panel filename header (`detail.slint:259`). Currently:
  ```slint
  Text { text: root.selected-filename; font-size: 16px; ... }
  ```
  Becomes:
  ```slint
  LineEdit {
      text: root.selected-filename;
      read-only: true;
      font-size: 16px;
      horizontal-stretch: 1;
  }
  ```
- Metadata-row values (`detail.slint:352-355`): the `value` Text becomes a read-only `LineEdit`. The `key` label stays plain `Text`.

**Multi-line displays** (use read-only `TextEdit`):

- Saved-note body (`detail.slint:376`):
  ```slint
  TextEdit {
      text: note.text;
      read-only: true;
      wrap: word-wrap;
      font-size: 12px;
  }
  ```
  Timestamp (`note.at`) stays plain `Text`.

**Multi-line editable** (note draft — use `TextEdit`):

- `note_input` (`detail.slint:387`) becomes a `TextEdit` with `wrap: word-wrap`.
- Submit semantics:
  - Plain `Enter` inserts a newline (default `TextEdit` behavior).
  - `Cmd+Enter` (macOS) / `Ctrl+Enter` (linux) submits. Detected in `key-pressed`:
    ```slint
    key-pressed(event) => {
        if (event.text == Key.Return
            && (event.modifiers.control || event.modifiers.meta)) {
            root.add-note(self.text);
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
    ```
  - An explicit small "Add" button sits next to the text area and also calls `root.add-note`. Disabled when `self.text` is empty.
- The existing `note-draft` in-out property continues to mirror `self.text` via `edited`.

**Lightbox note input** (`lightbox.slint:305`): same conversion to `TextEdit`, same Cmd/Ctrl+Enter semantics. Add an "Add" button to the lightbox note overlay as well so the two flows stay symmetric.

### Tests

UI tests are minimal here (most of the verification is visual). The existing add-note tests should be re-checked against the new key-press path. Add:

- `add_note_via_ctrl_enter_clears_draft`: drive the Slint TextEdit's key-press with `Return` + control modifier, assert `add-note` was called with the text and `note-draft` is empty.

## Fix 5 — Mouse-wheel zoom in lightbox (feature)

Slint's `TouchArea` exposes `scroll-event(event) -> EventResult` where `event` has `delta-x: length` and `delta-y: length` (positive `delta-y` = scroll up = zoom in, per platform conventions).

In `lightbox.slint`, add `scroll-event` to the existing `drag_touch` TouchArea (which already covers the image body, lines 98-119):

```slint
scroll-event(event) => {
    if (!root.has-image) {
        return reject;
    }
    // Exit Fit on first wheel tick; anchor at current displayed scale.
    if (root.fit) {
        root.zoom-changed(root.fit-scale);
    }
    // delta-y is in length units; divide by a constant to get a sane factor.
    // 60px per "notch" ≈ 1.0–1.5× zoom on a typical mouse wheel; smoother on trackpads.
    root.zoom-changed(clamp(root.zoom * pow(1.1, event.delta-y / 60px),
                            0.1, 8.0));
    return accept;
}
```

Notes:
- `root.zoom-changed(root.fit-scale)` triggers the Rust side's `vm.zoom_set(z)` which clears `fit` (confirmed in `view_model.rs:424-427` — `zoom_set` sets `self.lightbox_view.fit = false`). The subsequent `zoom-changed` call applies the wheel delta.
- The existing `+` / `-` keypress handlers and the slider keep working unchanged.
- The existing drag-to-pan keeps working unchanged after zoom (`drag_touch.moved`).

### Tests

- `lightbox_wheel_zoom_exits_fit`: in `view_model.rs`, simulate the sequence (fit=true, fit-scale=0.5) → `zoom_set(0.5)` → assert `fit == false` and `zoom == 0.5`.
- `lightbox_wheel_zoom_clamps_at_bounds`: drive enough fictional wheel events to push zoom past 8.0; assert it clamps.

## Architecture impact

These fixes touch three files plus tests:

- `crates/utmost-gui/ui/detail.slint` — selection indicator, key bindings, `n` focus, LineEdit/TextEdit swaps, "Add" button.
- `crates/utmost-gui/ui/lightbox.slint` — wheel zoom, note input TextEdit, "Add" button.
- `crates/utmost-gui/ui/main.slint` — propagate the new `selected_id` and `gallery-nav` callback.
- `crates/utmost-gui/src/slint_adapter.rs` — chip-name lowercase fix, bookmark-chip-always-push, `selected_id` mirror, `on_gallery_nav` wiring, `display_name` field for chips.
- `crates/utmost-gui/src/view_model.rs` — `NavDirection` enum, `gallery_move`, new tests.

No new dependencies. No changes to `utmost-lib`, no changes to the event log format, no changes to journal/recovery code.

The `FilterChipData` struct gains a `display_name` field; this is internal to the GUI crate and not part of any persisted format.

## Risk and rollout

- All seven fixes are local to the GUI crate. Library tests are unaffected.
- The chip-name fix is the only one with subtle external consequences (third-party introspection of the chip name string). There is none today.
- The `n`-focus fix has a documented fallback if direct cross-FocusScope focus calls fail at runtime.
- Auto-scroll on keyboard navigation is the most likely piece to be deferred if Flickable viewport math turns out fiddly; the rest of fix 3 is independent.

## Out of scope / follow-ups

- Selectable text on gallery tile labels (filename + size/type) — visually noisy with `LineEdit` chrome on every tile.
- Selectable text in lightbox top-bar filename — easy mirror of fix 4 but separate concern.
- Auto-scroll the gallery Flickable when keyboard navigation moves selection out of view — see Fix 3b notes; defer if Flickable viewport math is non-trivial.
- Pinch-to-zoom on trackpads — separate input path, separate test.

## Validation

For each fix the implementer should:
1. Run `cargo fmt && cargo clippy --all-targets` (project rule from CLAUDE.md).
2. Run `cargo test -p utmost-gui`.
3. For the visual/interaction fixes (1, 2, 3a, 4, 5, 6, 7), launch the GUI manually, reproduce the original symptom from the bug list, confirm the fix.

If any UI behavior turns out to not work as designed in Slint (in particular: cross-FocusScope `focus()` calls, `LineEdit` selection behavior in read-only mode, or `TouchArea.scroll-event` semantics), pause and check in before working around it.
