# Detail page filter extensions — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add sort dropdown + direction toggle + "Bookmarked first" modifier, a "Hide no-preview" pill toggle, and a two-knob log-scale size-range slider to the detail page's filter UI.

**Architecture:** All filter and sort state extends the existing pure-Rust `FilterState` in `crates/utmost-gui/src/view_model.rs`. New Slint widget (`range_slider.slint`) provides the two-knob range slider; `detail.slint` exposes new properties and callbacks; `slint_adapter.rs` wires callbacks → view model and pushes UI state. Thumbnail readiness for `hide_no_preview` is tracked in the view model and fed by the existing `ThumbWorker::on_complete` callback.

**Tech Stack:** Rust, Slint (slint-rs), existing `crates/utmost-gui` setup, `cargo test` for view-model unit tests.

**Spec:** `docs/superpowers/specs/2026-05-18-detail-filter-extensions-design.md`.

---

## File map

**Modify:**
- `crates/utmost-gui/src/view_model.rs` — new `SortKey` variants, new `FilterState` fields, `thumbnail_ready: BTreeSet<FileId>`, `set_thumbnail_ready`, `size_filter_max`, updated `recompute_visible` (filter pipeline + sort), byte-conversion helpers, unit tests.
- `crates/utmost-gui/ui/detail.slint` — new top-toolbar controls and properties/callbacks; new size-slider row inside the filters block.
- `crates/utmost-gui/src/slint_adapter.rs` — new callbacks; wire `on_complete` to view model; push new properties.

**Create:**
- `crates/utmost-gui/ui/range_slider.slint` — two-knob range slider component.

---

## Task 1: Add `SortKey::FileType` + sort logic

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs` (enum near line 26; sort match near line 350)
- Test: same file, `#[cfg(test)] mod tests`

- [ ] **Step 1: Write failing tests**

Add to the test module in `crates/utmost-gui/src/view_model.rs` (after `sort_by_size_desc`):

```rust
    #[test]
    fn sort_by_file_type_asc() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.pdf", FileType::Pdf, 1);
        add_file(&mut vm, 0, "b.jpg", FileType::Jpeg, 1);
        vm.filter.enabled_types = [FileType::Jpeg, FileType::Pdf].into_iter().collect();
        vm.filter.sort_key = SortKey::FileType;
        vm.filter.sort_dir = SortDir::Asc;
        vm.recompute_visible();
        let first = vm
            .files
            .iter()
            .find(|f| f.id == vm.visible_files[0])
            .unwrap();
        // "jpeg" < "pdf" lexicographically
        assert_eq!(first.file.file_type, "jpeg");
    }

    #[test]
    fn sort_by_file_type_desc() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.pdf", FileType::Pdf, 1);
        add_file(&mut vm, 0, "b.jpg", FileType::Jpeg, 1);
        vm.filter.enabled_types = [FileType::Jpeg, FileType::Pdf].into_iter().collect();
        vm.filter.sort_key = SortKey::FileType;
        vm.filter.sort_dir = SortDir::Desc;
        vm.recompute_visible();
        let first = vm
            .files
            .iter()
            .find(|f| f.id == vm.visible_files[0])
            .unwrap();
        assert_eq!(first.file.file_type, "pdf");
    }
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `cargo test -p utmost-gui sort_by_file_type --lib`
Expected: FAIL (unknown variant `SortKey::FileType`).

- [ ] **Step 3: Add variant + sort match arm**

Update the enum at `crates/utmost-gui/src/view_model.rs:26`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortKey {
    #[default]
    Filename,
    Size,
    FileType,
    SourceOffset,
}
```

Update the sort match in `recompute_visible()` (around line 350):

```rust
        ids.sort_by(|a, b| {
            let fa = by_id[a];
            let fb = by_id[b];
            let cmp = match self.filter.sort_key {
                SortKey::Filename => fa.file.filename.cmp(&fb.file.filename),
                SortKey::Size => fa.file.filesize.cmp(&fb.file.filesize),
                SortKey::FileType => fa.file.file_type.cmp(&fb.file.file_type),
                SortKey::SourceOffset => fa.img_offset.cmp(&fb.img_offset),
            };
            match self.filter.sort_dir {
                SortDir::Asc => cmp,
                SortDir::Desc => cmp.reverse(),
            }
        });
```

(`SourceOffset` is added now even though Task 2 covers its tests — adding both variants here avoids a non-exhaustive match warning.)

- [ ] **Step 4: Run tests, verify they pass**

Run: `cargo test -p utmost-gui sort_by_file_type --lib`
Expected: PASS.

- [ ] **Step 5: Run full test suite**

Run: `cargo test -p utmost-gui --lib`
Expected: all tests PASS.

- [ ] **Step 6: Format + clippy**

Run: `cargo fmt && cargo clippy --all-targets`
Expected: no warnings.

- [ ] **Step 7: Commit**

```bash
git add crates/utmost-gui/src/view_model.rs
git commit -m "feat(gui): add SortKey::FileType and SortKey::SourceOffset variants

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 2: Tests for `SortKey::SourceOffset`

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs` (test module + a new `add_file_at_offset` helper)

- [ ] **Step 1: Add a helper that injects `img_offset`**

In the test module of `crates/utmost-gui/src/view_model.rs`, near the existing `add_file` helper (around line 1059), add:

```rust
    fn add_file_at_offset(
        vm: &mut ViewModel,
        sid: u32,
        name: &str,
        ft: FileType,
        sz: u64,
        img_offset: u64,
    ) {
        let fo = create_file_object(name, ft, sz, img_offset, None, 0);
        vm.apply(&CarveEvent::FileFound {
            source_id: sid,
            file: fo,
            img_offset,
            written_path: name.into(),
        });
    }
```

- [ ] **Step 2: Write failing tests**

Add after `sort_by_file_type_desc`:

```rust
    #[test]
    fn sort_by_source_offset_asc() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file_at_offset(&mut vm, 0, "a.jpg", FileType::Jpeg, 1, 5000);
        add_file_at_offset(&mut vm, 0, "b.jpg", FileType::Jpeg, 1, 1000);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.sort_key = SortKey::SourceOffset;
        vm.filter.sort_dir = SortDir::Asc;
        vm.recompute_visible();
        let first = vm
            .files
            .iter()
            .find(|f| f.id == vm.visible_files[0])
            .unwrap();
        assert_eq!(first.img_offset, 1000);
    }

    #[test]
    fn sort_by_source_offset_desc() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file_at_offset(&mut vm, 0, "a.jpg", FileType::Jpeg, 1, 5000);
        add_file_at_offset(&mut vm, 0, "b.jpg", FileType::Jpeg, 1, 1000);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.sort_key = SortKey::SourceOffset;
        vm.filter.sort_dir = SortDir::Desc;
        vm.recompute_visible();
        let first = vm
            .files
            .iter()
            .find(|f| f.id == vm.visible_files[0])
            .unwrap();
        assert_eq!(first.img_offset, 5000);
    }
```

- [ ] **Step 3: Run tests, verify PASS (implementation already in place from Task 1)**

Run: `cargo test -p utmost-gui sort_by_source_offset --lib`
Expected: both PASS.

- [ ] **Step 4: Format + clippy + commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/src/view_model.rs
git commit -m "test(gui): add sort_by_source_offset tests

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 3: Add `bookmarked_first` sort modifier

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs` (FilterState near line 88; sort logic near line 347)

- [ ] **Step 1: Write failing tests**

Add to the test module after the source-offset tests:

```rust
    #[test]
    fn bookmarked_first_floats_bookmarks_to_top_asc() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 0, "b.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 0, "c.jpg", FileType::Jpeg, 1);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.sort_key = SortKey::Filename;
        vm.filter.sort_dir = SortDir::Asc;
        vm.filter.bookmarked_first = true;
        // Bookmark only "c.jpg" (id = 2).
        vm.bookmarks.insert(2);
        vm.recompute_visible();
        let names: Vec<&str> = vm
            .visible_files
            .iter()
            .map(|id| {
                vm.files
                    .iter()
                    .find(|f| f.id == *id)
                    .unwrap()
                    .file
                    .filename
                    .as_str()
            })
            .collect();
        assert_eq!(names, vec!["c.jpg", "a.jpg", "b.jpg"]);
    }

    #[test]
    fn bookmarked_first_floats_bookmarks_to_top_desc() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 0, "b.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 0, "c.jpg", FileType::Jpeg, 1);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.sort_key = SortKey::Filename;
        vm.filter.sort_dir = SortDir::Desc;
        vm.filter.bookmarked_first = true;
        // Bookmark "a.jpg" (id = 0).
        vm.bookmarks.insert(0);
        vm.recompute_visible();
        let names: Vec<&str> = vm
            .visible_files
            .iter()
            .map(|id| {
                vm.files
                    .iter()
                    .find(|f| f.id == *id)
                    .unwrap()
                    .file
                    .filename
                    .as_str()
            })
            .collect();
        // Bookmark first, then non-bookmarks in desc filename order.
        assert_eq!(names, vec!["a.jpg", "c.jpg", "b.jpg"]);
    }
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `cargo test -p utmost-gui bookmarked_first --lib`
Expected: FAIL (unknown field `bookmarked_first`).

- [ ] **Step 3: Add field to `FilterState`**

In `crates/utmost-gui/src/view_model.rs`, update `FilterState` (around line 88):

```rust
#[derive(Debug, Clone, Default)]
pub struct FilterState {
    pub enabled_types: BTreeSet<FileType>,
    pub enabled_partial_types: BTreeSet<FileType>,
    pub bookmarked_only: bool,
    pub source_filter: Option<u32>,
    pub sort_key: SortKey,
    pub sort_dir: SortDir,
    pub bookmarked_first: bool,
}
```

- [ ] **Step 4: Update sort logic to honor the modifier**

Replace the `ids.sort_by(...)` block in `recompute_visible()` with:

```rust
        ids.sort_by(|a, b| {
            if self.filter.bookmarked_first {
                let ba = self.bookmarks.contains(a);
                let bb = self.bookmarks.contains(b);
                if ba != bb {
                    // true (bookmarked) sorts first
                    return bb.cmp(&ba);
                }
            }
            let fa = by_id[a];
            let fb = by_id[b];
            let cmp = match self.filter.sort_key {
                SortKey::Filename => fa.file.filename.cmp(&fb.file.filename),
                SortKey::Size => fa.file.filesize.cmp(&fb.file.filesize),
                SortKey::FileType => fa.file.file_type.cmp(&fb.file.file_type),
                SortKey::SourceOffset => fa.img_offset.cmp(&fb.img_offset),
            };
            match self.filter.sort_dir {
                SortDir::Asc => cmp,
                SortDir::Desc => cmp.reverse(),
            }
        });
```

- [ ] **Step 5: Run tests, verify they pass**

Run: `cargo test -p utmost-gui bookmarked_first --lib`
Expected: both PASS.

- [ ] **Step 6: Run full suite**

Run: `cargo test -p utmost-gui --lib`
Expected: all PASS.

- [ ] **Step 7: Format + clippy + commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/src/view_model.rs
git commit -m "feat(gui): add bookmarked_first sort modifier

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 4: Add `thumbnail_ready` + `hide_no_preview` filter

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs` (`ViewModel` struct, `FilterState`, new method `set_thumbnail_ready`, filter pipeline in `recompute_visible`)

- [ ] **Step 1: Write failing tests**

Add to the test module:

```rust
    #[test]
    fn hide_no_preview_hides_files_without_thumbnail() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 0, "b.jpg", FileType::Jpeg, 1);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.hide_no_preview = true;
        // Only file id=0 has a thumbnail.
        vm.set_thumbnail_ready(0, true);
        vm.recompute_visible();
        assert_eq!(vm.visible_files, vec![0]);
    }

    #[test]
    fn hide_no_preview_off_keeps_all_files() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 0, "b.jpg", FileType::Jpeg, 1);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.hide_no_preview = false;
        vm.set_thumbnail_ready(0, true);
        vm.recompute_visible();
        assert_eq!(vm.visible_files.len(), 2);
    }

    #[test]
    fn hide_no_preview_composes_with_chip_filter() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 0, "b.pdf", FileType::Pdf, 1);
        // Both have thumbnails.
        vm.set_thumbnail_ready(0, true);
        vm.set_thumbnail_ready(1, true);
        // Chip filter to jpeg only.
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.hide_no_preview = true;
        vm.recompute_visible();
        assert_eq!(vm.visible_files, vec![0]);
    }

    #[test]
    fn set_thumbnail_ready_false_removes_from_visible_when_hide_on() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.hide_no_preview = true;
        vm.set_thumbnail_ready(0, true);
        vm.recompute_visible();
        assert_eq!(vm.visible_files.len(), 1);
        vm.set_thumbnail_ready(0, false);
        vm.recompute_visible();
        assert!(vm.visible_files.is_empty());
    }
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `cargo test -p utmost-gui hide_no_preview --lib`
Expected: FAIL (unknown field `hide_no_preview`, unknown method `set_thumbnail_ready`).

- [ ] **Step 3: Add `hide_no_preview` to `FilterState`**

```rust
#[derive(Debug, Clone, Default)]
pub struct FilterState {
    pub enabled_types: BTreeSet<FileType>,
    pub enabled_partial_types: BTreeSet<FileType>,
    pub bookmarked_only: bool,
    pub source_filter: Option<u32>,
    pub sort_key: SortKey,
    pub sort_dir: SortDir,
    pub bookmarked_first: bool,
    pub hide_no_preview: bool,
}
```

- [ ] **Step 4: Add `thumbnail_ready` field to `ViewModel`**

Find the `ViewModel` struct definition (search for `pub struct ViewModel`) and add a new field. Initialize it in `ViewModel::new()` as well (search for `pub fn new() -> Self`). Add `pub thumbnail_ready: BTreeSet<FileId>,` alongside `pub bookmarks: BTreeSet<FileId>,`. Init it as `thumbnail_ready: BTreeSet::new(),`.

- [ ] **Step 5: Add `set_thumbnail_ready` method**

Add to the `impl ViewModel { ... }` block (alongside `toggle_bookmark`, etc., around line 612):

```rust
    /// Update the thumbnail-ready set for a single file. Caller is expected to
    /// call `recompute_visible()` afterwards if `hide_no_preview` is enabled.
    pub fn set_thumbnail_ready(&mut self, file_id: FileId, ready: bool) {
        if ready {
            self.thumbnail_ready.insert(file_id);
        } else {
            self.thumbnail_ready.remove(&file_id);
        }
    }
```

- [ ] **Step 6: Update filter pipeline in `recompute_visible`**

In the existing filter chain (the `.filter(|f| { ... })` block around line 315), add a `hide_no_preview` check after the bookmarked check and before the type-chip check:

```rust
                if self.filter.hide_no_preview
                    && !self.thumbnail_ready.contains(&f.file.file_id)
                {
                    return false;
                }
```

(Use `f.id` or `f.file.file_id` — they're the same; `f.id` is the `FoundFile` field. Use whichever matches the surrounding code.)

- [ ] **Step 7: Run tests, verify pass**

Run: `cargo test -p utmost-gui hide_no_preview --lib`
Expected: all 4 tests PASS.

- [ ] **Step 8: Run full suite**

Run: `cargo test -p utmost-gui --lib`
Expected: all PASS.

- [ ] **Step 9: Format + clippy + commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/src/view_model.rs
git commit -m "feat(gui): add hide_no_preview filter + thumbnail_ready tracking

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 5: Add `size_range` filter

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs`

- [ ] **Step 1: Write failing tests**

Add to the test module:

```rust
    #[test]
    fn size_range_none_matches_all() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 10);
        add_file(&mut vm, 0, "b.jpg", FileType::Jpeg, 1_000_000);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.size_range = None;
        vm.recompute_visible();
        assert_eq!(vm.visible_files.len(), 2);
    }

    #[test]
    fn size_range_inclusive_bounds() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "tiny.jpg", FileType::Jpeg, 10);
        add_file(&mut vm, 0, "mid.jpg", FileType::Jpeg, 100);
        add_file(&mut vm, 0, "big.jpg", FileType::Jpeg, 1000);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.size_range = Some((100, 1000)); // lo and hi both inclusive
        vm.recompute_visible();
        assert_eq!(vm.visible_files.len(), 2);
        let sizes: Vec<u64> = vm
            .visible_files
            .iter()
            .map(|id| {
                vm.files
                    .iter()
                    .find(|f| f.id == *id)
                    .unwrap()
                    .file
                    .filesize
            })
            .collect();
        assert!(sizes.contains(&100));
        assert!(sizes.contains(&1000));
    }

    #[test]
    fn size_range_composes_with_chip_filter() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 50);
        add_file(&mut vm, 0, "b.pdf", FileType::Pdf, 50);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.size_range = Some((0, 100));
        vm.recompute_visible();
        assert_eq!(vm.visible_files.len(), 1);
    }
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `cargo test -p utmost-gui size_range --lib`
Expected: FAIL (unknown field `size_range`).

- [ ] **Step 3: Add `size_range` to `FilterState`**

```rust
#[derive(Debug, Clone, Default)]
pub struct FilterState {
    pub enabled_types: BTreeSet<FileType>,
    pub enabled_partial_types: BTreeSet<FileType>,
    pub bookmarked_only: bool,
    pub source_filter: Option<u32>,
    pub sort_key: SortKey,
    pub sort_dir: SortDir,
    pub bookmarked_first: bool,
    pub hide_no_preview: bool,
    pub size_range: Option<(u64, u64)>,
}
```

- [ ] **Step 4: Update filter pipeline**

Add to the filter chain in `recompute_visible()`, after the `hide_no_preview` check:

```rust
                if let Some((lo, hi)) = self.filter.size_range
                    && (f.file.filesize < lo || f.file.filesize > hi)
                {
                    return false;
                }
```

- [ ] **Step 5: Run tests, verify pass**

Run: `cargo test -p utmost-gui size_range --lib`
Expected: all 3 PASS.

- [ ] **Step 6: Run full suite + clippy + commit**

```bash
cargo test -p utmost-gui --lib
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/src/view_model.rs
git commit -m "feat(gui): add size_range filter to FilterState

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 6: Add `size_filter_max()` method + clamping helper

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs`

- [ ] **Step 1: Write failing tests**

Add to the test module:

```rust
    #[test]
    fn size_filter_max_empty_returns_zero() {
        let vm = ViewModel::new();
        assert_eq!(vm.size_filter_max(), 0);
    }

    #[test]
    fn size_filter_max_uses_filtered_set() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "small.jpg", FileType::Jpeg, 100);
        add_file(&mut vm, 0, "big.pdf", FileType::Pdf, 9999);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        // pdf is filtered out — max should be 100, not 9999.
        assert_eq!(vm.size_filter_max(), 100);
    }

    #[test]
    fn size_filter_max_ignores_size_range_itself() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 500);
        add_file(&mut vm, 0, "b.jpg", FileType::Jpeg, 5000);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        // User has set a range that excludes the 5000-byte file — but the
        // max should still report 5000 to avoid a feedback loop.
        vm.filter.size_range = Some((0, 1000));
        assert_eq!(vm.size_filter_max(), 5000);
    }

    #[test]
    fn clamp_size_range_to_max_drops_to_none_on_collapse() {
        let mut vm = ViewModel::new();
        vm.filter.size_range = Some((0, 0));
        vm.clamp_size_range_to(0);
        assert_eq!(vm.filter.size_range, None);
    }

    #[test]
    fn clamp_size_range_to_max_clamps_hi() {
        let mut vm = ViewModel::new();
        vm.filter.size_range = Some((100, 9999));
        vm.clamp_size_range_to(500);
        assert_eq!(vm.filter.size_range, Some((100, 500)));
    }

    #[test]
    fn clamp_size_range_to_max_clamps_lo_and_hi() {
        let mut vm = ViewModel::new();
        vm.filter.size_range = Some((1000, 9999));
        vm.clamp_size_range_to(500);
        // lo > new max — clamp both.
        assert_eq!(vm.filter.size_range, Some((500, 500)));
    }
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `cargo test -p utmost-gui size_filter_max --lib && cargo test -p utmost-gui clamp_size_range --lib`
Expected: FAIL.

- [ ] **Step 3: Implement methods**

Add to the `impl ViewModel { ... }` block (near `recompute_visible`):

```rust
    /// Largest file size among files that pass all filters *except* the size
    /// range itself. Used as the upper bound for the size slider. Returns 0
    /// if the otherwise-filtered set is empty.
    pub fn size_filter_max(&self) -> u64 {
        self.files
            .iter()
            .filter(|f| {
                if let Some(sid) = self.filter.source_filter
                    && f.source_id != sid
                {
                    return false;
                }
                if self.filter.bookmarked_only && !self.bookmarks.contains(&f.id) {
                    return false;
                }
                if self.filter.hide_no_preview && !self.thumbnail_ready.contains(&f.id) {
                    return false;
                }
                if let Some(ft) = parse_file_type(&f.file.file_type) {
                    let is_partial = f
                        .file
                        .jpeg_scan
                        .as_ref()
                        .map(|s| s.partial)
                        .unwrap_or(false);
                    let ok = if is_partial {
                        self.filter.enabled_partial_types.contains(&ft)
                    } else {
                        self.filter.enabled_types.contains(&ft)
                    };
                    if !ok {
                        return false;
                    }
                }
                true
            })
            .map(|f| f.file.filesize)
            .max()
            .unwrap_or(0)
    }

    /// Clamp `size_range` to a new maximum. Collapses to `None` if the
    /// resulting range is `(0, 0)` (the slider is effectively unset).
    pub fn clamp_size_range_to(&mut self, new_max: u64) {
        if let Some((lo, hi)) = self.filter.size_range {
            let new_lo = lo.min(new_max);
            let new_hi = hi.min(new_max);
            if new_lo == 0 && new_hi == 0 {
                self.filter.size_range = None;
            } else {
                self.filter.size_range = Some((new_lo, new_hi));
            }
        }
    }
```

If `parse_file_type` is private — confirm with `grep -n "fn parse_file_type" crates/utmost-gui/src/view_model.rs` — and it's already used by `recompute_visible`, so it's in scope.

- [ ] **Step 4: Run tests, verify pass**

Run: `cargo test -p utmost-gui size_filter_max --lib && cargo test -p utmost-gui clamp_size_range --lib`
Expected: all PASS.

- [ ] **Step 5: Format + clippy + commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/src/view_model.rs
git commit -m "feat(gui): add size_filter_max() and clamp_size_range_to()

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 7: Add log byte ↔ track conversion helpers + `format_bytes`

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs` (add module-level free functions)

- [ ] **Step 1: Write failing tests**

Add to the test module:

```rust
    #[test]
    fn track_to_bytes_endpoints() {
        assert_eq!(track_to_bytes(0.0, 1_000_000), 0);
        assert_eq!(track_to_bytes(1.0, 1_000_000), 1_000_000);
    }

    #[test]
    fn track_to_bytes_zero_max_safe() {
        // Degenerate max — should not panic and right edge should be 0.
        assert_eq!(track_to_bytes(0.0, 0), 0);
        assert_eq!(track_to_bytes(1.0, 0), 0);
    }

    #[test]
    fn bytes_to_track_endpoints() {
        assert!((bytes_to_track(0, 1_000_000) - 0.0).abs() < 1e-9);
        assert!((bytes_to_track(1_000_000, 1_000_000) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn track_to_bytes_round_trip_samples() {
        let max = 10_000_000u64;
        for sample in [1u64, 10, 100, 1024, 1_000_000, 9_999_999] {
            let pos = bytes_to_track(sample, max);
            let back = track_to_bytes(pos, max);
            // Log round-trip; expect within ±1% or within 1 byte for tiny values.
            let tolerance = (sample as f64 * 0.01).max(1.0) as u64;
            assert!(
                back.abs_diff(sample) <= tolerance,
                "sample={sample} back={back} tol={tolerance}"
            );
        }
    }

    #[test]
    fn format_bytes_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1_500_000), "1.5 MB");
        assert_eq!(format_bytes(2_500_000_000), "2.5 GB");
    }
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `cargo test -p utmost-gui track_to_bytes --lib && cargo test -p utmost-gui bytes_to_track --lib && cargo test -p utmost-gui format_bytes --lib`
Expected: FAIL (unresolved imports).

- [ ] **Step 3: Implement helpers**

At the bottom of `crates/utmost-gui/src/view_model.rs` (before the `#[cfg(test)] mod tests` block), add:

```rust
const LOG_MIN_BYTES_F64: f64 = 1.0;

/// Convert a normalized track position in `[0.0, 1.0]` to a byte count using
/// a logarithmic mapping. Track position 0 always maps to 0 bytes; position
/// 1 maps to `max_bytes` exactly.
pub fn track_to_bytes(pos: f64, max_bytes: u64) -> u64 {
    if pos <= 0.0 || max_bytes == 0 {
        return 0;
    }
    let pos = pos.clamp(0.0, 1.0);
    if pos >= 1.0 {
        return max_bytes;
    }
    let lo = LOG_MIN_BYTES_F64.ln();
    let hi = (max_bytes.max(1) as f64).ln();
    let bytes = (lo + (hi - lo) * pos).exp();
    bytes.round() as u64
}

/// Inverse of `track_to_bytes`. Returns 0.0 for byte counts at or below 1
/// (the left edge), and 1.0 for byte counts at or above `max_bytes`.
pub fn bytes_to_track(bytes: u64, max_bytes: u64) -> f64 {
    if bytes == 0 || max_bytes <= 1 {
        return 0.0;
    }
    if bytes >= max_bytes {
        return 1.0;
    }
    let lo = LOG_MIN_BYTES_F64.ln();
    let hi = (max_bytes as f64).ln();
    ((bytes as f64).ln() - lo) / (hi - lo)
}

/// Format a byte count using decimal SI units (B, KB, MB, GB). Uses one
/// decimal place for KB and larger.
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1_000;
    const MB: u64 = 1_000_000;
    const GB: u64 = 1_000_000_000;
    if bytes < KB {
        format!("{} B", bytes)
    } else if bytes < MB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else if bytes < GB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    }
}
```

Update the test module imports — at the top of `mod tests { ... }`, add `use super::{track_to_bytes, bytes_to_track, format_bytes};` if not already covered by `use super::*;`. If `use super::*;` is present, no change needed.

Note on `format_bytes(1024)`: 1024 / 1000 = 1.024 → formatted with one decimal as `"1.0 KB"`. The test expects this exact string.

- [ ] **Step 4: Run tests, verify pass**

Run: `cargo test -p utmost-gui track_to_bytes --lib && cargo test -p utmost-gui bytes_to_track --lib && cargo test -p utmost-gui format_bytes --lib`
Expected: all PASS.

- [ ] **Step 5: Full suite + clippy + commit**

```bash
cargo test -p utmost-gui --lib
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/src/view_model.rs
git commit -m "feat(gui): add log-scale byte<->track conversion and format_bytes helpers

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 8: Create `RangeSlider` Slint component

**Files:**
- Create: `crates/utmost-gui/ui/range_slider.slint`

- [ ] **Step 1: Write the component**

Create `crates/utmost-gui/ui/range_slider.slint`:

```slint
// Two-knob range slider operating in normalized [0.0, 1.0] track space.
// Emits range-changed(lo, hi) on drag. Owns its own visual state; the caller
// owns the semantic meaning of (lo, hi).
export component RangeSlider inherits Rectangle {
    in-out property <float> lo: 0.0;
    in-out property <float> hi: 1.0;
    callback range-changed(float, float);

    property <length> knob-size: 14px;
    property <length> track-h: 4px;
    property <length> usable-w: self.width - self.knob-size;

    height: 24px;

    // Track background
    Rectangle {
        x: root.knob-size / 2;
        y: (parent.height - root.track-h) / 2;
        width: parent.width - root.knob-size;
        height: root.track-h;
        background: #444;
        border-radius: root.track-h / 2;
    }

    // Selected range (between knobs)
    Rectangle {
        x: root.knob-size / 2 + root.lo * root.usable-w;
        y: (parent.height - root.track-h) / 2;
        width: (root.hi - root.lo) * root.usable-w;
        height: root.track-h;
        background: #3a6;
        border-radius: root.track-h / 2;
    }

    // Low knob
    lo-knob := Rectangle {
        x: root.lo * root.usable-w;
        y: (parent.height - root.knob-size) / 2;
        width: root.knob-size;
        height: root.knob-size;
        background: lo-touch.has-hover || lo-touch.pressed ? #5c8 : #3a6;
        border-radius: root.knob-size / 2;

        lo-touch := TouchArea {
            width: parent.width;
            height: parent.height;
            moved => {
                if (self.pressed) {
                    // Translate pointer x within parent coordinate space.
                    // `self.mouse-x` is relative to this TouchArea's origin.
                    // The knob's left edge is at root.lo * usable-w, so the
                    // pointer's parent-x is: knob.x + self.mouse-x.
                    // We want the knob center under the pointer, so subtract
                    // knob-size/2.
                    property <length> pointer-px: parent.x + self.mouse-x - root.knob-size / 2;
                    property <float> raw: pointer-px / root.usable-w;
                    root.lo = clamp(raw, 0.0, root.hi);
                    root.range-changed(root.lo, root.hi);
                }
            }
        }
    }

    // High knob
    hi-knob := Rectangle {
        x: root.hi * root.usable-w;
        y: (parent.height - root.knob-size) / 2;
        width: root.knob-size;
        height: root.knob-size;
        background: hi-touch.has-hover || hi-touch.pressed ? #5c8 : #3a6;
        border-radius: root.knob-size / 2;

        hi-touch := TouchArea {
            width: parent.width;
            height: parent.height;
            moved => {
                if (self.pressed) {
                    property <length> pointer-px: parent.x + self.mouse-x - root.knob-size / 2;
                    property <float> raw: pointer-px / root.usable-w;
                    root.hi = clamp(raw, root.lo, 1.0);
                    root.range-changed(root.lo, root.hi);
                }
            }
        }
    }
}
```

Note: Slint syntax for declaring properties inside callback bodies uses `property` keyword (see existing `detail.slint` for `cols`/`row_count` patterns). If the compiler rejects in-callback property declarations, fall back to inline expressions — replace the body with:

```slint
                    root.lo = clamp((parent.x + self.mouse-x - root.knob-size / 2) / root.usable-w, 0.0, root.hi);
                    root.range-changed(root.lo, root.hi);
```

(Same for the hi-knob.)

- [ ] **Step 2: Wire the component into `detail.slint`**

Add an import at the top of `crates/utmost-gui/ui/detail.slint`:

```slint
import { RangeSlider } from "range_slider.slint";
```

- [ ] **Step 3: Verify compilation**

Run: `cargo build -p utmost-gui`
Expected: clean build.

- [ ] **Step 4: Commit**

```bash
git add crates/utmost-gui/ui/range_slider.slint crates/utmost-gui/ui/detail.slint
git commit -m "feat(gui): add RangeSlint two-knob range slider component

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 9: Add `Hide no-preview` pill to detail.slint top toolbar

**Files:**
- Modify: `crates/utmost-gui/ui/detail.slint` (top toolbar around line 175-207)
- Modify: `crates/utmost-gui/src/slint_adapter.rs` (callback wiring + push)

- [ ] **Step 1: Add property + callback to `DetailPage`**

In `crates/utmost-gui/ui/detail.slint` at the property declarations (around line 99-100), add:

```slint
    in-out property <bool> hide-no-preview-enabled: false;
```

And in the callbacks block (around line 116-117):

```slint
    callback hide-no-preview-toggle();
```

- [ ] **Step 2: Add the pill button in the top toolbar**

After the existing `Bookmarked` pill (around line 192-207), add another `Rectangle` pill, e.g.:

```slint
            Rectangle {
                background: root.hide-no-preview-enabled ? #cc6 : #555;
                border-radius: 12px;
                width: 150px;
                height: 28px;
                TouchArea {
                    clicked => { root.hide-no-preview-toggle(); }
                }
                Text {
                    text: "Hide no-preview";
                    color: white;
                    horizontal-alignment: center;
                    vertical-alignment: center;
                }
            }
```

- [ ] **Step 3: Wire callback in `slint_adapter.rs`**

In `crates/utmost-gui/src/slint_adapter.rs`, where the existing `on_bookmarked_filter_toggle` is registered (around line 170-175), add a sibling block:

```rust
        {
            let vm_cb = vm.clone();
            window.on_hide_no_preview_toggle(move || {
                let mut v = vm_cb.lock().unwrap();
                v.filter.hide_no_preview = !v.filter.hide_no_preview;
                v.recompute_visible();
            });
        }
```

- [ ] **Step 4: Push state in `sync()`**

In `crates/utmost-gui/src/slint_adapter.rs::sync` near the existing `set_bookmarked_filter_enabled` call (around line 644-645), add:

```rust
        self.window
            .set_hide_no_preview_enabled(vm.filter.hide_no_preview);
```

- [ ] **Step 5: Build and verify**

Run: `cargo build -p utmost-gui`
Expected: clean build.

- [ ] **Step 6: Commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/ui/detail.slint crates/utmost-gui/src/slint_adapter.rs
git commit -m "feat(gui): add Hide no-preview pill toggle to detail toolbar

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 10: Add sort controls (combo + direction + bookmarked-first) to top toolbar

**Files:**
- Modify: `crates/utmost-gui/ui/detail.slint`
- Modify: `crates/utmost-gui/src/slint_adapter.rs`

- [ ] **Step 1: Add new `DetailPage` properties and callbacks**

In `detail.slint`, add to the property block:

```slint
    in-out property <[string]> sort-key-items: ["Filename", "Size", "File type", "Source offset"];
    in-out property <int> sort-key-index: 0;
    in-out property <bool> sort-dir-asc: true;
    in-out property <bool> bookmarked-first-enabled: false;
```

And callbacks:

```slint
    callback sort-key-changed(int);
    callback sort-dir-toggle();
    callback bookmarked-first-toggle();
```

- [ ] **Step 2: Add a flexible spacer + controls in the top toolbar**

Add at the top of the file (if not already present):

```slint
import { ComboBox } from "std-widgets.slint";
```

(Check existing imports at line 1 — extend the named import list.)

After the `Hide no-preview` pill from Task 9, inside the same `HorizontalBox`, add:

```slint
            // Spacer pushes sort controls to the right.
            Rectangle { horizontal-stretch: 1; }

            ComboBox {
                model: root.sort-key-items;
                current-index: root.sort-key-index;
                selected(_) => { root.sort-key-changed(self.current-index); }
            }

            // Direction toggle button (↑ asc, ↓ desc)
            Rectangle {
                background: #555;
                border-radius: 4px;
                width: 28px;
                height: 28px;
                TouchArea {
                    clicked => { root.sort-dir-toggle(); }
                }
                Text {
                    text: root.sort-dir-asc ? "↑" : "↓";
                    color: white;
                    horizontal-alignment: center;
                    vertical-alignment: center;
                }
            }

            // Bookmarked-first modifier toggle
            Rectangle {
                background: root.bookmarked-first-enabled ? #cc6 : #555;
                border-radius: 12px;
                width: 140px;
                height: 28px;
                TouchArea {
                    clicked => { root.bookmarked-first-toggle(); }
                }
                Text {
                    text: "★ Bookmarked first";
                    color: white;
                    horizontal-alignment: center;
                    vertical-alignment: center;
                }
            }
```

- [ ] **Step 3: Wire callbacks in slint_adapter.rs**

In the same area as the `hide_no_preview_toggle` from Task 9:

```rust
        {
            let vm_cb = vm.clone();
            window.on_sort_key_changed(move |idx| {
                let mut v = vm_cb.lock().unwrap();
                v.filter.sort_key = match idx {
                    0 => crate::view_model::SortKey::Filename,
                    1 => crate::view_model::SortKey::Size,
                    2 => crate::view_model::SortKey::FileType,
                    3 => crate::view_model::SortKey::SourceOffset,
                    _ => crate::view_model::SortKey::Filename,
                };
                v.recompute_visible();
            });
        }
        {
            let vm_cb = vm.clone();
            window.on_sort_dir_toggle(move || {
                let mut v = vm_cb.lock().unwrap();
                v.filter.sort_dir = match v.filter.sort_dir {
                    crate::view_model::SortDir::Asc => crate::view_model::SortDir::Desc,
                    crate::view_model::SortDir::Desc => crate::view_model::SortDir::Asc,
                };
                v.recompute_visible();
            });
        }
        {
            let vm_cb = vm.clone();
            window.on_bookmarked_first_toggle(move || {
                let mut v = vm_cb.lock().unwrap();
                v.filter.bookmarked_first = !v.filter.bookmarked_first;
                v.recompute_visible();
            });
        }
```

- [ ] **Step 4: Push state in `sync()`**

Near the `set_hide_no_preview_enabled` line from Task 9:

```rust
        self.window.set_sort_key_index(match vm.filter.sort_key {
            crate::view_model::SortKey::Filename => 0,
            crate::view_model::SortKey::Size => 1,
            crate::view_model::SortKey::FileType => 2,
            crate::view_model::SortKey::SourceOffset => 3,
        });
        self.window.set_sort_dir_asc(matches!(
            vm.filter.sort_dir,
            crate::view_model::SortDir::Asc
        ));
        self.window
            .set_bookmarked_first_enabled(vm.filter.bookmarked_first);
```

- [ ] **Step 5: Build and verify**

Run: `cargo build -p utmost-gui`
Expected: clean build.

- [ ] **Step 6: Commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/ui/detail.slint crates/utmost-gui/src/slint_adapter.rs
git commit -m "feat(gui): add sort dropdown, direction toggle, bookmarked-first modifier

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 11: Add size slider row to detail.slint filters block

**Files:**
- Modify: `crates/utmost-gui/ui/detail.slint`
- Modify: `crates/utmost-gui/src/slint_adapter.rs`

- [ ] **Step 1: Add new properties + callback in `detail.slint`**

In the property block:

```slint
    in-out property <float> size-lo-norm: 0.0;
    in-out property <float> size-hi-norm: 1.0;
    in-out property <string> size-range-label: "";
    in-out property <string> size-max-label: "";
    in-out property <bool> size-slider-visible: false;
```

Callback:

```slint
    callback size-range-changed(float, float);
```

- [ ] **Step 2: Add the slider row in the filters block**

Inside the `if root.filters-visible: VerticalBox { ... }` block (around line 208-251), append a new conditional row after the existing sub-chip row:

```slint
            if root.size-slider-visible: VerticalBox {
                padding: 0px;
                spacing: 2px;
                HorizontalBox {
                    padding: 0px;
                    Text {
                        text: "Size:";
                        color: white;
                        vertical-alignment: center;
                    }
                    Rectangle { horizontal-stretch: 1; }
                    Text {
                        text: root.size-range-label;
                        color: #aaa;
                        vertical-alignment: center;
                    }
                }
                RangeSlider {
                    lo: root.size-lo-norm;
                    hi: root.size-hi-norm;
                    range-changed(lo, hi) => {
                        root.size-lo-norm = lo;
                        root.size-hi-norm = hi;
                        root.size-range-changed(lo, hi);
                    }
                }
                HorizontalBox {
                    padding: 0px;
                    Text {
                        text: "0 B";
                        color: #777;
                        font-size: 10px;
                    }
                    Rectangle { horizontal-stretch: 1; }
                    Text {
                        text: root.size-max-label;
                        color: #777;
                        font-size: 10px;
                    }
                }
            }
```

- [ ] **Step 3: Wire callback in `slint_adapter.rs`**

In the same area as the other new toggles:

```rust
        {
            let vm_cb = vm.clone();
            window.on_size_range_changed(move |lo_norm, hi_norm| {
                let mut v = vm_cb.lock().unwrap();
                let max_bytes = v.size_filter_max();
                if max_bytes == 0 {
                    v.filter.size_range = None;
                    v.recompute_visible();
                    return;
                }
                let lo = crate::view_model::track_to_bytes(lo_norm as f64, max_bytes);
                let hi = crate::view_model::track_to_bytes(hi_norm as f64, max_bytes);
                // If both knobs are at the extremes, treat as "untouched".
                if lo == 0 && hi == max_bytes {
                    v.filter.size_range = None;
                } else {
                    v.filter.size_range = Some((lo, hi));
                }
                v.recompute_visible();
            });
        }
```

- [ ] **Step 4: Push state in `sync()`**

Compute size-max once at the start of the slider section. Near the other set_* calls for sort/hide-no-preview, add:

```rust
        let size_max = vm.size_filter_max();
        self.window.set_size_slider_visible(size_max > 0);
        if size_max > 0 {
            let (lo_b, hi_b) = vm.filter.size_range.unwrap_or((0, size_max));
            let lo_norm = crate::view_model::bytes_to_track(lo_b, size_max) as f32;
            let hi_norm = crate::view_model::bytes_to_track(hi_b, size_max) as f32;
            self.window.set_size_lo_norm(lo_norm);
            self.window.set_size_hi_norm(hi_norm);
            let range_label = format!(
                "{} — {}",
                crate::view_model::format_bytes(lo_b),
                crate::view_model::format_bytes(hi_b)
            );
            self.window
                .set_size_range_label(slint::SharedString::from(range_label));
            self.window
                .set_size_max_label(slint::SharedString::from(crate::view_model::format_bytes(
                    size_max,
                )));
        } else {
            self.window.set_size_lo_norm(0.0);
            self.window.set_size_hi_norm(1.0);
            self.window
                .set_size_range_label(slint::SharedString::from(""));
            self.window
                .set_size_max_label(slint::SharedString::from(""));
        }
```

- [ ] **Step 5: Build and verify**

Run: `cargo build -p utmost-gui`
Expected: clean build.

- [ ] **Step 6: Commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/ui/detail.slint crates/utmost-gui/src/slint_adapter.rs
git commit -m "feat(gui): add log-scale size range slider to filters block

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 12: Wire `ThumbWorker::on_complete` → `vm.set_thumbnail_ready`

**Files:**
- Modify: `crates/utmost-gui/src/slint_adapter.rs` (around line 92-95)

- [ ] **Step 1: Replace the no-op on_complete**

Find the existing block in `slint_adapter.rs` (around line 92-95):

```rust
        // No-op completion callback: the periodic re-sync timer (Task 34)
        // will pick up newly-cached thumbnails on the next tick.
        let on_complete: Arc<dyn Fn(crate::view_model::FileId) + Send + Sync> = Arc::new(|_id| {});
        let thumbs = ThumbWorker::start(registry.clone(), resolver.clone(), 256, 2, on_complete);
```

Replace with:

```rust
        let vm_for_thumbs = vm.clone();
        let on_complete: Arc<dyn Fn(crate::view_model::FileId) + Send + Sync> =
            Arc::new(move |id| {
                let mut v = vm_for_thumbs.lock().unwrap();
                v.set_thumbnail_ready(id, true);
                // Only recompute when the hide_no_preview filter is engaged —
                // skipping this for the common case avoids redundant work.
                if v.filter.hide_no_preview {
                    v.recompute_visible();
                }
            });
        let thumbs = ThumbWorker::start(registry.clone(), resolver.clone(), 256, 2, on_complete);
```

- [ ] **Step 2: Build and verify**

Run: `cargo build -p utmost-gui`
Expected: clean build.

- [ ] **Step 3: Run tests**

Run: `cargo test -p utmost-gui`
Expected: all PASS.

- [ ] **Step 4: Format + clippy + commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/src/slint_adapter.rs
git commit -m "feat(gui): notify view model when thumbnails finish decoding

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 13: Clamp `size_range` on every `sync()` to handle max changes

**Files:**
- Modify: `crates/utmost-gui/src/slint_adapter.rs::sync`

**Why:** When other filters change the size-filter-max (e.g. toggling a chip), an existing `Some((lo, hi))` may now exceed the new max. The sync push needs to clamp before computing norms or labels so the slider stays consistent. Without this, knobs render past the right edge or get stuck.

- [ ] **Step 1: Change `sync` to accept `&mut ViewModel`**

Update the signature in `slint_adapter.rs` (around line 577):

```rust
    pub fn sync(&self, vm: &mut ViewModel) {
```

Update the callers in `crates/utmost-gui/src/lib.rs`:

```rust
        let mut v = vm.lock().unwrap();
        ui.sync(&mut v);
```

(Two call sites — lines 111-112 and 132-133. The second is inside the timer closure; `vm_for_timer.lock().unwrap()` already gives a `MutexGuard<ViewModel>`, just bind it as `let mut v = ...`.)

- [ ] **Step 2: Call clamp at the start of the slider section**

Before computing `size_max` in the slider section added in Task 11, insert:

```rust
        let size_max = vm.size_filter_max();
        vm.clamp_size_range_to(size_max);
```

The rest of the block continues with `size_max` as before.

- [ ] **Step 3: Build and verify**

Run: `cargo build -p utmost-gui && cargo test -p utmost-gui`
Expected: clean build and all tests PASS.

- [ ] **Step 4: Format + clippy + commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/src/slint_adapter.rs crates/utmost-gui/src/lib.rs
git commit -m "fix(gui): clamp size_range on sync to track filter-max changes

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 14: Manual UX pass + verification

**Files:** None (testing only)

- [ ] **Step 1: Run the GUI against a real run output**

Run: `cargo run -p utmost-gui --release -- <path/to/output/dir>`

(Use any prior carve output. If none, run a quick carve first: `cargo run -p utmost-cli -- -t jpeg,pdf <small image>` to produce `out/carve_events.bin`, then point the GUI at `out/`.)

- [ ] **Step 2: Exercise each new control**

  - Toggle "Hide no-preview". Tiles without thumbnails disappear/reappear.
  - Open the sort dropdown. Pick each option in turn; verify visible order.
  - Click the direction arrow. Order reverses; arrow flips between ↑ and ↓.
  - Toggle "Bookmarked first". With at least one bookmark set, the bookmark pins to top regardless of direction.
  - Drag the size slider's left and right knobs. Range label updates live.
  - Toggle chip filters; verify the slider's max relabels and the range clamps if needed.
  - Collapse filters with "Hide filters"; verify the slider hides but its filter stays in effect (visible tile count unchanged).

- [ ] **Step 3: Note any rough edges + fix**

If any of the following occur, fix and commit before completing the task:
- Knobs drift past the track edge when window resizes
- Range label format incorrect for sub-1KB sizes
- ComboBox doesn't fire `selected()` on first selection (Slint quirk — may need `current-index-changed` instead)
- Hover feedback missing on direction button

- [ ] **Step 4: Run lint and test gates**

Run: `cargo fmt && cargo clippy --all-targets && cargo test -p utmost-gui`
Expected: clean.

- [ ] **Step 5: Commit any UX fixes**

If fixes made:

```bash
git add -A
git commit -m "polish(gui): UX cleanup for new filter controls

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

If no fixes needed, skip the commit.

---

## Spec coverage check

- ✅ Sort keys: Filename / Size (existing) + FileType / SourceOffset (Tasks 1–2)
- ✅ Direction toggle with arrow (Task 10)
- ✅ Bookmarked-first modifier (Task 3 logic; Task 10 UI)
- ✅ Hide-no-preview pill in top toolbar (Tasks 4, 9, 12)
- ✅ Size-range filter with log-scale slider (Tasks 5, 7, 8, 11)
- ✅ Dynamic max with clamping (Tasks 6, 13)
- ✅ Range labels + endpoint labels (Tasks 7, 11)
- ✅ Slider hidden when filtered set empty (Task 11 — `set_size_slider_visible`)
- ✅ Slider hides with filters block but state persists (Task 11 — placed inside `if filters-visible`)
- ✅ Tests cover every view-model behavior (Tasks 1–7)
- ✅ Non-goals (no persistence, no keyboard shortcuts, no animation): nothing to implement
