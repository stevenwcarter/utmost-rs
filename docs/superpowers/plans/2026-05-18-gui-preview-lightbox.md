# Detail-Panel Large Preview & Lightbox Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Every task is TDD: write failing test → run to verify fail → minimal impl → run to verify pass → commit. The pre-commit hook runs `cargo fmt` + `cargo clippy --all-targets` and rejects on any warning.

**Goal:** Add a larger preview at the top of the detail-page side panel, plus a full-screen lightbox viewer that follows the grid sort order, supports zoom controls, and is designed from day one as a generic preview viewer (image now; text/icon already wired).

**Architecture:** All state additions live in the pure-Rust `ViewModel` (lightbox open/closed, zoom, fit) and are exercised by unit tests with no Slint dependency. The `PreviewRegistry` gains a `render_full` method with a default that delegates to `render`; `JpegPreview` overrides it to decode at native resolution. A new `LargePreview` Slint sub-component renders any `PreviewOutput` variant and is reused by the side panel and the lightbox. A new `ui/lightbox.slint` overlay z-stacks over `DetailPage` so the grid is never torn down on open/close. Three close gestures (X button, click empty grid, ESC) clear the selection; ESC has a two-level behaviour — closes the lightbox first, then on the second press closes the side panel.

**Tech Stack:** Rust (workspace), Slint 1.16, `image` crate, `anyhow`, existing `utmost-lib` types.

**Spec:** `docs/superpowers/specs/2026-05-18-gui-preview-lightbox-design.md`

---

## File Structure

**Modified:**

- `crates/utmost-gui/src/view_model.rs` — `LightboxView`, `lightbox` field, eight new methods, ~12 new unit tests
- `crates/utmost-gui/src/preview/mod.rs` — `PreviewOutput::Text(String)` variant, `render_full` trait method, `PreviewRegistry::render_full_for`
- `crates/utmost-gui/src/preview/jpeg.rs` — override `render_full` for native-resolution decode
- `crates/utmost-gui/src/preview/generic.rs` — no override needed (inherits default)
- `crates/utmost-gui/src/slint_adapter.rs` — new callback bindings, full-res image cache, sync extension for lightbox properties
- `crates/utmost-gui/ui/detail.slint` — `LargePreview` sub-component, side-panel header (filename + X), `large-preview-clicked` callback, empty-grid TouchArea, `tile-double-clicked` + `tile-enter-pressed` callbacks
- `crates/utmost-gui/ui/main.slint` — lightbox-related in/out properties, MainWindow-level callbacks, lightbox z-stack
- `crates/utmost-gui/tests/jpeg_preview.rs` — extend with `render_full` test
- `crates/utmost-gui/tests/replay_snapshot.rs` — extend with select → open lightbox → arrow nav → ESC scenario

**Created:**

- `crates/utmost-gui/ui/lightbox.slint` — `Lightbox` overlay component (TopBar, body, side arrows, BottomBar with zoom controls, FocusScope for keyboard)

---

## Phase A — Preview pipeline extension

### Task 1: Add `PreviewOutput::Text` variant + `render_full` trait method

**Files:**
- Modify: `crates/utmost-gui/src/preview/mod.rs`
- Test: `crates/utmost-gui/src/preview/mod.rs` (inline `#[cfg(test)]`)

- [ ] **Step 1: Add the failing test**

Append to the existing `#[cfg(test)] mod tests` block at the bottom of `crates/utmost-gui/src/preview/mod.rs`:

```rust
    #[test]
    fn default_render_full_delegates_to_render() {
        // GenericIcon does not override render_full; calling it must
        // produce the same Icon output as render() does.
        let reg = PreviewRegistry::with_defaults();
        let f = dummy_file(FileType::Pdf);
        let normal = reg
            .render_for(FileType::Pdf, std::path::Path::new("/x"), &f)
            .unwrap();
        let full = reg
            .render_full_for(FileType::Pdf, std::path::Path::new("/x"), &f)
            .unwrap();
        match (normal, full) {
            (PreviewOutput::Icon(a), PreviewOutput::Icon(b)) => assert_eq!(a, b),
            other => panic!("expected matching Icon outputs, got {other:?}"),
        }
    }

    #[test]
    fn preview_output_has_text_variant() {
        // Compile-time check that the Text variant exists.
        let _t = PreviewOutput::Text("hello".to_string());
    }
```

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test -p utmost-gui --lib preview::tests`
Expected: compile error — `render_full_for` not defined; `PreviewOutput::Text` not defined.

- [ ] **Step 3: Implement the additions**

In `crates/utmost-gui/src/preview/mod.rs`:

Change `PreviewOutput` to add the new variant:

```rust
#[derive(Debug, Clone)]
pub enum PreviewOutput {
    Image(image::RgbaImage),
    Text(String),
    HexDump(String),
    Icon(IconKind),
}
```

Change the `PreviewRenderer` trait — add a defaulted `render_full`:

```rust
pub trait PreviewRenderer: Send + Sync {
    fn supports(&self, file_type: FileType) -> bool;
    fn render(&self, path: &Path, file: &FoundFile) -> Result<PreviewOutput>;
    /// Higher-resolution rendering used by the side panel large preview and
    /// the lightbox. The default delegates to `render`; renderers that
    /// produce a downscaled thumbnail in `render` should override this to
    /// decode at native resolution.
    fn render_full(&self, path: &Path, file: &FoundFile) -> Result<PreviewOutput> {
        self.render(path, file)
    }
    fn render_side_panel_metadata(&self, file: &FoundFile) -> Vec<(String, String)>;
}
```

In `impl PreviewRegistry`, add the new lookup method right below `render_for`:

```rust
    pub fn render_full_for(
        &self,
        file_type: FileType,
        path: &Path,
        file: &FoundFile,
    ) -> Result<PreviewOutput> {
        for r in &self.renderers {
            if r.supports(file_type) {
                return r.render_full(path, file);
            }
        }
        anyhow::bail!("no renderer for {file_type:?}")
    }
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test -p utmost-gui --lib preview::tests`
Expected: all preview tests pass.

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/src/preview/mod.rs
git commit -m "feat(gui): add PreviewOutput::Text and PreviewRenderer::render_full"
```

---

### Task 2: Override `JpegPreview::render_full` for native-resolution decode

**Files:**
- Modify: `crates/utmost-gui/src/preview/jpeg.rs`
- Modify: `crates/utmost-gui/tests/jpeg_preview.rs`

- [ ] **Step 1: Add the failing test**

In `crates/utmost-gui/tests/jpeg_preview.rs`, append after the existing test:

```rust
#[test]
fn jpeg_preview_render_full_returns_native_resolution() {
    use image::{Rgb, RgbImage};
    use std::path::Path;

    let tmp = tempfile::tempdir().unwrap();
    // Source image is 400x300 — larger than the 256 thumbnail cap.
    let src = tmp.path().join("big.jpg");
    let mut img = RgbImage::new(400, 300);
    for px in img.pixels_mut() {
        *px = Rgb([0, 128, 255]);
    }
    img.save(&src).unwrap();

    let file = FoundFile {
        id: 0,
        source_id: 0,
        file: create_file_object(
            "big.jpg",
            FileType::Jpeg,
            10_000,
            0,
            Some(JpegScanInfo {
                width: Some(400),
                height: Some(300),
                fragmentation_point_img_offset: None,
                has_restart_markers: false,
                status: JpegScanStatus::Complete,
            }),
        ),
        written_path: src.clone(),
        img_offset: 0,
    };

    let reg = PreviewRegistry::with_defaults_and_jpeg();
    let thumb = reg.render_for(FileType::Jpeg, &src, &file).unwrap();
    let full = reg.render_full_for(FileType::Jpeg, &src, &file).unwrap();

    let (tw, th) = match thumb {
        PreviewOutput::Image(i) => (i.width(), i.height()),
        other => panic!("expected thumbnail Image, got {other:?}"),
    };
    let (fw, fh) = match full {
        PreviewOutput::Image(i) => (i.width(), i.height()),
        other => panic!("expected full-res Image, got {other:?}"),
    };

    // Thumbnail is capped at MAX_EDGE = 256; full must be larger than that
    // along the long edge.
    assert!(tw <= 256 && th <= 256, "thumbnail not within 256px cap: {tw}x{th}");
    assert!(fw > 256 || fh > 256, "full-res not larger than thumbnail cap: {fw}x{fh}");
    // Defensive: full-res shouldn't be smaller than thumbnail in either dim.
    assert!(fw >= tw && fh >= th);

    let _ = Path::new(""); // suppress unused-import warning if Path winds up unused
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p utmost-gui --test jpeg_preview jpeg_preview_render_full_returns_native_resolution`
Expected: test fails — `render_full` currently delegates to `render`, so full and thumbnail are both ≤256px.

- [ ] **Step 3: Implement `render_full` on `JpegPreview`**

Edit `crates/utmost-gui/src/preview/jpeg.rs` and add a `render_full` method inside `impl PreviewRenderer for JpegPreview`, after the existing `render` method:

```rust
    fn render_full(&self, path: &Path, _file: &FoundFile) -> Result<PreviewOutput> {
        let img = ImageReader::open(path)
            .with_context(|| format!("open {}", path.display()))?
            .with_guessed_format()?
            .decode()
            .with_context(|| format!("decode {}", path.display()))?;
        Ok(PreviewOutput::Image(img.to_rgba8()))
    }
```

- [ ] **Step 4: Run test to verify pass**

Run: `cargo test -p utmost-gui --test jpeg_preview`
Expected: both jpeg preview tests pass.

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/src/preview/jpeg.rs crates/utmost-gui/tests/jpeg_preview.rs
git commit -m "feat(gui): JpegPreview.render_full decodes at native resolution"
```

---

## Phase B — ViewModel lightbox state

### Task 3: Add `LightboxView` struct + `lightbox` field

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs`

- [ ] **Step 1: Add the failing test**

Inside the `#[cfg(test)] mod tests` block at the bottom of `crates/utmost-gui/src/view_model.rs`, append:

```rust
    #[test]
    fn new_view_model_has_lightbox_closed() {
        let vm = ViewModel::new();
        assert!(vm.lightbox.is_none());
        assert!(vm.lightbox_view.fit);
        assert!((vm.lightbox_view.zoom - 1.0).abs() < f32::EPSILON);
    }
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p utmost-gui --lib view_model::tests::new_view_model_has_lightbox_closed`
Expected: compile error — `lightbox`, `lightbox_view`, and `LightboxView` not defined.

- [ ] **Step 3: Add the struct and field**

Edit `crates/utmost-gui/src/view_model.rs`. Add a new struct above `pub struct ViewModel`:

```rust
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LightboxView {
    pub zoom: f32,
    pub fit: bool,
}

impl Default for LightboxView {
    fn default() -> Self {
        Self { zoom: 1.0, fit: true }
    }
}
```

Extend `pub struct ViewModel` to add two new fields (keep the existing `#[derive(Debug, Default, Clone)]` — `LightboxView::Default` is defined above and `Option<FileId>` is already `Default`):

```rust
pub struct ViewModel {
    pub run: RunSummary,
    pub sources: Vec<SourceRow>,
    pub files: Vec<FoundFile>,
    pub type_counts: BTreeMap<FileType, u64>,
    pub filter: FilterState,
    pub selection: Option<FileId>,
    pub visible_files: Vec<FileId>,
    pub lightbox: Option<FileId>,
    pub lightbox_view: LightboxView,
    next_file_id: FileId,
}
```

- [ ] **Step 4: Run test to verify pass**

Run: `cargo test -p utmost-gui --lib view_model::tests::new_view_model_has_lightbox_closed`
Expected: pass.

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/src/view_model.rs
git commit -m "feat(gui): add LightboxView state to ViewModel"
```

---

### Task 4: Add `open_lightbox` / `close_lightbox`

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs`

- [ ] **Step 1: Add the failing tests**

Append inside the `#[cfg(test)] mod tests` block:

```rust
    #[test]
    fn open_lightbox_uses_current_selection() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        vm.recompute_visible();
        let id = vm.visible_files[0];
        vm.selection = Some(id);
        vm.open_lightbox();
        assert_eq!(vm.lightbox, Some(id));
        // Fit/zoom reset on open.
        assert!(vm.lightbox_view.fit);
        assert!((vm.lightbox_view.zoom - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn open_lightbox_noop_without_selection() {
        let mut vm = ViewModel::new();
        vm.selection = None;
        vm.open_lightbox();
        assert!(vm.lightbox.is_none());
    }

    #[test]
    fn close_lightbox_clears_lightbox_keeps_selection() {
        let mut vm = ViewModel::new();
        vm.selection = Some(7);
        vm.lightbox = Some(7);
        vm.close_lightbox();
        assert_eq!(vm.selection, Some(7));
        assert!(vm.lightbox.is_none());
    }
```

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test -p utmost-gui --lib view_model::tests::open_lightbox`
Expected: compile error — `open_lightbox` and `close_lightbox` not defined.

- [ ] **Step 3: Implement the methods**

Inside `impl ViewModel`, append:

```rust
    pub fn open_lightbox(&mut self) {
        if let Some(id) = self.selection {
            self.lightbox = Some(id);
            self.lightbox_view = LightboxView::default();
        }
    }

    pub fn close_lightbox(&mut self) {
        self.lightbox = None;
    }
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test -p utmost-gui --lib view_model::tests`
Expected: all view_model tests pass.

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/src/view_model.rs
git commit -m "feat(gui): open_lightbox/close_lightbox on ViewModel"
```

---

### Task 5: Add `lightbox_next` / `lightbox_prev` with wrap-around

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs`

- [ ] **Step 1: Add the failing tests**

Append inside the `#[cfg(test)] mod tests` block:

```rust
    #[test]
    fn lightbox_next_wraps_at_end() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 0, "b.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 0, "c.jpg", FileType::Jpeg, 1);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.recompute_visible();
        let ids = vm.visible_files.clone();
        vm.selection = Some(ids[2]);
        vm.open_lightbox();
        vm.lightbox_next();
        assert_eq!(vm.lightbox, Some(ids[0])); // wrapped
    }

    #[test]
    fn lightbox_prev_wraps_at_start() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 0, "b.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 0, "c.jpg", FileType::Jpeg, 1);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.recompute_visible();
        let ids = vm.visible_files.clone();
        vm.selection = Some(ids[0]);
        vm.open_lightbox();
        vm.lightbox_prev();
        assert_eq!(vm.lightbox, Some(ids[2])); // wrapped to end
    }

    #[test]
    fn lightbox_next_on_empty_visible_is_noop() {
        let mut vm = ViewModel::new();
        // No files added; visible_files is empty.
        vm.lightbox = None;
        vm.lightbox_next();
        assert!(vm.lightbox.is_none());
    }

    #[test]
    fn lightbox_next_resets_zoom_to_fit() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 0, "b.jpg", FileType::Jpeg, 1);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.recompute_visible();
        let ids = vm.visible_files.clone();
        vm.selection = Some(ids[0]);
        vm.open_lightbox();
        vm.lightbox_view.fit = false;
        vm.lightbox_view.zoom = 2.5;
        vm.lightbox_next();
        assert!(vm.lightbox_view.fit);
        assert!((vm.lightbox_view.zoom - 1.0).abs() < f32::EPSILON);
    }
```

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test -p utmost-gui --lib view_model::tests::lightbox_next`
Expected: compile error — `lightbox_next`, `lightbox_prev` not defined.

- [ ] **Step 3: Implement the methods**

Append inside `impl ViewModel`:

```rust
    pub fn lightbox_next(&mut self) {
        self.lightbox_step(1);
    }

    pub fn lightbox_prev(&mut self) {
        self.lightbox_step(-1);
    }

    fn lightbox_step(&mut self, delta: isize) {
        let Some(cur) = self.lightbox else { return };
        let n = self.visible_files.len();
        if n == 0 {
            return;
        }
        let Some(idx) = self.visible_files.iter().position(|id| *id == cur) else {
            return;
        };
        let next_idx = ((idx as isize + delta).rem_euclid(n as isize)) as usize;
        self.lightbox = Some(self.visible_files[next_idx]);
        self.lightbox_view = LightboxView::default();
    }
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test -p utmost-gui --lib view_model::tests`
Expected: all view_model tests pass.

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/src/view_model.rs
git commit -m "feat(gui): lightbox_next/prev with wrap-around in visible_files"
```

---

### Task 6: Add `deselect` and `close_or_deselect`

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs`

- [ ] **Step 1: Add the failing tests**

Append inside the `#[cfg(test)] mod tests` block:

```rust
    #[test]
    fn deselect_clears_selection_and_lightbox() {
        let mut vm = ViewModel::new();
        vm.selection = Some(3);
        vm.lightbox = Some(3);
        vm.deselect();
        assert!(vm.selection.is_none());
        assert!(vm.lightbox.is_none());
    }

    #[test]
    fn close_or_deselect_closes_lightbox_first() {
        let mut vm = ViewModel::new();
        vm.selection = Some(3);
        vm.lightbox = Some(3);
        vm.close_or_deselect();
        // Lightbox closed, selection kept.
        assert_eq!(vm.selection, Some(3));
        assert!(vm.lightbox.is_none());
        // Second press clears selection.
        vm.close_or_deselect();
        assert!(vm.selection.is_none());
        assert!(vm.lightbox.is_none());
    }

    #[test]
    fn close_or_deselect_with_nothing_is_noop() {
        let mut vm = ViewModel::new();
        vm.close_or_deselect();
        assert!(vm.selection.is_none());
        assert!(vm.lightbox.is_none());
    }
```

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test -p utmost-gui --lib view_model::tests::deselect view_model::tests::close_or_deselect`
Expected: compile error — `deselect`, `close_or_deselect` not defined.

- [ ] **Step 3: Implement the methods**

Append inside `impl ViewModel`:

```rust
    pub fn deselect(&mut self) {
        self.selection = None;
        self.lightbox = None;
    }

    pub fn close_or_deselect(&mut self) {
        if self.lightbox.is_some() {
            self.lightbox = None;
        } else {
            self.selection = None;
        }
    }
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test -p utmost-gui --lib view_model::tests`
Expected: all view_model tests pass.

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/src/view_model.rs
git commit -m "feat(gui): deselect + close_or_deselect (ESC two-level behaviour)"
```

---

### Task 7: Add `zoom_set` and `zoom_fit`

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs`

- [ ] **Step 1: Add the failing tests**

Append inside the `#[cfg(test)] mod tests` block:

```rust
    #[test]
    fn zoom_set_clamps_and_disables_fit() {
        let mut vm = ViewModel::new();
        vm.zoom_set(2.0);
        assert!((vm.lightbox_view.zoom - 2.0).abs() < f32::EPSILON);
        assert!(!vm.lightbox_view.fit);

        // Below 0.1 clamps to 0.1.
        vm.zoom_set(0.05);
        assert!((vm.lightbox_view.zoom - 0.1).abs() < f32::EPSILON);

        // Above 8.0 clamps to 8.0.
        vm.zoom_set(20.0);
        assert!((vm.lightbox_view.zoom - 8.0).abs() < f32::EPSILON);
    }

    #[test]
    fn zoom_fit_flips_fit_on_and_resets_zoom() {
        let mut vm = ViewModel::new();
        vm.lightbox_view.fit = false;
        vm.lightbox_view.zoom = 3.0;
        vm.zoom_fit();
        assert!(vm.lightbox_view.fit);
        assert!((vm.lightbox_view.zoom - 1.0).abs() < f32::EPSILON);
    }
```

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test -p utmost-gui --lib view_model::tests::zoom`
Expected: compile error — `zoom_set`, `zoom_fit` not defined.

- [ ] **Step 3: Implement the methods**

Append inside `impl ViewModel`:

```rust
    pub fn zoom_set(&mut self, z: f32) {
        self.lightbox_view.zoom = z.clamp(0.1, 8.0);
        self.lightbox_view.fit = false;
    }

    pub fn zoom_fit(&mut self) {
        self.lightbox_view = LightboxView::default();
    }
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test -p utmost-gui --lib view_model::tests`
Expected: all view_model tests pass.

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/src/view_model.rs
git commit -m "feat(gui): zoom_set (clamped) + zoom_fit on ViewModel"
```

---

### Task 8: Replay-style integration test for lightbox navigation

**Files:**
- Modify: `crates/utmost-gui/tests/replay_snapshot.rs`

- [ ] **Step 1: Add the failing test**

Append to `crates/utmost-gui/tests/replay_snapshot.rs`:

```rust
#[test]
fn lightbox_select_open_navigate_esc_sequence() {
    use utmost_gui::view_model::ViewModel;

    let mut vm = ViewModel::new();

    // Synthesize a single-source run with three JPEGs.
    let run = CarveEvent::RunStarted {
        utmost_version: "t".into(),
        format_version: CURRENT_FORMAT_VERSION,
        started_at: "t".into(),
        command_line: vec![],
        working_directory: "/".into(),
        execution_environment: empty_env(),
        cli_config: empty_cli(),
        case: None,
        configured_types: vec![FileType::Jpeg],
        sources: vec![SourceDescriptor {
            source_id: 0,
            filename: "src.bin".into(),
            total_bytes: 1000,
            output_subdir: String::new(),
        }],
        output_root: "out".into(),
    };
    vm.apply(&run);
    for name in ["a.jpg", "b.jpg", "c.jpg"] {
        vm.apply(&CarveEvent::FileFound {
            source_id: 0,
            file: create_file_object(name, FileType::Jpeg, 1024, 0, None),
            img_offset: 0,
            written_path: name.into(),
        });
    }
    vm.recompute_visible();
    let ids = vm.visible_files.clone();
    assert_eq!(ids.len(), 3);

    // 1) Click first tile.
    vm.selection = Some(ids[0]);
    assert!(vm.lightbox.is_none());

    // 2) Open lightbox via the side panel large preview.
    vm.open_lightbox();
    assert_eq!(vm.lightbox, Some(ids[0]));

    // 3) Right arrow twice.
    vm.lightbox_next();
    assert_eq!(vm.lightbox, Some(ids[1]));
    vm.lightbox_next();
    assert_eq!(vm.lightbox, Some(ids[2]));

    // 4) ESC closes lightbox; selection is preserved.
    vm.close_or_deselect();
    assert!(vm.lightbox.is_none());
    assert_eq!(vm.selection, Some(ids[0]));

    // 5) ESC again clears the side panel.
    vm.close_or_deselect();
    assert!(vm.selection.is_none());
}
```

- [ ] **Step 2: Run test to verify pass**

Run: `cargo test -p utmost-gui --test replay_snapshot`
Expected: the new test passes (Phase B already implemented all the required methods).

- [ ] **Step 3: Commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/tests/replay_snapshot.rs
git commit -m "test(gui): integration test for lightbox open/navigate/ESC"
```

---

## Phase C — Slint UI: side panel + close gestures

> Slint UI tasks below cannot be strictly TDD because there's no built-in way to assert against the Slint tree without rendering. Each task pairs the Slint edit with an adapter change whose effect IS observable via the existing `ViewModel` state pattern. After each task, build with `cargo build -p utmost-gui` and run the full suite with `cargo test -p utmost-gui` to catch syntax errors and regressions.

### Task 9: Extract `LargePreview` sub-component in `detail.slint`

**Files:**
- Modify: `crates/utmost-gui/ui/detail.slint`

- [ ] **Step 1: Add a sub-component above `DetailPage`**

Edit `crates/utmost-gui/ui/detail.slint`. After the `MetadataRow` struct and before `export component DetailPage`, insert:

```slint
export component LargePreview inherits Rectangle {
    in property <bool> has-image: false;
    in property <image> source-image;
    in property <string> caption: "";

    background: #0a0a0a;
    border-color: #2a2a2a;
    border-width: 1px;

    if root.has-image: Image {
        source: root.source-image;
        width: parent.width - 8px;
        height: parent.height - 8px;
        x: 4px;
        y: 4px;
        image-fit: contain;
    }

    if !root.has-image: Text {
        text: root.caption;
        color: #888;
        horizontal-alignment: center;
        vertical-alignment: center;
        width: parent.width;
        height: parent.height;
    }
}
```

- [ ] **Step 2: Verify the workspace still builds**

Run: `cargo build -p utmost-gui`
Expected: clean build.

- [ ] **Step 3: Commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/ui/detail.slint
git commit -m "feat(gui): add LargePreview sub-component to detail.slint"
```

---

### Task 10: Wire the `LargePreview` into the side panel + add side-panel close X

**Files:**
- Modify: `crates/utmost-gui/ui/detail.slint`
- Modify: `crates/utmost-gui/src/slint_adapter.rs`

- [ ] **Step 1: Add new properties + callbacks to `DetailPage`**

Edit `crates/utmost-gui/ui/detail.slint`. In `export component DetailPage`, add new `in-out` properties below `selected-filename`:

```slint
    in-out property <bool> selected-has-preview: false;
    in-out property <image> selected-preview;

    callback large-preview-clicked();
    callback side-panel-close();
```

- [ ] **Step 2: Modify the side panel to host `LargePreview` + X button**

In `detail.slint`, replace the existing `if root.side-panel-open: Rectangle { ... }` block with:

```slint
            if root.side-panel-open: Rectangle {
                background: #1e1e1e;
                width: 280px;
                VerticalBox {
                    HorizontalBox {
                        Text {
                            text: root.selected-filename;
                            font-size: 16px;
                            color: white;
                            horizontal-stretch: 1;
                        }
                        close_touch := TouchArea {
                            width: 24px;
                            height: 24px;
                            clicked => {
                                root.side-panel-close();
                            }
                            Rectangle {
                                background: close_touch.has-hover ? #444 : #333;
                                border-radius: 12px;
                                width: parent.width;
                                height: parent.height;
                                Text {
                                    text: "×";
                                    color: white;
                                    horizontal-alignment: center;
                                    vertical-alignment: center;
                                    font-size: 16px;
                                }
                            }
                        }
                    }
                    preview_touch := TouchArea {
                        height: 240px;
                        clicked => {
                            root.large-preview-clicked();
                        }
                        LargePreview {
                            width: parent.width;
                            height: parent.height;
                            has-image: root.selected-has-preview;
                            source-image: root.selected-preview;
                            caption: root.selected-has-preview ? "" : "(no preview)";
                        }
                    }
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
                }
            }
```

- [ ] **Step 3: Bubble the new callbacks up through `MainWindow`**

Edit `crates/utmost-gui/ui/main.slint`. In `export component MainWindow`, add below the existing properties:

```slint
    in-out property <bool> selected-has-preview: false;
    in-out property <image> selected-preview;

    callback large-preview-clicked();
    callback side-panel-close();
```

In the same file, inside the `DetailPage { ... }` instantiation, add:

```slint
            selected-has-preview: root.selected-has-preview;
            selected-preview: root.selected-preview;
            large-preview-clicked => {
                root.large-preview-clicked();
            }
            side-panel-close => {
                root.side-panel-close();
            }
```

- [ ] **Step 4: Wire callbacks in the adapter**

Edit `crates/utmost-gui/src/slint_adapter.rs`. Inside `UiState::new`, after the existing `on_back_clicked` block, append:

```rust
        {
            let vm_cb = vm.clone();
            window.on_side_panel_close(move || {
                let mut v = vm_cb.lock().unwrap();
                v.deselect();
            });
        }
        {
            let vm_cb = vm.clone();
            window.on_large_preview_clicked(move || {
                let mut v = vm_cb.lock().unwrap();
                v.open_lightbox();
            });
        }
```

- [ ] **Step 5: Add the full-resolution image cache + sync the preview properties**

In `slint_adapter.rs`, extend `pub struct UiState` to add a second cache field (next to `image_cache`):

```rust
    image_cache_full: RefCell<HashMap<FileId, slint::Image>>,
```

In `UiState::new`, change the returned struct literal to include the new field:

```rust
        Ok(Self {
            window,
            sources_model,
            chips_model,
            tiles_model,
            metadata_model,
            registry,
            thumbs,
            image_cache: RefCell::new(HashMap::new()),
            image_cache_full: RefCell::new(HashMap::new()),
        })
```

In the `sync()` method, replace the entire `if let Some(sel_id) = vm.selection ...` block with this version that also publishes the large preview:

```rust
        if let Some(sel_id) = vm.selection
            && let Some(f) = vm.files.iter().find(|f| f.id == sel_id)
        {
            let mut rows: Vec<MetadataRow> = Vec::new();
            rows.push(MetadataRow {
                key: SharedString::from("Filename"),
                value: SharedString::from(f.file.filename.as_str()),
            });
            rows.push(MetadataRow {
                key: SharedString::from("Size"),
                value: SharedString::from(format!("{} B", f.file.filesize)),
            });
            rows.push(MetadataRow {
                key: SharedString::from("Path"),
                value: SharedString::from(f.written_path.display().to_string()),
            });
            rows.push(MetadataRow {
                key: SharedString::from("Source offset"),
                value: SharedString::from(format!("0x{:x}", f.img_offset)),
            });
            let ft_opt = parse_file_type_pub(&f.file.file_type);
            if let Some(ft) = ft_opt {
                for (k, v) in self.registry.metadata_for(ft, f) {
                    rows.push(MetadataRow {
                        key: SharedString::from(k),
                        value: SharedString::from(v),
                    });
                }
            }
            replace_model(&self.metadata_model, rows);
            self.window
                .set_selected_filename(SharedString::from(f.file.filename.as_str()));
            self.window.set_side_panel_open(true);

            // Large preview: render full-res on first miss, cache by FileId.
            let large_img: Option<slint::Image> = {
                let mut ic = self.image_cache_full.borrow_mut();
                if let Some(img) = ic.get(&f.id) {
                    Some(img.clone())
                } else if let Some(ft) = ft_opt {
                    match self.registry.render_full_for(ft, &f.written_path, f) {
                        Ok(crate::preview::PreviewOutput::Image(rgba)) => {
                            let (w, h) = (rgba.width(), rgba.height());
                            let mut buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::new(w, h);
                            buf.make_mut_bytes().copy_from_slice(&rgba);
                            let img = slint::Image::from_rgba8(buf);
                            ic.insert(f.id, img.clone());
                            Some(img)
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            };
            self.window.set_selected_has_preview(large_img.is_some());
            self.window
                .set_selected_preview(large_img.unwrap_or_default());
        } else {
            replace_model(&self.metadata_model, Vec::<MetadataRow>::new());
            self.window.set_side_panel_open(false);
            self.window.set_selected_filename(SharedString::from(""));
            self.window.set_selected_has_preview(false);
            self.window
                .set_selected_preview(slint::Image::default());
        }
```

- [ ] **Step 6: Build + test**

Run: `cargo build -p utmost-gui && cargo test -p utmost-gui`
Expected: clean build; all tests still pass.

- [ ] **Step 7: Commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/ui/detail.slint crates/utmost-gui/ui/main.slint crates/utmost-gui/src/slint_adapter.rs
git commit -m "feat(gui): large preview + close X in side panel"
```

---

### Task 11: Empty-grid-area click → deselect

**Files:**
- Modify: `crates/utmost-gui/ui/detail.slint`
- Modify: `crates/utmost-gui/ui/main.slint`
- Modify: `crates/utmost-gui/src/slint_adapter.rs`

- [ ] **Step 1: Add a `grid-background-clicked` callback to `DetailPage`**

Edit `crates/utmost-gui/ui/detail.slint`. In the `callback` block of `DetailPage`, add:

```slint
    callback grid-background-clicked();
```

Inside the existing `Flickable { ... }`, add a low-Z `TouchArea` BEFORE the `for tile[i] in root.tiles` block so per-tile TouchAreas (rendered after, higher Z) intercept first:

```slint
                    TouchArea {
                        width: parent.width;
                        height: parent.height;
                        clicked => {
                            root.grid-background-clicked();
                        }
                    }
```

- [ ] **Step 2: Bubble up through `MainWindow`**

Edit `crates/utmost-gui/ui/main.slint`. Add:

```slint
    callback grid-background-clicked();
```

In the `DetailPage { ... }` instantiation, add:

```slint
            grid-background-clicked => {
                root.grid-background-clicked();
            }
```

- [ ] **Step 3: Wire callback in the adapter**

Edit `crates/utmost-gui/src/slint_adapter.rs`. In `UiState::new`, append after the previously added blocks:

```rust
        {
            let vm_cb = vm.clone();
            window.on_grid_background_clicked(move || {
                let mut v = vm_cb.lock().unwrap();
                v.deselect();
            });
        }
```

- [ ] **Step 4: Build + test**

Run: `cargo build -p utmost-gui && cargo test -p utmost-gui`
Expected: clean build; all tests pass.

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/ui/detail.slint crates/utmost-gui/ui/main.slint crates/utmost-gui/src/slint_adapter.rs
git commit -m "feat(gui): click empty grid area to deselect"
```

---

## Phase D — Slint UI: Lightbox component

### Task 12: Create `ui/lightbox.slint` (skeleton with close + nav arrows)

**Files:**
- Create: `crates/utmost-gui/ui/lightbox.slint`
- Modify: `crates/utmost-gui/ui/main.slint`

- [ ] **Step 1: Create the new Slint file**

Create `crates/utmost-gui/ui/lightbox.slint`:

```slint
import { HorizontalBox, VerticalBox, Button, Slider } from "std-widgets.slint";

export component Lightbox inherits Rectangle {
    in property <bool> has-image: false;
    in property <image> source-image;
    in property <string> filename: "";
    in property <int> index1: 0;
    in property <int> total: 0;
    in property <float> zoom: 1.0;
    in property <bool> fit: true;
    in property <string> caption: "";

    callback close();
    callback nav-next();
    callback nav-prev();
    callback zoom-changed(float);
    callback zoom-fit();

    background: #0a0a0a;

    // Body: image area with overlaid hover nav arrows.
    Rectangle {
        x: 0;
        y: 36px;
        width: parent.width;
        height: parent.height - 36px - 40px;
        clip: true;

        if root.has-image && root.fit: Image {
            source: root.source-image;
            x: 0;
            y: 0;
            width: parent.width;
            height: parent.height;
            image-fit: contain;
        }
        if root.has-image && !root.fit: Image {
            source: root.source-image;
            width: self.source.width * 1px * root.zoom;
            height: self.source.height * 1px * root.zoom;
            x: (parent.width - self.width) / 2;
            y: (parent.height - self.height) / 2;
            image-fit: preserve;
        }
        if !root.has-image: Text {
            text: root.caption;
            color: #aaa;
            horizontal-alignment: center;
            vertical-alignment: center;
            width: parent.width;
            height: parent.height;
        }

        // Left arrow
        prev_touch := TouchArea {
            width: 60px;
            height: parent.height;
            x: 0;
            y: 0;
            clicked => {
                root.nav-prev();
            }
            Rectangle {
                background: prev_touch.has-hover ? rgba(0,0,0,0.5) : transparent;
                width: parent.width;
                height: parent.height;
                Text {
                    text: "‹";
                    color: prev_touch.has-hover ? white : transparent;
                    font-size: 32px;
                    horizontal-alignment: center;
                    vertical-alignment: center;
                    width: parent.width;
                    height: parent.height;
                }
            }
        }

        // Right arrow
        next_touch := TouchArea {
            width: 60px;
            height: parent.height;
            x: parent.width - self.width;
            y: 0;
            clicked => {
                root.nav-next();
            }
            Rectangle {
                background: next_touch.has-hover ? rgba(0,0,0,0.5) : transparent;
                width: parent.width;
                height: parent.height;
                Text {
                    text: "›";
                    color: next_touch.has-hover ? white : transparent;
                    font-size: 32px;
                    horizontal-alignment: center;
                    vertical-alignment: center;
                    width: parent.width;
                    height: parent.height;
                }
            }
        }
    }

    // Top bar
    Rectangle {
        x: 0;
        y: 0;
        width: parent.width;
        height: 36px;
        background: rgba(0,0,0,0.85);
        HorizontalBox {
            padding: 8px;
            Text {
                text: root.filename;
                color: white;
                horizontal-stretch: 1;
                vertical-alignment: center;
            }
            Text {
                text: root.index1 + " of " + root.total;
                color: #aaa;
                vertical-alignment: center;
            }
            close_touch := TouchArea {
                width: 24px;
                height: 24px;
                clicked => {
                    root.close();
                }
                Rectangle {
                    background: close_touch.has-hover ? #444 : #333;
                    border-radius: 12px;
                    width: parent.width;
                    height: parent.height;
                    Text {
                        text: "×";
                        color: white;
                        horizontal-alignment: center;
                        vertical-alignment: center;
                        font-size: 16px;
                    }
                }
            }
        }
    }

    // Bottom bar
    Rectangle {
        x: 0;
        y: parent.height - 40px;
        width: parent.width;
        height: 40px;
        background: rgba(0,0,0,0.85);
        HorizontalBox {
            padding: 8px;
            spacing: 8px;
            Rectangle { horizontal-stretch: 1; }
            fit_btn := TouchArea {
                width: 50px;
                height: 24px;
                clicked => {
                    root.zoom-fit();
                }
                Rectangle {
                    background: fit_btn.has-hover ? #444 : #333;
                    border-radius: 3px;
                    width: parent.width;
                    height: parent.height;
                    Text {
                        text: "Fit";
                        color: white;
                        horizontal-alignment: center;
                        vertical-alignment: center;
                    }
                }
            }
            Text {
                text: "Zoom";
                color: #888;
                vertical-alignment: center;
            }
            Slider {
                width: 160px;
                minimum: 0.1;
                maximum: 8.0;
                value: root.zoom;
                changed(v) => {
                    root.zoom-changed(v);
                }
            }
            Text {
                text: floor(root.zoom * 100) + "%";
                color: white;
                vertical-alignment: center;
                width: 50px;
                horizontal-alignment: right;
            }
        }
    }
}
```

- [ ] **Step 2: Import + instantiate in `main.slint`**

Edit `crates/utmost-gui/ui/main.slint`. Add at the top:

```slint
import { Lightbox } from "lightbox.slint";
```

Add new in/out properties to `MainWindow`:

```slint
    in-out property <bool> lightbox-open: false;
    in-out property <bool> lightbox-has-image: false;
    in-out property <image> lightbox-image;
    in-out property <string> lightbox-filename: "";
    in-out property <int> lightbox-index1: 0;
    in-out property <int> lightbox-total: 0;
    in-out property <float> lightbox-zoom: 1.0;
    in-out property <bool> lightbox-fit: true;

    callback lightbox-close();
    callback lightbox-next();
    callback lightbox-prev();
    callback lightbox-zoom-changed(float);
    callback lightbox-zoom-fit();
```

At the end of `MainWindow` (after the existing `if !root.show-detail: VerticalBox { ... }` block, still inside the `Window`), add:

```slint
    if root.lightbox-open: Lightbox {
        width: parent.width;
        height: parent.height;
        has-image: root.lightbox-has-image;
        source-image: root.lightbox-image;
        filename: root.lightbox-filename;
        index1: root.lightbox-index1;
        total: root.lightbox-total;
        zoom: root.lightbox-zoom;
        fit: root.lightbox-fit;
        caption: "(no preview)";
        close => {
            root.lightbox-close();
        }
        nav-next => {
            root.lightbox-next();
        }
        nav-prev => {
            root.lightbox-prev();
        }
        zoom-changed(v) => {
            root.lightbox-zoom-changed(v);
        }
        zoom-fit => {
            root.lightbox-zoom-fit();
        }
    }
```

- [ ] **Step 3: Build to confirm Slint compiles**

Run: `cargo build -p utmost-gui`
Expected: clean build.

- [ ] **Step 4: Commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/ui/lightbox.slint crates/utmost-gui/ui/main.slint
git commit -m "feat(gui): Lightbox slint component with nav arrows and zoom controls"
```

---

### Task 13: Wire lightbox callbacks + sync in adapter

**Files:**
- Modify: `crates/utmost-gui/src/slint_adapter.rs`

- [ ] **Step 1: Add lightbox callback handlers in `UiState::new`**

Append inside `UiState::new`, after the previously added blocks:

```rust
        {
            let vm_cb = vm.clone();
            window.on_lightbox_close(move || {
                let mut v = vm_cb.lock().unwrap();
                v.close_lightbox();
            });
        }
        {
            let vm_cb = vm.clone();
            window.on_lightbox_next(move || {
                let mut v = vm_cb.lock().unwrap();
                v.lightbox_next();
            });
        }
        {
            let vm_cb = vm.clone();
            window.on_lightbox_prev(move || {
                let mut v = vm_cb.lock().unwrap();
                v.lightbox_prev();
            });
        }
        {
            let vm_cb = vm.clone();
            window.on_lightbox_zoom_changed(move |z| {
                let mut v = vm_cb.lock().unwrap();
                v.zoom_set(z);
            });
        }
        {
            let vm_cb = vm.clone();
            window.on_lightbox_zoom_fit(move || {
                let mut v = vm_cb.lock().unwrap();
                v.zoom_fit();
            });
        }
```

- [ ] **Step 2: Sync lightbox state to Slint at the end of `sync()`**

At the end of `UiState::sync`, after the existing side-panel block, append:

```rust
        // Lightbox properties.
        if let Some(lb_id) = vm.lightbox
            && let Some(f) = vm.files.iter().find(|f| f.id == lb_id)
        {
            let idx = vm
                .visible_files
                .iter()
                .position(|id| *id == lb_id)
                .unwrap_or(0);
            self.window.set_lightbox_open(true);
            self.window
                .set_lightbox_filename(SharedString::from(f.file.filename.as_str()));
            self.window.set_lightbox_index1((idx + 1) as i32);
            self.window
                .set_lightbox_total(vm.visible_files.len() as i32);
            self.window.set_lightbox_zoom(vm.lightbox_view.zoom);
            self.window.set_lightbox_fit(vm.lightbox_view.fit);

            // Render full-res image if available (cache shared with side panel).
            let img: Option<slint::Image> = {
                let mut ic = self.image_cache_full.borrow_mut();
                if let Some(img) = ic.get(&f.id) {
                    Some(img.clone())
                } else if let Some(ft) = parse_file_type_pub(&f.file.file_type) {
                    match self.registry.render_full_for(ft, &f.written_path, f) {
                        Ok(crate::preview::PreviewOutput::Image(rgba)) => {
                            let (w, h) = (rgba.width(), rgba.height());
                            let mut buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::new(w, h);
                            buf.make_mut_bytes().copy_from_slice(&rgba);
                            let img = slint::Image::from_rgba8(buf);
                            ic.insert(f.id, img.clone());
                            Some(img)
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            };
            self.window.set_lightbox_has_image(img.is_some());
            self.window
                .set_lightbox_image(img.unwrap_or_default());
        } else {
            self.window.set_lightbox_open(false);
            self.window.set_lightbox_has_image(false);
            self.window
                .set_lightbox_image(slint::Image::default());
            self.window.set_lightbox_filename(SharedString::from(""));
            self.window.set_lightbox_index1(0);
            self.window.set_lightbox_total(0);
        }
```

- [ ] **Step 3: Build + test**

Run: `cargo build -p utmost-gui && cargo test -p utmost-gui`
Expected: clean build; all tests pass.

- [ ] **Step 4: Commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/src/slint_adapter.rs
git commit -m "feat(gui): wire lightbox callbacks and property sync in adapter"
```

---

### Task 14: Open the lightbox via tile double-click and Enter key

**Files:**
- Modify: `crates/utmost-gui/ui/detail.slint`
- Modify: `crates/utmost-gui/ui/main.slint`
- Modify: `crates/utmost-gui/src/slint_adapter.rs`

- [ ] **Step 1: Add `tile-double-clicked` callback to `DetailPage`**

Edit `crates/utmost-gui/ui/detail.slint`. Add to the callback block of `DetailPage`:

```slint
    callback tile-double-clicked(int);
```

In the per-tile `TouchArea`, change the existing `tile_touch := TouchArea { ... }` to also handle double clicks. Slint's TouchArea has `clicked` only; for double-click we use the `double-clicked` callback (Slint 1.5+). Replace the existing TouchArea block:

```slint
                        tile_touch := TouchArea {
                            clicked => {
                                root.tile-clicked(tile.id);
                            }
                            double-clicked => {
                                root.tile-double-clicked(tile.id);
                            }
                            ...
```

Note: only the surrounding `clicked` / `double-clicked` definitions change. Leave the inner `if tile.has_thumbnail: Image { ... }` and `Text { ... }` children unchanged.

If Slint's compiler rejects `double-clicked` (some versions only expose `clicked`), substitute the following manual double-click detector at the top of the tile (above `tile_touch`):

```slint
                        property <int> last-click-ms: 0;
```

…and change the existing `clicked => { root.tile-clicked(tile.id); }` to:

```slint
                            clicked => {
                                if (animation-tick() / 1ms - parent.last-click-ms < 300) {
                                    root.tile-double-clicked(tile.id);
                                } else {
                                    root.tile-clicked(tile.id);
                                }
                                parent.last-click-ms = animation-tick() / 1ms;
                            }
```

Use whichever variant compiles. Verify with `cargo build -p utmost-gui` after the edit.

- [ ] **Step 2: Add `tile-enter-pressed` callback driven by a key handler**

In `DetailPage`, wrap the outermost `VerticalBox { ... }` in a `FocusScope`:

```slint
    FocusScope {
        VerticalBox {
            ...existing children...
        }
        key-pressed(event) => {
            if (event.text == Key.Return) {
                root.tile-enter-pressed();
                return accept;
            }
            if (event.text == Key.Escape) {
                root.detail-escape-pressed();
                return accept;
            }
            return reject;
        }
    }
```

Add to the `DetailPage` callback block:

```slint
    callback tile-enter-pressed();
    callback detail-escape-pressed();
```

- [ ] **Step 3: Bubble through `MainWindow`**

Edit `crates/utmost-gui/ui/main.slint`. Add to `MainWindow` callbacks:

```slint
    callback tile-double-clicked(int);
    callback tile-enter-pressed();
    callback detail-escape-pressed();
```

In the `DetailPage { ... }` instantiation, add:

```slint
            tile-double-clicked(id) => {
                root.tile-double-clicked(id);
            }
            tile-enter-pressed => {
                root.tile-enter-pressed();
            }
            detail-escape-pressed => {
                root.detail-escape-pressed();
            }
```

- [ ] **Step 4: Wire callbacks in the adapter**

Edit `crates/utmost-gui/src/slint_adapter.rs`. Append after the existing handlers in `UiState::new`:

```rust
        {
            let vm_cb = vm.clone();
            window.on_tile_double_clicked(move |id| {
                let mut v = vm_cb.lock().unwrap();
                v.selection = Some(id as u64);
                v.open_lightbox();
            });
        }
        {
            let vm_cb = vm.clone();
            window.on_tile_enter_pressed(move || {
                let mut v = vm_cb.lock().unwrap();
                v.open_lightbox();
            });
        }
        {
            let vm_cb = vm.clone();
            window.on_detail_escape_pressed(move || {
                let mut v = vm_cb.lock().unwrap();
                v.close_or_deselect();
            });
        }
```

- [ ] **Step 5: Build + test**

Run: `cargo build -p utmost-gui && cargo test -p utmost-gui`
Expected: clean build; all tests pass.

- [ ] **Step 6: Commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/ui/detail.slint crates/utmost-gui/ui/main.slint crates/utmost-gui/src/slint_adapter.rs
git commit -m "feat(gui): open lightbox via double-click + Enter; ESC dispatch"
```

---

### Task 15: Keyboard nav (Left/Right/0) inside the lightbox

**Files:**
- Modify: `crates/utmost-gui/ui/lightbox.slint`

- [ ] **Step 1: Wrap the lightbox in a `FocusScope` and handle keys**

Edit `crates/utmost-gui/ui/lightbox.slint`. Replace `export component Lightbox inherits Rectangle {` with the wrapper:

```slint
export component Lightbox inherits FocusScope {
```

…and at the end of the component (just before the final `}`), add the key handler:

```slint
    key-pressed(event) => {
        if (event.text == Key.Escape) {
            root.close();
            return accept;
        }
        if (event.text == Key.LeftArrow) {
            root.nav-prev();
            return accept;
        }
        if (event.text == Key.RightArrow) {
            root.nav-next();
            return accept;
        }
        if (event.text == "0") {
            root.zoom-fit();
            return accept;
        }
        return reject;
    }
```

Important: `FocusScope` doesn't carry `background`, so the existing `background: #0a0a0a;` line needs to move to a child Rectangle. Wrap the existing three layout children (body, top bar, bottom bar) in a single `Rectangle { background: #0a0a0a; width: 100%; height: 100%; ... }` parent, OR set `background` on the existing body Rectangle and add a full-coverage `Rectangle { background: #0a0a0a; }` at z-index 0.

Cleanest approach: add as the FIRST child of the component:

```slint
    Rectangle {
        background: #0a0a0a;
        width: parent.width;
        height: parent.height;
        x: 0;
        y: 0;
    }
```

Remove the `background: #0a0a0a;` property from the component's top-level declarations.

- [ ] **Step 2: Make sure the lightbox grabs focus when opened**

In `crates/utmost-gui/ui/main.slint`, the `Lightbox { ... }` instantiation must call `focus()` when it first appears. Slint's `init` callback fires on creation; add inside the instantiation:

```slint
        init => {
            self.focus();
        }
```

- [ ] **Step 3: Build to confirm Slint compiles**

Run: `cargo build -p utmost-gui`
Expected: clean build.

- [ ] **Step 4: Commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/ui/lightbox.slint crates/utmost-gui/ui/main.slint
git commit -m "feat(gui): lightbox keyboard nav (Esc/Left/Right/0)"
```

---

## Phase E — Smoke test and polish

### Task 16: Manual smoke test + fixup

**Files:**
- None (manual run)

This task is intentionally not TDD — it's an exploratory verification of the integrated feature against a real run.

- [ ] **Step 1: Build the release binary**

Run: `cargo build --release`
Expected: clean build for the whole workspace.

- [ ] **Step 2: Carve a test image to generate fixture data**

Run from the project root (substitute a real test image you have):

```bash
./target/release/utmost --gui -o /tmp/utmost-smoke /path/to/test.img
```

If you don't have a test image handy, run the existing test fixtures used by `tests/jpeg_preview.rs` against any `.img`-like blob — `examples/` or `test-data/` may contain one.

- [ ] **Step 3: Walk the feature manually and verify each behaviour**

Verify each in turn. If any fails, capture the symptom (which step, what happened vs expected) and create a follow-up task before declaring the smoke complete.

- Click a source row in the list — detail page opens, grid renders.
- Click a tile — side panel appears with the large preview at top, X button next to filename.
- Click the X — side panel closes; selection cleared.
- Click a tile again — side panel reopens.
- Click an empty grid area between tiles — side panel closes.
- Click a tile, then click the large preview — lightbox opens.
- Press Right arrow — lightbox advances; counter increments; image changes.
- Press Right past the last item — wraps to first.
- Press Left past the first item — wraps to last.
- Drag the zoom slider — image scales; percent readout updates.
- Click "Fit" — image scales to fit.
- Press 0 key — image scales to fit.
- Click the X in the lightbox top bar — lightbox closes; side panel still open.
- Press ESC with lightbox open — lightbox closes; side panel still open.
- Press ESC again — side panel closes.
- Double-click a tile — lightbox opens directly (skipping the side panel preview step).
- Click a tile (single click), then press Enter — lightbox opens.
- Navigate to a non-image file (e.g., a PDF tile) — lightbox shows a centered icon or "(no preview)" caption + correct filename and counter.

- [ ] **Step 4: Run the full test suite**

Run: `cargo test`
Expected: full workspace test suite passes.

- [ ] **Step 5: Commit any cleanup**

If the smoke surfaced minor fixes (typos, layout tweaks), commit them as:

```bash
cargo fmt && cargo clippy --all-targets
git add -A
git commit -m "fix(gui): smoke-test followups"
```

If the smoke passes cleanly, skip the commit step.

---

## Notes for the executing agent

- The pre-commit hook runs `cargo fmt` + `cargo clippy --all-targets`. Every commit must pass both. If clippy warns about unused imports introduced by a step, remove them before committing.
- TDD is mandatory for Phases A and B (Tasks 1–8). Phases C–E (Tasks 9–15) modify Slint files where there's no in-process Slint assertion API; verify via `cargo build` (syntax) + `cargo test` (no view-model regressions) + manual smoke at the end.
- The `image_cache_full` is shared between the side-panel large preview and the lightbox, so the JPEG is only decoded once per selection.
- If Slint syntax errors trip you up: the project is on Slint 1.16 per `Cargo.lock`. Reference `crates/utmost-gui/ui/detail.slint` for the established style.
- DO NOT touch `crates/utmost-gui/src/thumb_worker.rs` — the grid thumbnail path is unchanged in this work.
