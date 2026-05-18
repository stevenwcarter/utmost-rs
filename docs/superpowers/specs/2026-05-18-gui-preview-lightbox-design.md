# Utmost GUI — Preview Panel & Lightbox

**Date:** 2026-05-18
**Status:** Approved
**Author:** Steven Carter (with brainstorming assistance)

## 1. Overview

Extend the existing Slint GUI detail page with two related features:

1. **Larger preview in the side panel.** When a tile is selected, a sizeable
   preview of the file renders above the metadata in the side panel. Today
   the side panel shows metadata only.
2. **Full-screen lightbox viewer.** Clicking the larger preview opens a
   modal overlay that displays the full content. Left/right keys navigate
   through the same sorted/filtered list the grid shows. A zoom slider plus
   "Fit" button live in the bottom-right; images default to zoom-to-fit.

The same lightbox is built as a generic preview viewer, not an image-only
viewer. It renders whatever `PreviewOutput` the registry produces (image,
text, hex dump, or icon). This is the path that lets us add `.txt` previews
later without rewriting the viewer.

This design also closes a gap noticed during the discussion: today there is
no way to deselect a file or close the side panel. Three gestures get
wired up — X button, click empty grid area, and ESC.

## 2. Goals / Non-goals

**Goals**

- Side panel keeps its current ~280px width; the large preview spans the
  panel width and sits above the metadata.
- Lightbox is a top-level overlay rendered above the detail page; the grid
  state survives every open/close.
- Lightbox navigation (left/right keys, on-hover side arrows) walks
  `ViewModel.visible_files` and wraps at the ends.
- Lightbox handles **every** visible file type — images render as images,
  icons render centered, text (future) will render scrollable. No file is
  unreachable.
- Zoom slider range 10%–800% for image previews. "Fit" button and Zero key
  return to fit-to-window. Fit is the default on every open and every
  navigation.
- Three close gestures for the side panel: X button, click empty grid
  background, ESC key. ESC has a two-level behaviour — closes the lightbox
  first if open, then on a second press closes the side panel.
- Three open gestures for the lightbox: click the large preview in the
  side panel, double-click a grid tile, press Enter on a selected tile.
- All state transitions are unit-testable in pure Rust without Slint.

**Non-goals**

- No text-preview renderer in this work. The `Text(String)` variant of
  `PreviewOutput` is added so the lightbox component knows how to render it
  when a renderer eventually arrives. No `.txt` PreviewRenderer ships here.
- No drag-to-pan on zoomed images in v1. Slint's `Image` properties
  (`source-clip-*`) make this easy to add later; the slider is enough now.
- No spacebar Quick Look shortcut (conflicts with future list-scroll
  spacebar).
- No sort-control UI changes — sort already lives in `ViewModel.filter` and
  the lightbox simply follows whatever order `visible_files` is in.
- No background worker for full-resolution decode; the first cut decodes on
  the UI thread on demand. Easy to move later if it stutters.

## 3. ViewModel changes

All new state lives in `crates/utmost-gui/src/view_model.rs` and is
exercised by unit tests with no Slint dependency.

```rust
pub struct LightboxView {
    pub zoom: f32,   // 1.0 = 100%; clamped to 0.1..=8.0
    pub fit: bool,   // true = auto-fit; reset to true on open & navigation
}

pub struct ViewModel {
    // existing fields unchanged
    pub lightbox: Option<FileId>,    // None = closed
    pub lightbox_view: LightboxView, // zoom + fit; resets each open
}
```

`selection: Option<FileId>` already exists; no change.

New methods:

```rust
impl ViewModel {
    pub fn open_lightbox(&mut self);       // uses self.selection; no-op if None
    pub fn close_lightbox(&mut self);      // selection survives
    pub fn lightbox_next(&mut self);       // wraps; no-op on empty list
    pub fn lightbox_prev(&mut self);       // wraps; no-op on empty list
    pub fn close_or_deselect(&mut self);   // ESC: lightbox first, then selection
    pub fn deselect(&mut self);            // clears selection + closes lightbox
    pub fn zoom_set(&mut self, z: f32);    // clamped to 0.1..=8.0, sets fit=false
    pub fn zoom_fit(&mut self);            // fit = true
}
```

Wrap-around math: `idx = (idx + n + delta) % n` over `visible_files`.

Skip-Icon: **not skipped.** Every visible file is reachable. Icon-only files
render as a centered icon with filename + metadata in the lightbox.

## 4. Slint UI changes

### 4.1 `ui/detail.slint`

Three additions:

1. **`LargePreview` sub-component.** Takes a `kind` discriminator plus
   `image`, `text-content`, and `icon-kind` properties. Used in two places:
   the side panel header and the lightbox center. Renders one of:
   - `Image { image-fit: contain }` for image content
   - Scrollable `Text` for text content (future)
   - Centered icon for icon content (with the IconKind enum)

2. **Side panel header row.** Adds the filename label and an X close
   button. Below the header, a `LargePreview` sits above the metadata
   rows, with a TouchArea wrapping the preview that fires
   `large-preview-clicked`.

3. **Empty-grid deselect.** Wrap the `Flickable` in a TouchArea fired only
   when the click misses every tile. Cleanest implementation: keep tile
   TouchAreas on top so they intercept first; the outer area fires only on
   uncaught clicks. Adapter maps this to `vm.deselect()`.

### 4.2 `ui/lightbox.slint` (new file)

Top-level overlay component, rendered above `DetailPage` in `MainWindow`:

```
if lightbox-open: Lightbox {
    width: parent.width;
    height: parent.height;
    z: 100;
    // ...
}
```

Structure:

- `TopBar` — filename, "n of total" counter, `×` close button
- Center — `LargePreview` from `detail.slint`, sized by zoom/fit
- `BottomBar` — Fit button, zoom slider (10–800%), percent readout
- Two side-arrow buttons (left/right) inside the body; visible only on
  hover via `parent.has-hover`
- A FocusScope around the whole component that captures `key-pressed` for
  Escape, Left, Right, Plus, Minus, and Zero (Zero = fit-to-window)

Image zoom binding: the inner `Image` has its `width` and `height` set
from `LightboxView.zoom` × native dimensions (or `image-fit: contain`
within the available area when `fit` is true).

### 4.3 `ui/main.slint`

`MainWindow` gets new in/out properties to drive the lightbox:
`lightbox-open`, `lightbox-kind`, `lightbox-image`, `lightbox-text`,
`lightbox-icon-kind`, `lightbox-filename`, `lightbox-counter`,
`lightbox-zoom`, `lightbox-fit`. New callbacks:
`lightbox-open-requested`, `lightbox-close`, `lightbox-next`,
`lightbox-prev`, `lightbox-zoom-set(float)`, `lightbox-zoom-fit`,
`large-preview-clicked`, `side-panel-close`, `grid-background-clicked`,
`tile-double-clicked(int)`, `tile-enter-pressed`.

## 5. Preview pipeline extension

In `crates/utmost-gui/src/preview/mod.rs`:

```rust
pub enum PreviewOutput {
    Image(image::RgbaImage),
    Text(String),       // NEW
    HexDump(String),    // existing
    Icon(IconKind),     // existing
}

pub trait PreviewRenderer: Send + Sync {
    fn supports(&self, file_type: FileType) -> bool;
    fn render(&self, path: &Path, file: &FoundFile) -> Result<PreviewOutput>;

    // NEW — used by side panel large preview and the lightbox.
    fn render_full(&self, path: &Path, file: &FoundFile) -> Result<PreviewOutput> {
        self.render(path, file)
    }

    fn render_side_panel_metadata(&self, file: &FoundFile) -> Vec<(String, String)>;
}

pub struct PreviewRegistry { /* unchanged */ }

impl PreviewRegistry {
    // NEW
    pub fn render_full_for(
        &self,
        file_type: FileType,
        path: &Path,
        file: &FoundFile,
    ) -> Result<PreviewOutput>;
}
```

`JpegPreview` overrides `render_full` to decode at native resolution
(no 256px cap). `GenericIcon` inherits the default. The `Text` variant
exists so the lightbox switch is exhaustive when a renderer is added.

`ThumbWorker` is unchanged — it is the grid thumbnail cache.

Side panel large preview and lightbox both consume `render_full`. To
avoid decoding twice when the user opens the lightbox after selecting,
the adapter caches the last full-res result keyed by `FileId`. Cache size
1 is enough for the first cut.

## 6. Adapter wiring

In `crates/utmost-gui/src/slint_adapter.rs`:

**New image caches:**
- `image_cache_full: RefCell<HashMap<FileId, slint::Image>>` for full-res
  decoded images (lightbox + side-panel large preview).
- Existing 256px `image_cache` continues to drive the grid.

**Callback handlers** (each one acquires `vm.lock()` then mutates state;
the existing 100 ms timer publishes the new state to Slint):

| Callback | Action |
|---|---|
| `tile-clicked(id)` | `vm.selection = Some(id)` (unchanged) |
| `tile-double-clicked(id)` | `vm.selection = Some(id); vm.open_lightbox()` |
| `tile-enter-pressed` | `vm.open_lightbox()` (uses current selection) |
| `large-preview-clicked` | `vm.open_lightbox()` |
| `lightbox-close` | `vm.close_lightbox()` |
| `lightbox-next` / `prev` | `vm.lightbox_next()` / `vm.lightbox_prev()` |
| `lightbox-zoom-set(f)` | `vm.zoom_set(f)` |
| `lightbox-zoom-fit` | `vm.zoom_fit()` |
| `side-panel-close` | `vm.deselect()` |
| `grid-background-clicked` | `vm.deselect()` |
| Slint `key-pressed` (ESC) | `vm.close_or_deselect()` |

**Sync extension:** the existing `sync` method gains a block that writes
the lightbox-related window properties from `vm.lightbox`,
`vm.lightbox_view`, and the cached full-res preview. When `vm.lightbox`
is `None`, `lightbox_open` is set to false and the rest is left blank.

## 7. Testing

**Pure ViewModel tests** in `view_model.rs`:

- `open_lightbox` uses current selection; no-op when selection is None
- `close_lightbox` clears `lightbox` but keeps `selection`
- `lightbox_next` / `prev` wrap from end → start and start → end
- `lightbox_next` / `prev` are no-ops when `visible_files` is empty
- `close_or_deselect` closes lightbox first, then selection on second call
- `deselect` clears both `selection` and `lightbox`
- `zoom_set` clamps to `0.1..=8.0` and flips `fit` to false
- `zoom_fit` flips `fit` to true
- Lightbox navigation uses `visible_files` ordering (verified by setting
  sort key + direction, then walking next/prev)

**Preview pipeline tests:**

- `JpegPreview::render_full` returns the source image's native dimensions
  against a fixture file
- `GenericIcon::render_full` returns the same `PreviewOutput::Icon` as
  `render` (default-impl path)

**Replay-style integration** in `tests/replay_snapshot.rs`:

- Drive a scripted sequence: select tile → open lightbox → arrow right →
  arrow right → ESC → ESC. Assert `selection` and `lightbox` at each step.

**Manual smoke:** build, launch with a known case directory, click through
select → side panel preview → lightbox → arrow navigation → zoom → fit →
ESC. Verify X-button, empty-grid-click, and ESC all clear the side panel.

## 8. Open questions

None at design time. Decisions on zoom range, end-of-list wrap, non-image
navigation behaviour, and open/close gestures were made during
brainstorming and are baked into sections 2–6.

## 9. Out-of-scope follow-ups (intentionally not in this work)

- `.txt` PreviewRenderer that produces `PreviewOutput::Text(String)`.
- Drag-to-pan when zoomed beyond 100%.
- Background full-resolution decode (move `render_full` off the UI thread
  if measured latency warrants it).
- Sort controls in the detail page UI. (Navigation already respects
  whatever `visible_files` order is in.)
