# Detail page filter extensions — sort, hide-no-preview, size range

**Date:** 2026-05-18
**Scope:** `crates/utmost-gui` only. No changes to `utmost-lib`, `utmost-cli`, or `utmost-viewer`.

## Goal

Add three new controls to the detail page's filter UI:

1. **Sort dropdown + direction toggle + "Bookmarked first" modifier** — in the always-visible top toolbar, far right.
2. **"Hide no-preview" toggle** — pill button next to the existing Bookmarked toggle in the top toolbar.
3. **Size range slider** — two-knob log-scale slider as the bottom row of the collapsible filters block.

## Layout

### Top toolbar (always visible, single row, may wrap on narrow windows)

```
[ Back ] [ Select all ] [ Select none ] [ Hide filters ] [ ★ Bookmarked ] [ ⚆ Hide no-preview ]
   ───spacer──→
[ Sort: Filename ▾ ] [ ↑ ] [ ★ Bookmarked first ]
```

- **Hide no-preview**: pill button matching the existing `Bookmarked` style. Yellow (`#cc6`) when on, gray (`#555`) when off.
- **Sort combo**: Slint `ComboBox` with items `Filename | Size | File type | Source offset`.
- **Direction button**: 28×28 square next to the combo; shows `↑` (asc) or `↓` (desc); click toggles.
- **Bookmarked first**: small pill toggle modifier. Independent of sort direction.

### Filters block (only when `filters-visible == true`)

```
[ Image (24) ] [ Video (3) ] [ Text (7) ] ...               ← group tabs row (existing)
[ jpeg (18) ] [ png (6) ] [ Partial jpeg (2) ] ...          ← sub-chip row (existing)
Size:                                          24 KB — 1.8 MB
[ ●───────●──────────────────────●──○ ]
                0 B                                            1.8 MB
```

- Size slider sits below the sub-chip row.
- Range label (e.g., `"24 KB — 1.8 MB"`) is right-aligned above the slider; `"Size:"` label on the left.
- Endpoint labels under the knobs: `"0 B"` (left), `"{max formatted}"` (right).
- Slider hides with the rest of the filters block when filters are collapsed, but its filter state stays in effect.
- Slider hidden entirely when the otherwise-filtered set is empty.

## Data model

All new state lives in `FilterState` in `crates/utmost-gui/src/view_model.rs`. Keeping it there means it composes with `visible_ids()` and is testable without Slint.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortKey {
    #[default] Filename,
    Size,
    FileType,        // new
    SourceOffset,    // new
}

#[derive(Debug, Clone, Default)]
pub struct FilterState {
    pub enabled_types: BTreeSet<FileType>,
    pub enabled_partial_types: BTreeSet<FileType>,
    pub bookmarked_only: bool,
    pub source_filter: Option<u32>,
    pub sort_key: SortKey,
    pub sort_dir: SortDir,

    // --- new ---
    pub bookmarked_first: bool,          // sort modifier
    pub hide_no_preview: bool,           // filter
    pub size_range: Option<(u64, u64)>,  // None = no filter; Some((lo, hi)) = inclusive byte range
}
```

### Why `Option<(u64, u64)>` for size range

- `None` is the "untouched" state — no filter applied; slider sits at extremes.
- `Some((lo, hi))` means the user has constrained the range. Distinguishing these matters when the dataset's max grows mid-run: an untouched slider follows the new max; a user-set range stays put (and clamps to the new max if it overshoots).

### Thumbnail-availability tracking

`hide_no_preview` filters on whether a file has a thumbnail, but `has_thumbnail` is currently computed in `slint_adapter.rs` from the `PreviewRegistry` / `thumb_worker`. To filter on it inside the pure-Rust view model, the view model needs to know which `FileId`s have a thumbnail.

The cleanest fix: add a `BTreeSet<FileId>` field on `ViewModel` (e.g., `thumbnail_ready: BTreeSet<FileId>`), and expose `set_thumbnail_ready(file_id, ready: bool)`. `slint_adapter` calls it whenever a thumbnail becomes available (or fails to decode). `visible_ids()` reads the set when `hide_no_preview` is on.

This keeps the view model pure-Rust, unit-testable, and free of any Slint or worker dependency.

## Filter pipeline

`visible_ids()` becomes (in order, all conjunctive):

1. source filter (existing)
2. `bookmarked_only` (existing)
3. file-type / partial-type chips (existing)
4. **`hide_no_preview`** — `thumbnail_ready.contains(&file_id)` required
5. **`size_range`** — `lo <= file.size <= hi` (inclusive)
6. sort (existing key set + new keys, with `bookmarked_first` modifier below)

### Sort with `bookmarked_first`

```rust
ids.sort_by(|a, b| {
    if self.filter.bookmarked_first {
        let ba = self.bookmarks.contains(a);
        let bb = self.bookmarks.contains(b);
        if ba != bb { return bb.cmp(&ba); }  // bookmarked = true first
    }
    let cmp = match self.filter.sort_key {
        SortKey::Filename     => a_name.cmp(&b_name),
        SortKey::Size         => a_size.cmp(&b_size),
        SortKey::FileType     => a_type.cmp(&b_type),
        SortKey::SourceOffset => a_offset.cmp(&b_offset),
    };
    match self.filter.sort_dir { SortDir::Asc => cmp, SortDir::Desc => cmp.reverse() }
});
```

`bookmarked_first` is unaffected by `sort_dir` — bookmarks always pin to top. Only the secondary sort respects direction.

## Size slider mechanics

### Log-scale conversion

The slider's two knobs operate in normalized `[0.0, 1.0]` "track position" space; bytes are derived by an exp transform.

```rust
const LOG_MIN_BYTES: f64 = 1.0;  // avoid log(0); the left edge is special-cased to 0 B

fn track_to_bytes(pos: f64, max_bytes: u64) -> u64 {
    if pos <= 0.0 { return 0; }
    let lo = LOG_MIN_BYTES.ln();
    let hi = (max_bytes.max(1) as f64).ln();
    let bytes = (lo + (hi - lo) * pos.clamp(0.0, 1.0)).exp();
    bytes.round() as u64
}

fn bytes_to_track(bytes: u64, max_bytes: u64) -> f64 {
    if bytes == 0 || max_bytes <= 1 { return 0.0; }
    let lo = LOG_MIN_BYTES.ln();
    let hi = (max_bytes as f64).ln();
    ((bytes as f64).ln() - lo) / (hi - lo)
}
```

- Left knob at position `0.0` → `lo_bytes = 0` (special-cased so the smallest files are always included).
- Right knob at position `1.0` → `hi_bytes = max_bytes` exactly.

### Dynamic max bound

`ViewModel` exposes:

```rust
/// Largest size among files that pass all filters *except* the size range itself.
/// Returns 0 if the otherwise-filtered set is empty.
pub fn size_filter_max(&self) -> u64 { ... }
```

This avoids the feedback loop where dragging the right knob would shrink the max. The slider widget receives `max_bytes = size_filter_max()` on each `push_to_ui()`.

### Clamping when the max changes

1. **`size_range == None`** (slider "untouched"): nothing to do. The slider always renders both knobs at the extremes.
2. **`size_range == Some((lo, hi))`**: when the new `size_filter_max` drops below `hi`, clamp `hi = new_max`. If `lo > new_max` also, clamp `lo = new_max`. If clamping collapses to `lo == hi == 0`, drop back to `None`.

### Slint widget

Slint `std-widgets` does not ship a two-knob range slider. Build a small `RangeSlider` component in `crates/utmost-gui/ui/range_slider.slint`: two `TouchArea`s over a track `Rectangle`, with `moved` for live drag updates. Owns its own normalized state; emits `range-changed(float, float)` with `(lo_norm, hi_norm)`.

## Adapter wiring

In `crates/utmost-gui/src/slint_adapter.rs`:

- **New `DetailPage` properties** (added to `crates/utmost-gui/ui/detail.slint`):
  - `in-out property <bool> hide-no-preview-enabled;`
  - `in-out property <bool> bookmarked-first-enabled;`
  - `in-out property <[string]> sort-key-items;` (combo items)
  - `in-out property <int> sort-key-index;` (selected combo index)
  - `in-out property <bool> sort-dir-asc;` (true = ascending; arrow shows `↑`)
  - `in-out property <float> size-lo-norm;` `<float> size-hi-norm;`
  - `in-out property <string> size-range-label;` `<string> size-max-label;`
  - `in-out property <bool> size-slider-visible;`
- **New callbacks:**
  - `hide-no-preview-toggle()`
  - `bookmarked-first-toggle()`
  - `sort-key-changed(int)` (combo index)
  - `sort-dir-toggle()`
  - `size-range-changed(float, float)`
- **Push pipeline** (`push_to_ui()`): translate `FilterState` → properties; compute `size_filter_max`; format range/max labels via `format_bytes(u64)` (decimal SI: B/KB/MB/GB).
- **Thumbnail-ready feed:** wherever a thumbnail completes or fails in `slint_adapter.rs` / `thumb_worker.rs`, call `view_model.set_thumbnail_ready(file_id, true/false)` and then `push_to_ui()`.

## Testing

`crates/utmost-gui/src/view_model.rs` already has sort tests near line 1184. Extend the same `#[cfg(test)] mod tests` block:

1. **Sort keys:** `sort_by_file_type_asc` / `_desc`; `sort_by_source_offset_asc` / `_desc`.
2. **`bookmarked_first` modifier:** combined with each sort key, asc + desc. Bookmarks pin to top regardless of direction; non-bookmarks respect direction.
3. **`hide_no_preview` filter:** with and without `set_thumbnail_ready`; combined with chip filters (conjunctive).
4. **Size-range filter:** `None` matches all; inclusive bounds (`lo == size` and `hi == size` both included); combined with chip filters.
5. **`size_filter_max`:** returns 0 on empty filtered set; ignores the size range itself (no feedback loop); recomputes when chips change.
6. **Clamping:** when `size_filter_max` drops below current `hi`, `hi` clamps to new max; collapse to `lo == hi == 0` drops `size_range` back to `None`.
7. **Log conversion:** `track_to_bytes(0.0, max) == 0`; `track_to_bytes(1.0, max) == max`; round-trip `bytes_to_track ∘ track_to_bytes` within epsilon.

**Slint-side smoke test:** one test in `crates/utmost-gui/tests/` that drives the adapter through `set_filter_state(...)` and checks rendered `DetailPage` properties. Not exhaustive — the view-model tests carry the logic.

## Implementation phases

1. **View-model extensions** — `SortKey::{FileType, SourceOffset}`, `FilterState` new fields, `set_thumbnail_ready`, `size_filter_max`, updated `visible_ids()` + sort, byte-conversion helpers, all unit tests. No Slint changes yet.
2. **`RangeSlider` Slint component** — `crates/utmost-gui/ui/range_slider.slint`. Visual + drag logic only; no view-model knowledge.
3. **`DetailPage` markup additions** — new top-toolbar controls (sort combo + dir + bookmarked-first + hide-no-preview pill), new size-slider row inside the filters block, new properties/callbacks.
4. **Adapter wiring** — `slint_adapter.rs` callbacks update `FilterState` and call `push_to_ui()`; thumbnail completion path calls `set_thumbnail_ready`.
5. **Polish & manual UX pass** — narrow-window wrapping, dir-button hover state, slider hidden on empty set, log-conversion edge cases (sub-1 B files, single-file runs).

## Non-goals

- **No persistence across runs.** `FilterState` stays in-memory only, consistent with the rest of the app.
- **No keyboard shortcuts** for sort or size. Can be added later.
- **No "Reset filters" button.** Existing chip-toggle model covers per-filter reset case-by-case.
- **No animation** on slider drag or filter changes.
- **No throttling/debouncing** of `size-range-changed` in v1. `visible_ids()` is already `O(files)` with small constants; if profiling later shows lag on 100k+ files, add a 16 ms throttle in the adapter.
