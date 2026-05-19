# Filter Groups Design

**Date:** 2026-05-18
**Status:** Approved

## Goal

Replace the flat single-row chip filter bar with a two-row grouped tab system. The top row shows file-type groups (Image, Text, Video, Archives, Executables, Other) as navigation tabs. The bottom row shows the specific sub-types for the selected tab. A Show/Hide Filters button controls visibility. The Bookmarked filter moves to the toolbar row.

## File Type → Group Mapping

| Group | FileType variants |
|---|---|
| Image | Jpeg, Gif, Bmp, Png, VJpeg |
| Video | Mpg, Avi, Wmv, Mov, Mp4, Riff |
| Text | Pdf, Doc, Htm, Docx, Xlsx, Pptx, Xls, Ppt, Wpd, Sxw, Sxc, Sxi, Ole, Cpp, Config, Reg |
| Archives | Zip, Rar, Gzip |
| Executables | Exe, Elf |
| Other | Wav |

Partial-type chips (kind == "partial") follow the same group as their base type and appear alongside regular types in the sub-row.

This mapping lives in a single pure function `file_type_group(ft: FileType) -> Group` in `view_model.rs`, making it easy to extend when new file types are added.

## Data Model

Three outputs replace the single flat `chips` list:

### GroupTabData (new)
```
name: string          // machine key: "image", "text", etc.
display_name: string  // "Image", "Text", etc.
active_count: int     // count of enabled sub-types in this group
is_selected: bool
```

### sub_chips (repurposes existing chips model)
`Vec<FilterChipData>` — type + partial chips for the currently selected tab. Empty when no tab is selected in multi-group mode. Contains all types when in single-group mode.

### Bookmarked
Exits the chips model. Becomes a dedicated `bookmarked_filter_enabled: bool` Slint property, toggled via a new `bookmarked-filter-toggle()` callback.

## ViewModel Changes (`view_model.rs`)

### New types
```rust
pub enum Group { Image, Text, Video, Archives, Executables, Other }
pub fn file_type_group(ft: FileType) -> Group { ... }
```

### New fields on ViewModel
```rust
pub selected_group: Option<Group>  // None = no tab selected; persists across filter hide/show
pub filters_visible: bool          // default: true
// computed, populated by recompute_chips():
pub computed_group_chips: Vec<GroupTabData>
pub computed_sub_chips: Vec<FilterChipData>
```

### recompute_chips() — called at the end of recompute_visible()
1. Walk `visible_files`, collect which groups have at least one file and which `FileType`s are present.
2. Count types per group that are both present in `visible_files` AND in `filter.enabled_types` → `active_count`.
3. **Single-group optimization:** if exactly one group has any files, set `computed_group_chips = vec![]` and `computed_sub_chips` = all chips for that group (ignoring `selected_group`).
4. Otherwise: build `computed_group_chips` (one per present group, sorted by Group discriminant), set `computed_sub_chips` = chips for `selected_group` (empty vec if `None`).

### New methods
- `set_selected_group(&str)` — parses name to Group; clicking the active tab deselects it (sets to None); calls `recompute_chips()`.
- `toggle_filters_visible()` — flips `filters_visible`; no chip recompute needed.

## Slint Changes (`detail.slint`)

### New struct and properties on DetailPage
```
struct GroupTabData { name: string, display_name: string, active_count: int, is_selected: bool }

in-out property <[GroupTabData]> group-chips: []
in-out property <bool> filters-visible: true
in-out property <bool> bookmarked-filter-enabled: false
callback group-tab-clicked(string)
callback filters-toggle()
callback bookmarked-filter-toggle()
```

### Layout
```
VerticalBox {
    // Toolbar row
    HorizontalBox {
        Button { "Back" }
        Button { "Select all" }
        Button { "Select none" }
        Button { filters-visible ? "Hide filters" : "Show filters" }  // => filters-toggle()
        [Bookmarked pill — inline, driven by bookmarked-filter-enabled]  // => bookmarked-filter-toggle()
    }

    // Filter area — conditional
    if root.filters-visible: VerticalBox {
        // Row A: group tabs — hidden when only one group present
        if root.group-chips.length > 0: HorizontalBox {
            for g in root.group-chips:
                [tab pill: g.display_name + " (" + g.active_count + ")", highlighted if g.is_selected]
                => group-tab-clicked(g.name)
        }
        // Row B: sub-type chips (empty if no tab selected in multi-group mode)
        HorizontalBox {
            for chip in root.chips: [existing chip pill rendering, unchanged]
        }
    }

    // Gallery grid + side panel — unchanged
    HorizontalBox { ... }
}
```

## Adapter & Sync Changes (`slint_adapter.rs`)

### UiState
Add `group_chips_model: Rc<VecModel<GroupTabData>>`, registered with `window.set_group_chips(...)`.

### New callbacks (in UiState::new)
- `on_group_tab_clicked` → `vm.set_selected_group(&name)`
- `on_filters_toggle` → `vm.toggle_filters_visible()`
- `on_bookmarked_filter_toggle` → `v.filter.bookmarked_only = !v.filter.bookmarked_only; v.recompute_visible()`

### Modified callbacks
- `on_chip_toggled`: drop the `"bookmarked"` branch (handled by `on_bookmarked_filter_toggle`). Type and partial branches unchanged.

### Sync loop additions
```rust
replace_model(&group_chips_model, vm.computed_group_chips.clone());
replace_model(&chips_model, vm.computed_sub_chips.clone());
window.set_bookmarked_filter_enabled(vm.filter.bookmarked_only);
window.set_filters_visible(vm.filters_visible);
```

## Behavior Notes

- **Tab persistence:** `selected_group` lives in the ViewModel and is never reset by `toggle_filters_visible()`, so the same tab is shown when filters are re-opened.
- **Initial state:** `selected_group` is `None`; in multi-group mode the sub-row is empty until the user picks a tab.
- **Deselect:** clicking the active tab again sets `selected_group = None`, collapsing the sub-row.
- **Single-group shortcut:** when all carved files belong to one group, Row A is omitted and sub-types are shown directly, with no tab interaction needed.

## Testing

- Unit tests in `view_model.rs` for `recompute_chips()`: multi-group, single-group optimization, tab select/deselect, active_count accuracy, partial chips in correct group.
- Extend existing integration test or add a new one covering: filter toggle visibility, group tab click → sub-chips change, bookmarked toggle.
