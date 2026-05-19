# Filter Groups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the flat chip filter bar with a two-row grouped tab system (Image / Text / Video / Archives / Executables / Other), keeping the Bookmarked pill in the toolbar.

**Architecture:** All grouping logic and new UI state (`selected_group`, `filters_visible`) live in `ViewModel`; the adapter and Slint layer just render what they're given. Two new on-demand methods (`group_chip_descriptors()`, `sub_filter_chips()`) replace the single `filter_chips()` call in the sync loop.

**Tech Stack:** Rust, Slint 1.x, `crates/utmost-gui`

---

## File map

| File | Role |
|---|---|
| `crates/utmost-gui/src/view_model.rs` | Add `Group` enum, `GroupChipDescriptor`, new ViewModel fields, new methods |
| `crates/utmost-gui/ui/detail.slint` | Add `GroupTabData` struct, new properties/callbacks, revised layout |
| `crates/utmost-gui/src/slint_adapter.rs` | Add `group_chips_model`, wire new callbacks, update sync loop |

---

### Task 1: Group enum and file_type_group() mapping

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs`

- [ ] **Step 1: Write the failing test**

Add inside `#[cfg(test)] mod tests { ... }` at the bottom of `view_model.rs`:

```rust
#[test]
fn file_type_group_maps_all_variants() {
    use FileType::*;
    assert_eq!(file_type_group(Jpeg),       Group::Image);
    assert_eq!(file_type_group(Gif),        Group::Image);
    assert_eq!(file_type_group(Bmp),        Group::Image);
    assert_eq!(file_type_group(Png),        Group::Image);
    assert_eq!(file_type_group(VJpeg),      Group::Image);
    assert_eq!(file_type_group(Mpg),        Group::Video);
    assert_eq!(file_type_group(Avi),        Group::Video);
    assert_eq!(file_type_group(Wmv),        Group::Video);
    assert_eq!(file_type_group(Mov),        Group::Video);
    assert_eq!(file_type_group(Mp4),        Group::Video);
    assert_eq!(file_type_group(Riff),       Group::Video);
    assert_eq!(file_type_group(Pdf),        Group::Text);
    assert_eq!(file_type_group(Doc),        Group::Text);
    assert_eq!(file_type_group(Htm),        Group::Text);
    assert_eq!(file_type_group(Docx),       Group::Text);
    assert_eq!(file_type_group(Xlsx),       Group::Text);
    assert_eq!(file_type_group(Pptx),       Group::Text);
    assert_eq!(file_type_group(Xls),        Group::Text);
    assert_eq!(file_type_group(Ppt),        Group::Text);
    assert_eq!(file_type_group(Wpd),        Group::Text);
    assert_eq!(file_type_group(Sxw),        Group::Text);
    assert_eq!(file_type_group(Sxc),        Group::Text);
    assert_eq!(file_type_group(Sxi),        Group::Text);
    assert_eq!(file_type_group(Ole),        Group::Text);
    assert_eq!(file_type_group(Cpp),        Group::Text);
    assert_eq!(file_type_group(Config),     Group::Text);
    assert_eq!(file_type_group(Reg),        Group::Text);
    assert_eq!(file_type_group(Zip),        Group::Archives);
    assert_eq!(file_type_group(Rar),        Group::Archives);
    assert_eq!(file_type_group(Gzip),       Group::Archives);
    assert_eq!(file_type_group(Exe),        Group::Executables);
    assert_eq!(file_type_group(Elf),        Group::Executables);
    assert_eq!(file_type_group(Wav),        Group::Other);
}
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
cargo test -p utmost-gui file_type_group_maps_all_variants 2>&1 | tail -10
```

Expected: `error[E0425]: cannot find function 'file_type_group'`

- [ ] **Step 3: Add the Group enum and mapping**

In `view_model.rs`, after the `NavDirection` enum (around line 154), add:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Group {
    Image,
    Text,
    Video,
    Archives,
    Executables,
    Other,
}

impl Group {
    pub fn as_key_str(self) -> &'static str {
        match self {
            Group::Image => "image",
            Group::Text => "text",
            Group::Video => "video",
            Group::Archives => "archives",
            Group::Executables => "executables",
            Group::Other => "other",
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Group::Image => "Image",
            Group::Text => "Text",
            Group::Video => "Video",
            Group::Archives => "Archives",
            Group::Executables => "Executables",
            Group::Other => "Other",
        }
    }

    pub fn from_key_str(s: &str) -> Option<Self> {
        match s {
            "image" => Some(Group::Image),
            "text" => Some(Group::Text),
            "video" => Some(Group::Video),
            "archives" => Some(Group::Archives),
            "executables" => Some(Group::Executables),
            "other" => Some(Group::Other),
            _ => None,
        }
    }
}

pub fn file_type_group(ft: FileType) -> Group {
    match ft {
        FileType::Jpeg
        | FileType::Gif
        | FileType::Bmp
        | FileType::Png
        | FileType::VJpeg => Group::Image,
        FileType::Mpg
        | FileType::Avi
        | FileType::Wmv
        | FileType::Mov
        | FileType::Mp4
        | FileType::Riff => Group::Video,
        FileType::Pdf
        | FileType::Doc
        | FileType::Htm
        | FileType::Docx
        | FileType::Xlsx
        | FileType::Pptx
        | FileType::Xls
        | FileType::Ppt
        | FileType::Wpd
        | FileType::Sxw
        | FileType::Sxc
        | FileType::Sxi
        | FileType::Ole
        | FileType::Cpp
        | FileType::Config
        | FileType::Reg => Group::Text,
        FileType::Zip | FileType::Rar | FileType::Gzip => Group::Archives,
        FileType::Exe | FileType::Elf => Group::Executables,
        FileType::Wav => Group::Other,
    }
}
```

- [ ] **Step 4: Run test to confirm it passes**

```bash
cargo test -p utmost-gui file_type_group_maps_all_variants 2>&1 | tail -5
```

Expected: `test file_type_group_maps_all_variants ... ok`

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-gui/src/view_model.rs
git commit -m "feat(gui): Group enum + file_type_group() mapping"
```

---

### Task 2: GroupChipDescriptor + group_chip_descriptors() method

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs`

- [ ] **Step 1: Write the failing tests**

Add to the test module:

```rust
#[test]
fn group_chip_descriptors_empty_when_no_files() {
    let vm = ViewModel::new();
    assert!(vm.group_chip_descriptors().is_empty());
}

#[test]
fn group_chip_descriptors_single_group_returns_empty() {
    // Single group → skip Row A (tab row) entirely
    let mut vm = ViewModel::new();
    vm.apply(&run_started_with_sources(&[0]));
    vm.apply(&CarveEvent::FileFound {
        source_id: 0,
        file: create_file_object("a.jpg", FileType::Jpeg, 100, 0, None, 1),
        img_offset: 0,
        written_path: "a.jpg".into(),
    });
    vm.apply(&CarveEvent::FileFound {
        source_id: 0,
        file: create_file_object("b.gif", FileType::Gif, 100, 0, None, 2),
        img_offset: 0,
        written_path: "b.gif".into(),
    });
    assert!(vm.group_chip_descriptors().is_empty());
}

#[test]
fn group_chip_descriptors_multi_group_shows_present_groups() {
    let mut vm = ViewModel::new();
    vm.apply(&run_started_with_sources(&[0]));
    vm.apply(&CarveEvent::FileFound {
        source_id: 0,
        file: create_file_object("a.jpg", FileType::Jpeg, 100, 0, None, 1),
        img_offset: 0,
        written_path: "a.jpg".into(),
    });
    vm.apply(&CarveEvent::FileFound {
        source_id: 0,
        file: create_file_object("b.zip", FileType::Zip, 100, 0, None, 2),
        img_offset: 0,
        written_path: "b.zip".into(),
    });
    let tabs = vm.group_chip_descriptors();
    assert_eq!(tabs.len(), 2);
    assert_eq!(tabs[0].name, "image");
    assert_eq!(tabs[1].name, "archives");
}

#[test]
fn group_chip_descriptors_active_count_reflects_enabled_types() {
    let mut vm = ViewModel::new();
    vm.apply(&run_started_with_sources(&[0]));
    vm.apply(&CarveEvent::FileFound {
        source_id: 0,
        file: create_file_object("a.jpg", FileType::Jpeg, 100, 0, None, 1),
        img_offset: 0,
        written_path: "a.jpg".into(),
    });
    vm.apply(&CarveEvent::FileFound {
        source_id: 0,
        file: create_file_object("b.gif", FileType::Gif, 100, 0, None, 2),
        img_offset: 0,
        written_path: "b.gif".into(),
    });
    vm.apply(&CarveEvent::FileFound {
        source_id: 0,
        file: create_file_object("c.zip", FileType::Zip, 100, 0, None, 3),
        img_offset: 0,
        written_path: "c.zip".into(),
    });
    // Both Jpeg and Gif are enabled by default (run_started populates enabled_types)
    let tabs = vm.group_chip_descriptors();
    let img = tabs.iter().find(|t| t.name == "image").unwrap();
    assert_eq!(img.active_count, 2); // Jpeg + Gif both enabled
    // Disable Jpeg
    vm.filter.enabled_types.remove(&FileType::Jpeg);
    let tabs = vm.group_chip_descriptors();
    let img = tabs.iter().find(|t| t.name == "image").unwrap();
    assert_eq!(img.active_count, 1); // only Gif enabled
}

#[test]
fn group_chip_descriptors_is_selected_reflects_selected_group() {
    let mut vm = ViewModel::new();
    vm.apply(&run_started_with_sources(&[0]));
    vm.apply(&CarveEvent::FileFound {
        source_id: 0,
        file: create_file_object("a.jpg", FileType::Jpeg, 100, 0, None, 1),
        img_offset: 0,
        written_path: "a.jpg".into(),
    });
    vm.apply(&CarveEvent::FileFound {
        source_id: 0,
        file: create_file_object("b.zip", FileType::Zip, 100, 0, None, 2),
        img_offset: 0,
        written_path: "b.zip".into(),
    });
    vm.selected_group = Some(Group::Image);
    let tabs = vm.group_chip_descriptors();
    assert!(tabs.iter().find(|t| t.name == "image").unwrap().is_selected);
    assert!(!tabs.iter().find(|t| t.name == "archives").unwrap().is_selected);
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cargo test -p utmost-gui group_chip_descriptors 2>&1 | tail -10
```

Expected: compile errors about missing `GroupChipDescriptor`, `group_chip_descriptors`, `selected_group`.

- [ ] **Step 3: Add GroupChipDescriptor struct and ViewModel fields**

In `view_model.rs`, after `FilterChipDescriptor` (around line 152), add:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupChipDescriptor {
    pub name: String,
    pub display_name: String,
    pub active_count: i32,
    pub is_selected: bool,
}
```

In the `ViewModel` struct, add two fields after `next_note_id`:

```rust
pub selected_group: Option<Group>,
pub filters_visible: bool,
```

In `ViewModel::new()`, change it to set `filters_visible: true`:

```rust
pub fn new() -> Self {
    Self {
        filters_visible: true,
        ..Self::default()
    }
}
```

- [ ] **Step 4: Add group_chip_descriptors() method**

Inside `impl ViewModel`, add after `filter_chips()`:

```rust
pub fn group_chip_descriptors(&self) -> Vec<GroupChipDescriptor> {
    use std::collections::BTreeMap;

    // Build map of Group → FileTypes present (using type_counts as source of truth)
    let mut groups: BTreeMap<Group, Vec<FileType>> = BTreeMap::new();
    for ft in self.type_counts.keys() {
        groups.entry(file_type_group(*ft)).or_default().push(*ft);
    }

    // Single-group optimization: return empty so Row A is hidden
    if groups.len() <= 1 {
        return vec![];
    }

    groups
        .iter()
        .map(|(g, types)| {
            let active_count = types
                .iter()
                .filter(|ft| self.filter.enabled_types.contains(*ft))
                .count() as i32;
            GroupChipDescriptor {
                name: g.as_key_str().to_string(),
                display_name: g.display_name().to_string(),
                active_count,
                is_selected: self.selected_group == Some(*g),
            }
        })
        .collect()
}
```

- [ ] **Step 5: Run tests to confirm they pass**

```bash
cargo test -p utmost-gui group_chip_descriptors 2>&1 | tail -10
```

Expected: all 5 tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-gui/src/view_model.rs
git commit -m "feat(gui): GroupChipDescriptor + group_chip_descriptors()"
```

---

### Task 3: sub_filter_chips() method

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs`

- [ ] **Step 1: Write the failing tests**

Add to the test module:

```rust
#[test]
fn sub_filter_chips_empty_when_no_group_selected_and_multi_group() {
    let mut vm = ViewModel::new();
    vm.apply(&run_started_with_sources(&[0]));
    vm.apply(&CarveEvent::FileFound {
        source_id: 0,
        file: create_file_object("a.jpg", FileType::Jpeg, 100, 0, None, 1),
        img_offset: 0,
        written_path: "a.jpg".into(),
    });
    vm.apply(&CarveEvent::FileFound {
        source_id: 0,
        file: create_file_object("b.zip", FileType::Zip, 100, 0, None, 2),
        img_offset: 0,
        written_path: "b.zip".into(),
    });
    // multi-group, no tab selected
    assert!(vm.selected_group.is_none());
    assert!(vm.sub_filter_chips().is_empty());
}

#[test]
fn sub_filter_chips_returns_selected_group_types() {
    let mut vm = ViewModel::new();
    vm.apply(&run_started_with_sources(&[0]));
    vm.apply(&CarveEvent::FileFound {
        source_id: 0,
        file: create_file_object("a.jpg", FileType::Jpeg, 100, 0, None, 1),
        img_offset: 0,
        written_path: "a.jpg".into(),
    });
    vm.apply(&CarveEvent::FileFound {
        source_id: 0,
        file: create_file_object("b.gif", FileType::Gif, 100, 0, None, 2),
        img_offset: 0,
        written_path: "b.gif".into(),
    });
    vm.apply(&CarveEvent::FileFound {
        source_id: 0,
        file: create_file_object("c.zip", FileType::Zip, 100, 0, None, 3),
        img_offset: 0,
        written_path: "c.zip".into(),
    });
    vm.selected_group = Some(Group::Image);
    let chips = vm.sub_filter_chips();
    let names: Vec<&str> = chips.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"jpeg"), "expected jpeg in {names:?}");
    assert!(names.contains(&"gif"),  "expected gif in {names:?}");
    assert!(!names.contains(&"zip"), "zip should not appear in Image tab");
    assert!(chips.iter().all(|c| c.kind == FilterChipKind::Type || c.kind == FilterChipKind::Partial));
}

#[test]
fn sub_filter_chips_single_group_shows_all_types_without_selection() {
    // Single group → no tabs, but sub-row shows all types
    let mut vm = ViewModel::new();
    vm.apply(&run_started_with_sources(&[0]));
    vm.apply(&CarveEvent::FileFound {
        source_id: 0,
        file: create_file_object("a.jpg", FileType::Jpeg, 100, 0, None, 1),
        img_offset: 0,
        written_path: "a.jpg".into(),
    });
    vm.apply(&CarveEvent::FileFound {
        source_id: 0,
        file: create_file_object("b.gif", FileType::Gif, 100, 0, None, 2),
        img_offset: 0,
        written_path: "b.gif".into(),
    });
    // selected_group is None but only Image group is present → show all
    assert!(vm.selected_group.is_none());
    let chips = vm.sub_filter_chips();
    let names: Vec<&str> = chips.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"jpeg"));
    assert!(names.contains(&"gif"));
}

#[test]
fn sub_filter_chips_excludes_bookmarked() {
    let mut vm = ViewModel::new();
    vm.apply(&run_started_with_sources(&[0]));
    vm.apply(&CarveEvent::FileFound {
        source_id: 0,
        file: create_file_object("a.jpg", FileType::Jpeg, 100, 0, None, 1),
        img_offset: 0,
        written_path: "a.jpg".into(),
    });
    let chips = vm.sub_filter_chips();
    assert!(chips.iter().all(|c| c.kind != FilterChipKind::Bookmarked));
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cargo test -p utmost-gui sub_filter_chips 2>&1 | tail -10
```

Expected: compile error — `sub_filter_chips` not found.

- [ ] **Step 3: Add sub_filter_chips() method**

Inside `impl ViewModel`, add after `group_chip_descriptors()`:

```rust
pub fn sub_filter_chips(&self) -> Vec<FilterChipDescriptor> {
    use std::collections::BTreeMap;

    let mut groups: BTreeMap<Group, Vec<FileType>> = BTreeMap::new();
    for ft in self.type_counts.keys() {
        groups.entry(file_type_group(*ft)).or_default().push(*ft);
    }

    let is_single_group = groups.len() <= 1;

    // Determine which types to show
    let types_to_show: std::collections::BTreeSet<FileType> = if is_single_group {
        self.type_counts.keys().copied().collect()
    } else if let Some(sg) = self.selected_group {
        groups.get(&sg).cloned().unwrap_or_default().into_iter().collect()
    } else {
        std::collections::BTreeSet::new()
    };

    if types_to_show.is_empty() {
        return vec![];
    }

    let mut chips: Vec<FilterChipDescriptor> = self
        .type_counts
        .iter()
        .filter(|(ft, _)| types_to_show.contains(*ft))
        .map(|(ft, count)| {
            let debug = format!("{ft:?}");
            FilterChipDescriptor {
                name: debug.to_lowercase(),
                display_name: debug,
                enabled: self.filter.enabled_types.contains(ft),
                count: *count as i32,
                kind: FilterChipKind::Type,
            }
        })
        .collect();

    for (ft, count) in &self.partial_counts {
        if types_to_show.contains(ft) {
            let ft_string = format!("{ft:?}").to_lowercase();
            chips.push(FilterChipDescriptor {
                name: format!("partial:{ft_string}"),
                display_name: format!("{ft:?}"),
                enabled: self.filter.enabled_partial_types.contains(ft),
                count: *count as i32,
                kind: FilterChipKind::Partial,
            });
        }
    }

    chips
}
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
cargo test -p utmost-gui sub_filter_chips 2>&1 | tail -10
```

Expected: all 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-gui/src/view_model.rs
git commit -m "feat(gui): sub_filter_chips() for grouped tab sub-row"
```

---

### Task 4: set_selected_group() and toggle_filters_visible()

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs`

- [ ] **Step 1: Write the failing tests**

Add to the test module:

```rust
#[test]
fn set_selected_group_selects_group() {
    let mut vm = ViewModel::new();
    assert!(vm.selected_group.is_none());
    vm.set_selected_group("image");
    assert_eq!(vm.selected_group, Some(Group::Image));
}

#[test]
fn set_selected_group_deselects_when_same_group_clicked() {
    let mut vm = ViewModel::new();
    vm.set_selected_group("image");
    vm.set_selected_group("image"); // click active tab again
    assert!(vm.selected_group.is_none());
}

#[test]
fn set_selected_group_switches_to_different_group() {
    let mut vm = ViewModel::new();
    vm.set_selected_group("image");
    vm.set_selected_group("video");
    assert_eq!(vm.selected_group, Some(Group::Video));
}

#[test]
fn set_selected_group_ignores_unknown_key() {
    let mut vm = ViewModel::new();
    vm.set_selected_group("bogus");
    assert!(vm.selected_group.is_none());
}

#[test]
fn toggle_filters_visible_flips_state() {
    let mut vm = ViewModel::new();
    assert!(vm.filters_visible); // new() defaults to true
    vm.toggle_filters_visible();
    assert!(!vm.filters_visible);
    vm.toggle_filters_visible();
    assert!(vm.filters_visible);
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cargo test -p utmost-gui "set_selected_group|toggle_filters_visible" 2>&1 | tail -10
```

Expected: compile error — methods not found.

- [ ] **Step 3: Add the methods**

Inside `impl ViewModel`, add after `sub_filter_chips()`:

```rust
pub fn set_selected_group(&mut self, name: &str) {
    let group = Group::from_key_str(name);
    if group == self.selected_group {
        self.selected_group = None;
    } else {
        self.selected_group = group;
    }
}

pub fn toggle_filters_visible(&mut self) {
    self.filters_visible = !self.filters_visible;
}
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
cargo test -p utmost-gui "set_selected_group|toggle_filters_visible" 2>&1 | tail -10
```

Expected: all 5 tests pass.

- [ ] **Step 5: Run full test suite to make sure nothing is broken**

```bash
cargo test -p utmost-gui 2>&1 | tail -15
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-gui/src/view_model.rs
git commit -m "feat(gui): set_selected_group() + toggle_filters_visible()"
```

---

### Task 5: Slint — GroupTabData struct and new DetailPage properties/callbacks

**Files:**
- Modify: `crates/utmost-gui/ui/detail.slint`

- [ ] **Step 1: Add GroupTabData struct and new properties/callbacks**

At the top of `detail.slint`, after the `VariantThumbData` struct (around line 31), add:

```slint
export struct GroupTabData {
    name: string,
    display_name: string,
    active_count: int,
    is_selected: bool,
}
```

Inside `DetailPage`, after the existing `in-out property <int> selected-id: -1;` (around line 89), add:

```slint
in-out property <[GroupTabData]> group-chips: [];
in-out property <bool> filters-visible: true;
in-out property <bool> bookmarked-filter-enabled: false;

callback group-tab-clicked(string);
callback filters-toggle();
callback bookmarked-filter-toggle();
```

- [ ] **Step 2: Verify the build**

```bash
cargo build -p utmost-gui 2>&1 | tail -10
```

Expected: `Finished` with no errors.

- [ ] **Step 3: Commit**

```bash
git add crates/utmost-gui/ui/detail.slint
git commit -m "feat(gui): GroupTabData + new DetailPage properties and callbacks"
```

---

### Task 6: Slint — revised toolbar and new filter area layout

**Files:**
- Modify: `crates/utmost-gui/ui/detail.slint`

- [ ] **Step 1: Replace the toolbar HorizontalBox**

Find and replace the current toolbar `HorizontalBox` (lines 159–202, the one containing Back/Select all/Select none/for-chip):

Old:
```slint
        HorizontalBox {
            Button {
                text: "Back";
                clicked => {
                    root.back();
                }
            }
            Button {
                text: "Select all";
                clicked => {
                    root.select-all();
                }
            }
            Button {
                text: "Select none";
                clicked => {
                    root.select-none();
                }
            }
            for chip in root.chips: Rectangle {
                background: chip.enabled
                    ? (chip.kind == "partial" ? #c66 : (chip.kind == "bookmarked" ? #cc6 : #3a6))
                    : #555;
                border-radius: 12px;
                width: chip.kind == "partial" ? 130px : (chip.kind == "bookmarked" ? 130px : 90px);
                height: 28px;
                TouchArea {
                    clicked => { root.chip-toggled(chip.name); }
                }
                // display_name is always non-empty for type, partial, and bookmarked chips;
                // the fallback to chip.name is defensive only.
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
            }
        }
```

New:
```slint
        HorizontalBox {
            Button {
                text: "Back";
                clicked => { root.back(); }
            }
            Button {
                text: "Select all";
                clicked => { root.select-all(); }
            }
            Button {
                text: "Select none";
                clicked => { root.select-none(); }
            }
            Button {
                text: root.filters-visible ? "Hide filters" : "Show filters";
                clicked => { root.filters-toggle(); }
            }
            Rectangle {
                background: root.bookmarked-filter-enabled ? #cc6 : #555;
                border-radius: 12px;
                width: 130px;
                height: 28px;
                TouchArea {
                    clicked => { root.bookmarked-filter-toggle(); }
                }
                Text {
                    text: "Bookmarked";
                    color: white;
                    horizontal-alignment: center;
                    vertical-alignment: center;
                }
            }
        }
```

- [ ] **Step 2: Add the filter area between toolbar and grid HorizontalBox**

Immediately after the toolbar `HorizontalBox` closing brace and before the `HorizontalBox {` that contains `grid_pane`, add:

```slint
        if root.filters-visible: VerticalBox {
            padding: 0px;
            spacing: 4px;
            if root.group-chips.length > 0: HorizontalBox {
                padding: 0px;
                for g in root.group-chips: Rectangle {
                    background: g.is_selected ? #3a6 : #555;
                    border-radius: 12px;
                    width: 110px;
                    height: 28px;
                    TouchArea {
                        clicked => { root.group-tab-clicked(g.name); }
                    }
                    Text {
                        text: g.display_name + " (" + g.active_count + ")";
                        color: white;
                        horizontal-alignment: center;
                        vertical-alignment: center;
                    }
                }
            }
            HorizontalBox {
                padding: 0px;
                for chip in root.chips: Rectangle {
                    background: chip.enabled
                        ? (chip.kind == "partial" ? #c66 : #3a6)
                        : #555;
                    border-radius: 12px;
                    width: chip.kind == "partial" ? 130px : 90px;
                    height: 28px;
                    TouchArea {
                        clicked => { root.chip-toggled(chip.name); }
                    }
                    Text {
                        text: (chip.kind == "partial" ? "Partial " : "")
                            + (chip.display_name == "" ? chip.name : chip.display_name)
                            + " (" + chip.count + ")";
                        color: white;
                        horizontal-alignment: center;
                        vertical-alignment: center;
                    }
                }
            }
        }
```

- [ ] **Step 3: Verify the build**

```bash
cargo build -p utmost-gui 2>&1 | tail -10
```

Expected: `Finished` with no errors.

- [ ] **Step 4: Commit**

```bash
git add crates/utmost-gui/ui/detail.slint
git commit -m "feat(gui): grouped filter bar layout — tab row + sub-chip row"
```

---

### Task 7: Adapter — group_chips_model field and new callback wiring

**Files:**
- Modify: `crates/utmost-gui/src/slint_adapter.rs`

- [ ] **Step 1: Add group_chips_model to UiState**

In the `UiState` struct (around line 36), add after `chips_model`:

```rust
pub group_chips_model: Rc<VecModel<GroupTabData>>,
```

- [ ] **Step 2: Initialise the model in UiState::new()**

After `window.set_chips(chips_model.clone().into());` (around line 80), add:

```rust
let group_chips_model: Rc<VecModel<GroupTabData>> = Rc::new(VecModel::default());
window.set_group_chips(group_chips_model.clone().into());
```

- [ ] **Step 3: Wire the three new callbacks**

After the existing `on_chip_toggled` block (around line 152), add three new callback blocks:

```rust
{
    let vm_cb = vm.clone();
    window.on_group_tab_clicked(move |name| {
        let mut v = vm_cb.lock().unwrap();
        v.set_selected_group(name.as_str());
    });
}
{
    let vm_cb = vm.clone();
    window.on_filters_toggle(move || {
        let mut v = vm_cb.lock().unwrap();
        v.toggle_filters_visible();
    });
}
{
    let vm_cb = vm.clone();
    window.on_bookmarked_filter_toggle(move || {
        let mut v = vm_cb.lock().unwrap();
        v.filter.bookmarked_only = !v.filter.bookmarked_only;
        v.recompute_visible();
    });
}
```

- [ ] **Step 4: Drop the bookmarked branch from on_chip_toggled**

In the existing `on_chip_toggled` handler, remove these lines:

```rust
                if name == "bookmarked" {
                    v.filter.bookmarked_only = !v.filter.bookmarked_only;
                } else if let Some(ft_str) = name.strip_prefix("partial:") {
```

Replace with:

```rust
                if let Some(ft_str) = name.strip_prefix("partial:") {
```

- [ ] **Step 5: Add group_chips_model to the Ok(Self { ... }) return**

In the `Ok(Self { ... })` block at the end of `UiState::new()`, add:

```rust
group_chips_model,
```

- [ ] **Step 6: Verify the build**

```bash
cargo build -p utmost-gui 2>&1 | tail -10
```

Expected: `Finished` with no errors. If there are unused-import warnings, note them for the next step.

- [ ] **Step 7: Commit**

```bash
git add crates/utmost-gui/src/slint_adapter.rs
git commit -m "feat(gui): group_chips_model + new callback wiring in adapter"
```

---

### Task 8: Adapter sync loop — replace filter_chips() with new methods

**Files:**
- Modify: `crates/utmost-gui/src/slint_adapter.rs`

- [ ] **Step 1: Replace the chips sync block in the sync method**

Find the chips sync block (around line 592–606):

```rust
        // Chips (filter chips): delegate to ViewModel::filter_chips() so the
        // chip set is testable without the Slint layer.
        let chips: Vec<FilterChipData> = vm
            .filter_chips()
            .into_iter()
            .map(|c| FilterChipData {
                name: SharedString::from(c.name),
                display_name: SharedString::from(c.display_name),
                enabled: c.enabled,
                count: c.count,
                kind: SharedString::from(c.kind.as_wire_str()),
            })
            .collect();

        replace_model(&self.chips_model, chips);
```

Replace with:

```rust
        // Sub-chips: type + partial chips for the currently selected group tab.
        let chips: Vec<FilterChipData> = vm
            .sub_filter_chips()
            .into_iter()
            .map(|c| FilterChipData {
                name: SharedString::from(c.name),
                display_name: SharedString::from(c.display_name),
                enabled: c.enabled,
                count: c.count,
                kind: SharedString::from(c.kind.as_wire_str()),
            })
            .collect();
        replace_model(&self.chips_model, chips);

        // Group tab chips (Row A).
        let group_chips: Vec<GroupTabData> = vm
            .group_chip_descriptors()
            .into_iter()
            .map(|g| GroupTabData {
                name: SharedString::from(g.name),
                display_name: SharedString::from(g.display_name),
                active_count: g.active_count,
                is_selected: g.is_selected,
            })
            .collect();
        replace_model(&self.group_chips_model, group_chips);

        // Bookmarked filter pill in toolbar.
        self.window
            .set_bookmarked_filter_enabled(vm.filter.bookmarked_only);

        // Filter area visibility.
        self.window.set_filters_visible(vm.filters_visible);
```

- [ ] **Step 2: Verify the build**

```bash
cargo build -p utmost-gui 2>&1 | tail -10
```

Expected: `Finished` with no errors.

- [ ] **Step 3: Run all tests**

```bash
cargo test -p utmost-gui 2>&1 | tail -20
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add crates/utmost-gui/src/slint_adapter.rs
git commit -m "feat(gui): sync group tabs + sub-chips via new ViewModel methods"
```

---

### Task 9: Lint, format, and full test run

**Files:** none (verification only)

- [ ] **Step 1: Format**

```bash
cargo fmt
```

- [ ] **Step 2: Clippy**

```bash
cargo clippy --all-targets 2>&1 | grep -E "^error|^warning\[" | head -20
```

Expected: no errors. Fix any warnings that appear (unused imports, dead code, etc.) then re-run.

- [ ] **Step 3: Full test suite**

```bash
cargo test 2>&1 | tail -20
```

Expected: all tests pass across all crates.

- [ ] **Step 4: Commit any lint fixes**

```bash
git add -p   # stage only lint-fix changes
git commit -m "chore: fmt + clippy fixes for filter groups feature"
```

If no changes needed, skip this step.
