//! Pure-Rust view-model that consumes CarveEvents. No Slint imports.

use std::collections::{BTreeMap, BTreeSet};
use utmost_lib::events::CarveEvent;
use utmost_lib::types::FileType;

// Core data types now live in `utmost_index::model` (and `db::models`) after
// the Diesel→turso migration. Re-export them so the GUI's existing
// `crate::view_model::*` paths keep resolving unchanged.
pub use utmost_index::db::models::FileStub;
pub use utmost_index::model::{
    FileId, FilterState, FilterStateSnapshot, FoundFile, NoteEntry, RecoveryUiState, RunStatus,
    RunSummary, SortDir, SortKey, SourceRow, SourceStatus, UiStateSnapshot, VariantSet,
    ViewModelSnapshot, parse_file_type, parse_file_type_pub,
};

/// On-disk schema version of [`UiStateSnapshot`]. Bump when adding a
/// non-additive (renamed / removed / re-typed) field and add a migration arm
/// in [`ui_snapshot_into_runtime`]. Purely additive changes don't need a bump.
pub const UI_STATE_CURRENT_VERSION: u32 = 1;

/// Build an empty [`RunSummary`] (the `Pending`, all-zero default).
///
/// `RunSummary` now lives in `utmost-index` without a `Default` impl, so this
/// helper replaces the previous `RunSummary::default()` for GUI construction.
pub fn empty_run_summary() -> RunSummary {
    RunSummary {
        started_at: String::new(),
        output_root: String::new(),
        source_image_path: String::new(),
        configured_types: Vec::new(),
        status: RunStatus::Pending,
        case: None,
        elapsed_ms: 0,
        total_files: 0,
    }
}

/// Capture the current UI-relevant subset of `vm` into a [`UiStateSnapshot`].
///
/// Free function (not an inherent method) because `UiStateSnapshot` is now a
/// foreign type from `utmost-index` and the orphan rule forbids an `impl` here.
/// Pure: no I/O, no locks held.
pub fn ui_snapshot_from_view_model(vm: &ViewModel) -> UiStateSnapshot {
    let sort_key = match vm.filter.sort_key {
        SortKey::Filename => "Filename",
        SortKey::Size => "Size",
        SortKey::FileType => "FileType",
        SortKey::SourceOffset => "SourceOffset",
    };
    let sort_dir = match vm.filter.sort_dir {
        SortDir::Asc => "Asc",
        SortDir::Desc => "Desc",
    };
    UiStateSnapshot {
        v: UI_STATE_CURRENT_VERSION,
        filter: FilterStateSnapshot {
            enabled_types: vm
                .filter
                .enabled_types
                .iter()
                .map(|ft| file_type_to_pub_str(*ft).to_string())
                .collect(),
            enabled_partial_types: vm
                .filter
                .enabled_partial_types
                .iter()
                .map(|ft| file_type_to_pub_str(*ft).to_string())
                .collect(),
            bookmarked_only: vm.filter.bookmarked_only,
            source_filter: vm.filter.source_filter,
            sort_key: sort_key.into(),
            sort_dir: sort_dir.into(),
            bookmarked_first: vm.filter.bookmarked_first,
            hide_no_preview: vm.filter.hide_no_preview,
            size_range: vm.filter.size_range,
        },
        filters_visible: vm.filters_visible,
        selected_group: vm.selected_group.map(|g| g.as_key_str().to_string()),
        selection_file_id: vm.selection,
    }
}

/// Convert `snap` into runtime ViewModel-bound values, validating against the
/// current case's run and sources. Best-effort: anything that can't be mapped
/// (unknown file types, off-configuration entries, missing sources, invalid
/// size ranges, unknown sort strings) is dropped silently or replaced with the
/// default. Never errors.
///
/// Free function for the same orphan-rule reason as
/// [`ui_snapshot_from_view_model`].
///
/// Returns: (filter, filters_visible, selected_group, selection_file_id).
/// The caller (`UiState::new`) assigns these into the live ViewModel.
pub fn ui_snapshot_into_runtime(
    snap: UiStateSnapshot,
    run: &RunSummary,
    sources: &[SourceRow],
) -> (FilterState, bool, Option<Group>, Option<FileId>) {
    // Handle schema-version drift.
    if snap.v != UI_STATE_CURRENT_VERSION {
        tracing::warn!(
            "UiStateSnapshot: unknown schema v={}, expected {}; using defaults",
            snap.v,
            UI_STATE_CURRENT_VERSION,
        );
        return (FilterState::default(), true, None, None);
    }

    let configured: std::collections::BTreeSet<FileType> =
        run.configured_types.iter().copied().collect();

    let map_types = |strings: &[String]| -> std::collections::BTreeSet<FileType> {
        strings
            .iter()
            .filter_map(|s| parse_file_type_pub(s))
            .filter(|ft| configured.is_empty() || configured.contains(ft))
            .collect()
    };

    let sort_key = match snap.filter.sort_key.as_str() {
        "Filename" => SortKey::Filename,
        "Size" => SortKey::Size,
        "FileType" => SortKey::FileType,
        "SourceOffset" => SortKey::SourceOffset,
        other => {
            tracing::debug!("UiStateSnapshot: unknown sort_key {other:?}, defaulting");
            SortKey::default()
        }
    };
    let sort_dir = match snap.filter.sort_dir.as_str() {
        "Asc" => SortDir::Asc,
        "Desc" => SortDir::Desc,
        other => {
            tracing::debug!("UiStateSnapshot: unknown sort_dir {other:?}, defaulting");
            SortDir::default()
        }
    };

    let source_filter = snap
        .filter
        .source_filter
        .filter(|sid| sources.iter().any(|s| s.source_id == *sid));

    let size_range = match snap.filter.size_range {
        Some((lo, hi)) if lo > hi => None,
        Some((0, 0)) => None,
        other => other,
    };

    let filter = FilterState {
        enabled_types: map_types(&snap.filter.enabled_types),
        enabled_partial_types: map_types(&snap.filter.enabled_partial_types),
        bookmarked_only: snap.filter.bookmarked_only,
        source_filter,
        sort_key,
        sort_dir,
        bookmarked_first: snap.filter.bookmarked_first,
        hide_no_preview: snap.filter.hide_no_preview,
        size_range,
    };

    let selected_group = snap.selected_group.as_deref().and_then(Group::from_key_str);

    (
        filter,
        snap.filters_visible,
        selected_group,
        snap.selection_file_id,
    )
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LightboxView {
    pub zoom: f32,
    pub fit: bool,
}

impl Default for LightboxView {
    fn default() -> Self {
        Self {
            zoom: 1.0,
            fit: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NoteInputState {
    pub target: FileId,
    pub draft: String,
}

/// Plain-Rust descriptor of a single filter chip. The slint_adapter maps each
/// into a Slint `FilterChipData`. Keeping the descriptor list in `ViewModel`
/// makes the chip set directly testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterChipDescriptor {
    pub name: String,
    pub display_name: String,
    pub enabled: bool,
    pub count: i32,
    pub kind: FilterChipKind,
}

/// Plain-Rust descriptor of a single group chip (the "Row A" tab bar that
/// groups file types into Image / Video / Text / Archives / Executables / Other).
/// Returned by `ViewModel::group_chip_descriptors()`. Empty when only one group
/// is present (tab row is hidden in that case).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupChipDescriptor {
    pub name: String,
    pub display_name: String,
    pub active_count: i32,
    pub is_selected: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavDirection {
    Left,
    Right,
    Up,
    Down,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Group {
    Image,
    Video,
    Text,
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
        FileType::Jpeg | FileType::Gif | FileType::Bmp | FileType::Png | FileType::VJpeg => {
            Group::Image
        }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterChipKind {
    Type,
    Partial,
    Bookmarked,
}

impl FilterChipKind {
    pub fn as_wire_str(self) -> &'static str {
        match self {
            FilterChipKind::Type => "type",
            FilterChipKind::Partial => "partial",
            FilterChipKind::Bookmarked => "bookmarked",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ViewModel {
    // ── existing fields, unchanged ──
    pub run: RunSummary,
    pub sources: Vec<SourceRow>,
    pub type_counts: BTreeMap<FileType, u64>,
    pub filter: FilterState,
    pub selection: Option<FileId>,
    pub lightbox: Option<FileId>,
    pub lightbox_view: LightboxView,

    // ── Task 12: windowed-files migration ──
    /// Full filter+sort result computed by the indexer thread via SQL. Replaces
    /// the old in-Rust `Vec<FoundFile> files` + `Vec<FileId> visible_files`
    /// pair: the UI walks `match_ids` for navigation/nav order, then pulls the
    /// currently-windowed rows from `window`.
    pub match_ids: Vec<FileStub>,
    /// Files currently materialised in memory, keyed by `FileObject.file_id`.
    /// Filled by `apply_window_filled` from a `fetch_window` result.
    pub window: BTreeMap<u64, FoundFile>,
    /// Range of indices into `match_ids` whose `FoundFile`s are present in
    /// `window`. Empty `0..0` when no fetch has completed yet.
    pub window_range: std::ops::Range<usize>,
    /// Last observed `meta.preview_status_version` from the indexer. The UI
    /// requeries when this advances and `hide_no_preview` is active.
    pub preview_status_version: u64,
    /// Monotonic epoch the UI bumps before posting `Requery` / `FetchWindow`.
    /// Stale results (epoch < current_epoch) are dropped on arrival.
    pub current_epoch: u64,

    pub variants: BTreeMap<FileId, VariantSet>,
    pub variant_of: BTreeMap<FileId, FileId>,
    pub bookmarks: BTreeSet<FileId>,
    pub notes: BTreeMap<FileId, Vec<NoteEntry>>,
    pub best_choices: BTreeMap<FileId, FileId>,
    pub partial_counts: BTreeMap<FileType, u64>,
    pub recovery_state: RecoveryUiState,
    pub variant_viewer: Option<FileId>,
    pub note_input: Option<NoteInputState>,
    #[allow(dead_code)] // used by Task 11's add_note method
    pub(crate) next_note_id: u64,

    /// The currently selected group tab in Row A. `None` means "All".
    pub selected_group: Option<Group>,
    /// Whether the filter panel (Row B chips) is visible.
    pub filters_visible: bool,
}

impl Default for ViewModel {
    fn default() -> Self {
        Self {
            run: empty_run_summary(),
            sources: Vec::new(),
            type_counts: BTreeMap::new(),
            filter: FilterState::default(),
            selection: None,
            lightbox: None,
            lightbox_view: LightboxView::default(),
            match_ids: Vec::new(),
            window: BTreeMap::new(),
            window_range: 0..0,
            preview_status_version: 0,
            current_epoch: 0,
            variants: BTreeMap::new(),
            variant_of: BTreeMap::new(),
            bookmarks: BTreeSet::new(),
            notes: BTreeMap::new(),
            best_choices: BTreeMap::new(),
            partial_counts: BTreeMap::new(),
            recovery_state: RecoveryUiState::default(),
            variant_viewer: None,
            note_input: None,
            next_note_id: 0,
            selected_group: None,
            filters_visible: false,
        }
    }
}

impl ViewModel {
    pub fn new() -> Self {
        Self {
            filters_visible: true,
            ..Self::default()
        }
    }

    pub fn recompute_visible(&mut self) {
        // no-op; filter/sort now run on the indexer thread.
        //
        // Callers still invoke this from many places (chip toggles, sort
        // changes, etc.) — those will be migrated to post `Requery` commands
        // to the indexer thread in Task 13. Until that wiring lands this
        // method exists as a no-op shim so existing call sites continue to
        // compile.
    }

    /// Replace the current `match_ids` with a freshly-computed list from the
    /// indexer thread. The caller (UI timer) will issue a `FetchWindow` on
    /// the next tick to bring the window in sync with the new positions.
    ///
    /// We PRESERVE `vm.window` entries whose file_id still appears in the
    /// new `match_ids`, and PRUNE the rest. The window is keyed by file_id
    /// (not by row index), so carryover entries remain valid for
    /// `build_tiles` to render full-data tiles during the ~100 ms gap
    /// between this MatchIds and the follow-up WindowFilled response.
    /// Without this carryover, every Requery (notably the debounced
    /// `hide_no_preview` refresh) would briefly render every tile as a
    /// stub — the visible flicker between lowercase `"jpeg"` (full data)
    /// and uppercase `"Jpeg"` (`format!("{:?}", file_type)` Debug repr).
    /// Pruning bounds memory: `window` ends up no larger than the union
    /// of the previous window and the new `match_ids` set.
    ///
    /// Late arrivals from a stale epoch are silently dropped so racing
    /// requeries don't clobber a more recent result.
    pub fn apply_match_ids(&mut self, stubs: Vec<FileStub>, epoch: u64) {
        if epoch < self.current_epoch {
            return;
        }
        // Sync the UI epoch with the indexer's auto-tick re-queries. The
        // indexer bumps its own `current_epoch` when emitting MatchIds from
        // a Tick; if we don't advance ours to match, the next UI-initiated
        // FetchWindow uses a stale epoch and is dropped by the indexer.
        self.current_epoch = self.current_epoch.max(epoch);

        // Prune the window to file_ids still present in the new match_ids.
        // This is the load-bearing change vs. a full `window.clear()`: it
        // preserves FoundFile data for the typical case where most
        // file_ids carry over (filter narrowed by a few rows), avoiding
        // the brief stub flicker on the next sync tick.
        let new_ids: std::collections::HashSet<u64> = stubs.iter().map(|s| s.file_id).collect();
        self.window.retain(|id, _| new_ids.contains(id));

        self.match_ids = stubs;
        // Preserve selection only if the id still appears in the new match list.
        if let Some(sel) = self.selection
            && !self.match_ids.iter().any(|s| s.file_id == sel)
        {
            self.selection = None;
        }
        // Reset window range; UI will issue FetchWindow next tick.
        self.window_range = 0..0;
    }

    /// Replace the window contents with rows fetched by the indexer thread.
    /// `range_start` is the offset into `match_ids` that the first returned
    /// row corresponds to; `window_range` ends at `range_start + rows.len()`.
    pub fn apply_window_filled(&mut self, rows: Vec<FoundFile>, range_start: usize, epoch: u64) {
        if epoch < self.current_epoch {
            return;
        }
        // Sync the UI epoch with the indexer's auto-tick re-queries (see
        // `apply_match_ids` for the rationale; this branch is here for
        // symmetry in case a WindowFilled arrives on a freshly-bumped
        // epoch before any MatchIds for that epoch).
        self.current_epoch = self.current_epoch.max(epoch);
        self.window.clear();
        for r in rows {
            self.window.insert(r.file.file_id, r);
        }
        self.window_range = range_start..(range_start + self.window.len());
    }

    /// Decide whether the currently-loaded window needs to slide given the
    /// visible row range. Returns `Some(new_range)` if a slide is needed;
    /// `None` if the current window already contains the visible rows plus
    /// `slide_trigger` rows of slack on either side, OR if the window is
    /// already pinned to the relevant boundary (no room to slide further),
    /// OR if the computed range would equal the current window.
    ///
    /// The boundary check is load-bearing: when the user opens the gallery,
    /// `window_range.start == 0` AND `visible_first_row == 0`. Without the
    /// boundary exception, the predicate `start + slide_trigger <= visible_first`
    /// is `0 + 4 <= 0` = false, so the UI would propose a slide every tick,
    /// repeatedly clearing and refilling `self.window` and causing tile
    /// data to flicker between stub (uppercase Debug repr of `file_type`)
    /// and full-data (lowercase engine-emitted) rendering paths.
    pub fn need_slide(
        &self,
        visible_first_row: usize,
        visible_last_row: usize,
        window_size: usize,
        slide_trigger: usize,
    ) -> Option<std::ops::Range<usize>> {
        let total = self.match_ids.len();
        if total == 0 {
            return None;
        }
        let at_top_boundary = self.window_range.start == 0;
        let at_bot_boundary = self.window_range.end >= total;
        let top_ok =
            at_top_boundary || self.window_range.start + slide_trigger <= visible_first_row;
        let bot_ok = at_bot_boundary || visible_last_row + slide_trigger < self.window_range.end;
        if top_ok && bot_ok {
            return None;
        }
        let target_center = (visible_first_row + visible_last_row) / 2;
        let half = window_size / 2;
        let start = target_center
            .saturating_sub(half)
            .min(total.saturating_sub(window_size));
        let end = (start + window_size).min(total);
        let proposed = start..end;
        if proposed == self.window_range {
            return None;
        }
        Some(proposed)
    }

    pub fn apply(&mut self, event: &CarveEvent) {
        match event {
            CarveEvent::RunStarted {
                started_at,
                output_root,
                configured_types,
                case,
                sources,
                ..
            } => {
                self.run.started_at = started_at.clone();
                self.run.output_root = output_root.clone();
                self.run.source_image_path = sources
                    .iter()
                    .next()
                    .map(|s| s.filename.clone())
                    .unwrap_or_default();
                self.run.configured_types = configured_types.clone();
                self.run.case = case.clone();
                self.run.status = RunStatus::Running;
                self.sources = sources
                    .iter()
                    .map(|s| SourceRow {
                        source_id: s.source_id,
                        filename: s.filename.clone(),
                        output_subdir: s.output_subdir.clone(),
                        total_bytes: s.total_bytes,
                        bytes_read: 0,
                        files_found: 0,
                        status: SourceStatus::Pending,
                        duration_ms: None,
                    })
                    .collect();
                self.filter.enabled_types = configured_types.iter().copied().collect();
            }
            CarveEvent::SourceStarted { source_id } => {
                if let Some(row) = self.sources.iter_mut().find(|r| r.source_id == *source_id) {
                    row.status = SourceStatus::Running;
                }
            }
            CarveEvent::FileFound {
                source_id, file, ..
            } => {
                // Task 12: the file is durably written to SQLite by the
                // indexer writer thread; we no longer hold a `Vec<FoundFile>`
                // in the VM. Live-mode pickup will arrive via a debounced
                // `Requery` (Task 16); cold/warm open hydrates via `Requery`
                // posted after lib.rs finishes the initial snapshot load.
                //
                // We still maintain in-VM derived state that is _not_ in
                // SQLite, namely the type/partial chip counts and per-source
                // running file counter, so chips and progress UI stay live
                // without waiting for the next requery.
                let ft = parse_file_type(&file.file_type);
                if let Some(ft) = ft {
                    *self.type_counts.entry(ft).or_insert(0) += 1;
                    if self.run.configured_types.is_empty() {
                        self.filter.enabled_types.insert(ft);
                    }
                }
                let is_partial = file
                    .jpeg_scan
                    .as_ref()
                    .map(|s| s.status != utmost_lib::types::JpegScanStatus::Complete)
                    .unwrap_or(false);
                if is_partial && let Some(ft) = ft {
                    *self.partial_counts.entry(ft).or_insert(0) += 1;
                }
                if let Some(row) = self.sources.iter_mut().find(|r| r.source_id == *source_id) {
                    row.files_found += 1;
                }
                self.run.total_files += 1;
            }
            CarveEvent::ProgressTick {
                source_id,
                bytes_read,
            } => {
                if let Some(row) = self.sources.iter_mut().find(|r| r.source_id == *source_id) {
                    row.bytes_read = *bytes_read;
                }
            }
            CarveEvent::SourceFinished {
                source_id,
                bytes_read,
                duration_ms,
            } => {
                if let Some(row) = self.sources.iter_mut().find(|r| r.source_id == *source_id) {
                    row.status = SourceStatus::Finished;
                    row.bytes_read = *bytes_read;
                    row.duration_ms = Some(*duration_ms);
                }
            }
            CarveEvent::RunFinished {
                duration_ms,
                total_files_written: _,
            } => {
                self.run.status = RunStatus::Finished;
                self.run.elapsed_ms = *duration_ms;
                if !self.partial_counts.is_empty()
                    && self.recovery_state == RecoveryUiState::Disabled
                {
                    self.recovery_state = RecoveryUiState::NotRun;
                }
            }
            CarveEvent::RecoveryStarted { .. } => {
                self.recovery_state = RecoveryUiState::Running;
            }
            CarveEvent::RecoveryFinished { .. } => {
                self.recovery_state = RecoveryUiState::Finished;
            }
            CarveEvent::RecoveryCandidate {
                original_file_id,
                candidate_file_id,
                ..
            } => {
                let entry = self
                    .variants
                    .entry(*original_file_id)
                    .or_insert_with(|| VariantSet {
                        original_id: *original_file_id,
                        variant_ids: Vec::new(),
                    });
                if !entry.variant_ids.contains(candidate_file_id) {
                    entry.variant_ids.push(*candidate_file_id);
                }
                self.variant_of
                    .insert(*candidate_file_id, *original_file_id);
            }
            CarveEvent::Bookmark {
                file_id,
                bookmarked,
                ..
            } => {
                if *bookmarked {
                    self.bookmarks.insert(*file_id);
                } else {
                    self.bookmarks.remove(file_id);
                }
            }
            CarveEvent::Note {
                note_id,
                file_id,
                text,
                at,
            } => {
                self.notes.entry(*file_id).or_default().push(NoteEntry {
                    note_id: *note_id,
                    text: text.clone(),
                    at: at.clone(),
                });
                self.next_note_id = self.next_note_id.max(*note_id + 1);
            }
            CarveEvent::MarkAsBest {
                original_file_id,
                chosen_file_id,
                ..
            } => {
                self.best_choices.insert(*original_file_id, *chosen_file_id);
            }
        }
    }

    pub fn open_lightbox(&mut self) {
        if let Some(id) = self.selection {
            self.lightbox = Some(id);
            self.lightbox_view = LightboxView::default();
        }
    }

    pub fn close_lightbox(&mut self) {
        self.lightbox = None;
    }

    pub fn lightbox_next(&mut self) {
        self.lightbox_step(1);
    }

    pub fn lightbox_prev(&mut self) {
        self.lightbox_step(-1);
    }

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

    pub fn gallery_move(&mut self, dir: NavDirection, cols: usize) {
        if self.match_ids.is_empty() {
            return;
        }
        let cols = cols.max(1);
        let cur_idx = self
            .selection
            .and_then(|id| self.match_ids.iter().position(|s| s.file_id == id));
        let len = self.match_ids.len();
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
        self.selection = Some(self.match_ids[new_idx].file_id);
    }

    pub fn zoom_set(&mut self, z: f32) {
        self.lightbox_view.zoom = z.clamp(0.1, 8.0);
        self.lightbox_view.fit = false;
    }

    pub fn zoom_fit(&mut self) {
        self.lightbox_view = LightboxView::default();
    }

    pub fn toggle_bookmark(&mut self, file_id: FileId) -> CarveEvent {
        let was = self.bookmarks.contains(&file_id);
        let bookmarked = !was;
        if bookmarked {
            self.bookmarks.insert(file_id);
        } else {
            self.bookmarks.remove(&file_id);
        }
        CarveEvent::Bookmark {
            file_id,
            bookmarked,
            at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// No-op shim for the legacy thumbnail-ready set.
    ///
    /// Pre-Task-12 the VM owned a `BTreeSet<FileId> thumbnail_ready` populated
    /// from `ThumbWorker` completions. Post-Task-12 preview status lives in
    /// SQLite (Task 6's `file.preview_status` column); the worker writes
    /// outcomes through the `PreviewOutcome` channel (Task 7) and the indexer
    /// bumps `preview_status_version`. The UI requeries via that version
    /// signal, so the per-file flag is no longer needed in the VM.
    ///
    /// Kept as a stub so the existing `ThumbWorker` completion callback can
    /// continue to call it without conditional logic; Task 13 will drop the
    /// call site entirely.
    pub fn set_thumbnail_ready(&mut self, _file_id: FileId, _ready: bool) {
        // intentionally empty
    }

    pub fn add_note(&mut self, file_id: FileId, text: String) -> CarveEvent {
        self.next_note_id = self.next_note_id.max(1);
        let note_id = self.next_note_id;
        self.next_note_id += 1;
        let at = chrono::Utc::now().to_rfc3339();
        self.notes.entry(file_id).or_default().push(NoteEntry {
            note_id,
            text: text.clone(),
            at: at.clone(),
        });
        CarveEvent::Note {
            note_id,
            file_id,
            text,
            at,
        }
    }

    pub fn mark_as_best(&mut self, original_file_id: FileId, chosen_file_id: FileId) -> CarveEvent {
        self.best_choices.insert(original_file_id, chosen_file_id);
        CarveEvent::MarkAsBest {
            original_file_id,
            chosen_file_id,
            at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Opens the variant viewer for the currently selected file.
    ///
    /// Post-Task-8 unification, `self.selection` holds `FoundFile.id` which
    /// equals the engine-allocated `FileObject.file_id`, so the
    /// `self.variants.contains_key` lookup succeeds without any translation.
    pub fn open_variant_viewer(&mut self) {
        if let Some(sel) = self.selection
            && self.variants.contains_key(&sel)
        {
            self.variant_viewer = Some(sel);
        }
    }

    pub fn close_variant_viewer(&mut self) {
        self.variant_viewer = None;
    }

    /// The full list of filter chips the UI should render, in display order:
    /// type chips → partial chips → bookmarked chip. The bookmarked chip is
    /// always present so the filter can be toggled off even when bookmarks
    /// are empty.
    pub fn filter_chips(&self) -> Vec<FilterChipDescriptor> {
        let mut chips: Vec<FilterChipDescriptor> = self
            .type_counts
            .iter()
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
            let ft_string = format!("{:?}", ft).to_lowercase();
            chips.push(FilterChipDescriptor {
                name: format!("partial:{}", ft_string),
                display_name: format!("{ft:?}"),
                enabled: self.filter.enabled_partial_types.contains(ft),
                count: *count as i32,
                kind: FilterChipKind::Partial,
            });
        }

        chips.push(FilterChipDescriptor {
            name: "bookmarked".to_string(),
            display_name: "Bookmarked".to_string(),
            enabled: self.filter.bookmarked_only,
            count: self.bookmarks.len() as i32,
            kind: FilterChipKind::Bookmarked,
        });

        chips
    }

    /// Returns the group chips for Row A (the tab bar above the filter chips).
    ///
    /// Returns an empty `Vec` when only one group is present — in that case the
    /// tab row should be hidden entirely (single-group optimisation).
    pub fn group_chip_descriptors(&self) -> Vec<GroupChipDescriptor> {
        use std::collections::BTreeMap;

        // Build map of Group → FileTypes present (using type_counts as source of truth)
        let mut groups: BTreeMap<Group, Vec<FileType>> = BTreeMap::new();
        for ft in self.type_counts.keys() {
            groups.entry(file_type_group(*ft)).or_default().push(*ft);
        }

        // Single-group optimisation: return empty so Row A is hidden
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

    /// Returns the sub-filter chips for Row B (type-level chips inside the
    /// selected group tab). Excludes the Bookmarked chip — that lives in
    /// `filter_chips()` only.
    ///
    /// Behaviour:
    /// - Multi-group with no tab selected → empty (Row B is hidden).
    /// - Multi-group with a tab selected → chips for types in that group.
    /// - Single-group (tab row hidden) → chips for all present types.
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
            groups
                .get(&sg)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .collect()
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

    /// Largest file size among files in the current match list. Used as the
    /// upper bound for the size slider. Returns 0 if `match_ids` is empty.
    ///
    /// Task 12 transitional implementation: walks `match_ids` (which already
    /// reflects the active filter+sort, sans the size_range itself — that
    /// filter is computed in SQL by `query_match_ids`). A future task will
    /// compute this as `MAX(filesize)` over the same filter directly in SQL
    /// for accuracy; for now we approximate from the loaded stubs, which is
    /// sufficient for the slider's upper bound.
    pub fn size_filter_max(&self) -> u64 {
        self.match_ids.iter().map(|s| s.filesize).max().unwrap_or(0)
    }

    /// Clamp `size_range` to a new maximum. Collapses to `None` if the
    /// resulting range is `(0, 0)` (the slider is effectively unset).
    ///
    /// `new_max == 0` is treated as "no data to clamp against" (e.g. the
    /// first sync right after case hydration, before MatchIds arrives) and
    /// leaves `size_range` untouched — the slider is hidden in that state
    /// but the saved value must survive until a real upper bound is known.
    pub fn clamp_size_range_to(&mut self, new_max: u64) {
        if new_max == 0 {
            return;
        }
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

    pub fn open_lightbox_for_variant(&mut self, variant_id: FileId) {
        self.lightbox = Some(variant_id);
        self.lightbox_view = LightboxView::default();
    }

    fn lightbox_step(&mut self, delta: isize) {
        let Some(cur) = self.lightbox else { return };
        let n = self.match_ids.len();
        if n == 0 {
            return;
        }
        let Some(idx) = self.match_ids.iter().position(|s| s.file_id == cur) else {
            return;
        };
        let next_idx = ((idx as isize + delta).rem_euclid(n as isize)) as usize;
        self.lightbox = Some(self.match_ids[next_idx].file_id);
        self.lightbox_view = LightboxView::default();
    }

    /// Replace state with the contents of `snap`.
    ///
    /// Task 12: the snapshot no longer carries `Vec<FoundFile>` — the file
    /// list now lives in SQLite and the caller posts a `Requery` to populate
    /// `match_ids` + `window` after hydration completes.
    pub fn hydrate_from(&mut self, snap: ViewModelSnapshot) {
        self.run = snap.run;
        self.sources = snap.sources;
        self.bookmarks = snap.bookmarks;
        self.notes = snap.notes;
        self.best_choices = snap.best_choices;
        self.variants = snap.variants;
        self.variant_of = snap.variant_of;
        self.type_counts = snap.type_counts;
        self.partial_counts = snap.partial_counts;
        self.recovery_state = snap.recovery_state;
        self.next_note_id = snap.next_note_id;
        self.filter.enabled_types = self.run.configured_types.iter().copied().collect();
    }
}

/// Canonical lowercase string for a [`FileType`]. Inverse of
/// [`parse_file_type_pub`]. Each new `FileType` variant must add a
/// match arm here; the `view_model::tests::file_type_string_round_trip`
/// test guards the inverse property.
pub fn file_type_to_pub_str(ft: FileType) -> &'static str {
    match ft {
        FileType::Jpeg => "jpeg",
        FileType::Gif => "gif",
        FileType::Bmp => "bmp",
        FileType::Mpg => "mpg",
        FileType::Pdf => "pdf",
        FileType::Doc => "doc",
        FileType::Avi => "avi",
        FileType::Wmv => "wmv",
        FileType::Htm => "htm",
        FileType::Zip => "zip",
        FileType::Mov => "mov",
        FileType::Xls => "xls",
        FileType::Ppt => "ppt",
        FileType::Wpd => "wpd",
        FileType::Cpp => "cpp",
        FileType::Ole => "ole",
        FileType::Gzip => "gzip",
        FileType::Riff => "riff",
        FileType::Wav => "wav",
        FileType::VJpeg => "vjpeg",
        FileType::Sxw => "sxw",
        FileType::Sxc => "sxc",
        FileType::Sxi => "sxi",
        FileType::Png => "png",
        FileType::Rar => "rar",
        FileType::Exe => "exe",
        FileType::Elf => "elf",
        FileType::Reg => "reg",
        FileType::Docx => "docx",
        FileType::Xlsx => "xlsx",
        FileType::Pptx => "pptx",
        FileType::Mp4 => "mp4",
        FileType::Config => "config",
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_view_model_is_empty() {
        let vm = ViewModel::new();
        assert_eq!(vm.sources.len(), 0);
        // Task 12: file list now lives in SQLite via `match_ids` + `window`;
        // both start empty until a Requery completes.
        assert_eq!(vm.match_ids.len(), 0);
        assert!(vm.window.is_empty());
        assert_eq!(vm.run.status, RunStatus::Pending);
        assert!(vm.selection.is_none());
    }

    use utmost_lib::events::*;
    use utmost_lib::reporting::create_file_object;
    use utmost_lib::types::{ExecutionEnvironment, FileType};

    fn empty_env() -> ExecutionEnvironment {
        ExecutionEnvironment {
            os_sysname: String::new(),
            os_release: String::new(),
            os_version: String::new(),
            host: String::new(),
            arch: String::new(),
            uid: 0,
            start_time: String::new(),
        }
    }
    fn empty_cli() -> CliConfigSnapshot {
        CliConfigSnapshot {
            output_directory: "out".into(),
            types: vec![],
            disable_builtin: false,
            config_file: None,
            concurrent_files: 1,
            disable_validation: false,
            report_only: false,
            disable_report: false,
            disable_audit: false,
            disable_export: false,
            gui_enabled: false,
            quick: false,
            block_size: 512,
            prefix_filenames: false,
            write_all: false,
            keep_incomplete_jpeg: false,
        }
    }

    fn run_started_with_sources(ids: &[u32]) -> CarveEvent {
        CarveEvent::RunStarted {
            utmost_version: "test".into(),
            format_version: CURRENT_FORMAT_VERSION,
            started_at: "t".into(),
            command_line: vec![],
            working_directory: "/".into(),
            execution_environment: empty_env(),
            cli_config: empty_cli(),
            case: None,
            configured_types: vec![FileType::Jpeg],
            sources: ids
                .iter()
                .map(|i| SourceDescriptor {
                    source_id: *i,
                    filename: format!("src{i}.bin"),
                    total_bytes: 1000,
                    output_subdir: format!("output-{i}"),
                })
                .collect(),
            output_root: "out".into(),
        }
    }

    #[test]
    fn run_started_populates_run_and_sources() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0, 1]));
        assert_eq!(vm.sources.len(), 2);
        assert_eq!(vm.sources[0].source_id, 0);
        assert_eq!(vm.run.status, RunStatus::Running);
        assert_eq!(vm.run.output_root, "out");
        assert_eq!(vm.run.configured_types, vec![FileType::Jpeg]);
    }

    #[test]
    fn source_started_sets_source_running() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        vm.apply(&CarveEvent::SourceStarted { source_id: 0 });
        assert_eq!(vm.sources[0].status, SourceStatus::Running);
    }

    #[test]
    fn file_found_adds_file_and_increments_counts() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        let fo = create_file_object("a.jpg", FileType::Jpeg, 1024, 0, None, 1);
        vm.apply(&CarveEvent::FileFound {
            source_id: 0,
            file: fo,
            img_offset: 0,
            written_path: "a.jpg".into(),
        });
        // Task 12: FileFound no longer maintains a Vec<FoundFile> in the VM;
        // the indexer writer thread durably stores the row in SQLite and the
        // UI picks it up on the next Requery (Task 13/16). We still check the
        // derived counters that apply() maintains directly.
        assert_eq!(vm.type_counts.get(&FileType::Jpeg), Some(&1));
        assert_eq!(vm.sources[0].files_found, 1);
        assert_eq!(vm.run.total_files, 1);
    }

    #[test]
    fn progress_tick_updates_source_bytes_read() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        vm.apply(&CarveEvent::ProgressTick {
            source_id: 0,
            bytes_read: 500,
        });
        assert_eq!(vm.sources[0].bytes_read, 500);
    }

    #[test]
    fn source_finished_flips_status_and_records_duration() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        vm.apply(&CarveEvent::SourceFinished {
            source_id: 0,
            bytes_read: 1000,
            duration_ms: 42,
        });
        assert_eq!(vm.sources[0].status, SourceStatus::Finished);
        assert_eq!(vm.sources[0].duration_ms, Some(42));
        assert_eq!(vm.sources[0].bytes_read, 1000);
    }

    /// Regression for the "Jpeg/jpeg flicker" bug: when `hide_no_preview` is
    /// on and the outcomes writer emits a fresh `PreviewStatusVersion`, the
    /// UI's debounced observer fires a Requery. The resulting `MatchIds`
    /// event flows into `apply_match_ids` — which used to wipe `vm.window`
    /// wholesale, forcing the next sync's `build_tiles` to render every
    /// tile as a stub (uppercase Debug repr of `file_type`, no thumbnail)
    /// until the follow-up `WindowFilled` round-tripped back.
    ///
    /// File IDs that carry over to the new `match_ids` still have valid
    /// FoundFile data in the old window, so apply_match_ids must KEEP
    /// those entries and only prune file_ids that dropped out of
    /// `match_ids`. Memory stays bounded; tiles render correctly during
    /// the brief gap between MatchIds and WindowFilled.
    #[test]
    fn apply_match_ids_preserves_carryover_window_entries() {
        let mut vm = ViewModel::new();
        // Old state: window has FoundFiles for ids 1, 2 (carryover) and 3
        // (filtered out by the new Requery, e.g., its preview_status flipped
        // to no_preview).
        let fo_for =
            |id: u64, name: &str| create_file_object(name, FileType::Jpeg, 100, 0, None, id);
        let ff_for = |id: u64, name: &str| FoundFile {
            id,
            source_id: 1,
            file: fo_for(id, name),
            written_path: name.into(),
            img_offset: 0,
        };
        vm.window.insert(1, ff_for(1, "01.jpg"));
        vm.window.insert(2, ff_for(2, "02.jpg"));
        vm.window.insert(3, ff_for(3, "03.jpg"));
        let stub = |id: u64, name: &str| FileStub {
            file_id: id,
            filename: name.to_string(),
            filesize: 100,
            file_type: FileType::Jpeg,
        };

        vm.apply_match_ids(vec![stub(1, "01.jpg"), stub(2, "02.jpg")], 1);

        assert!(
            vm.window.contains_key(&1),
            "carryover id 1 must remain so build_tiles renders full data, not a stub"
        );
        assert!(
            vm.window.contains_key(&2),
            "carryover id 2 must remain so build_tiles renders full data, not a stub"
        );
        assert!(
            !vm.window.contains_key(&3),
            "dropped id 3 must be pruned to keep memory bounded"
        );
    }

    #[test]
    fn run_finished_flips_run_status() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        vm.apply(&CarveEvent::RunFinished {
            duration_ms: 100,
            total_files_written: 3,
        });
        assert_eq!(vm.run.status, RunStatus::Finished);
        assert_eq!(vm.run.elapsed_ms, 100);
    }

    #[test]
    #[ignore = "Task 13: behaviour now lives in the writer/indexer; the VM no longer keeps a Vec<FoundFile>, and the row will be inserted into SQLite by `IndexDbWriter::apply`. Covered indirectly by the writer's integration tests."]
    fn file_found_before_known_source_still_inserted() {
        let mut vm = ViewModel::new();
        // Skip RunStarted entirely
        let fo = create_file_object("a.jpg", FileType::Jpeg, 1, 0, None, 1);
        vm.apply(&CarveEvent::FileFound {
            source_id: 99,
            file: fo,
            img_offset: 0,
            written_path: "a.jpg".into(),
        });
    }

    /// Task 12 test helper: populate `match_ids` + `window` directly,
    /// bypassing the old in-VM `files` Vec. Navigation tests that walk
    /// `match_ids` continue to work; filter/sort tests have been
    /// `#[ignore]`'d since that logic now lives in SQL.
    fn add_file(vm: &mut ViewModel, sid: u32, name: &str, ft: FileType, sz: u64) {
        add_file_at_offset(vm, sid, name, ft, sz, 0);
    }

    fn add_file_at_offset(
        vm: &mut ViewModel,
        sid: u32,
        name: &str,
        ft: FileType,
        sz: u64,
        img_offset: u64,
    ) {
        let id = vm.match_ids.len() as u64;
        let fo = create_file_object(name, ft, sz, img_offset, None, id);
        let stub = FileStub {
            file_id: id,
            filename: name.to_string(),
            filesize: sz,
            file_type: ft,
        };
        vm.match_ids.push(stub);
        let found = FoundFile {
            id,
            source_id: sid,
            file: fo,
            written_path: name.into(),
            img_offset,
        };
        vm.window.insert(id, found);
        vm.window_range = 0..vm.match_ids.len();
        // Still apply the FileFound event so derived state (type_counts,
        // sources[*].files_found, run.total_files) stays consistent with
        // production behaviour.
        let fo2 = create_file_object(name, ft, sz, img_offset, None, id);
        vm.apply(&CarveEvent::FileFound {
            source_id: sid,
            file: fo2,
            img_offset,
            written_path: name.into(),
        });
    }

    fn vm_with_n_visible(n: usize) -> ViewModel {
        let mut vm = ViewModel::new();
        vm.filter.enabled_types.insert(FileType::Jpeg);
        for i in 0..n {
            add_file(&mut vm, 1, &format!("f{i}.jpg"), FileType::Jpeg, 100);
        }
        vm.recompute_visible();
        vm
    }

    /// Task 12: many tests reference `vm.visible_files` directly. Until those
    /// tests are restored against the new SQL-backed flow in Task 13 we expose
    /// the windowed match list under the old name so the navigation tests
    /// continue to compile. The semantics are equivalent in the helpers above
    /// (everything is in `match_ids`, everything is in `window`).
    fn visible_ids(vm: &ViewModel) -> Vec<FileId> {
        vm.match_ids.iter().map(|s| s.file_id).collect()
    }

    /// Task 13: replay the VM's current files into a fresh in-memory IndexDb,
    /// run `query_match_ids` against it, and apply the result via
    /// `apply_match_ids`. This is the unit-test analog of what
    /// [`crate::indexer_thread::run_query_loop`] does on receipt of a
    /// `Requery` command. Tests that exercise filter/sort logic that lived in
    /// `recompute_visible` pre-Task-12 call this in place of
    /// `vm.recompute_visible()` so the SQL-backed query produces `match_ids`.
    ///
    /// `preview_status_overrides` lets a test pin specific files'
    /// `preview_status` (used by `hide_no_preview` tests). Files not in the
    /// override map default to `"unknown"`, which the `hide_no_preview`
    /// filter treats as "show".
    fn requery_via_sql_with_previews(
        vm: &mut ViewModel,
        preview_status_overrides: &std::collections::BTreeMap<FileId, &'static str>,
    ) {
        use crate::index_db::queries::query_match_ids;
        use crate::index_db::{IndexDb, block_on};
        use turso::Value;

        let db = IndexDb::open_in_memory().expect("open in-memory db");
        let pool = db.pool().clone();

        // Synthesize a source row for any source_id referenced by a window
        // file but not present in vm.sources (some tests skip RunStarted).
        let mut known_sources: std::collections::BTreeSet<u32> =
            vm.sources.iter().map(|s| s.source_id).collect();
        let mut synth_sources: Vec<u32> = Vec::new();
        for f in vm.window.values() {
            if known_sources.insert(f.source_id) {
                synth_sources.push(f.source_id);
            }
        }

        block_on(async {
            let mut conn = pool.get().await.unwrap();
            let tx = conn.transaction().await.unwrap();
            for s in &vm.sources {
                tx.execute(
                    "INSERT INTO source (source_id, filename, output_subdir, total_bytes, \
                     bytes_read, files_found, status) VALUES (?1, ?2, '', ?3, ?4, ?5, 'Running')",
                    turso::params_from_iter(vec![
                        Value::Integer(s.source_id as i64),
                        Value::Text(s.filename.clone()),
                        Value::Integer(s.total_bytes as i64),
                        Value::Integer(s.bytes_read as i64),
                        Value::Integer(s.files_found as i64),
                    ]),
                )
                .await
                .unwrap();
            }
            for sid in &synth_sources {
                tx.execute(
                    "INSERT INTO source (source_id, filename, output_subdir, total_bytes, \
                     bytes_read, files_found, status) VALUES (?1, ?2, '', 0, 0, 0, 'Running')",
                    turso::params_from_iter(vec![
                        Value::Integer(*sid as i64),
                        Value::Text(format!("synth-source-{sid}.bin")),
                    ]),
                )
                .await
                .unwrap();
            }
            for (id, f) in &vm.window {
                let jpeg_status = f.file.jpeg_scan.as_ref().map(|j| match j.status {
                    utmost_lib::types::JpegScanStatus::Complete => "complete",
                    utmost_lib::types::JpegScanStatus::Truncated => "truncated",
                    utmost_lib::types::JpegScanStatus::Fragmented => "fragmented",
                });
                let preview_status = preview_status_overrides
                    .get(id)
                    .copied()
                    .unwrap_or("unknown");
                tx.execute(
                    "INSERT INTO file (file_id, source_id, filename, filesize, file_type, \
                     img_offset, written_path, byte_runs_json, jpeg_status, preview_status) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, '[]', ?8, ?9)",
                    turso::params_from_iter(vec![
                        Value::Integer(*id as i64),
                        Value::Integer(f.source_id as i64),
                        Value::Text(f.file.filename.clone()),
                        Value::Integer(f.file.filesize as i64),
                        Value::Text(f.file.file_type.clone()),
                        Value::Integer(f.img_offset as i64),
                        Value::Text(f.written_path.display().to_string()),
                        match jpeg_status {
                            Some(s) => Value::Text(s.to_owned()),
                            None => Value::Null,
                        },
                        Value::Text(preview_status.to_owned()),
                    ]),
                )
                .await
                .unwrap();
            }
            for fid in &vm.bookmarks {
                tx.execute(
                    "INSERT INTO bookmark (file_id, at) VALUES (?1, 't')",
                    (Value::Integer(*fid as i64),),
                )
                .await
                .unwrap();
            }
            for (orig, vs) in &vm.variants {
                for (i, vid) in vs.variant_ids.iter().enumerate() {
                    tx.execute(
                        "INSERT INTO variant (original_file_id, candidate_file_id, rank, method, \
                         entropy_score, continuation_img_offset) \
                         VALUES (?1, ?2, ?3, 'direct_continuation', 0.0, 0)",
                        turso::params_from_iter(vec![
                            Value::Integer(*orig as i64),
                            Value::Integer(*vid as i64),
                            Value::Integer((i + 1) as i64),
                        ]),
                    )
                    .await
                    .unwrap();
                }
            }
            tx.commit().await.unwrap();
        });

        let filter = vm.filter.clone();
        let stubs = query_match_ids(&pool, &filter).expect("query_match_ids");
        vm.current_epoch += 1;
        let epoch = vm.current_epoch;
        // Stash window contents so apply_match_ids' window.clear() doesn't
        // throw away the FoundFiles our tests need to inspect.
        let preserved_window = std::mem::take(&mut vm.window);
        vm.apply_match_ids(stubs, epoch);
        vm.window = preserved_window;
        vm.window_range = 0..vm.match_ids.len();
    }

    /// Convenience wrapper: requery with no preview-status overrides (all
    /// files default to `"unknown"`). Most ignored tests want this.
    fn requery_via_sql(vm: &mut ViewModel) {
        requery_via_sql_with_previews(vm, &std::collections::BTreeMap::new());
    }

    #[test]
    fn gallery_move_with_no_selection_selects_first() {
        let mut vm = vm_with_n_visible(5);
        assert!(vm.selection.is_none());
        vm.gallery_move(NavDirection::Right, 3);
        assert_eq!(vm.selection, Some(visible_ids(&vm)[0]));
    }

    #[test]
    fn gallery_move_left_crosses_row_boundary() {
        let mut vm = vm_with_n_visible(6); // cols=3, two rows
        vm.selection = Some(visible_ids(&vm)[3]); // start of row 1
        vm.gallery_move(NavDirection::Left, 3);
        assert_eq!(vm.selection, Some(visible_ids(&vm)[2])); // end of row 0
    }

    #[test]
    fn gallery_move_left_wraps_from_first_to_last() {
        let mut vm = vm_with_n_visible(6);
        vm.selection = Some(visible_ids(&vm)[0]);
        vm.gallery_move(NavDirection::Left, 3);
        assert_eq!(vm.selection, Some(visible_ids(&vm)[5]));
    }

    #[test]
    fn gallery_move_right_wraps_from_last_to_first() {
        let mut vm = vm_with_n_visible(6);
        vm.selection = Some(visible_ids(&vm)[5]);
        vm.gallery_move(NavDirection::Right, 3);
        assert_eq!(vm.selection, Some(visible_ids(&vm)[0]));
    }

    #[test]
    fn gallery_move_up_clamps_at_top_row() {
        let mut vm = vm_with_n_visible(6);
        vm.selection = Some(visible_ids(&vm)[1]); // top row
        vm.gallery_move(NavDirection::Up, 3);
        assert_eq!(vm.selection, Some(visible_ids(&vm)[1])); // unchanged
    }

    #[test]
    fn gallery_move_down_clamps_at_bottom_row() {
        let mut vm = vm_with_n_visible(5); // cols=3, row 0 has 3, row 1 has 2
        vm.selection = Some(visible_ids(&vm)[4]); // bottom row
        vm.gallery_move(NavDirection::Down, 3);
        assert_eq!(vm.selection, Some(visible_ids(&vm)[4])); // clamped
    }

    #[test]
    fn gallery_move_down_into_partial_bottom_row_clamps() {
        let mut vm = vm_with_n_visible(5); // cols=3, row 1 has only 2 tiles (indices 3, 4)
        vm.selection = Some(visible_ids(&vm)[2]); // row 0, col 2 — would land at index 5 which doesn't exist
        vm.gallery_move(NavDirection::Down, 3);
        assert_eq!(vm.selection, Some(visible_ids(&vm)[2])); // clamped
    }

    #[test]
    fn gallery_move_on_empty_visible_is_noop() {
        let mut vm = ViewModel::new();
        assert!(visible_ids(&vm).is_empty());
        vm.gallery_move(NavDirection::Right, 3);
        assert_eq!(vm.selection, None);
    }

    #[test]
    fn gallery_move_single_item_left_or_right_stays_in_place() {
        let mut vm = vm_with_n_visible(1);
        vm.selection = Some(visible_ids(&vm)[0]);
        vm.gallery_move(NavDirection::Right, 3);
        assert_eq!(vm.selection, Some(visible_ids(&vm)[0]));
        vm.gallery_move(NavDirection::Left, 3);
        assert_eq!(vm.selection, Some(visible_ids(&vm)[0]));
    }

    #[test]
    fn gallery_move_cols_one_up_down_clamps() {
        let mut vm = vm_with_n_visible(3);
        vm.selection = Some(visible_ids(&vm)[0]); // top
        vm.gallery_move(NavDirection::Up, 1);
        assert_eq!(vm.selection, Some(visible_ids(&vm)[0])); // clamped at top

        vm.selection = Some(visible_ids(&vm)[1]); // middle
        vm.gallery_move(NavDirection::Up, 1);
        assert_eq!(vm.selection, Some(visible_ids(&vm)[0])); // moves up by 1

        vm.gallery_move(NavDirection::Down, 1);
        assert_eq!(vm.selection, Some(visible_ids(&vm)[1])); // moves down by 1

        vm.selection = Some(visible_ids(&vm)[2]); // bottom
        vm.gallery_move(NavDirection::Down, 1);
        assert_eq!(vm.selection, Some(visible_ids(&vm)[2])); // clamped at bottom
    }

    #[test]
    fn visible_files_includes_only_enabled_types() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 100);
        add_file(&mut vm, 0, "b.pdf", FileType::Pdf, 200);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        requery_via_sql(&mut vm);
        assert_eq!(visible_ids(&vm).len(), 1);
    }

    #[test]
    fn sort_by_filename_asc() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "z.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.sort_key = SortKey::Filename;
        vm.filter.sort_dir = SortDir::Asc;
        requery_via_sql(&mut vm);
        let first_id = visible_ids(&vm)[0];
        let first = vm.window.get(&first_id).unwrap();
        assert_eq!(first.file.filename, "a.jpg");
    }

    #[test]
    fn sort_by_size_desc() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "x.jpg", FileType::Jpeg, 100);
        add_file(&mut vm, 0, "y.jpg", FileType::Jpeg, 999);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.sort_key = SortKey::Size;
        vm.filter.sort_dir = SortDir::Desc;
        requery_via_sql(&mut vm);
        let first_id = visible_ids(&vm)[0];
        let first = vm.window.get(&first_id).unwrap();
        assert_eq!(first.file.filesize, 999);
    }

    #[test]
    fn sort_by_file_type_asc() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.pdf", FileType::Pdf, 1);
        add_file(&mut vm, 0, "b.jpg", FileType::Jpeg, 1);
        vm.filter.enabled_types = [FileType::Jpeg, FileType::Pdf].into_iter().collect();
        vm.filter.sort_key = SortKey::FileType;
        vm.filter.sort_dir = SortDir::Asc;
        requery_via_sql(&mut vm);
        let first_id = visible_ids(&vm)[0];
        let first = vm.window.get(&first_id).unwrap();
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
        requery_via_sql(&mut vm);
        let first_id = visible_ids(&vm)[0];
        let first = vm.window.get(&first_id).unwrap();
        assert_eq!(first.file.file_type, "pdf");
    }

    #[test]
    fn sort_by_source_offset_asc() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file_at_offset(&mut vm, 0, "a.jpg", FileType::Jpeg, 1, 5000);
        add_file_at_offset(&mut vm, 0, "b.jpg", FileType::Jpeg, 1, 1000);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.sort_key = SortKey::SourceOffset;
        vm.filter.sort_dir = SortDir::Asc;
        requery_via_sql(&mut vm);
        let first_id = visible_ids(&vm)[0];
        let first = vm.window.get(&first_id).unwrap();
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
        requery_via_sql(&mut vm);
        let first_id = visible_ids(&vm)[0];
        let first = vm.window.get(&first_id).unwrap();
        assert_eq!(first.img_offset, 5000);
    }

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
        vm.bookmarks.insert(2);
        requery_via_sql(&mut vm);
        let names: Vec<&str> = visible_ids(&vm)
            .iter()
            .map(|id| vm.window.get(id).unwrap().file.filename.as_str())
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
        vm.bookmarks.insert(0);
        requery_via_sql(&mut vm);
        let names: Vec<&str> = visible_ids(&vm)
            .iter()
            .map(|id| vm.window.get(id).unwrap().file.filename.as_str())
            .collect();
        // Bookmark first, then non-bookmarks in desc filename order.
        assert_eq!(names, vec!["a.jpg", "c.jpg", "b.jpg"]);
    }

    #[test]
    fn source_filter_limits_to_one_source() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0, 1]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 1, "b.jpg", FileType::Jpeg, 1);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.source_filter = Some(1);
        requery_via_sql(&mut vm);
        assert_eq!(visible_ids(&vm).len(), 1);
        let first_id = visible_ids(&vm)[0];
        let f = vm.window.get(&first_id).unwrap();
        assert_eq!(f.source_id, 1);
    }

    #[test]
    fn new_view_model_has_lightbox_closed() {
        let vm = ViewModel::new();
        assert!(vm.lightbox.is_none());
        assert!(vm.lightbox_view.fit);
        assert!((vm.lightbox_view.zoom - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn open_lightbox_uses_current_selection() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        vm.recompute_visible();
        let id = visible_ids(&vm)[0];
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

    #[test]
    fn lightbox_next_wraps_at_end() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 0, "b.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 0, "c.jpg", FileType::Jpeg, 1);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.recompute_visible();
        let ids = visible_ids(&vm).clone();
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
        let ids = visible_ids(&vm).clone();
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
        let ids = visible_ids(&vm).clone();
        vm.selection = Some(ids[0]);
        vm.open_lightbox();
        vm.lightbox_view.fit = false;
        vm.lightbox_view.zoom = 2.5;
        vm.lightbox_next();
        assert!(vm.lightbox_view.fit);
        assert!((vm.lightbox_view.zoom - 1.0).abs() < f32::EPSILON);
    }

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

    #[test]
    fn apply_recovery_candidate_populates_variants() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));

        // Set up an original partial JPEG (file_id 10) and a candidate (file_id 11)
        let mut fo_orig = create_file_object("orig.jpg", FileType::Jpeg, 100, 0, None, 10);
        fo_orig.jpeg_scan = Some(utmost_lib::types::JpegScanInfo {
            width: None,
            height: None,
            fragmentation_point_img_offset: None,
            has_restart_markers: false,
            status: utmost_lib::types::JpegScanStatus::Truncated,
        });
        vm.apply(&CarveEvent::FileFound {
            source_id: 0,
            file: fo_orig,
            img_offset: 0,
            written_path: "orig.jpg".into(),
        });

        let fo_cand =
            create_file_object("orig_recovered_1.jpg", FileType::Jpeg, 200, 5000, None, 11);
        vm.apply(&CarveEvent::FileFound {
            source_id: 0,
            file: fo_cand,
            img_offset: 5000,
            written_path: "orig_recovered_1.jpg".into(),
        });

        vm.apply(&CarveEvent::RecoveryCandidate {
            original_file_id: 10,
            candidate_file_id: 11,
            rank: 1,
            method: utmost_lib::events::RecoveryMethod::DirectContinuation,
            entropy_score: 7.9,
            ff_validity_score: Some(0.97),
            huffman_mcu_count: Some(412),
            continuation_img_offset: 5000,
        });

        let vs = vm.variants.get(&10).expect("variant set");
        assert_eq!(vs.variant_ids, vec![11]);
        assert_eq!(vm.variant_of.get(&11), Some(&10));
    }

    #[test]
    fn recovery_started_finished_toggle_recovery_state() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        vm.recovery_state = RecoveryUiState::NotRun;

        vm.apply(&CarveEvent::RecoveryStarted {
            started_at: "t".into(),
            keep_candidates: 5,
            search_window: 50_000_000,
            block_size: 512,
            min_entropy_score: 7.0,
            huffman_validation: true,
        });
        assert_eq!(vm.recovery_state, RecoveryUiState::Running);

        vm.apply(&CarveEvent::RecoveryFinished {
            duration_ms: 100,
            partials_processed: 1,
            candidates_written: 1,
        });
        assert_eq!(vm.recovery_state, RecoveryUiState::Finished);
    }

    #[test]
    fn new_view_model_has_empty_annotation_state() {
        let vm = ViewModel::new();
        assert!(vm.variants.is_empty());
        assert!(vm.variant_of.is_empty());
        assert!(vm.bookmarks.is_empty());
        assert!(vm.notes.is_empty());
        assert!(vm.best_choices.is_empty());
        assert!(vm.partial_counts.is_empty());
        assert_eq!(vm.recovery_state, RecoveryUiState::Disabled);
        assert!(vm.variant_viewer.is_none());
        assert!(vm.note_input.is_none());
    }

    #[test]
    fn apply_bookmark_toggles_membership() {
        let mut vm = ViewModel::new();
        vm.apply(&CarveEvent::Bookmark {
            file_id: 7,
            bookmarked: true,
            at: "t".into(),
        });
        assert!(vm.bookmarks.contains(&7));
        vm.apply(&CarveEvent::Bookmark {
            file_id: 7,
            bookmarked: false,
            at: "t".into(),
        });
        assert!(!vm.bookmarks.contains(&7));
    }

    #[test]
    fn apply_note_appends_chronologically_and_tracks_next_id() {
        let mut vm = ViewModel::new();
        vm.apply(&CarveEvent::Note {
            note_id: 1,
            file_id: 7,
            text: "a".into(),
            at: "t1".into(),
        });
        vm.apply(&CarveEvent::Note {
            note_id: 2,
            file_id: 7,
            text: "b".into(),
            at: "t2".into(),
        });
        let entries = vm.notes.get(&7).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].text, "a");
        assert_eq!(entries[1].text, "b");
        assert_eq!(vm.next_note_id, 3);
    }

    #[test]
    #[ignore = "Task 13: variant exclusion not yet implemented in SQL query (see queries.rs module docs — variants exclusion was deferred to the windowed-UI hydration step). Will be restored when that filter is added."]
    fn recompute_visible_excludes_variants_from_main_grid() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        vm.filter.enabled_types.insert(FileType::Jpeg);

        // After Task 8 unification, FoundFile.id == file.file_id, so the
        // engine-allocated ids 1 (a.jpg) and 2 (b.jpg) appear directly in
        // visible_files.
        let fo_a = create_file_object("a.jpg", FileType::Jpeg, 100, 0, None, 1);
        let fo_b = create_file_object("b.jpg", FileType::Jpeg, 100, 0, None, 2);
        vm.apply(&CarveEvent::FileFound {
            source_id: 0,
            file: fo_a,
            img_offset: 0,
            written_path: "a.jpg".into(),
        });
        vm.apply(&CarveEvent::FileFound {
            source_id: 0,
            file: fo_b,
            img_offset: 0,
            written_path: "b.jpg".into(),
        });

        // Mark b.jpg (file_id=2) as a recovery candidate of a.jpg (file_id=1).
        vm.apply(&CarveEvent::RecoveryCandidate {
            original_file_id: 1,
            candidate_file_id: 2,
            rank: 1,
            method: utmost_lib::events::RecoveryMethod::DirectContinuation,
            entropy_score: 7.5,
            ff_validity_score: None,
            huffman_mcu_count: None,
            continuation_img_offset: 0,
        });

        // a.jpg (file_id=1) is not a variant → visible.
        // b.jpg (file_id=2) is a variant of a.jpg → excluded.
        assert_eq!(visible_ids(&vm), vec![1]);
    }

    #[test]
    #[ignore = "Task 13: partial-vs-original distinction not represented in SQL (see queries.rs module docs — enabled_types and enabled_partial_types are unioned in WHERE). Will be restored once the partial check is layered on top of the SQL result."]
    fn partial_chip_is_independent_of_normal_chip() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));

        // After Task 8: FoundFile.id == file.file_id, so c.jpg → 1, p.jpg → 2.
        let mut fo_complete = create_file_object("c.jpg", FileType::Jpeg, 100, 0, None, 1);
        fo_complete.jpeg_scan = Some(utmost_lib::types::JpegScanInfo {
            width: None,
            height: None,
            fragmentation_point_img_offset: None,
            has_restart_markers: false,
            status: utmost_lib::types::JpegScanStatus::Complete,
        });
        let mut fo_partial = create_file_object("p.jpg", FileType::Jpeg, 100, 0, None, 2);
        fo_partial.jpeg_scan = Some(utmost_lib::types::JpegScanInfo {
            width: None,
            height: None,
            fragmentation_point_img_offset: None,
            has_restart_markers: false,
            status: utmost_lib::types::JpegScanStatus::Truncated,
        });
        vm.apply(&CarveEvent::FileFound {
            source_id: 0,
            file: fo_complete,
            img_offset: 0,
            written_path: "c.jpg".into(),
        });
        vm.apply(&CarveEvent::FileFound {
            source_id: 0,
            file: fo_partial,
            img_offset: 0,
            written_path: "p.jpg".into(),
        });

        // Only "Partial JPG" enabled — should show only p.jpg (file_id=2).
        vm.filter.enabled_types.clear();
        vm.filter.enabled_partial_types.insert(FileType::Jpeg);
        vm.recompute_visible();
        assert_eq!(visible_ids(&vm), vec![2]);

        // Only "JPG" enabled — should show only c.jpg (file_id=1).
        vm.filter.enabled_types.insert(FileType::Jpeg);
        vm.filter.enabled_partial_types.clear();
        vm.recompute_visible();
        assert_eq!(visible_ids(&vm), vec![1]);

        // Both enabled — both visible.
        vm.filter.enabled_partial_types.insert(FileType::Jpeg);
        vm.recompute_visible();
        assert_eq!(visible_ids(&vm), vec![1, 2]);
    }

    #[test]
    fn bookmarked_only_filter_narrows_grid() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        vm.filter.enabled_types.insert(FileType::Jpeg);

        // Use add_file so vm.window is populated for the SQL-roundtrip helper.
        // ids are assigned monotonically by add_file: a.jpg → 0, b.jpg → 1.
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 100);
        add_file(&mut vm, 0, "b.jpg", FileType::Jpeg, 100);

        // Bookmark b.jpg by its file_id.
        let bookmark_target_id = 1u64;
        vm.apply(&CarveEvent::Bookmark {
            file_id: bookmark_target_id,
            bookmarked: true,
            at: "t".into(),
        });
        vm.filter.bookmarked_only = true;
        requery_via_sql(&mut vm);
        assert_eq!(visible_ids(&vm), vec![bookmark_target_id]);
    }

    #[test]
    fn apply_mark_as_best_is_last_writer_wins() {
        let mut vm = ViewModel::new();
        vm.apply(&CarveEvent::MarkAsBest {
            original_file_id: 10,
            chosen_file_id: 11,
            at: "t1".into(),
        });
        vm.apply(&CarveEvent::MarkAsBest {
            original_file_id: 10,
            chosen_file_id: 12,
            at: "t2".into(),
        });
        assert_eq!(vm.best_choices.get(&10), Some(&12));
    }

    #[test]
    fn toggle_bookmark_returns_event_and_updates_state() {
        let mut vm = ViewModel::new();
        let ev = vm.toggle_bookmark(7);
        match ev {
            CarveEvent::Bookmark {
                file_id,
                bookmarked,
                ..
            } => {
                assert_eq!(file_id, 7);
                assert!(bookmarked);
            }
            _ => panic!("expected Bookmark"),
        }
        assert!(vm.bookmarks.contains(&7));

        // Toggle again → un-bookmark
        let ev2 = vm.toggle_bookmark(7);
        match ev2 {
            CarveEvent::Bookmark { bookmarked, .. } => assert!(!bookmarked),
            _ => panic!(),
        }
        assert!(!vm.bookmarks.contains(&7));
    }

    #[test]
    fn add_note_allocates_monotonic_ids_and_returns_event() {
        let mut vm = ViewModel::new();
        let e1 = vm.add_note(7, "first".into());
        let e2 = vm.add_note(7, "second".into());
        let id1 = match e1 {
            CarveEvent::Note { note_id, .. } => note_id,
            _ => panic!(),
        };
        let id2 = match e2 {
            CarveEvent::Note { note_id, .. } => note_id,
            _ => panic!(),
        };
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(vm.notes.get(&7).unwrap().len(), 2);
    }

    #[test]
    fn mark_as_best_returns_event_and_records_choice() {
        let mut vm = ViewModel::new();
        let ev = vm.mark_as_best(10, 11);
        match ev {
            CarveEvent::MarkAsBest {
                original_file_id,
                chosen_file_id,
                ..
            } => {
                assert_eq!(original_file_id, 10);
                assert_eq!(chosen_file_id, 11);
            }
            _ => panic!(),
        }
        assert_eq!(vm.best_choices.get(&10), Some(&11));
    }

    #[test]
    fn keyboard_shortcuts_call_correct_view_model_methods() {
        // Simulates what the Slint key handlers do: invoke the corresponding
        // view-model method directly. Validates the wiring contract without
        // requiring slint-test-harness.
        let mut vm = ViewModel::new();

        // 'b' on a selected file → toggle_bookmark(file_id) returns a
        // Bookmark event with bookmarked=true on first call.
        let ev = vm.toggle_bookmark(42);
        assert!(
            matches!(
                ev,
                CarveEvent::Bookmark {
                    file_id: 42,
                    bookmarked: true,
                    ..
                }
            ),
            "expected Bookmark{{file_id:42, bookmarked:true}}, got {ev:?}"
        );

        // 'n' → add_note passes draft text and returns a Note event.
        let ev = vm.add_note(42, "via key".into());
        assert!(
            matches!(ev, CarveEvent::Note { file_id: 42, .. }),
            "expected Note{{file_id:42}}, got {ev:?}"
        );

        // 'm' → mark_as_best(original, chosen) returns a MarkAsBest event.
        let ev = vm.mark_as_best(42, 43);
        assert!(
            matches!(
                ev,
                CarveEvent::MarkAsBest {
                    original_file_id: 42,
                    chosen_file_id: 43,
                    ..
                }
            ),
            "expected MarkAsBest{{original:42, chosen:43}}, got {ev:?}"
        );
    }

    #[test]
    fn bookmark_filter_can_be_toggled_off_when_zero_bookmarks() {
        // Bug reproducer: chip must still be present (and toggleable) when
        // bookmarks is empty but bookmarked_only is on. Without that, the user
        // is stranded with the filter on and no UI to turn it off.
        let mut vm = ViewModel::new();
        vm.filter.bookmarked_only = true;
        assert!(vm.bookmarks.is_empty());

        let chips = vm.filter_chips();
        let bookmark = chips
            .iter()
            .find(|c| c.kind == FilterChipKind::Bookmarked)
            .expect("bookmark chip must be present when bookmarks is empty");
        assert!(bookmark.enabled);
        assert_eq!(bookmark.count, 0);
        assert_eq!(bookmark.name, "bookmarked");
    }

    #[test]
    fn parse_file_type_pub_accepts_chip_name_format() {
        // The slint_adapter populates chip name as lowercase of Debug formatter.
        // This test pins that contract.
        let name = format!("{:?}", FileType::Jpeg).to_lowercase();
        assert_eq!(name, "jpeg");
        assert_eq!(parse_file_type_pub(&name), Some(FileType::Jpeg));
    }

    #[test]
    fn chip_toggled_with_lowercase_name_flips_enabled_types() {
        let mut vm = ViewModel::new();
        vm.filter.enabled_types.insert(FileType::Jpeg);
        // NOTE: this test inlines the body of on_chip_toggled in
        // crates/utmost-gui/src/slint_adapter.rs (search for `on_chip_toggled`).
        // If that handler changes, update this block to match.
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

    #[test]
    fn file_found_increments_partial_counts_for_partial_jpegs() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));

        let mut fo = create_file_object("part.jpg", FileType::Jpeg, 100, 0, None, 1);
        fo.jpeg_scan = Some(utmost_lib::types::JpegScanInfo {
            width: None,
            height: None,
            fragmentation_point_img_offset: None,
            has_restart_markers: false,
            status: utmost_lib::types::JpegScanStatus::Truncated,
        });
        vm.apply(&CarveEvent::FileFound {
            source_id: 0,
            file: fo,
            img_offset: 0,
            written_path: "part.jpg".into(),
        });

        assert_eq!(*vm.partial_counts.get(&FileType::Jpeg).unwrap(), 1);
    }

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
        // Explicitly enable both image types to test active_count
        vm.filter.enabled_types.insert(FileType::Jpeg);
        vm.filter.enabled_types.insert(FileType::Gif);
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
        assert!(
            !tabs
                .iter()
                .find(|t| t.name == "archives")
                .unwrap()
                .is_selected
        );
    }

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
        vm.filter.enabled_types.insert(FileType::Jpeg);
        vm.filter.enabled_types.insert(FileType::Gif);
        let chips = vm.sub_filter_chips();
        let names: Vec<&str> = chips.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"jpeg"), "expected jpeg in {names:?}");
        assert!(names.contains(&"gif"), "expected gif in {names:?}");
        assert!(
            !names.contains(&"zip"),
            "zip should not appear in Image tab"
        );
        assert!(
            chips
                .iter()
                .all(|c| c.kind == FilterChipKind::Type || c.kind == FilterChipKind::Partial)
        );
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
        vm.filter.enabled_types.insert(FileType::Jpeg);
        vm.filter.enabled_types.insert(FileType::Gif);
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

    #[test]
    fn file_type_group_maps_all_variants() {
        use FileType::*;
        assert_eq!(file_type_group(Jpeg), Group::Image);
        assert_eq!(file_type_group(Gif), Group::Image);
        assert_eq!(file_type_group(Bmp), Group::Image);
        assert_eq!(file_type_group(Png), Group::Image);
        assert_eq!(file_type_group(VJpeg), Group::Image);
        assert_eq!(file_type_group(Mpg), Group::Video);
        assert_eq!(file_type_group(Avi), Group::Video);
        assert_eq!(file_type_group(Wmv), Group::Video);
        assert_eq!(file_type_group(Mov), Group::Video);
        assert_eq!(file_type_group(Mp4), Group::Video);
        assert_eq!(file_type_group(Riff), Group::Video);
        assert_eq!(file_type_group(Pdf), Group::Text);
        assert_eq!(file_type_group(Doc), Group::Text);
        assert_eq!(file_type_group(Htm), Group::Text);
        assert_eq!(file_type_group(Docx), Group::Text);
        assert_eq!(file_type_group(Xlsx), Group::Text);
        assert_eq!(file_type_group(Pptx), Group::Text);
        assert_eq!(file_type_group(Xls), Group::Text);
        assert_eq!(file_type_group(Ppt), Group::Text);
        assert_eq!(file_type_group(Wpd), Group::Text);
        assert_eq!(file_type_group(Sxw), Group::Text);
        assert_eq!(file_type_group(Sxc), Group::Text);
        assert_eq!(file_type_group(Sxi), Group::Text);
        assert_eq!(file_type_group(Ole), Group::Text);
        assert_eq!(file_type_group(Cpp), Group::Text);
        assert_eq!(file_type_group(Config), Group::Text);
        assert_eq!(file_type_group(Reg), Group::Text);
        assert_eq!(file_type_group(Zip), Group::Archives);
        assert_eq!(file_type_group(Rar), Group::Archives);
        assert_eq!(file_type_group(Gzip), Group::Archives);
        assert_eq!(file_type_group(Exe), Group::Executables);
        assert_eq!(file_type_group(Elf), Group::Executables);
        assert_eq!(file_type_group(Wav), Group::Other);
    }

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

    #[test]
    fn hide_no_preview_hides_files_without_thumbnail() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 0, "b.jpg", FileType::Jpeg, 1);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.hide_no_preview = true;
        // Task 13: post-SQL semantics — `hide_no_preview` excludes rows
        // whose `preview_status = 'no_preview'`. Tag b.jpg (id=1) with
        // no_preview; a.jpg (id=0) stays at the default `unknown` and is
        // therefore included.
        let mut overrides = std::collections::BTreeMap::new();
        overrides.insert(1u64, "no_preview");
        requery_via_sql_with_previews(&mut vm, &overrides);
        assert_eq!(visible_ids(&vm), vec![0]);
    }

    #[test]
    fn hide_no_preview_off_keeps_all_files() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 0, "b.jpg", FileType::Jpeg, 1);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.hide_no_preview = false;
        // Even with one row marked `no_preview`, both must be visible when
        // the filter is off.
        let mut overrides = std::collections::BTreeMap::new();
        overrides.insert(0u64, "has_preview");
        overrides.insert(1u64, "no_preview");
        requery_via_sql_with_previews(&mut vm, &overrides);
        assert_eq!(visible_ids(&vm).len(), 2);
    }

    #[test]
    fn hide_no_preview_composes_with_chip_filter() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 0, "b.pdf", FileType::Pdf, 1);
        // Both have a preview; only the jpeg chip is enabled, so only a.jpg
        // should be visible.
        let mut overrides = std::collections::BTreeMap::new();
        overrides.insert(0u64, "has_preview");
        overrides.insert(1u64, "has_preview");
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.hide_no_preview = true;
        requery_via_sql_with_previews(&mut vm, &overrides);
        assert_eq!(visible_ids(&vm), vec![0]);
    }

    #[test]
    fn set_thumbnail_ready_false_removes_from_visible_when_hide_on() {
        // Task 13: the in-VM `set_thumbnail_ready` is a no-op stub; the
        // production flow is ThumbWorker → preview_outcomes_tx → writer
        // → `preview_status` column → next Requery. We simulate that here
        // by passing the preview_status directly into the SQL roundtrip.
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.hide_no_preview = true;

        let mut overrides = std::collections::BTreeMap::new();
        overrides.insert(0u64, "has_preview");
        requery_via_sql_with_previews(&mut vm, &overrides);
        assert_eq!(visible_ids(&vm).len(), 1);

        overrides.insert(0u64, "no_preview");
        requery_via_sql_with_previews(&mut vm, &overrides);
        assert!(visible_ids(&vm).is_empty());
    }

    #[test]
    fn size_range_none_matches_all() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 10);
        add_file(&mut vm, 0, "b.jpg", FileType::Jpeg, 1_000_000);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.size_range = None;
        requery_via_sql(&mut vm);
        assert_eq!(visible_ids(&vm).len(), 2);
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
        requery_via_sql(&mut vm);
        assert_eq!(visible_ids(&vm).len(), 2);
        let sizes: Vec<u64> = visible_ids(&vm)
            .iter()
            .map(|id| vm.window.get(id).unwrap().file.filesize)
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
        requery_via_sql(&mut vm);
        assert_eq!(visible_ids(&vm).len(), 1);
    }

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
        requery_via_sql(&mut vm);
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
        // Use a non-zero new_max here: new_max == 0 is its own special case
        // (no data to clamp against) and is covered by
        // clamp_size_range_to_zero_max_preserves_range below.
        vm.clamp_size_range_to(100);
        assert_eq!(vm.filter.size_range, None);
    }

    #[test]
    fn clamp_size_range_to_zero_max_preserves_range() {
        // Regression: during the first sync() right after case hydration,
        // match_ids is empty (the initial Requery hasn't returned yet), so
        // size_filter_max() returns 0. clamp_size_range_to(0) must NOT
        // destroy the user's saved size_range — the slider is hidden in
        // this state via size_slider_visible=false, but the value has to
        // survive until the indexer responds with MatchIds and the real
        // upper bound is known. Same applies when the user narrows the
        // filter to zero matches mid-session.
        let mut vm = ViewModel::new();
        vm.filter.size_range = Some((1_000_000, 10_000_000));
        vm.clamp_size_range_to(0);
        assert_eq!(vm.filter.size_range, Some((1_000_000, 10_000_000)));
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

    // ── UiStateSnapshot tests ──────────────────────────────────────────────

    fn all_known_file_types() -> Vec<FileType> {
        // Source from the existing parse_file_type matches by feeding it every
        // string the codebase recognises. If parse_file_type recognises a string
        // not present in file_type_to_pub_str, the assertion above catches it.
        let candidates = [
            "jpeg", "gif", "bmp", "mpg", "pdf", "doc", "avi", "wmv", "htm", "zip", "mov", "xls",
            "ppt", "wpd", "cpp", "ole", "gzip", "riff", "wav", "vjpeg", "sxw", "sxc", "sxi", "png",
            "rar", "exe", "elf", "reg", "docx", "xlsx", "pptx", "mp4", "config",
        ];
        candidates
            .iter()
            .filter_map(|s| parse_file_type_pub(s))
            .collect()
    }

    #[test]
    fn file_type_string_round_trip() {
        // Walk every variant via the iterator used by chips/groups; if any
        // variant is missing from file_type_to_pub_str, this fails.
        for ft in all_known_file_types() {
            let s = file_type_to_pub_str(ft);
            assert_ne!(
                s, "unknown",
                "file_type_to_pub_str missing arm for {:?}",
                ft
            );
            let back = parse_file_type_pub(s);
            assert_eq!(back, Some(ft), "round-trip failed for {:?} via {:?}", ft, s);
        }
    }

    #[test]
    fn snapshot_from_default_view_model_round_trips() {
        let vm = ViewModel::new();
        let snap = ui_snapshot_from_view_model(&vm);
        assert_eq!(snap.v, UI_STATE_CURRENT_VERSION);

        let run = RunSummary {
            configured_types: vec![FileType::Jpeg, FileType::Pdf],
            ..empty_run_summary()
        };
        let sources = vec![];
        let (filter, vis, group, sel) = ui_snapshot_into_runtime(snap, &run, &sources);

        assert_eq!(filter, FilterState::default());
        assert!(vis);
        assert_eq!(group, None);
        assert_eq!(sel, None);
    }

    #[test]
    fn into_runtime_drops_unknown_file_types() {
        let snap = UiStateSnapshot {
            v: 1,
            filter: FilterStateSnapshot {
                enabled_types: vec!["jpeg".into(), "totally-bogus".into(), "pdf".into()],
                enabled_partial_types: vec![],
                bookmarked_only: false,
                source_filter: None,
                sort_key: "Filename".into(),
                sort_dir: "Asc".into(),
                bookmarked_first: false,
                hide_no_preview: false,
                size_range: None,
            },
            filters_visible: true,
            selected_group: None,
            selection_file_id: None,
        };
        let run = RunSummary {
            configured_types: vec![FileType::Jpeg, FileType::Pdf],
            ..empty_run_summary()
        };
        let (filter, _, _, _) = ui_snapshot_into_runtime(snap, &run, &[]);
        assert!(filter.enabled_types.contains(&FileType::Jpeg));
        assert!(filter.enabled_types.contains(&FileType::Pdf));
        assert_eq!(filter.enabled_types.len(), 2, "bogus type must be dropped");
    }

    #[test]
    fn into_runtime_intersects_with_configured_types() {
        let snap = UiStateSnapshot {
            v: 1,
            filter: FilterStateSnapshot {
                enabled_types: vec!["jpeg".into(), "pdf".into()],
                enabled_partial_types: vec![],
                bookmarked_only: false,
                source_filter: None,
                sort_key: "Filename".into(),
                sort_dir: "Asc".into(),
                bookmarked_first: false,
                hide_no_preview: false,
                size_range: None,
            },
            filters_visible: true,
            selected_group: None,
            selection_file_id: None,
        };
        let run = RunSummary {
            configured_types: vec![FileType::Jpeg], // PDF NOT configured
            ..empty_run_summary()
        };
        let (filter, _, _, _) = ui_snapshot_into_runtime(snap, &run, &[]);
        assert!(filter.enabled_types.contains(&FileType::Jpeg));
        assert!(
            !filter.enabled_types.contains(&FileType::Pdf),
            "PDF must be dropped because it's not in configured_types"
        );
    }

    #[test]
    fn into_runtime_clears_source_filter_for_missing_source() {
        let snap = UiStateSnapshot {
            v: 1,
            filter: FilterStateSnapshot {
                enabled_types: vec![],
                enabled_partial_types: vec![],
                bookmarked_only: false,
                source_filter: Some(99),
                sort_key: "Filename".into(),
                sort_dir: "Asc".into(),
                bookmarked_first: false,
                hide_no_preview: false,
                size_range: None,
            },
            filters_visible: true,
            selected_group: None,
            selection_file_id: None,
        };
        let run = empty_run_summary();
        let sources = vec![SourceRow {
            source_id: 0,
            filename: "a.img".into(),
            output_subdir: "a".into(),
            total_bytes: 0,
            bytes_read: 0,
            files_found: 0,
            status: SourceStatus::Finished,
            duration_ms: None,
        }];
        let (filter, _, _, _) = ui_snapshot_into_runtime(snap, &run, &sources);
        assert_eq!(
            filter.source_filter, None,
            "missing source must clear filter"
        );
    }

    #[test]
    fn into_runtime_clamps_invalid_size_range() {
        let mk = |range: Option<(u64, u64)>| UiStateSnapshot {
            v: 1,
            filter: FilterStateSnapshot {
                enabled_types: vec![],
                enabled_partial_types: vec![],
                bookmarked_only: false,
                source_filter: None,
                sort_key: "Filename".into(),
                sort_dir: "Asc".into(),
                bookmarked_first: false,
                hide_no_preview: false,
                size_range: range,
            },
            filters_visible: true,
            selected_group: None,
            selection_file_id: None,
        };
        let run = empty_run_summary();

        let (f, _, _, _) = ui_snapshot_into_runtime(mk(Some((100, 50))), &run, &[]);
        assert_eq!(f.size_range, None, "lo>hi must clamp to None");

        let (f, _, _, _) = ui_snapshot_into_runtime(mk(Some((0, 0))), &run, &[]);
        assert_eq!(f.size_range, None, "(0,0) must clamp to None");

        let (f, _, _, _) = ui_snapshot_into_runtime(mk(Some((10, 100))), &run, &[]);
        assert_eq!(f.size_range, Some((10, 100)), "valid range preserved");
    }

    #[test]
    fn into_runtime_drops_bogus_sort_strings_to_default() {
        let snap = UiStateSnapshot {
            v: 1,
            filter: FilterStateSnapshot {
                enabled_types: vec![],
                enabled_partial_types: vec![],
                bookmarked_only: false,
                source_filter: None,
                sort_key: "BogusKey".into(),
                sort_dir: "BogusDir".into(),
                bookmarked_first: false,
                hide_no_preview: false,
                size_range: None,
            },
            filters_visible: true,
            selected_group: None,
            selection_file_id: None,
        };
        let run = empty_run_summary();
        let (filter, _, _, _) = ui_snapshot_into_runtime(snap, &run, &[]);
        assert_eq!(filter.sort_key, SortKey::default());
        assert_eq!(filter.sort_dir, SortDir::default());
    }

    #[test]
    fn into_runtime_unknown_schema_version_returns_defaults() {
        let snap = UiStateSnapshot {
            v: 9999,
            filter: FilterStateSnapshot {
                enabled_types: vec!["jpeg".into()],
                enabled_partial_types: vec![],
                bookmarked_only: true,
                source_filter: Some(0),
                sort_key: "Size".into(),
                sort_dir: "Desc".into(),
                bookmarked_first: true,
                hide_no_preview: true,
                size_range: Some((10, 100)),
            },
            filters_visible: false,
            selected_group: Some("image".into()),
            selection_file_id: Some(42),
        };
        let run = RunSummary {
            configured_types: vec![FileType::Jpeg],
            ..empty_run_summary()
        };
        let (filter, vis, group, sel) = ui_snapshot_into_runtime(snap, &run, &[]);
        assert_eq!(filter, FilterState::default());
        assert!(vis);
        assert_eq!(group, None);
        assert_eq!(sel, None);
    }

    #[test]
    fn from_view_model_round_trips_all_fields() {
        let mut vm = ViewModel::new();
        vm.filter.enabled_types.insert(FileType::Jpeg);
        vm.filter.enabled_partial_types.insert(FileType::Pdf);
        vm.filter.bookmarked_only = true;
        vm.filter.source_filter = Some(0);
        vm.filter.sort_key = SortKey::Size;
        vm.filter.sort_dir = SortDir::Desc;
        vm.filter.bookmarked_first = true;
        vm.filter.hide_no_preview = true;
        vm.filter.size_range = Some((10, 100));
        vm.filters_visible = false;
        vm.selected_group = Some(Group::Image);
        vm.selection = Some(7);

        let snap = ui_snapshot_from_view_model(&vm);

        // Round-trip through into_runtime with a permissive case.
        let run = RunSummary {
            configured_types: vec![FileType::Jpeg, FileType::Pdf],
            ..empty_run_summary()
        };
        let sources = vec![SourceRow {
            source_id: 0,
            filename: "a.img".into(),
            output_subdir: "a".into(),
            total_bytes: 0,
            bytes_read: 0,
            files_found: 0,
            status: SourceStatus::Finished,
            duration_ms: None,
        }];
        let (f, vis, g, sel) = ui_snapshot_into_runtime(snap, &run, &sources);

        assert_eq!(f.enabled_types, vm.filter.enabled_types);
        assert_eq!(f.enabled_partial_types, vm.filter.enabled_partial_types);
        assert!(f.bookmarked_only);
        assert_eq!(f.source_filter, Some(0));
        assert_eq!(f.sort_key, SortKey::Size);
        assert_eq!(f.sort_dir, SortDir::Desc);
        assert!(f.bookmarked_first);
        assert!(f.hide_no_preview);
        assert_eq!(f.size_range, Some((10, 100)));
        assert!(!vis);
        assert_eq!(g, Some(Group::Image));
        assert_eq!(sel, Some(7));
    }

    #[test]
    fn snapshot_deserializes_with_missing_fields() {
        // A future-compatible JSON missing some fields must still parse.
        let json = r#"{"v": 1}"#;
        let snap: UiStateSnapshot = serde_json::from_str(json).expect("must deserialize");
        assert_eq!(snap.v, 1);
        assert_eq!(snap.filter, FilterStateSnapshot::default());
        assert!(!snap.filters_visible);
        assert!(snap.selected_group.is_none());
        assert!(snap.selection_file_id.is_none());
    }
}
