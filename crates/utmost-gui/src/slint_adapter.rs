//! Bridges the pure-Rust ViewModel to the Slint MainWindow.

use slint::{ComponentHandle, Model, SharedString, VecModel};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use crate::indexer_thread::{IndexerCommand, IndexerEvent};
use crate::preview::PreviewRegistry;
use crate::thumb_worker::{PreviewOutcome, ThumbWorker};
use crate::view_model::{FileId, NavDirection, SourceStatus, ViewModel, parse_file_type_pub};

/// Window size for the leading fetch (used when `MatchIds` arrives before
/// the user has scrolled). Subsequent scroll-driven slides compute a size
/// from the visible-tile count and clamp into `[WINDOW_SIZE_MIN, WINDOW_SIZE_MAX]`.
const WINDOW_SIZE_DEFAULT: usize = 500;
const WINDOW_SIZE_MIN: usize = 500;
const WINDOW_SIZE_MAX: usize = 5000;
/// Number of rows of slack on each side of the visible range before we
/// schedule a new `FetchWindow`. Mirrors `vm.need_slide`'s `slide_trigger`.
const SLIDE_TRIGGER_ROWS: usize = 4;
/// Tile dimensions in logical pixels — mirrors `tile_h` + `gap` in
/// `detail.slint`. Must stay in sync with the Slint side; the pitch is used
/// both for the slide math and for the cols approximation in tests.
const TILE_PITCH_Y: f32 = 168.0 + 8.0;
/// Vertical chrome above the grid pane (header bar + filter chips + tab
/// bar). Used to approximate the grid pane's visible height from the
/// window's total height. This is an upper bound on the chrome; the actual
/// value depends on whether the filter chips are visible. Slight over- or
/// under-estimation is harmless: it shifts `visible_count` by a tile or two
/// which only changes the slide trigger and window-size math at the
/// margins.
const GRID_CHROME_HEIGHT_PX: f32 = 200.0;

slint::include_modules!();

/// Bump the VM's `current_epoch` and post a `Requery` to the indexer thread
/// (when wired). Filter/sort callbacks call this after mutating
/// `v.filter` to ask the query-loop thread to recompute `match_ids`.
fn requery(tx: &Option<crossbeam_channel::Sender<IndexerCommand>>, v: &mut ViewModel) {
    v.current_epoch += 1;
    if let Some(tx) = tx {
        let _ = tx.send(IndexerCommand::Requery {
            filter: v.filter.clone(),
            epoch: v.current_epoch,
        });
    }
}

/// Forward a UI-originated annotation event (`Bookmark`, `Note`, `MarkAsBest`)
/// to the indexer thread so it lands in SQLite immediately. Without this,
/// these events sit in the `.pending` journal until `RunFinished` folds them
/// — which means filter chips like "Bookmarked" return zero rows mid-run even
/// though `vm.bookmarks` has the entry. The journal write is still required
/// for crash recovery; on next session, the folded events are re-applied via
/// `IndexDbWriter::apply` and the writer's `on_conflict` upserts make the
/// double-write idempotent.
fn forward_annotation(
    tx: &Option<crossbeam_channel::Sender<IndexerCommand>>,
    ev: &utmost_lib::events::CarveEvent,
) {
    if let Some(tx) = tx {
        let _ = tx.send(IndexerCommand::ApplyAnnotation(Box::new(ev.clone())));
    }
}

/// Replace the contents of a `VecModel` while preserving repeated component
/// instances. Uses `set_row_data` / `push` / `remove` so the corresponding
/// Slint `for` repeater fires `row_changed` notifications instead of a full
/// model reset — TouchArea instances, hover state, and Image elements survive
/// each tick. Calling `model.set_vec` instead would tear down and rebuild
/// every repeated component, which destroys hover state and eats clicks.
fn replace_model<T: Clone + 'static>(model: &VecModel<T>, new_rows: Vec<T>) {
    let cur = model.row_count();
    let n = new_rows.len();
    let common = cur.min(n);
    for (i, row) in new_rows.iter().take(common).enumerate() {
        model.set_row_data(i, row.clone());
    }
    for row in new_rows.iter().skip(common) {
        model.push(row.clone());
    }
    while model.row_count() > n {
        model.remove(model.row_count() - 1);
    }
}

pub struct UiState {
    pub window: MainWindow,
    pub sources_model: Rc<VecModel<SourceRowData>>,
    pub chips_model: Rc<VecModel<FilterChipData>>,
    pub group_chips_model: Rc<VecModel<GroupTabData>>,
    pub tiles_model: Rc<VecModel<FileTileData>>,
    pub metadata_model: Rc<VecModel<MetadataRow>>,
    pub registry: Arc<PreviewRegistry>,
    /// Locates source images by `source_id` for the byte-range thumb fallback.
    /// Kept in sync with `thumbs.sources_by_id`: both reflect the same source
    /// set; the resolver maps `source_id -> path`, the map is populated each
    /// sync from `vm.sources`. Task 7 wires the user-supplied --source values.
    pub resolver: Arc<crate::source_resolver::SourceResolver>,
    pub thumbs: ThumbWorker,
    /// UI-thread cache of `slint::Image` instances keyed by FileId. Re-using
    /// the same `Image` handle across syncs makes the property setter on the
    /// Image element see no change (Slint compares `Image` by handle), which
    /// prevents the texture re-upload + briefly-blank state that would
    /// otherwise happen 10 times per second.
    image_cache: RefCell<HashMap<FileId, slint::Image>>,
    /// Cache of full-resolution images for the side-panel preview and lightbox.
    /// `None` is a negative-cache entry: the renderer was attempted and produced
    /// no image (decode error, unparseable type, or non-image preview output).
    /// Storing the negative result prevents re-running the renderer on every
    /// sync tick when a file's preview can't be produced.
    image_cache_full: RefCell<HashMap<FileId, Option<slint::Image>>>,
    /// Shared journal handle. Wrapped in Arc<Mutex<Option<...>>> so callbacks
    /// (which capture it at construction time as FnMut closures) can see a
    /// journal installed later via `set_journal`.
    pub journal: Arc<Mutex<Option<Arc<crate::journal::Journal>>>>,
    /// Receiver end of the background recovery worker channel. `None` until
    /// `on_run_recovery` spawns the worker. Drained by the periodic timer in
    /// `lib.rs::launch_ui_with_journal`.
    pub recovery_rx:
        Rc<RefCell<Option<crossbeam_channel::Receiver<utmost_lib::events::CarveEvent>>>>,
    /// Receiver end of the background indexer-progress channel. `None` until
    /// `run_from_file` installs one. Drained at the top of [`UiState::sync`]
    /// to drive the indexing overlay.
    pub indexer_rx:
        RefCell<Option<crossbeam_channel::Receiver<crate::indexer_thread::IndexProgress>>>,
    /// Wall-clock instant at which the most recent indexer run reported
    /// `Started`. Used to debounce the overlay so short runs (<250 ms) do
    /// not flash it on screen.
    pub indexer_started_at: RefCell<Option<std::time::Instant>>,
    /// Total bytes reported by the most recent `Started` message. Zero when
    /// the indexer was unable to stat the bin (overlay shows an
    /// indeterminate progress bar).
    pub indexer_total_bytes: RefCell<u64>,
    /// Most recent `Bytes` tick value, used as the numerator for the
    /// progress bar.
    pub indexer_last_bytes: RefCell<u64>,
    /// Most recent `Files` tick value, displayed as "N files indexed".
    pub indexer_last_files: RefCell<u64>,
    /// Performance recorder shared with the rest of the GUI subsystem. Cheap to
    /// clone (Arc); guards returned from `phase()` are zero-cost when the
    /// recorder is disabled (the common case unless `UTMOST_PERF_TRACE=1`).
    pub perf: Arc<crate::telemetry::PerfRecorder>,
    /// Command sender for the query-loop indexer thread. `None` when the
    /// UiState is constructed without indexer plumbing (e.g. unit tests that
    /// don't drive the indexer). Filter/sort mutations bump
    /// `vm.current_epoch` and post a [`IndexerCommand::Requery`] here.
    pub indexer_cmd_tx: Option<crossbeam_channel::Sender<IndexerCommand>>,
    /// Event receiver for the query-loop indexer thread. Drained at the top
    /// of [`UiState::sync`]; each [`IndexerEvent`] is applied to the VM.
    pub indexer_event_rx: Option<crossbeam_channel::Receiver<IndexerEvent>>,
    /// Most recent `preview_status_version` observed at the end of a sync
    /// tick. When this lags `vm.preview_status_version` AND
    /// `vm.filter.hide_no_preview` is on, the next sync issues a debounced
    /// `Requery` so files that just flipped to `no_preview` drop out of
    /// the visible grid.
    last_observed_preview_version: std::cell::Cell<u64>,
    /// Wall-clock instant of the most recent auto-requery driven by a
    /// preview-status version bump. Used to debounce repeated bumps from
    /// the thumb worker; one auto-requery per second is plenty for the UI
    /// to feel "live" without thrashing SQL.
    last_preview_requery_at: std::cell::Cell<std::time::Instant>,
}

impl UiState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vm: Arc<Mutex<ViewModel>>,
        source_search_locations: Vec<std::path::PathBuf>,
        event_log_path: Option<std::path::PathBuf>,
        indexer_rx: Option<crossbeam_channel::Receiver<crate::indexer_thread::IndexProgress>>,
        perf: Arc<crate::telemetry::PerfRecorder>,
        preview_outcomes_tx: Option<crossbeam_channel::Sender<PreviewOutcome>>,
        indexer_cmd_tx: Option<crossbeam_channel::Sender<IndexerCommand>>,
        indexer_event_rx: Option<crossbeam_channel::Receiver<IndexerEvent>>,
    ) -> Result<Self, slint::PlatformError> {
        let window = MainWindow::new()?;
        let sources_model: Rc<VecModel<SourceRowData>> = Rc::new(VecModel::default());
        let chips_model: Rc<VecModel<FilterChipData>> = Rc::new(VecModel::default());
        let tiles_model: Rc<VecModel<FileTileData>> = Rc::new(VecModel::default());
        let metadata_model: Rc<VecModel<MetadataRow>> = Rc::new(VecModel::default());
        window.set_sources(sources_model.clone().into());
        window.set_chips(chips_model.clone().into());
        let group_chips_model: Rc<VecModel<GroupTabData>> = Rc::new(VecModel::default());
        window.set_group_chips(group_chips_model.clone().into());
        window.set_tiles(tiles_model.clone().into());
        window.set_selected_metadata(metadata_model.clone().into());

        let registry = Arc::new(PreviewRegistry::with_defaults_and_jpeg());
        let resolver = Arc::new(crate::source_resolver::SourceResolver::new(
            source_search_locations,
            event_log_path.clone(),
        ));
        let vm_for_thumbs = vm.clone();
        // on_complete only fires on successful decode (HasPreview outcomes);
        // the failure path stores the id in the `failed` set without calling
        // back. HasPreview doesn't change the hide_no_preview filter result
        // (files with previews are SHOWN, not hidden), so requerying here
        // would just churn the window without changing match_ids. The
        // *actual* filter refresh path is the preview-status-version
        // observer at the top of `sync()`, fed by the outcomes writer
        // emitting `IndexerEvent::PreviewStatusVersion` after each batch.
        let on_complete: Arc<dyn Fn(crate::view_model::FileId) + Send + Sync> =
            Arc::new(move |id| {
                let mut v = vm_for_thumbs.lock().unwrap();
                v.set_thumbnail_ready(id, true);
            });
        let thumbs = ThumbWorker::start(
            registry.clone(),
            resolver.clone(),
            256,
            2,
            on_complete,
            preview_outcomes_tx,
        );

        // Shared journal handle: None until set_journal is called from lib.rs.
        // Using Arc<Mutex<Option<...>>> so closures can capture it at
        // construction time while lib.rs installs the real journal later.
        let journal_handle: Arc<Mutex<Option<Arc<crate::journal::Journal>>>> =
            Arc::new(Mutex::new(None));

        // Recovery channel handle: None until on_run_recovery spawns the worker.
        // Rc<RefCell<...>> because it is only accessed on the UI thread.
        let recovery_rx_handle: Rc<
            RefCell<Option<crossbeam_channel::Receiver<utmost_lib::events::CarveEvent>>>,
        > = Rc::new(RefCell::new(None));

        // Wire Slint callbacks → view-model mutations. The periodic 100ms timer
        // in `launch_ui` will pick up the mutations on the next tick and resync.
        {
            let weak = window.as_weak();
            let vm_cb = vm.clone();
            let tx_cb = indexer_cmd_tx.clone();
            window.on_row_clicked(move |source_id| {
                let mut v = vm_cb.lock().unwrap();
                v.filter.source_filter = Some(source_id as u32);
                v.selection = None;
                requery(&tx_cb, &mut v);
                if let Some(w) = weak.upgrade() {
                    w.set_show_detail(true);
                }
            });
        }
        {
            let vm_cb = vm.clone();
            window.on_tile_clicked(move |id| {
                let mut v = vm_cb.lock().unwrap();
                v.selection = Some(id as u64);
            });
        }
        {
            let vm_cb = vm.clone();
            let tx_cb = indexer_cmd_tx.clone();
            window.on_chip_toggled(move |name| {
                let mut v = vm_cb.lock().unwrap();
                let name = name.to_string();
                if let Some(ft_str) = name.strip_prefix("partial:") {
                    if let Some(ft) = parse_file_type_pub(ft_str) {
                        if v.filter.enabled_partial_types.contains(&ft) {
                            v.filter.enabled_partial_types.remove(&ft);
                        } else {
                            v.filter.enabled_partial_types.insert(ft);
                        }
                    }
                } else if let Some(ft) = parse_file_type_pub(&name) {
                    if v.filter.enabled_types.contains(&ft) {
                        v.filter.enabled_types.remove(&ft);
                    } else {
                        v.filter.enabled_types.insert(ft);
                    }
                }
                requery(&tx_cb, &mut v);
            });
        }
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
            let tx_cb = indexer_cmd_tx.clone();
            window.on_bookmarked_filter_toggle(move || {
                let mut v = vm_cb.lock().unwrap();
                v.filter.bookmarked_only = !v.filter.bookmarked_only;
                requery(&tx_cb, &mut v);
            });
        }
        {
            let vm_cb = vm.clone();
            let tx_cb = indexer_cmd_tx.clone();
            window.on_hide_no_preview_toggle(move || {
                let mut v = vm_cb.lock().unwrap();
                v.filter.hide_no_preview = !v.filter.hide_no_preview;
                requery(&tx_cb, &mut v);
            });
        }
        {
            let vm_cb = vm.clone();
            let tx_cb = indexer_cmd_tx.clone();
            window.on_sort_key_changed(move |idx| {
                let mut v = vm_cb.lock().unwrap();
                v.filter.sort_key = match idx {
                    0 => crate::view_model::SortKey::Filename,
                    1 => crate::view_model::SortKey::Size,
                    2 => crate::view_model::SortKey::FileType,
                    3 => crate::view_model::SortKey::SourceOffset,
                    _ => crate::view_model::SortKey::Filename,
                };
                requery(&tx_cb, &mut v);
            });
        }
        {
            let vm_cb = vm.clone();
            let tx_cb = indexer_cmd_tx.clone();
            window.on_sort_dir_toggle(move || {
                let mut v = vm_cb.lock().unwrap();
                v.filter.sort_dir = match v.filter.sort_dir {
                    crate::view_model::SortDir::Asc => crate::view_model::SortDir::Desc,
                    crate::view_model::SortDir::Desc => crate::view_model::SortDir::Asc,
                };
                requery(&tx_cb, &mut v);
            });
        }
        {
            let vm_cb = vm.clone();
            let tx_cb = indexer_cmd_tx.clone();
            window.on_bookmarked_first_toggle(move || {
                let mut v = vm_cb.lock().unwrap();
                v.filter.bookmarked_first = !v.filter.bookmarked_first;
                requery(&tx_cb, &mut v);
            });
        }
        {
            let vm_cb = vm.clone();
            let tx_cb = indexer_cmd_tx.clone();
            window.on_size_range_changed(move |lo_norm, hi_norm| {
                let mut v = vm_cb.lock().unwrap();
                let max_bytes = v.size_filter_max();
                if max_bytes == 0 {
                    v.filter.size_range = None;
                    requery(&tx_cb, &mut v);
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
                requery(&tx_cb, &mut v);
            });
        }
        {
            let vm_cb = vm.clone();
            window.on_gallery_nav(move |dir, cols| {
                let dir = match dir.as_str() {
                    "left" => NavDirection::Left,
                    "right" => NavDirection::Right,
                    "up" => NavDirection::Up,
                    "down" => NavDirection::Down,
                    other => {
                        debug_assert!(false, "unknown gallery-nav direction: {other}");
                        return;
                    }
                };
                let mut v = vm_cb.lock().unwrap();
                v.gallery_move(dir, cols as usize);
            });
        }
        {
            let vm_cb = vm.clone();
            let tx_cb = indexer_cmd_tx.clone();
            window.on_select_all(move || {
                let mut v = vm_cb.lock().unwrap();
                v.filter.enabled_types = v.type_counts.keys().copied().collect();
                requery(&tx_cb, &mut v);
            });
        }
        {
            let vm_cb = vm.clone();
            let tx_cb = indexer_cmd_tx.clone();
            window.on_select_none(move || {
                let mut v = vm_cb.lock().unwrap();
                v.filter.enabled_types.clear();
                requery(&tx_cb, &mut v);
            });
        }
        {
            let weak = window.as_weak();
            let vm_cb = vm.clone();
            let tx_cb = indexer_cmd_tx.clone();
            window.on_back_clicked(move || {
                let mut v = vm_cb.lock().unwrap();
                v.filter.source_filter = None;
                v.selection = None;
                v.lightbox = None;
                requery(&tx_cb, &mut v);
                if let Some(w) = weak.upgrade() {
                    w.set_show_detail(false);
                }
            });
        }
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
        {
            let vm_cb = vm.clone();
            window.on_grid_background_clicked(move || {
                let mut v = vm_cb.lock().unwrap();
                v.deselect();
            });
        }
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
        {
            let vm_cb = vm.clone();
            let journal_cb = journal_handle.clone();
            let tx_cb = indexer_cmd_tx.clone();
            window.on_lightbox_toggle_bookmark(move || {
                let mut v = vm_cb.lock().unwrap();
                if let Some(sel) = v.lightbox {
                    // Task 12: FoundFile.id == file.file_id since Task 8, and
                    // FileId is the engine-allocated durable file_id, so the
                    // lightbox selection itself is the library file_id.
                    let lib_file_id = sel;
                    let ev = v.toggle_bookmark(lib_file_id);
                    let j = journal_cb.lock().unwrap();
                    if let Some(ref journal) = *j {
                        if let Err(e) = journal.append(&ev) {
                            tracing::warn!("journal append failed: {e}");
                        }
                    } else {
                        tracing::debug!("annotation event with no journal handle: {ev:?}");
                    }
                    forward_annotation(&tx_cb, &ev);
                }
            });
        }
        {
            let vm_cb = vm.clone();
            let journal_cb = journal_handle.clone();
            let tx_cb = indexer_cmd_tx.clone();
            window.on_lightbox_add_note(move |text| {
                let mut v = vm_cb.lock().unwrap();
                if let Some(sel) = v.lightbox {
                    // Task 12: see comment in on_lightbox_toggle_bookmark.
                    let lib_file_id = sel;
                    let ev = v.add_note(lib_file_id, text.to_string());
                    let j = journal_cb.lock().unwrap();
                    if let Some(ref journal) = *j {
                        if let Err(e) = journal.append(&ev) {
                            tracing::warn!("journal append failed: {e}");
                        }
                    } else {
                        tracing::debug!("annotation event with no journal handle: {ev:?}");
                    }
                    forward_annotation(&tx_cb, &ev);
                }
            });
        }
        {
            let vm_cb = vm.clone();
            let journal_cb = journal_handle.clone();
            let tx_cb = indexer_cmd_tx.clone();
            window.on_lightbox_mark_best(move || {
                let mut v = vm_cb.lock().unwrap();
                if let Some(sel) = v.lightbox {
                    // Task 12: see comment in on_lightbox_toggle_bookmark.
                    let lib_file_id = sel;
                    if let Some(&orig) = v.variant_of.get(&lib_file_id) {
                        let ev = v.mark_as_best(orig, lib_file_id);
                        let j = journal_cb.lock().unwrap();
                        if let Some(ref journal) = *j {
                            if let Err(e) = journal.append(&ev) {
                                tracing::warn!("journal append failed: {e}");
                            }
                        } else {
                            tracing::debug!("annotation event with no journal handle: {ev:?}");
                        }
                        forward_annotation(&tx_cb, &ev);
                    }
                }
            });
        }
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
        {
            let vm_cb = vm.clone();
            let journal_cb = journal_handle.clone();
            let tx_cb = indexer_cmd_tx.clone();
            window.on_toggle_bookmark(move || {
                let mut v = vm_cb.lock().unwrap();
                if let Some(sel) = v.selection {
                    // Task 12: see comment in on_lightbox_toggle_bookmark.
                    let lib_file_id = sel;
                    // Variants are not bookmarkable per spec.
                    if v.variant_of.contains_key(&lib_file_id) {
                        return;
                    }
                    let ev = v.toggle_bookmark(lib_file_id);
                    let j = journal_cb.lock().unwrap();
                    if let Some(ref journal) = *j {
                        if let Err(e) = journal.append(&ev) {
                            tracing::warn!("journal append failed: {e}");
                        }
                    } else {
                        tracing::debug!("annotation event with no journal handle: {ev:?}");
                    }
                    forward_annotation(&tx_cb, &ev);
                }
            });
        }
        {
            let vm_cb = vm.clone();
            let journal_cb = journal_handle.clone();
            let tx_cb = indexer_cmd_tx.clone();
            window.on_add_note(move |text| {
                let mut v = vm_cb.lock().unwrap();
                if let Some(sel) = v.selection {
                    // Task 12: see comment in on_lightbox_toggle_bookmark.
                    let lib_file_id = sel;
                    let ev = v.add_note(lib_file_id, text.to_string());
                    let j = journal_cb.lock().unwrap();
                    if let Some(ref journal) = *j {
                        if let Err(e) = journal.append(&ev) {
                            tracing::warn!("journal append failed: {e}");
                        }
                    } else {
                        tracing::debug!("annotation event with no journal handle: {ev:?}");
                    }
                    forward_annotation(&tx_cb, &ev);
                }
            });
        }
        {
            let vm_cb = vm.clone();
            window.on_open_variant_viewer(move || {
                let mut v = vm_cb.lock().unwrap();
                if let Some(sel) = v.selection {
                    // Task 12: FileId is the library file_id.
                    let lib_file_id = sel;
                    if v.variants.contains_key(&lib_file_id) {
                        v.variant_viewer = Some(lib_file_id);
                    }
                }
            });
        }
        {
            let vm_cb = vm.clone();
            window.on_variant_thumb_double_clicked(move |variant_id| {
                let mut v = vm_cb.lock().unwrap();
                v.open_lightbox_for_variant(variant_id as u64);
            });
        }
        {
            let vm_cb = vm.clone();
            window.on_variant_thumb_clicked(move |_variant_id| {
                // Single-click sets selection to the variant (for preview pane swap).
                // No special action — adapter resync will reflect it.
                let _v = vm_cb.lock().unwrap();
            });
        }
        {
            let vm_cb = vm.clone();
            window.on_variant_viewer_close(move || {
                let mut v = vm_cb.lock().unwrap();
                v.close_variant_viewer();
            });
        }
        {
            let vm_cb = vm.clone();
            window.on_variant_viewer_thumb_clicked(move |variant_id| {
                // Single-click: select the variant (no other action — preview swap handled
                // by adapter resync when v.selection updates; but variants are not in
                // visible_files, so we set v.lightbox-like state by future tasks).
                let _ = variant_id;
                drop(vm_cb.lock().unwrap());
            });
        }
        {
            let vm_cb = vm.clone();
            window.on_variant_viewer_thumb_double_clicked(move |variant_id| {
                let mut v = vm_cb.lock().unwrap();
                v.open_lightbox_for_variant(variant_id as u64);
            });
        }
        {
            let vm_cb = vm.clone();
            let weak = window.as_weak();
            let recovery_rx_cb = recovery_rx_handle.clone();
            let event_log_path_cb = event_log_path.clone();
            window.on_run_recovery(move || {
                let keep_raw = weak
                    .upgrade()
                    .map(|w| w.get_keep_candidates() as usize)
                    .unwrap_or(crate::recovery::KEEP_CANDIDATES_DEFAULT);
                let keep = crate::recovery::clamp_keep_candidates(keep_raw);

                // No event log path was discovered at startup (e.g. GUI opened
                // without an output directory containing `<stem>-events.bin`).
                // Recovery has nothing to replay against, so bail silently —
                // the UI keeps the button in its prior state.
                let Some(event_log) = event_log_path_cb.clone() else {
                    return;
                };

                let req = {
                    let v = vm_cb.lock().unwrap();
                    // Allow starting from NotRun or Finished (re-run). Bail on
                    // Running (already in-flight) or Disabled (live carve active).
                    if !matches!(
                        v.recovery_state,
                        crate::view_model::RecoveryUiState::NotRun
                            | crate::view_model::RecoveryUiState::Finished
                    ) {
                        return;
                    }
                    crate::recovery::RecoveryRequest {
                        image_path: v.run.source_image_path.clone(),
                        report_path: format!("{}/carve_report.json", v.run.output_root),
                        output_dir: v.run.output_root.clone(),
                        event_log,
                        keep_candidates: keep,
                    }
                };

                // Flip state to Running BEFORE spawning so the button hides immediately.
                vm_cb.lock().unwrap().recovery_state = crate::view_model::RecoveryUiState::Running;

                let rx = crate::recovery::start_background(req);
                *recovery_rx_cb.borrow_mut() = Some(rx);
            });
        }

        Ok(Self {
            window,
            sources_model,
            chips_model,
            group_chips_model,
            tiles_model,
            metadata_model,
            registry,
            resolver,
            thumbs,
            image_cache: RefCell::new(HashMap::new()),
            image_cache_full: RefCell::new(HashMap::new()),
            journal: journal_handle,
            recovery_rx: recovery_rx_handle,
            indexer_rx: RefCell::new(indexer_rx),
            indexer_started_at: RefCell::new(None),
            indexer_total_bytes: RefCell::new(0),
            indexer_last_bytes: RefCell::new(0),
            indexer_last_files: RefCell::new(0),
            perf,
            indexer_cmd_tx,
            indexer_event_rx,
            last_observed_preview_version: std::cell::Cell::new(0),
            last_preview_requery_at: std::cell::Cell::new(std::time::Instant::now()),
        })
    }

    /// Install a journal on the UiState. Uses interior mutability so this can
    /// be called with a `&self` reference after construction.
    pub fn set_journal(&self, j: Arc<crate::journal::Journal>) {
        let mut lock = self.journal.lock().unwrap();
        *lock = Some(j);
    }

    /// Return the currently-installed journal handle, if any.
    pub fn get_journal(&self) -> Option<Arc<crate::journal::Journal>> {
        self.journal.lock().unwrap().clone()
    }

    /// Returns the cached full-resolution `slint::Image` for this file,
    /// rendering and caching it on first access. Returns `None` for files
    /// without an image renderer (icon/text/hex previews) or on decode error.
    ///
    /// Both successful and failed outcomes are cached: a `None` entry means
    /// "we tried and got no image" and prevents the sync timer from re-running
    /// the (potentially expensive, always failing) decode on every tick.
    fn full_res_image(&self, f: &crate::view_model::FoundFile) -> Option<slint::Image> {
        if let Some(entry) = self.image_cache_full.borrow().get(&f.id) {
            return entry.clone();
        }
        let result = (|| -> Option<slint::Image> {
            let ft = parse_file_type_pub(&f.file.file_type)?;
            let snap = self.thumbs.sources_by_id.read().unwrap().clone();
            match crate::preview::render_full_with_fallback(
                &self.registry,
                &self.resolver,
                &snap,
                ft,
                &f.written_path,
                f,
            ) {
                Ok(crate::preview::PreviewOutput::Image(rgba)) => {
                    let (w, h) = (rgba.width(), rgba.height());
                    let mut buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::new(w, h);
                    buf.make_mut_bytes().copy_from_slice(&rgba);
                    Some(slint::Image::from_rgba8(buf))
                }
                Ok(_) => None,
                Err(e) => {
                    eprintln!(
                        "full-res preview decode failed for {}: {}",
                        f.written_path.display(),
                        e
                    );
                    None
                }
            }
        })();
        self.image_cache_full
            .borrow_mut()
            .insert(f.id, result.clone());
        result
    }

    pub fn sync(&self, vm: &mut ViewModel) {
        let _total = self.perf.phase("total");

        // Drain indexer (query-loop) events. `MatchIds` replaces the
        // VM's match list and triggers an immediate `FetchWindow` for
        // the leading window; `WindowFilled` populates `vm.window` with
        // the corresponding `FoundFile`s. Stale-epoch payloads are
        // dropped inside the apply_* helpers, so we can forward each
        // event verbatim.
        {
            let _g = self.perf.phase("drain_events");
            if let Some(rx) = &self.indexer_event_rx {
                while let Ok(ev) = rx.try_recv() {
                    match ev {
                        IndexerEvent::MatchIds { stubs, epoch } => {
                            vm.apply_match_ids(stubs, epoch);
                            let win_size = WINDOW_SIZE_DEFAULT.min(vm.match_ids.len());
                            if win_size > 0 {
                                let ids: Vec<u64> = vm.match_ids[0..win_size]
                                    .iter()
                                    .map(|s| s.file_id)
                                    .collect();
                                if let Some(tx) = &self.indexer_cmd_tx {
                                    let _ = tx.send(IndexerCommand::FetchWindow {
                                        ids,
                                        range_start: 0,
                                        epoch: vm.current_epoch,
                                    });
                                }
                            }
                        }
                        IndexerEvent::WindowFilled {
                            rows,
                            range_start,
                            epoch,
                        } => {
                            vm.apply_window_filled(rows, range_start, epoch);
                        }
                        IndexerEvent::PreviewStatusVersion(v_new) => {
                            vm.preview_status_version = v_new;
                        }
                        IndexerEvent::Error { epoch, message } => {
                            tracing::warn!(?epoch, "indexer error: {message}");
                        }
                    }
                }
            }
        }

        // Preview-status version observer. The IndexerEvent drain above
        // may have just advanced `vm.preview_status_version` (when the
        // outcomes writer committed a fresh batch). If `hide_no_preview`
        // is engaged AND we haven't seen this version yet, issue a
        // debounced auto-requery so files that just flipped to
        // `no_preview` drop out of the grid. The 1 s floor prevents a
        // burst of small commits (one per ~100 outcomes / 500 ms) from
        // triggering a requery on every sync tick.
        if vm.filter.hide_no_preview
            && vm.preview_status_version != self.last_observed_preview_version.get()
            && self.last_preview_requery_at.get().elapsed() > std::time::Duration::from_secs(1)
        {
            vm.current_epoch += 1;
            if let Some(tx) = &self.indexer_cmd_tx {
                let _ = tx.send(IndexerCommand::Requery {
                    filter: vm.filter.clone(),
                    epoch: vm.current_epoch,
                });
            }
            self.last_preview_requery_at.set(std::time::Instant::now());
            self.last_observed_preview_version
                .set(vm.preview_status_version);
        }

        // Live-mode auto-requery: poke the indexer thread so it checks
        // whether the engine writer has appended new files since the last
        // Requery. The check is throttled inside the indexer thread to one
        // SQL row-count probe per ~500 ms, so it's safe to send this on
        // every 100 ms sync tick.
        if let Some(tx) = &self.indexer_cmd_tx {
            let _ = tx.send(IndexerCommand::Tick);
        }

        // Drain indexer progress (if a receiver is installed).
        {
            let mut all_done = false;
            let mut errored = false;
            if let Some(rx) = self.indexer_rx.borrow().as_ref() {
                loop {
                    match rx.try_recv() {
                        Ok(crate::indexer_thread::IndexProgress::Started { total_bytes }) => {
                            *self.indexer_started_at.borrow_mut() = Some(std::time::Instant::now());
                            *self.indexer_total_bytes.borrow_mut() = total_bytes.unwrap_or(0);
                            *self.indexer_last_bytes.borrow_mut() = 0;
                            *self.indexer_last_files.borrow_mut() = 0;
                        }
                        Ok(crate::indexer_thread::IndexProgress::Bytes { read }) => {
                            *self.indexer_last_bytes.borrow_mut() = read;
                        }
                        Ok(crate::indexer_thread::IndexProgress::Files { count }) => {
                            *self.indexer_last_files.borrow_mut() = count;
                        }
                        Ok(crate::indexer_thread::IndexProgress::Finished) => {
                            // Per-source done; do NOT drop rx — more sources
                            // may follow. The next `Started` will reset the
                            // per-source accumulators.
                        }
                        Ok(crate::indexer_thread::IndexProgress::Error(e)) => {
                            tracing::warn!("indexer error: {e}");
                            errored = true;
                        }
                        Err(crossbeam_channel::TryRecvError::Empty) => break,
                        Err(crossbeam_channel::TryRecvError::Disconnected) => {
                            // All senders have hung up — the orchestrator
                            // thread has finished every source. Safe to
                            // clear the receiver now.
                            all_done = true;
                            break;
                        }
                    }
                }
            }
            if all_done || errored {
                // Clear the receiver so we stop polling.
                *self.indexer_rx.borrow_mut() = None;
                *self.indexer_started_at.borrow_mut() = None;
            }
            let started_more_than_250ms_ago = self
                .indexer_started_at
                .borrow()
                .map(|t| t.elapsed() > std::time::Duration::from_millis(250))
                .unwrap_or(false);
            let active = self.indexer_rx.borrow().is_some() && started_more_than_250ms_ago;
            self.window.set_indexing_active(active);
            self.window
                .set_indexing_files(*self.indexer_last_files.borrow() as i32);
            let total = *self.indexer_total_bytes.borrow();
            let read = *self.indexer_last_bytes.borrow();
            self.window.set_indexing_progress(if total > 0 {
                read as f32 / total as f32
            } else {
                0.0
            });
        }

        let rows: Vec<SourceRowData> = vm
            .sources
            .iter()
            .map(|r| SourceRowData {
                source_id: r.source_id as i32,
                filename: SharedString::from(r.filename.as_str()),
                files_found: r.files_found as i32,
                progress: if r.total_bytes > 0 {
                    r.bytes_read as f32 / r.total_bytes as f32
                } else {
                    0.0
                },
                status: SharedString::from(match r.status {
                    SourceStatus::Pending => "Pending",
                    SourceStatus::Running => "Running",
                    SourceStatus::Finished => "Finished",
                    SourceStatus::Interrupted => "Interrupted",
                }),
            })
            .collect();
        replace_model(&self.sources_model, rows);

        // Mirror vm.sources into the thumb worker's sources_by_id so it can
        // resolve source paths for the byte-range fallback.
        {
            let mut map = self.thumbs.sources_by_id.write().unwrap();
            map.clear();
            for s in &vm.sources {
                map.insert(s.source_id, s.filename.clone());
            }
        }

        self.window
            .set_run_status(SharedString::from(format!("{:?}", vm.run.status)));
        self.window.set_total_files(vm.run.total_files as i32);
        self.window
            .set_elapsed(SharedString::from(format!("{}ms", vm.run.elapsed_ms)));

        {
            let _g = self.perf.phase("chips_refresh");
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
        }

        // Bookmarked filter pill in toolbar.
        self.window
            .set_bookmarked_filter_enabled(vm.filter.bookmarked_only);

        // Hide no-preview filter pill in toolbar.
        self.window
            .set_hide_no_preview_enabled(vm.filter.hide_no_preview);

        // Sort controls.
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

        // Filter area visibility.
        self.window.set_filters_visible(vm.filters_visible);

        // Size range slider.
        let size_max = vm.size_filter_max();
        let pre_clamp = vm.filter.size_range;
        vm.clamp_size_range_to(size_max);
        if vm.filter.size_range != pre_clamp {
            // The clamp shrunk the active size_range; re-run the SQL query
            // so `match_ids` reflects the tighter bound.
            requery(&self.indexer_cmd_tx, vm);
        }
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
                .set_size_range_label(SharedString::from(range_label));
            self.window
                .set_size_max_label(SharedString::from(crate::view_model::format_bytes(
                    size_max,
                )));
        } else {
            self.window.set_size_lo_norm(0.0);
            self.window.set_size_hi_norm(1.0);
            self.window.set_size_range_label(SharedString::from(""));
            self.window.set_size_max_label(SharedString::from(""));
        }

        // FileId is u64; Slint int is i32. Engine-allocated ids fit within
        // i32 in practice; tile rendering casts the same way (see tiles loop
        // below), keeping both sides consistent.
        let selected_id = vm.selection.map(|id| id as i32).unwrap_or(-1);
        self.window.set_selected_id(selected_id);

        // Task 14: read Slint's grid viewport position and column count, then
        // ask the ViewModel whether the visible row range has scrolled outside
        // the current window. When it has, post a `FetchWindow` to slide the
        // window to recenter on the viewport. `vm.window_range` is updated
        // optimistically here so the next sync renders the right placeholders;
        // the actual `FoundFile`s arrive asynchronously via `WindowFilled`.
        let (cols, visible_first_row, visible_last_row, window_size) = {
            let _g = self.perf.phase("viewport_read");
            let viewport_y_px: f32 = self.window.get_grid_viewport_y();
            let cols = self.window.get_grid_cols().max(1) as usize;
            // Approximate the grid pane's visible height by subtracting a fixed
            // chrome allowance from the window's total height. The window size
            // is in physical pixels; divide by scale_factor to get logical px,
            // which matches Slint's `length` unit and our pitch constants.
            let scale = self.window.window().scale_factor().max(1e-3);
            let window_h_logical = self.window.window().size().height as f32 / scale;
            let viewport_h_px = (window_h_logical - GRID_CHROME_HEIGHT_PX).max(TILE_PITCH_Y);

            // Slint's `viewport-y` is 0 at the top and decreases as the user
            // scrolls down. Convert to a non-negative scroll offset for the math.
            let scroll_px = (-viewport_y_px).max(0.0);
            let visible_first_row = (scroll_px / TILE_PITCH_Y).floor().max(0.0) as usize;
            let visible_count = (viewport_h_px / TILE_PITCH_Y).ceil() as usize + 1;
            let visible_last_row = visible_first_row + visible_count;

            let visible_tiles = cols.saturating_mul(visible_count);
            let window_size = (25 * visible_tiles).clamp(WINDOW_SIZE_MIN, WINDOW_SIZE_MAX);
            (cols, visible_first_row, visible_last_row, window_size)
        };

        {
            let _g = self.perf.phase("slide_decide");
            if let Some(new_range) = vm.need_slide(
                visible_first_row,
                visible_last_row,
                window_size,
                SLIDE_TRIGGER_ROWS,
            ) {
                vm.current_epoch += 1;
                let ids: Vec<u64> = vm.match_ids[new_range.clone()]
                    .iter()
                    .map(|s| s.file_id)
                    .collect();
                if let Some(tx) = &self.indexer_cmd_tx {
                    let _ = tx.send(IndexerCommand::FetchWindow {
                        ids,
                        range_start: new_range.start,
                        epoch: vm.current_epoch,
                    });
                }
                // Optimistic update: the next `WindowFilled` will overwrite this
                // with the freshly-loaded rows. Until then, tiles inside the new
                // window range with no FoundFile fall through to stub placeholders.
                vm.window_range = new_range;
            }
        }

        // Tiles: walk the windowed range of `match_ids`, emitting one
        // `FileTileData` per row. Rows whose `FoundFile` has not yet arrived
        // in `vm.window` render as stub placeholders (no thumbnail, stub
        // filename/size/type) until the next `WindowFilled` event. Each tile
        // carries its absolute (row, col) position so the Slint side can lay
        // it out inside the full virtual grid.
        let tiles: Vec<FileTileData> = {
            let _g = self.perf.phase("build_tiles");
            vm.match_ids
                .get(vm.window_range.clone())
                .into_iter()
                .flatten()
                .enumerate()
                .map(|(slot_idx, stub)| {
                    let abs_idx = vm.window_range.start + slot_idx;
                    let absolute_row = (abs_idx / cols) as i32;
                    let absolute_col = (abs_idx % cols) as i32;
                    let (has, img) = match vm.window.get(&stub.file_id) {
                        Some(f) => {
                            // Get-or-build a stable `slint::Image` for this FileId.
                            // Once the worker has decoded the buffer, the Image
                            // handle is stored in `image_cache` and reused for
                            // every sync — so the property setter on the Image
                            // element sees no change and skips the texture
                            // re-upload.
                            let cached_img: Option<slint::Image> = {
                                let mut ic = self.image_cache.borrow_mut();
                                if let Some(img) = ic.get(&f.id) {
                                    Some(img.clone())
                                } else if let Some(buf) = self.thumbs.get_buffer(f.id) {
                                    let img = slint::Image::from_rgba8(buf);
                                    ic.insert(f.id, img.clone());
                                    Some(img)
                                } else {
                                    None
                                }
                            };
                            let has = cached_img.is_some();
                            if !has && let Some(ft) = parse_file_type_pub(&f.file.file_type) {
                                self.thumbs
                                    .request(f.id, ft, f.written_path.clone(), f.clone());
                            }
                            (has, cached_img.unwrap_or_default())
                        }
                        None => (false, slint::Image::default()),
                    };
                    let (filename, filesize, file_type) = match vm.window.get(&stub.file_id) {
                        Some(f) => (
                            SharedString::from(f.file.filename.as_str()),
                            SharedString::from(format!("{} B", f.file.filesize)),
                            SharedString::from(f.file.file_type.as_str()),
                        ),
                        None => (
                            SharedString::from(stub.filename.as_str()),
                            SharedString::from(format!("{} B", stub.filesize)),
                            SharedString::from(format!("{:?}", stub.file_type)),
                        ),
                    };
                    FileTileData {
                        id: stub.file_id as i32,
                        filename,
                        filesize,
                        file_type,
                        has_thumbnail: has,
                        thumbnail: img,
                        absolute_row,
                        absolute_col,
                        is_bookmarked: vm.bookmarks.contains(&stub.file_id),
                    }
                })
                .collect()
        };
        // Total rows in the virtual grid (the Flickable's viewport-height
        // multiplier). Use ceiling division so the last partial row is
        // included. `cols` is clamped to >= 1 above so div_ceil is safe.
        //
        // Note: `grid-cols` is written by Slint via the `grid-cols-changed`
        // callback chain (detail.slint computes it reactively from the pane
        // width). Rust must NOT write it here — doing so would clobber the
        // Slint-side value and break the binding on subsequent layout
        // changes, leaving the grid stuck at whatever cols Rust last wrote.
        let total_rows = vm.match_ids.len().div_ceil(cols) as i32;
        self.window.set_total_rows(total_rows);
        {
            let _g = self.perf.phase("replace_tiles_model");
            replace_model(&self.tiles_model, tiles);
        }

        // Side panel metadata: driven by vm.selection.
        //
        // Task 12: FileId is the library file_id, so `vm.selection` IS the
        // library file_id when set. The full `FoundFile` is only available
        // if the selected row is in the current window — which is the case
        // when the user selects a tile (selection always tracks a visible
        // tile).
        let lib_file_id = vm.selection;

        {
            let _g = self.perf.phase("build_metadata");
            if let Some(sel_id) = vm.selection
                && let Some(f) = vm.window.get(&sel_id)
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
                let large_img = self.full_res_image(f);
                self.window.set_selected_has_preview(large_img.is_some());
                self.window
                    .set_selected_preview(large_img.unwrap_or_default());
            } else {
                replace_model(&self.metadata_model, Vec::<MetadataRow>::new());
                self.window.set_side_panel_open(false);
                self.window.set_selected_filename(SharedString::from(""));
                self.window.set_selected_has_preview(false);
                self.window.set_selected_preview(slint::Image::default());
            }
        }

        // New side-panel properties.
        self.window.set_selected_bookmarked(
            lib_file_id
                .map(|id| vm.bookmarks.contains(&id))
                .unwrap_or(false),
        );

        let notes_rows: Vec<NoteRowData> = lib_file_id
            .and_then(|id| vm.notes.get(&id))
            .map(|notes| {
                notes
                    .iter()
                    .map(|n| NoteRowData {
                        note_id: n.note_id as i32,
                        text: SharedString::from(n.text.as_str()),
                        at: SharedString::from(n.at.as_str()),
                    })
                    .collect()
            })
            .unwrap_or_default();
        self.window
            .set_selected_notes(slint::ModelRc::new(slint::VecModel::from(notes_rows)));

        let has_variants = lib_file_id
            .map(|id| vm.variants.contains_key(&id))
            .unwrap_or(false);
        self.window.set_selected_has_variants(has_variants);

        let variant_rows: Vec<VariantThumbData> = lib_file_id
            .and_then(|id| {
                vm.variants.get(&id).map(|vs| {
                    vs.variant_ids
                        .iter()
                        .enumerate()
                        .map(|(i, vid)| VariantThumbData {
                            file_id: *vid as i32,
                            rank: (i + 1) as i32,
                            has_thumbnail: false,
                            thumbnail: slint::Image::default(),
                            is_best: vm.best_choices.get(&id) == Some(vid),
                        })
                        .collect()
                })
            })
            .unwrap_or_default();
        self.window
            .set_selected_variants(slint::ModelRc::new(slint::VecModel::from(variant_rows)));

        // Recovery button: show whenever partial JPEGs exist, regardless of state.
        // Hidden only while a recovery run is in-flight.
        let has_partials = !vm.partial_counts.is_empty();
        let recovery_running = matches!(
            vm.recovery_state,
            crate::view_model::RecoveryUiState::Running
        );
        self.window
            .set_recovery_button_visible(has_partials && !recovery_running);
        // Enabled except while Running (in-flight) or Disabled (live carve in progress).
        let recovery_enabled = has_partials
            && !matches!(
                vm.recovery_state,
                crate::view_model::RecoveryUiState::Running
                    | crate::view_model::RecoveryUiState::Disabled
            );
        self.window.set_recovery_button_enabled(recovery_enabled);
        // Label: "Re-run recovery" after a successful recovery; "Run recovery" otherwise.
        let recovery_label = if matches!(
            vm.recovery_state,
            crate::view_model::RecoveryUiState::Finished
        ) {
            "Re-run recovery"
        } else {
            "Run recovery"
        };
        self.window
            .set_recovery_button_label(SharedString::from(recovery_label));

        // Lightbox properties.
        //
        // Task 12: FileId == library file_id, so `vm.lightbox` IS the lib
        // file id. We need the full `FoundFile` for filename + preview —
        // available when the lightbox target is windowed (the typical case
        // since the user opens lightbox on a visible tile).
        let lightbox_lib_id = vm.lightbox;
        if let Some(lb_id) = vm.lightbox
            && let Some(f) = vm.window.get(&lb_id)
        {
            let idx = vm
                .match_ids
                .iter()
                .position(|s| s.file_id == lb_id)
                .unwrap_or(0);
            self.window.set_lightbox_open(true);
            self.window
                .set_lightbox_filename(SharedString::from(f.file.filename.as_str()));
            self.window.set_lightbox_index1((idx + 1) as i32);
            self.window.set_lightbox_total(vm.match_ids.len() as i32);
            self.window.set_lightbox_zoom(vm.lightbox_view.zoom);
            self.window.set_lightbox_fit(vm.lightbox_view.fit);

            // Render full-res image if available (cache shared with side panel).
            let img = self.full_res_image(f);
            self.window.set_lightbox_has_image(img.is_some());
            self.window.set_lightbox_image(img.unwrap_or_default());
        } else {
            self.window.set_lightbox_open(false);
            self.window.set_lightbox_has_image(false);
            self.window.set_lightbox_image(slint::Image::default());
            self.window.set_lightbox_filename(SharedString::from(""));
            self.window.set_lightbox_index1(0);
            self.window.set_lightbox_total(0);
        }
        self.window.set_lightbox_bookmarked(
            lightbox_lib_id
                .map(|id| vm.bookmarks.contains(&id))
                .unwrap_or(false),
        );
        self.window.set_lightbox_mark_best_visible(
            lightbox_lib_id
                .map(|id| vm.variant_of.contains_key(&id))
                .unwrap_or(false),
        );

        // Variant viewer properties.
        let viewer_open = vm.variant_viewer.is_some();
        self.window.set_variant_viewer_open(viewer_open);

        if let Some(orig_lib_id) = vm.variant_viewer {
            // Find the original's filename via the window (variant_viewer holds
            // the library file_id, which is now identical to FileId). The
            // original is the selected row, which is always windowed; if
            // somehow not present we fall back to an empty filename — the
            // viewer will still render the variant tiles below.
            let filename = vm
                .window
                .get(&orig_lib_id)
                .map(|f| f.file.filename.clone())
                .unwrap_or_default();
            self.window
                .set_variant_viewer_filename(SharedString::from(filename.as_str()));

            let variants_vec: Vec<VariantThumbData> = vm
                .variants
                .get(&orig_lib_id)
                .map(|vs| {
                    vs.variant_ids
                        .iter()
                        .enumerate()
                        .map(|(i, vid)| VariantThumbData {
                            file_id: *vid as i32,
                            rank: (i + 1) as i32,
                            has_thumbnail: false,
                            thumbnail: slint::Image::default(),
                            is_best: vm.best_choices.get(&orig_lib_id) == Some(vid),
                        })
                        .collect()
                })
                .unwrap_or_default();
            self.window
                .set_variant_viewer_variants(slint::ModelRc::new(slint::VecModel::from(
                    variants_vec,
                )));
        } else {
            self.window
                .set_variant_viewer_filename(SharedString::from(""));
            self.window
                .set_variant_viewer_variants(slint::ModelRc::new(slint::VecModel::from(Vec::<
                    VariantThumbData,
                >::new(
                ))));
        }

        drop(_total);
        self.perf.tick();
    }
}
