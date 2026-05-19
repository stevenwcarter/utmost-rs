//! Bridges the pure-Rust ViewModel to the Slint MainWindow.

use slint::{ComponentHandle, Model, SharedString, VecModel};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use crate::preview::PreviewRegistry;
use crate::thumb_worker::ThumbWorker;
use crate::view_model::{FileId, NavDirection, SourceStatus, ViewModel, parse_file_type_pub};

slint::include_modules!();

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
    image_cache_full: RefCell<HashMap<FileId, slint::Image>>,
    /// Shared journal handle. Wrapped in Arc<Mutex<Option<...>>> so callbacks
    /// (which capture it at construction time as FnMut closures) can see a
    /// journal installed later via `set_journal`.
    pub journal: Arc<Mutex<Option<Arc<crate::journal::Journal>>>>,
    /// Receiver end of the background recovery worker channel. `None` until
    /// `on_run_recovery` spawns the worker. Drained by the periodic timer in
    /// `lib.rs::launch_ui_with_journal`.
    pub recovery_rx:
        Rc<RefCell<Option<crossbeam_channel::Receiver<utmost_lib::events::CarveEvent>>>>,
}

impl UiState {
    pub fn new(
        vm: Arc<Mutex<ViewModel>>,
        source_search_locations: Vec<std::path::PathBuf>,
        event_log_path: Option<std::path::PathBuf>,
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
            event_log_path,
        ));
        // No-op completion callback: the periodic re-sync timer (Task 34)
        // will pick up newly-cached thumbnails on the next tick.
        let on_complete: Arc<dyn Fn(crate::view_model::FileId) + Send + Sync> = Arc::new(|_id| {});
        let thumbs = ThumbWorker::start(registry.clone(), resolver.clone(), 256, 2, on_complete);

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
            window.on_row_clicked(move |source_id| {
                let mut v = vm_cb.lock().unwrap();
                v.filter.source_filter = Some(source_id as u32);
                v.selection = None;
                v.recompute_visible();
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
                v.recompute_visible();
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
            window.on_bookmarked_filter_toggle(move || {
                let mut v = vm_cb.lock().unwrap();
                v.filter.bookmarked_only = !v.filter.bookmarked_only;
                v.recompute_visible();
            });
        }
        {
            let vm_cb = vm.clone();
            window.on_hide_no_preview_toggle(move || {
                let mut v = vm_cb.lock().unwrap();
                v.filter.hide_no_preview = !v.filter.hide_no_preview;
                v.recompute_visible();
            });
        }
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
            window.on_select_all(move || {
                let mut v = vm_cb.lock().unwrap();
                v.filter.enabled_types = v.type_counts.keys().copied().collect();
                v.recompute_visible();
            });
        }
        {
            let vm_cb = vm.clone();
            window.on_select_none(move || {
                let mut v = vm_cb.lock().unwrap();
                v.filter.enabled_types.clear();
                v.recompute_visible();
            });
        }
        {
            let weak = window.as_weak();
            let vm_cb = vm.clone();
            window.on_back_clicked(move || {
                let mut v = vm_cb.lock().unwrap();
                v.filter.source_filter = None;
                v.selection = None;
                v.lightbox = None;
                v.recompute_visible();
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
            window.on_lightbox_toggle_bookmark(move || {
                let mut v = vm_cb.lock().unwrap();
                if let Some(sel) = v.lightbox {
                    let lib_file_id = match v.files.iter().find(|f| f.id == sel) {
                        Some(f) => f.file.file_id,
                        None => return,
                    };
                    let ev = v.toggle_bookmark(lib_file_id);
                    let j = journal_cb.lock().unwrap();
                    if let Some(ref journal) = *j {
                        if let Err(e) = journal.append(&ev) {
                            tracing::warn!("journal append failed: {e}");
                        }
                    } else {
                        tracing::debug!("annotation event with no journal handle: {ev:?}");
                    }
                }
            });
        }
        {
            let vm_cb = vm.clone();
            let journal_cb = journal_handle.clone();
            window.on_lightbox_add_note(move |text| {
                let mut v = vm_cb.lock().unwrap();
                if let Some(sel) = v.lightbox {
                    let lib_file_id = match v.files.iter().find(|f| f.id == sel) {
                        Some(f) => f.file.file_id,
                        None => return,
                    };
                    let ev = v.add_note(lib_file_id, text.to_string());
                    let j = journal_cb.lock().unwrap();
                    if let Some(ref journal) = *j {
                        if let Err(e) = journal.append(&ev) {
                            tracing::warn!("journal append failed: {e}");
                        }
                    } else {
                        tracing::debug!("annotation event with no journal handle: {ev:?}");
                    }
                }
            });
        }
        {
            let vm_cb = vm.clone();
            let journal_cb = journal_handle.clone();
            window.on_lightbox_mark_best(move || {
                let mut v = vm_cb.lock().unwrap();
                if let Some(sel) = v.lightbox {
                    let lib_file_id = match v.files.iter().find(|f| f.id == sel) {
                        Some(f) => f.file.file_id,
                        None => return,
                    };
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
            window.on_toggle_bookmark(move || {
                let mut v = vm_cb.lock().unwrap();
                if let Some(sel) = v.selection {
                    let lib_file_id = match v.files.iter().find(|f| f.id == sel) {
                        Some(f) => f.file.file_id,
                        None => return,
                    };
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
                }
            });
        }
        {
            let vm_cb = vm.clone();
            let journal_cb = journal_handle.clone();
            window.on_add_note(move |text| {
                let mut v = vm_cb.lock().unwrap();
                if let Some(sel) = v.selection {
                    let lib_file_id = match v.files.iter().find(|f| f.id == sel) {
                        Some(f) => f.file.file_id,
                        None => return,
                    };
                    let ev = v.add_note(lib_file_id, text.to_string());
                    let j = journal_cb.lock().unwrap();
                    if let Some(ref journal) = *j {
                        if let Err(e) = journal.append(&ev) {
                            tracing::warn!("journal append failed: {e}");
                        }
                    } else {
                        tracing::debug!("annotation event with no journal handle: {ev:?}");
                    }
                }
            });
        }
        {
            let vm_cb = vm.clone();
            window.on_open_variant_viewer(move || {
                let mut v = vm_cb.lock().unwrap();
                if let Some(sel) = v.selection
                    && let Some(f) = v.files.iter().find(|f| f.id == sel)
                {
                    let lib_file_id = f.file.file_id;
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
            window.on_run_recovery(move || {
                let keep_raw = weak
                    .upgrade()
                    .map(|w| w.get_keep_candidates() as usize)
                    .unwrap_or(crate::recovery::KEEP_CANDIDATES_DEFAULT);
                let keep = crate::recovery::clamp_keep_candidates(keep_raw);

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
                        event_log: std::path::PathBuf::from(&v.run.output_root)
                            .join("carve_events.bin"),
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
    fn full_res_image(&self, f: &crate::view_model::FoundFile) -> Option<slint::Image> {
        let mut ic = self.image_cache_full.borrow_mut();
        if let Some(img) = ic.get(&f.id) {
            return Some(img.clone());
        }
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
                let img = slint::Image::from_rgba8(buf);
                ic.insert(f.id, img.clone());
                Some(img)
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
    }

    pub fn sync(&self, vm: &ViewModel) {
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

        // FileId is u64; Slint int is i32. Ids are assigned sequentially from 0 so
        // truncation is safe in practice. Tile rendering casts the same way
        // (see tiles loop below), keeping both sides consistent.
        let selected_id = vm.selection.map(|id| id as i32).unwrap_or(-1);
        self.window.set_selected_id(selected_id);

        // Tiles: check thumb cache; on miss, request and continue with placeholder.
        let tiles: Vec<FileTileData> = vm
            .visible_files
            .iter()
            .filter_map(|fid| vm.files.iter().find(|f| f.id == *fid))
            .map(|f| {
                // Get-or-build a stable `slint::Image` for this FileId.
                // Once the worker has decoded the buffer, the Image handle
                // is stored in `image_cache` and reused for every sync —
                // so the property setter on the Image element sees no
                // change and skips the texture re-upload.
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
                FileTileData {
                    id: f.id as i32,
                    filename: SharedString::from(f.file.filename.as_str()),
                    filesize: SharedString::from(format!("{} B", f.file.filesize)),
                    file_type: SharedString::from(f.file.file_type.as_str()),
                    has_thumbnail: has,
                    thumbnail: cached_img.unwrap_or_default(),
                }
            })
            .collect();
        replace_model(&self.tiles_model, tiles);

        // Side panel metadata: driven by vm.selection.
        let lib_file_id = vm.selection.and_then(|sel| {
            vm.files
                .iter()
                .find(|f| f.id == sel)
                .map(|f| f.file.file_id)
        });

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
        let lightbox_lib_id = vm.lightbox.and_then(|sel| {
            vm.files
                .iter()
                .find(|f| f.id == sel)
                .map(|f| f.file.file_id)
        });
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
            // Find the original's filename via files lookup (variant_viewer holds the library file_id).
            let filename = vm
                .files
                .iter()
                .find(|f| f.file.file_id == orig_lib_id)
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
    }
}
