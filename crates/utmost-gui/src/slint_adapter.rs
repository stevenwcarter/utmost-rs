//! Bridges the pure-Rust ViewModel to the Slint MainWindow.

use slint::{ComponentHandle, Model, SharedString, VecModel};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use crate::preview::PreviewRegistry;
use crate::thumb_worker::ThumbWorker;
use crate::view_model::{FileId, SourceStatus, ViewModel, parse_file_type_pub};

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

fn send_annotation_to_journal(ev: utmost_lib::events::CarveEvent) {
    // Stub — Task 20 will route this to the journal sidecar.
    tracing::debug!("annotation event (not yet persisted): {ev:?}");
}

pub struct UiState {
    pub window: MainWindow,
    pub sources_model: Rc<VecModel<SourceRowData>>,
    pub chips_model: Rc<VecModel<FilterChipData>>,
    pub tiles_model: Rc<VecModel<FileTileData>>,
    pub metadata_model: Rc<VecModel<MetadataRow>>,
    pub registry: Arc<PreviewRegistry>,
    pub thumbs: ThumbWorker,
    /// UI-thread cache of `slint::Image` instances keyed by FileId. Re-using
    /// the same `Image` handle across syncs makes the property setter on the
    /// Image element see no change (Slint compares `Image` by handle), which
    /// prevents the texture re-upload + briefly-blank state that would
    /// otherwise happen 10 times per second.
    image_cache: RefCell<HashMap<FileId, slint::Image>>,
    /// Cache of full-resolution images for the side-panel preview and lightbox.
    image_cache_full: RefCell<HashMap<FileId, slint::Image>>,
}

impl UiState {
    pub fn new(vm: Arc<Mutex<ViewModel>>) -> Result<Self, slint::PlatformError> {
        let window = MainWindow::new()?;
        let sources_model: Rc<VecModel<SourceRowData>> = Rc::new(VecModel::default());
        let chips_model: Rc<VecModel<FilterChipData>> = Rc::new(VecModel::default());
        let tiles_model: Rc<VecModel<FileTileData>> = Rc::new(VecModel::default());
        let metadata_model: Rc<VecModel<MetadataRow>> = Rc::new(VecModel::default());
        window.set_sources(sources_model.clone().into());
        window.set_chips(chips_model.clone().into());
        window.set_tiles(tiles_model.clone().into());
        window.set_selected_metadata(metadata_model.clone().into());

        let registry = Arc::new(PreviewRegistry::with_defaults_and_jpeg());
        // No-op completion callback: the periodic re-sync timer (Task 34)
        // will pick up newly-cached thumbnails on the next tick.
        let on_complete: Arc<dyn Fn(crate::view_model::FileId) + Send + Sync> = Arc::new(|_id| {});
        let thumbs = ThumbWorker::start(registry.clone(), 256, 2, on_complete);

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
                if name == "bookmarked" {
                    v.filter.bookmarked_only = !v.filter.bookmarked_only;
                } else if let Some(ft_str) = name.strip_prefix("partial:") {
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
            window.on_lightbox_toggle_bookmark(move || {
                let mut v = vm_cb.lock().unwrap();
                if let Some(sel) = v.lightbox {
                    let lib_file_id = match v.files.iter().find(|f| f.id == sel) {
                        Some(f) => f.file.file_id,
                        None => return,
                    };
                    let ev = v.toggle_bookmark(lib_file_id);
                    send_annotation_to_journal(ev);
                }
            });
        }
        {
            let vm_cb = vm.clone();
            window.on_lightbox_add_note(move |text| {
                let mut v = vm_cb.lock().unwrap();
                if let Some(sel) = v.lightbox {
                    let lib_file_id = match v.files.iter().find(|f| f.id == sel) {
                        Some(f) => f.file.file_id,
                        None => return,
                    };
                    let ev = v.add_note(lib_file_id, text.to_string());
                    send_annotation_to_journal(ev);
                }
            });
        }
        {
            let vm_cb = vm.clone();
            window.on_lightbox_mark_best(move || {
                let mut v = vm_cb.lock().unwrap();
                if let Some(sel) = v.lightbox {
                    let lib_file_id = match v.files.iter().find(|f| f.id == sel) {
                        Some(f) => f.file.file_id,
                        None => return,
                    };
                    if let Some(&orig) = v.variant_of.get(&lib_file_id) {
                        let ev = v.mark_as_best(orig, lib_file_id);
                        send_annotation_to_journal(ev);
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
                    // Task 20 will replace this stub with journal.append(&ev).
                    send_annotation_to_journal(ev);
                }
            });
        }
        {
            let vm_cb = vm.clone();
            window.on_add_note(move |text| {
                let mut v = vm_cb.lock().unwrap();
                if let Some(sel) = v.selection {
                    let lib_file_id = match v.files.iter().find(|f| f.id == sel) {
                        Some(f) => f.file.file_id,
                        None => return,
                    };
                    let ev = v.add_note(lib_file_id, text.to_string());
                    send_annotation_to_journal(ev);
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
            let weak = window.as_weak();
            window.on_run_recovery(move || {
                // Task 21 fully wires this; for now we just mark the state as Running
                // so the button hides.
                let mut v = vm_cb.lock().unwrap();
                let _keep = weak
                    .upgrade()
                    .map(|w| w.get_keep_candidates() as usize)
                    .unwrap_or(5);
                v.recovery_state = crate::view_model::RecoveryUiState::Running;
            });
        }

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
        match self.registry.render_full_for(ft, &f.written_path, f) {
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
        self.window
            .set_run_status(SharedString::from(format!("{:?}", vm.run.status)));
        self.window.set_total_files(vm.run.total_files as i32);
        self.window
            .set_elapsed(SharedString::from(format!("{}ms", vm.run.elapsed_ms)));

        // Chips (filter chips)
        let mut chips: Vec<FilterChipData> = vm
            .type_counts
            .iter()
            .map(|(ft, count)| FilterChipData {
                name: SharedString::from(format!("{ft:?}")),
                enabled: vm.filter.enabled_types.contains(ft),
                count: *count as i32,
                kind: SharedString::from("type"),
            })
            .collect();

        // Partial-type chips: one per FileType present in vm.partial_counts.
        for (ft, count) in &vm.partial_counts {
            let ft_string = format!("{:?}", ft).to_lowercase();
            chips.push(FilterChipData {
                name: SharedString::from(format!("partial:{}", ft_string)),
                enabled: vm.filter.enabled_partial_types.contains(ft),
                count: *count as i32,
                kind: SharedString::from("partial"),
            });
        }

        // Bookmarked chip: appears once if any file is bookmarked.
        if !vm.bookmarks.is_empty() {
            chips.push(FilterChipData {
                name: SharedString::from("bookmarked"),
                enabled: vm.filter.bookmarked_only,
                count: vm.bookmarks.len() as i32,
                kind: SharedString::from("bookmarked"),
            });
        }

        replace_model(&self.chips_model, chips);

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

        self.window.set_recovery_button_visible(
            matches!(
                vm.recovery_state,
                crate::view_model::RecoveryUiState::NotRun
            ) && !vm.partial_counts.is_empty(),
        );

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
    }
}
