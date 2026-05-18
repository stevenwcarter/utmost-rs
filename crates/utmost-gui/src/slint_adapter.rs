//! Bridges the pure-Rust ViewModel to the Slint MainWindow.

use slint::{ComponentHandle, Model, SharedString, VecModel};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use crate::preview::PreviewRegistry;
use crate::thumb_worker::ThumbWorker;
use crate::view_model::{SourceStatus, ViewModel, parse_file_type_pub};

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
    pub tiles_model: Rc<VecModel<FileTileData>>,
    pub metadata_model: Rc<VecModel<MetadataRow>>,
    pub registry: Arc<PreviewRegistry>,
    pub thumbs: ThumbWorker,
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
                if let Some(ft) = parse_file_type_pub(&name.to_lowercase()) {
                    if v.filter.enabled_types.contains(&ft) {
                        v.filter.enabled_types.remove(&ft);
                    } else {
                        v.filter.enabled_types.insert(ft);
                    }
                    v.recompute_visible();
                }
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
                v.recompute_visible();
                if let Some(w) = weak.upgrade() {
                    w.set_show_detail(false);
                }
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
        })
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
        let chips: Vec<FilterChipData> = vm
            .type_counts
            .iter()
            .map(|(ft, count)| FilterChipData {
                name: SharedString::from(format!("{ft:?}")),
                enabled: vm.filter.enabled_types.contains(ft),
                count: *count as i32,
            })
            .collect();
        replace_model(&self.chips_model, chips);

        // Tiles: check thumb cache; on miss, request and continue with placeholder.
        let tiles: Vec<FileTileData> = vm
            .visible_files
            .iter()
            .filter_map(|fid| vm.files.iter().find(|f| f.id == *fid))
            .map(|f| {
                let cached = self.thumbs.get_image(f.id);
                let has = cached.is_some();
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
                    thumbnail: cached.unwrap_or_default(),
                }
            })
            .collect();
        replace_model(&self.tiles_model, tiles);

        // Side panel metadata: driven by vm.selection.
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
            if let Some(ft) = parse_file_type_pub(&f.file.file_type) {
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
        } else {
            replace_model(&self.metadata_model, Vec::<MetadataRow>::new());
            self.window.set_side_panel_open(false);
            self.window.set_selected_filename(SharedString::from(""));
        }
    }
}
