//! Bridges the pure-Rust ViewModel to the Slint MainWindow.

use slint::{SharedString, VecModel};
use std::rc::Rc;

use crate::view_model::{SourceStatus, ViewModel};

slint::include_modules!();

pub struct UiState {
    pub window: MainWindow,
    pub sources_model: Rc<VecModel<SourceRowData>>,
    pub chips_model: Rc<VecModel<FilterChipData>>,
    pub tiles_model: Rc<VecModel<FileTileData>>,
}

impl UiState {
    pub fn new() -> Result<Self, slint::PlatformError> {
        let window = MainWindow::new()?;
        let sources_model: Rc<VecModel<SourceRowData>> = Rc::new(VecModel::default());
        let chips_model: Rc<VecModel<FilterChipData>> = Rc::new(VecModel::default());
        let tiles_model: Rc<VecModel<FileTileData>> = Rc::new(VecModel::default());
        window.set_sources(sources_model.clone().into());
        window.set_chips(chips_model.clone().into());
        window.set_tiles(tiles_model.clone().into());
        Ok(Self {
            window,
            sources_model,
            chips_model,
            tiles_model,
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
        self.sources_model.set_vec(rows);
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
        self.chips_model.set_vec(chips);

        // Tiles (no thumbnails yet — placeholder)
        let tiles: Vec<FileTileData> = vm
            .visible_files
            .iter()
            .filter_map(|fid| vm.files.iter().find(|f| f.id == *fid))
            .map(|f| FileTileData {
                id: f.id as i32,
                filename: SharedString::from(f.file.filename.as_str()),
                filesize: SharedString::from(format!("{} B", f.file.filesize)),
                file_type: SharedString::from(f.file.file_type.as_str()),
                has_thumbnail: false,
                thumbnail: slint::Image::default(),
            })
            .collect();
        self.tiles_model.set_vec(tiles);
    }
}
