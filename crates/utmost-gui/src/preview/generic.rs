//! Fallback renderer that returns an Icon for any file type.

use anyhow::Result;
use std::path::Path;
use utmost_lib::types::FileType;

use crate::preview::{IconKind, PreviewOutput, PreviewRenderer};
use crate::view_model::FoundFile;

pub struct GenericIcon;

impl PreviewRenderer for GenericIcon {
    fn supports(&self, _: FileType) -> bool {
        true
    }
    fn render(&self, _: &Path, file: &FoundFile) -> Result<PreviewOutput> {
        let ft = crate::view_model::parse_file_type_pub(&file.file.file_type)
            .unwrap_or(FileType::Config);
        Ok(PreviewOutput::Icon(IconKind::for_type(ft)))
    }
    fn render_side_panel_metadata(&self, _file: &FoundFile) -> Vec<(String, String)> {
        Vec::new()
    }
}
