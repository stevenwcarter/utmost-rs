//! Pluggable file-preview renderers.

mod generic;
pub use generic::GenericIcon;

mod jpeg;
pub use jpeg::JpegPreview;

use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use utmost_lib::types::FileType;

use crate::view_model::FoundFile;

#[derive(Debug, Clone)]
pub enum PreviewOutput {
    Image(image::RgbaImage),
    HexDump(String),
    Icon(IconKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IconKind {
    Generic,
    Document,
    Archive,
    Image,
    Audio,
    Video,
    Executable,
}

impl IconKind {
    pub fn for_type(ft: FileType) -> Self {
        use FileType::*;
        match ft {
            Jpeg | Gif | Bmp | Png | VJpeg => Self::Image,
            Pdf | Doc | Docx | Xls | Xlsx | Ppt | Pptx | Sxw | Sxc | Sxi | Wpd | Htm => {
                Self::Document
            }
            Zip | Rar | Gzip => Self::Archive,
            Wav | Riff => Self::Audio,
            Avi | Wmv | Mov | Mpg | Mp4 => Self::Video,
            Exe | Elf | Ole => Self::Executable,
            Cpp | Reg | Config => Self::Generic,
        }
    }
}

pub trait PreviewRenderer: Send + Sync {
    fn supports(&self, file_type: FileType) -> bool;
    fn render(&self, path: &Path, file: &FoundFile) -> Result<PreviewOutput>;
    fn render_side_panel_metadata(&self, file: &FoundFile) -> Vec<(String, String)>;
}

pub struct PreviewRegistry {
    renderers: Vec<Arc<dyn PreviewRenderer>>,
}

impl PreviewRegistry {
    pub fn empty() -> Self {
        Self { renderers: vec![] }
    }

    pub fn with_defaults() -> Self {
        let mut r = Self::empty();
        r.renderers.push(Arc::new(GenericIcon));
        r
    }

    pub fn register(&mut self, r: Arc<dyn PreviewRenderer>) {
        // Insert before the first "supports everything" fallback.
        let pos = self
            .renderers
            .iter()
            .position(|x| x.supports(FileType::Pdf) && x.supports(FileType::Jpeg))
            .unwrap_or(self.renderers.len());
        self.renderers.insert(pos, r);
    }

    pub fn render_for(
        &self,
        file_type: FileType,
        path: &Path,
        file: &FoundFile,
    ) -> Result<PreviewOutput> {
        for r in &self.renderers {
            if r.supports(file_type) {
                return r.render(path, file);
            }
        }
        anyhow::bail!("no renderer for {file_type:?}")
    }

    pub fn metadata_for(&self, file_type: FileType, file: &FoundFile) -> Vec<(String, String)> {
        for r in &self.renderers {
            if r.supports(file_type) {
                return r.render_side_panel_metadata(file);
            }
        }
        Vec::new()
    }
}

impl PreviewRegistry {
    pub fn with_defaults_and_jpeg() -> Self {
        let mut r = Self::with_defaults();
        r.register(Arc::new(JpegPreview));
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use utmost_lib::reporting::create_file_object;

    fn dummy_file(ft: FileType) -> FoundFile {
        FoundFile {
            id: 0,
            source_id: 0,
            file: create_file_object("a", ft, 1, 0, None),
            written_path: PathBuf::from("a"),
            img_offset: 0,
        }
    }

    #[test]
    fn defaults_registry_uses_generic_icon_fallback() {
        let reg = PreviewRegistry::with_defaults();
        let out = reg
            .render_for(
                FileType::Pdf,
                std::path::Path::new("/does/not/exist"),
                &dummy_file(FileType::Pdf),
            )
            .unwrap();
        assert!(matches!(out, PreviewOutput::Icon(IconKind::Document)));
    }

    #[test]
    fn icon_kind_maps_jpeg_to_image() {
        assert_eq!(IconKind::for_type(FileType::Jpeg), IconKind::Image);
        assert_eq!(IconKind::for_type(FileType::Zip), IconKind::Archive);
    }
}
