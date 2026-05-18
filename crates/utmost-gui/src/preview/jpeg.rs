//! JPEG decoder + downscaler + side-panel metadata extractor.

use anyhow::{Context, Result};
use image::{ImageReader, imageops::FilterType};
use std::path::Path;
use utmost_lib::types::{FileType, JpegScanStatus};

use crate::preview::{PreviewOutput, PreviewRenderer};
use crate::view_model::FoundFile;

const MAX_EDGE: u32 = 256;

fn decode_image(path: &Path) -> Result<image::DynamicImage> {
    ImageReader::open(path)
        .with_context(|| format!("open {}", path.display()))?
        .with_guessed_format()?
        .decode()
        .with_context(|| format!("decode {}", path.display()))
}

pub struct JpegPreview;

impl PreviewRenderer for JpegPreview {
    fn supports(&self, ft: FileType) -> bool {
        matches!(ft, FileType::Jpeg)
    }

    fn render(&self, path: &Path, _file: &FoundFile) -> Result<PreviewOutput> {
        let img = decode_image(path)?;
        let (w, h) = (img.width(), img.height());
        let scale = (MAX_EDGE as f32 / w.max(h) as f32).min(1.0);
        let (nw, nh) = ((w as f32 * scale) as u32, (h as f32 * scale) as u32);
        let resized = if scale < 1.0 {
            img.resize(nw.max(1), nh.max(1), FilterType::Triangle)
                .to_rgba8()
        } else {
            img.to_rgba8()
        };
        Ok(PreviewOutput::Image(resized))
    }

    fn render_full(&self, path: &Path, _file: &FoundFile) -> Result<PreviewOutput> {
        Ok(PreviewOutput::Image(decode_image(path)?.to_rgba8()))
    }

    fn render_side_panel_metadata(&self, file: &FoundFile) -> Vec<(String, String)> {
        let mut out = Vec::new();
        if let Some(scan) = &file.file.jpeg_scan {
            if let (Some(w), Some(h)) = (scan.width, scan.height) {
                out.push(("Dimensions".into(), format!("{w} × {h}")));
            }
            out.push((
                "Restart markers".into(),
                if scan.has_restart_markers {
                    "yes".into()
                } else {
                    "no".into()
                },
            ));
            out.push((
                "Scan status".into(),
                match scan.status {
                    JpegScanStatus::Complete => "Complete".into(),
                    JpegScanStatus::Truncated => "Truncated".into(),
                    JpegScanStatus::Fragmented => "Fragmented".into(),
                },
            ));
            if let Some(p) = scan.fragmentation_point_img_offset {
                out.push(("Fragmentation point".into(), format!("0x{p:x}")));
            }
        }
        out
    }
}
