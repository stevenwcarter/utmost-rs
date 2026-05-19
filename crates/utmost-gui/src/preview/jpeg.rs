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
        Ok(PreviewOutput::Image(downscale_for_thumbnail(decode_image(
            path,
        )?)))
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

    fn render_from_bytes(&self, bytes: &[u8], _file: &FoundFile) -> Result<PreviewOutput> {
        Ok(PreviewOutput::Image(downscale_for_thumbnail(
            decode_image_from_bytes(bytes)?,
        )))
    }

    fn render_full_from_bytes(&self, bytes: &[u8], _file: &FoundFile) -> Result<PreviewOutput> {
        Ok(PreviewOutput::Image(
            decode_image_from_bytes(bytes)?.to_rgba8(),
        ))
    }
}

fn decode_image_from_bytes(bytes: &[u8]) -> Result<image::DynamicImage> {
    ImageReader::new(std::io::Cursor::new(bytes))
        .with_guessed_format()
        .context("guess format from bytes")?
        .decode()
        .context("decode bytes")
}

fn downscale_for_thumbnail(img: image::DynamicImage) -> image::RgbaImage {
    let (w, h) = (img.width(), img.height());
    let scale = (MAX_EDGE as f32 / w.max(h) as f32).min(1.0);
    let (nw, nh) = ((w as f32 * scale) as u32, (h as f32 * scale) as u32);
    if scale < 1.0 {
        img.resize(nw.max(1), nh.max(1), FilterType::Triangle)
            .to_rgba8()
    } else {
        img.to_rgba8()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use utmost_lib::types::{ByteRun, FileObject};

    const TINY_JPEG: &[u8] = include_bytes!("../../tests/fixtures/tiny_2x2.jpg");

    fn dummy_found_file() -> FoundFile {
        FoundFile {
            id: 1,
            source_id: 0,
            file: FileObject {
                file_id: 1,
                filename: "x.jpg".into(),
                filesize: TINY_JPEG.len() as u64,
                file_type: "jpeg".into(),
                byte_runs: vec![ByteRun {
                    offset: 0,
                    img_offset: 0,
                    len: TINY_JPEG.len() as u64,
                }],
                jpeg_scan: None,
            },
            written_path: PathBuf::new(),
            img_offset: 0,
        }
    }

    #[test]
    fn jpeg_renders_from_bytes() {
        let renderer = JpegPreview;
        let f = dummy_found_file();
        let out = renderer.render_from_bytes(TINY_JPEG, &f).expect("decode");
        match out {
            PreviewOutput::Image(img) => {
                assert_eq!(img.width(), 2);
                assert_eq!(img.height(), 2);
            }
            _other => panic!("expected Image variant"),
        }
    }

    #[test]
    fn jpeg_renders_full_from_bytes() {
        let renderer = JpegPreview;
        let f = dummy_found_file();
        let out = renderer
            .render_full_from_bytes(TINY_JPEG, &f)
            .expect("decode");
        match out {
            PreviewOutput::Image(img) => {
                assert_eq!(img.width(), 2);
                assert_eq!(img.height(), 2);
            }
            _ => panic!("expected Image variant"),
        }
    }

    #[test]
    fn jpeg_render_from_bytes_returns_err_on_garbage() {
        let renderer = JpegPreview;
        let f = dummy_found_file();
        let garbage = b"not a jpeg at all";
        assert!(renderer.render_from_bytes(garbage, &f).is_err());
    }
}
