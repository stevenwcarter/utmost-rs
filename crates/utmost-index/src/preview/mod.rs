//! Pluggable file-preview renderers.

mod generic;
pub use generic::GenericIcon;

mod jpeg;
pub use jpeg::JpegPreview;

use anyhow::{Context, Result};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;
use utmost_lib::types::FileType;

use crate::model::FoundFile;

#[derive(Debug, Clone)]
pub enum PreviewOutput {
    Image(image::RgbaImage),
    Text(String),
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
    /// Higher-resolution rendering used by the side panel large preview and
    /// the lightbox. The default delegates to `render`; renderers that
    /// produce a downscaled thumbnail in `render` should override this to
    /// decode at native resolution.
    fn render_full(&self, path: &Path, file: &FoundFile) -> Result<PreviewOutput> {
        self.render(path, file)
    }
    fn render_side_panel_metadata(&self, file: &FoundFile) -> Vec<(String, String)>;

    /// Byte-based decode for cases where no on-disk file exists (report-only
    /// carves, moved output dirs). Default impl returns `Err`; renderers that
    /// can decode in-memory override this.
    fn render_from_bytes(&self, _bytes: &[u8], _file: &FoundFile) -> Result<PreviewOutput> {
        anyhow::bail!("byte-based decode not supported for this renderer")
    }

    /// Full-resolution variant of [`render_from_bytes`]. Skips any thumbnail
    /// downscale. Default delegates to `render_from_bytes`.
    fn render_full_from_bytes(&self, bytes: &[u8], file: &FoundFile) -> Result<PreviewOutput> {
        self.render_from_bytes(bytes, file)
    }
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

    pub fn render_full_for(
        &self,
        file_type: FileType,
        path: &Path,
        file: &FoundFile,
    ) -> Result<PreviewOutput> {
        for r in &self.renderers {
            if r.supports(file_type) {
                return r.render_full(path, file);
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

    pub fn render_from_bytes_for(
        &self,
        file_type: FileType,
        bytes: &[u8],
        file: &FoundFile,
    ) -> Result<PreviewOutput> {
        for r in &self.renderers {
            if r.supports(file_type) {
                return r.render_from_bytes(bytes, file);
            }
        }
        anyhow::bail!("no renderer for file type {file_type:?}")
    }

    pub fn render_full_from_bytes_for(
        &self,
        file_type: FileType,
        bytes: &[u8],
        file: &FoundFile,
    ) -> Result<PreviewOutput> {
        for r in &self.renderers {
            if r.supports(file_type) {
                return r.render_full_from_bytes(bytes, file);
            }
        }
        anyhow::bail!("no renderer for file type {file_type:?}")
    }
}

impl PreviewRegistry {
    pub fn with_defaults_and_jpeg() -> Self {
        let mut r = Self::with_defaults();
        r.register(Arc::new(JpegPreview));
        r
    }
}

pub fn render_with_fallback(
    registry: &PreviewRegistry,
    resolver: &crate::source_resolver::SourceResolver,
    sources_by_id: &std::collections::HashMap<u32, String>,
    file_type: FileType,
    path: &Path,
    file: &FoundFile,
) -> Result<PreviewOutput> {
    if path.exists() {
        match registry.render_for(file_type, path, file) {
            Ok(out) => return Ok(out),
            Err(e) => tracing::debug!(
                "path-based render failed for {}: {}; falling back to source bytes",
                path.display(),
                e
            ),
        }
    }

    let bytes = read_source_bytes(resolver, sources_by_id, file)?;
    registry.render_from_bytes_for(file_type, &bytes, file)
}

pub fn render_full_with_fallback(
    registry: &PreviewRegistry,
    resolver: &crate::source_resolver::SourceResolver,
    sources_by_id: &std::collections::HashMap<u32, String>,
    file_type: FileType,
    path: &Path,
    file: &FoundFile,
) -> Result<PreviewOutput> {
    if path.exists() {
        match registry.render_full_for(file_type, path, file) {
            Ok(out) => return Ok(out),
            Err(e) => tracing::debug!(
                "path-based full render failed for {}: {}; falling back to source bytes",
                path.display(),
                e
            ),
        }
    }
    let bytes = read_source_bytes(resolver, sources_by_id, file)?;
    registry.render_full_from_bytes_for(file_type, &bytes, file)
}

fn read_source_bytes(
    resolver: &crate::source_resolver::SourceResolver,
    sources_by_id: &std::collections::HashMap<u32, String>,
    file: &FoundFile,
) -> Result<Vec<u8>> {
    if file.file.byte_runs.is_empty() {
        anyhow::bail!("file has no byte_runs");
    }
    let recorded = sources_by_id.get(&file.source_id).ok_or_else(|| {
        anyhow::anyhow!(
            "no recorded source filename for source_id {}",
            file.source_id
        )
    })?;
    let src_path = resolver
        .resolve(file.source_id, recorded)
        .ok_or_else(|| anyhow::anyhow!("source not resolvable for source_id {}", file.source_id))?;

    let mut f = std::fs::File::open(&src_path)
        .with_context(|| format!("open source {}", src_path.display()))?;
    let total_len: u64 = file.file.byte_runs.iter().map(|r| r.len).sum();
    let mut buf = Vec::with_capacity(total_len as usize);
    for run in &file.file.byte_runs {
        f.seek(SeekFrom::Start(run.img_offset))
            .with_context(|| format!("seek to {:#x} in {}", run.img_offset, src_path.display()))?;
        let mut chunk = vec![0u8; run.len as usize];
        f.read_exact(&mut chunk)
            .with_context(|| format!("read {} bytes at {:#x}", run.len, run.img_offset))?;
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

// ── JPEG thumbnail encoder ─────────────────────────────────────────────────────

/// JPEG quality used when encoding preview thumbnails.
pub const JPEG_QUALITY: u8 = 80;

/// Encode a raw RGBA8 pixel buffer as a JPEG byte stream.
///
/// `rgba` must be exactly `width * height * 4` bytes; otherwise an error is
/// returned. The alpha channel is dropped (JPEG is RGB-only). Quality is fixed
/// at [`JPEG_QUALITY`]; the codec/quality choice is also recorded in
/// `preview_blob.codec` so future encoders can be swapped in without a schema
/// migration.
pub fn encode_thumb_to_jpeg(rgba: &[u8], width: u32, height: u32) -> Result<Vec<u8>> {
    use image::ExtendedColorType;
    use image::codecs::jpeg::JpegEncoder;
    let expected = (width as usize) * (height as usize) * 4;
    if rgba.len() != expected {
        anyhow::bail!(
            "encode_thumb_to_jpeg: buffer len {} != width*height*4 = {}",
            rgba.len(),
            expected
        );
    }
    // Convert RGBA8 to RGB8 by dropping the alpha channel.
    let rgb: Vec<u8> = rgba
        .chunks_exact(4)
        .flat_map(|chunk| [chunk[0], chunk[1], chunk[2]])
        .collect();
    // JPEG at q80 is roughly 5-15 KB for a 256-px thumb; ~1/16 of raw RGBA
    // is a reasonable starting capacity that avoids a few early grow events
    // without overshooting.
    let mut out: Vec<u8> = Vec::with_capacity(rgba.len() / 16);
    JpegEncoder::new_with_quality(&mut out, JPEG_QUALITY).encode(
        &rgb,
        width,
        height,
        ExtendedColorType::Rgb8,
    )?;
    Ok(out)
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
            file: create_file_object("a", ft, 1, 0, None, 0),
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

    #[test]
    fn default_render_full_delegates_to_render() {
        // GenericIcon does not override render_full; calling it must
        // produce the same Icon output as render() does.
        let reg = PreviewRegistry::with_defaults();
        let f = dummy_file(FileType::Pdf);
        let normal = reg
            .render_for(FileType::Pdf, std::path::Path::new("/x"), &f)
            .unwrap();
        let full = reg
            .render_full_for(FileType::Pdf, std::path::Path::new("/x"), &f)
            .unwrap();
        match (normal, full) {
            (PreviewOutput::Icon(a), PreviewOutput::Icon(b)) => assert_eq!(a, b),
            other => panic!("expected matching Icon outputs, got {other:?}"),
        }
    }

    #[test]
    fn preview_output_has_text_variant() {
        // Compile-time check that the Text variant exists.
        let _t = PreviewOutput::Text("hello".to_string());
    }

    use crate::model::FoundFile;
    use std::collections::HashMap;
    use std::sync::Arc;
    use utmost_lib::types::{ByteRun, FileObject};

    #[test]
    fn render_with_fallback_uses_path_when_present() {
        let tmp = tempfile::TempDir::new().unwrap();
        let bytes = include_bytes!("../../tests/fixtures/tiny_2x2.jpg");
        let path = tmp.path().join("on-disk.jpg");
        std::fs::write(&path, bytes).unwrap();

        let registry = PreviewRegistry::with_defaults_and_jpeg();
        let resolver = Arc::new(crate::source_resolver::SourceResolver::new(vec![], None));
        let mut sources_by_id = HashMap::new();
        sources_by_id.insert(0u32, String::from("ignored.dd"));

        let file = FoundFile {
            id: 1,
            source_id: 0,
            file: FileObject {
                file_id: 1,
                filename: "on-disk.jpg".into(),
                filesize: bytes.len() as u64,
                file_type: "jpeg".into(),
                byte_runs: vec![ByteRun {
                    offset: 0,
                    img_offset: 0,
                    len: bytes.len() as u64,
                }],
                jpeg_scan: None,
            },
            written_path: path.clone(),
            img_offset: 0,
        };

        let out = render_with_fallback(
            &registry,
            &resolver,
            &sources_by_id,
            utmost_lib::types::FileType::Jpeg,
            &path,
            &file,
        )
        .expect("render");
        assert!(matches!(out, PreviewOutput::Image(_)));
    }

    #[test]
    fn render_with_fallback_uses_bytes_when_path_missing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let bytes = include_bytes!("../../tests/fixtures/tiny_2x2.jpg");
        let source_path = tmp.path().join("source.dd");
        std::fs::write(&source_path, bytes).unwrap();

        let registry = PreviewRegistry::with_defaults_and_jpeg();
        let resolver = Arc::new(crate::source_resolver::SourceResolver::new(
            vec![source_path.clone()],
            None,
        ));
        let mut sources_by_id = HashMap::new();
        sources_by_id.insert(0u32, source_path.to_str().unwrap().to_string());

        let nonexistent_written = tmp.path().join("output").join("missing.jpg");
        let file = FoundFile {
            id: 1,
            source_id: 0,
            file: FileObject {
                file_id: 1,
                filename: "missing.jpg".into(),
                filesize: bytes.len() as u64,
                file_type: "jpeg".into(),
                byte_runs: vec![ByteRun {
                    offset: 0,
                    img_offset: 0,
                    len: bytes.len() as u64,
                }],
                jpeg_scan: None,
            },
            written_path: nonexistent_written.clone(),
            img_offset: 0,
        };

        let out = render_with_fallback(
            &registry,
            &resolver,
            &sources_by_id,
            utmost_lib::types::FileType::Jpeg,
            &nonexistent_written,
            &file,
        )
        .expect("render");
        assert!(matches!(out, PreviewOutput::Image(_)));
    }

    #[test]
    fn render_with_fallback_concatenates_multiple_byte_runs() {
        let bytes = include_bytes!("../../tests/fixtures/tiny_2x2.jpg");
        let half = bytes.len() / 2;
        let head = &bytes[..half];
        let tail = &bytes[half..];

        let tmp = tempfile::TempDir::new().unwrap();
        let source = tmp.path().join("source.dd");
        // Layout: [16 bytes pad][head][16 bytes pad][tail]
        let mut buf = vec![0u8; 16];
        buf.extend_from_slice(head);
        buf.extend_from_slice(&[0u8; 16]);
        let tail_start = buf.len();
        buf.extend_from_slice(tail);
        std::fs::write(&source, &buf).unwrap();

        let registry = PreviewRegistry::with_defaults_and_jpeg();
        let resolver = Arc::new(crate::source_resolver::SourceResolver::new(
            vec![source.clone()],
            None,
        ));
        let mut sources_by_id = HashMap::new();
        sources_by_id.insert(0u32, source.to_str().unwrap().to_string());

        let file = FoundFile {
            id: 1,
            source_id: 0,
            file: FileObject {
                file_id: 1,
                filename: "x.jpg".into(),
                filesize: bytes.len() as u64,
                file_type: "jpeg".into(),
                byte_runs: vec![
                    ByteRun {
                        offset: 0,
                        img_offset: 16,
                        len: head.len() as u64,
                    },
                    ByteRun {
                        offset: head.len() as u64,
                        img_offset: tail_start as u64,
                        len: tail.len() as u64,
                    },
                ],
                jpeg_scan: None,
            },
            written_path: tmp.path().join("missing.jpg"),
            img_offset: 16,
        };

        let out = render_with_fallback(
            &registry,
            &resolver,
            &sources_by_id,
            utmost_lib::types::FileType::Jpeg,
            &file.written_path,
            &file,
        )
        .expect("render");
        assert!(matches!(out, PreviewOutput::Image(_)));
    }

    #[test]
    fn render_with_fallback_returns_err_when_neither_works() {
        let tmp = tempfile::TempDir::new().unwrap();
        let registry = PreviewRegistry::with_defaults_and_jpeg();
        let resolver = Arc::new(crate::source_resolver::SourceResolver::new(vec![], None));
        let sources_by_id = HashMap::new();

        let file = FoundFile {
            id: 1,
            source_id: 0,
            file: FileObject {
                file_id: 1,
                filename: "x.jpg".into(),
                filesize: 0,
                file_type: "jpeg".into(),
                byte_runs: vec![],
                jpeg_scan: None,
            },
            written_path: tmp.path().join("nope.jpg"),
            img_offset: 0,
        };

        let out = render_with_fallback(
            &registry,
            &resolver,
            &sources_by_id,
            utmost_lib::types::FileType::Jpeg,
            &file.written_path,
            &file,
        );
        assert!(out.is_err());
    }

    #[test]
    fn encode_thumb_to_jpeg_round_trips_dimensions() {
        // A 4×3 RGBA gradient encodes to JPEG bytes, and decoding those
        // bytes recovers the same dimensions.
        let w: u32 = 4;
        let h: u32 = 3;
        let rgba: Vec<u8> = (0..(w * h * 4))
            .map(|i| if i % 4 == 3 { 255 } else { (i % 256) as u8 })
            .collect();

        let encoded = encode_thumb_to_jpeg(&rgba, w, h).expect("encode");
        assert!(
            encoded.len() > 2 && encoded[0] == 0xFF && encoded[1] == 0xD8,
            "must start with JPEG SOI marker"
        );

        // Decode-back round trip via the `image` crate.
        let decoded = image::ImageReader::new(std::io::Cursor::new(encoded))
            .with_guessed_format()
            .expect("guess")
            .decode()
            .expect("decode jpeg");
        assert_eq!(decoded.width(), w);
        assert_eq!(decoded.height(), h);
    }
}
