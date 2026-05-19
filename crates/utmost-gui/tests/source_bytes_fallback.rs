//! End-to-end: source-byte thumbnail fallback when no on-disk file exists.

use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;
use utmost_gui::preview::{PreviewOutput, PreviewRegistry, render_with_fallback};
use utmost_gui::source_resolver::SourceResolver;
use utmost_gui::view_model::FoundFile;
use utmost_lib::types::{ByteRun, FileObject, FileType};

#[test]
fn report_only_carve_thumbnails_via_source_bytes() {
    // 1. Synthesise a source image: [64 bytes padding][tiny jpeg][64 bytes padding].
    let jpeg_bytes = include_bytes!("fixtures/tiny_2x2.jpg");
    let mut source: Vec<u8> = vec![0u8; 64];
    let jpeg_offset = source.len() as u64;
    source.extend_from_slice(jpeg_bytes);
    source.extend_from_slice(&[0u8; 64]);

    let tmp = TempDir::new().unwrap();
    let source_path = tmp.path().join("test_source.dd");
    std::fs::write(&source_path, &source).unwrap();

    // 2. Build a FoundFile as if a report-only carve had emitted it.
    let mut sources_by_id = HashMap::new();
    sources_by_id.insert(0u32, source_path.to_str().unwrap().to_string());

    let file = FoundFile {
        id: 1,
        source_id: 0,
        file: FileObject {
            file_id: 1,
            filename: "001-64.jpg".into(),
            filesize: jpeg_bytes.len() as u64,
            file_type: "jpeg".into(),
            byte_runs: vec![ByteRun {
                offset: 0,
                img_offset: jpeg_offset,
                len: jpeg_bytes.len() as u64,
            }],
            jpeg_scan: None,
        },
        // The would-be written path — never actually created.
        written_path: tmp.path().join("output").join("001-64.jpg"),
        img_offset: jpeg_offset,
    };

    // 3. SourceResolver knows about the source via a --source-equivalent.
    let resolver = Arc::new(SourceResolver::new(vec![source_path.clone()], None));

    // 4. Render via the fallback orchestrator.
    let registry = PreviewRegistry::with_defaults_and_jpeg();
    let out = render_with_fallback(
        &registry,
        &resolver,
        &sources_by_id,
        FileType::Jpeg,
        &file.written_path, // nonexistent
        &file,
    )
    .expect("fallback should decode the embedded jpeg");

    match out {
        PreviewOutput::Image(img) => {
            assert_eq!(img.width(), 2);
            assert_eq!(img.height(), 2);
        }
        _ => panic!("expected PreviewOutput::Image variant"),
    }
}

#[test]
fn fallback_uses_recorded_path_when_no_search_locations() {
    let jpeg_bytes = include_bytes!("fixtures/tiny_2x2.jpg");
    let tmp = TempDir::new().unwrap();
    let source_path = tmp.path().join("recorded.dd");
    std::fs::write(&source_path, jpeg_bytes).unwrap();

    let mut sources_by_id = HashMap::new();
    sources_by_id.insert(0u32, source_path.to_str().unwrap().to_string());

    let file = FoundFile {
        id: 1,
        source_id: 0,
        file: FileObject {
            file_id: 1,
            filename: "x.jpg".into(),
            filesize: jpeg_bytes.len() as u64,
            file_type: "jpeg".into(),
            byte_runs: vec![ByteRun {
                offset: 0,
                img_offset: 0,
                len: jpeg_bytes.len() as u64,
            }],
            jpeg_scan: None,
        },
        written_path: tmp.path().join("missing.jpg"),
        img_offset: 0,
    };

    let resolver = Arc::new(SourceResolver::new(vec![], None));
    let registry = PreviewRegistry::with_defaults_and_jpeg();
    let out = render_with_fallback(
        &registry,
        &resolver,
        &sources_by_id,
        FileType::Jpeg,
        &file.written_path,
        &file,
    )
    .expect("recorded path should resolve");
    assert!(matches!(out, PreviewOutput::Image(_)));
}
