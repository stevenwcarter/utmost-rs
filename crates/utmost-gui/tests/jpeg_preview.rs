use image::{Rgb, RgbImage};
use std::path::PathBuf;
use utmost_gui::preview::{PreviewOutput, PreviewRegistry};
use utmost_gui::view_model::FoundFile;
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::{FileType, JpegScanInfo, JpegScanStatus};

fn write_fixture_jpeg(dir: &std::path::Path) -> PathBuf {
    let path = dir.join("sample.jpg");
    let mut img = RgbImage::new(32, 32);
    for px in img.pixels_mut() {
        *px = Rgb([255, 0, 0]);
    }
    img.save(&path).unwrap();
    path
}

#[test]
fn jpeg_preview_decodes_fixture_to_image() {
    let tmp = tempfile::tempdir().unwrap();
    let path = write_fixture_jpeg(tmp.path());
    let file = FoundFile {
        id: 0,
        source_id: 0,
        file: create_file_object(
            "sample.jpg",
            FileType::Jpeg,
            1024,
            0,
            Some(JpegScanInfo {
                width: Some(32),
                height: Some(32),
                fragmentation_point_img_offset: None,
                has_restart_markers: false,
                status: JpegScanStatus::Complete,
            }),
        ),
        written_path: path.clone(),
        img_offset: 0,
    };

    let reg = PreviewRegistry::with_defaults_and_jpeg();
    let out = reg.render_for(FileType::Jpeg, &path, &file).unwrap();
    match out {
        PreviewOutput::Image(img) => {
            assert!(img.width() > 0 && img.height() > 0);
        }
        other => panic!("expected Image, got {other:?}"),
    }

    let meta = reg.metadata_for(FileType::Jpeg, &file);
    let labels: Vec<_> = meta.iter().map(|(k, _)| k.as_str()).collect();
    assert!(labels.contains(&"Dimensions"));
    assert!(labels.contains(&"Scan status"));
}

#[test]
fn jpeg_preview_render_full_returns_native_resolution() {
    let tmp = tempfile::tempdir().unwrap();
    // Source image is 400x300 — larger than the 256 thumbnail cap.
    let src = tmp.path().join("big.jpg");
    let mut img = RgbImage::new(400, 300);
    for px in img.pixels_mut() {
        *px = Rgb([0, 128, 255]);
    }
    img.save(&src).unwrap();

    let file = FoundFile {
        id: 0,
        source_id: 0,
        file: create_file_object(
            "big.jpg",
            FileType::Jpeg,
            10_000,
            0,
            Some(JpegScanInfo {
                width: Some(400),
                height: Some(300),
                fragmentation_point_img_offset: None,
                has_restart_markers: false,
                status: JpegScanStatus::Complete,
            }),
        ),
        written_path: src.clone(),
        img_offset: 0,
    };

    let reg = PreviewRegistry::with_defaults_and_jpeg();
    let thumb = reg.render_for(FileType::Jpeg, &src, &file).unwrap();
    let full = reg.render_full_for(FileType::Jpeg, &src, &file).unwrap();

    let (tw, th) = match thumb {
        PreviewOutput::Image(i) => (i.width(), i.height()),
        other => panic!("expected thumbnail Image, got {other:?}"),
    };
    let (fw, fh) = match full {
        PreviewOutput::Image(i) => (i.width(), i.height()),
        other => panic!("expected full-res Image, got {other:?}"),
    };

    // Thumbnail is capped at MAX_EDGE = 256; full must be larger than that
    // along the long edge.
    assert!(
        tw <= 256 && th <= 256,
        "thumbnail not within 256px cap: {tw}x{th}"
    );
    assert!(
        fw > 256 || fh > 256,
        "full-res not larger than thumbnail cap: {fw}x{fh}"
    );
    assert_eq!(
        (fw, fh),
        (400, 300),
        "full-res must match source dimensions"
    );
}
