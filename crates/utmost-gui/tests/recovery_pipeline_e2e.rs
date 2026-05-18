//! End-to-end test: drives the recovery pipeline through
//! `utmost_gui::recovery::recover_fragmented_jpegs_with_event_log_sink` and
//! verifies the view-model receives the expected variant events.

use std::path::PathBuf;

use crossbeam_channel::unbounded;
use utmost_gui::view_model::ViewModel;
use utmost_lib::events::{BincodeFileSink, CarveEvent, EventSink};
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::{ByteRun, FileObject, FileType, JpegScanInfo, JpegScanStatus};

/// Build a small synthetic disk image with a partial JPEG (SOI + APP0 header)
/// at offset 0, truncated scan data, and a high-entropy continuation block at
/// offset 512 that ends with FF D9 (EOI).
fn build_partial_jpeg_image() -> Vec<u8> {
    let mut img = vec![0u8; 2048];

    // Minimal JPEG header at offset 0: SOI + APP0 + dummy scan bytes.
    // No EOI in the first 512 bytes.
    let header: &[u8] = &[
        0xFF, 0xD8, // SOI
        0xFF, 0xE0, 0x00, 0x10, // APP0 marker + length 16
        b'J', b'F', b'I', b'F', 0x00, // JFIF identifier
        0x01, 0x01, 0x00, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00, // JFIF data
    ];
    img[..header.len()].copy_from_slice(header);

    // Fill the rest of the first block with varied (non-FF-D9) scan-ish bytes.
    for (i, byte) in img.iter_mut().enumerate().take(512).skip(header.len()) {
        *byte = ((i * 7 + 13) % 253) as u8; // avoid 0xFF and 0xD9 near each other
    }
    // Ensure no accidental EOI in first block.
    for i in 0..511 {
        if img[i] == 0xFF && img[i + 1] == 0xD9 {
            img[i + 1] = 0x00; // break any accidental EOI
        }
    }

    // At offset 512: high-entropy continuation data ending with FF D9 (EOI).
    for i in 0..510 {
        img[512 + i] = ((i * 13 + 37) ^ 0xA5) as u8;
    }
    img[512 + 510] = 0xFF;
    img[512 + 511] = 0xD9; // EOI

    img
}

/// Write a minimal carve_report.json that includes one incomplete JPEG at
/// offset 0 with file_id=`partial_fid`.
fn write_carve_report(report_path: &PathBuf, image_path: &str, partial_fid: u64) {
    let mut report = utmost_lib::types::CarveReport::new(image_path, 2048);
    let fo = FileObject {
        file_id: partial_fid,
        filename: "00000001.jpg".into(),
        filesize: 512,
        file_type: "jpeg".into(),
        byte_runs: vec![ByteRun {
            offset: 0,
            img_offset: 0,
            len: 512,
        }],
        jpeg_scan: Some(JpegScanInfo {
            width: None,
            height: None,
            fragmentation_point_img_offset: None,
            has_restart_markers: false,
            status: JpegScanStatus::Truncated,
        }),
    };
    report.fileobjects.push(fo);
    let json = serde_json::to_string_pretty(&report).unwrap();
    std::fs::write(report_path, json).unwrap();
}

#[test]
fn recovery_e2e_populates_view_model_variants() {
    let dir = tempfile::tempdir().unwrap();
    let image_path = dir.path().join("disk.img");
    let report_path = dir.path().join("carve_report.json");
    let output_dir = dir.path().to_path_buf();
    let bin_path = dir.path().join("carve_events.bin");

    // Write the synthetic disk image.
    let img = build_partial_jpeg_image();
    std::fs::write(&image_path, &img).unwrap();

    // Write a carve_report.json with one partial JPEG (file_id=10).
    let partial_fid: u64 = 10;
    write_carve_report(&report_path, image_path.to_str().unwrap(), partial_fid);

    // Pre-create carve_events.bin with a valid header + a FileFound for fid=10
    // so the recovery allocator seeds from file_id 10 and assigns >=11 to candidates.
    {
        let sink = BincodeFileSink::create(&bin_path).unwrap();
        let fo = create_file_object(
            "00000001.jpg",
            FileType::Jpeg,
            512,
            0,
            Some(JpegScanInfo {
                width: None,
                height: None,
                fragmentation_point_img_offset: None,
                has_restart_markers: false,
                status: JpegScanStatus::Truncated,
            }),
            partial_fid,
        );
        sink.emit(&CarveEvent::FileFound {
            source_id: 0,
            file: fo,
            img_offset: 0,
            written_path: "00000001.jpg".into(),
        });
    }

    // Replay the pre-existing events into a fresh VM.
    let mut vm = ViewModel::new();
    {
        let mut r = utmost_lib::events::BincodeFileReader::open(&bin_path).unwrap();
        while let Some(ev) = r.next_event().unwrap() {
            vm.apply(&ev);
        }
    }

    // Run recovery with relaxed settings so the synthetic fixture produces
    // at least one candidate. Bypass run_recovery_blocking (which uses
    // RecoveryConfig::default with min_entropy_score=7.0 and
    // huffman_validation=true, which synthetic data may not satisfy) and call
    // the library entry point directly with a custom config.
    let cfg = utmost_lib::jpeg_recover::RecoveryConfig {
        keep_candidates: 1,
        huffman_validation: false,
        min_entropy_score: 0.0,
        min_ff_validity_score: 0.0,
        block_size: 512,
        search_window: 4096,
        max_candidates: 3,
    };

    let (tx, rx) = unbounded::<CarveEvent>();
    let channel_sink = std::sync::Arc::new(utmost_lib::events::ChannelSink::new(tx))
        as std::sync::Arc<dyn utmost_lib::events::EventSink>;

    utmost_lib::jpeg_recover::recover_fragmented_jpegs_with_event_log_sink(
        image_path.to_str().unwrap(),
        report_path.to_str().unwrap(),
        output_dir.to_str().unwrap(),
        &cfg,
        Some(channel_sink),
        Some(&bin_path),
    )
    .expect("recovery should succeed against synthetic fixture");

    // Drain the channel and apply every event to the view-model.
    while let Ok(ev) = rx.try_recv() {
        vm.apply(&ev);
    }

    // The partial original (fid=10) must have at least one variant.
    let variant_ids: Vec<u64> = vm
        .variants
        .get(&partial_fid)
        .expect("variants populated for partial fid=10")
        .variant_ids
        .clone();
    assert!(!variant_ids.is_empty(), "expected >= 1 candidate, got 0");

    // Variants must be excluded from the main grid after recompute_visible.
    // Enable Jpeg type so any non-variant JPEG would show up.
    vm.filter.enabled_types.insert(FileType::Jpeg);
    vm.recompute_visible();

    for vid in &variant_ids {
        let in_visible = vm.visible_files.iter().any(|&internal_id| {
            vm.files
                .iter()
                .find(|f| f.id == internal_id)
                .map(|f| f.file.file_id)
                == Some(*vid)
        });
        assert!(
            !in_visible,
            "variant fid {} should not appear in main grid",
            vid
        );
    }
}
