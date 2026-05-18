use std::process::Command;

#[test]
fn one_input_produces_flat_layout() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.bin");
    let mut data = vec![0xFFu8, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
    data.extend_from_slice(b"JFIF\0");
    data.extend(std::iter::repeat_n(0xAAu8, 64));
    data.extend_from_slice(&[0xFF, 0xD9]);
    std::fs::write(&img, &data).unwrap();

    let out = tmp.path().join("out");
    let status = Command::new(env!("CARGO_BIN_EXE_utmost"))
        .args(["-t", "jpeg", "-o"])
        .arg(&out)
        .arg(&img)
        .status()
        .unwrap();
    assert!(status.success());

    assert!(
        out.join("carve_events.bin").exists(),
        "expected events file in flat root"
    );
    let has_subdir = std::fs::read_dir(&out)
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().starts_with("output-"));
    assert!(
        !has_subdir,
        "did not expect output-XX/ subdirs for single input"
    );
}

#[test]
fn two_inputs_produce_per_source_subdirs() {
    let tmp = tempfile::tempdir().unwrap();
    let img1 = tmp.path().join("a.bin");
    let img2 = tmp.path().join("b.bin");
    let mut data = vec![0xFFu8, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
    data.extend_from_slice(b"JFIF\0");
    data.extend(std::iter::repeat_n(0xAAu8, 64));
    data.extend_from_slice(&[0xFF, 0xD9]);
    std::fs::write(&img1, &data).unwrap();
    std::fs::write(&img2, &data).unwrap();

    let out = tmp.path().join("out");
    let status = Command::new(env!("CARGO_BIN_EXE_utmost"))
        .args(["-t", "jpeg", "-o"])
        .arg(&out)
        .arg(&img1)
        .arg(&img2)
        .status()
        .unwrap();
    assert!(status.success());

    let subdirs: Vec<_> = std::fs::read_dir(&out)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("output-"))
        .collect();
    assert_eq!(subdirs.len(), 2, "expected 2 output-XX/ subdirs");
    for d in subdirs {
        assert!(
            d.path().join("carve_events.bin").exists(),
            "expected events file in {}",
            d.path().display()
        );
    }
}

#[test]
fn disable_export_skips_events_file() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.bin");
    std::fs::write(&img, [0u8; 16]).unwrap();
    let out = tmp.path().join("out");
    let status = Command::new(env!("CARGO_BIN_EXE_utmost"))
        .args(["-t", "jpeg", "--disable-export", "-o"])
        .arg(&out)
        .arg(&img)
        .status()
        .unwrap();
    assert!(status.success());
    assert!(!out.join("carve_events.bin").exists());
}
