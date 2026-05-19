use utmost_gui::resolve_sources_for_test;

#[test]
fn discovers_stem_events_bin_in_subdirs() {
    let dir = tempfile::tempdir().unwrap();
    let sub_a = dir.path().join("output-disk1_dd");
    let sub_b = dir.path().join("output-disk2_dd");
    std::fs::create_dir_all(&sub_a).unwrap();
    std::fs::create_dir_all(&sub_b).unwrap();
    std::fs::write(sub_a.join("disk1_dd-events.bin"), b"").unwrap();
    std::fs::write(sub_b.join("disk2_dd-events.bin"), b"").unwrap();

    let mut found = resolve_sources_for_test(dir.path()).unwrap();
    found.sort();
    assert_eq!(found.len(), 2);
    assert!(found[0].ends_with("disk1_dd-events.bin"));
    assert!(found[1].ends_with("disk2_dd-events.bin"));
}

#[test]
fn discovers_stem_events_bin_when_target_is_dir_with_log() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("disk1_dd-events.bin");
    std::fs::write(&log, b"").unwrap();
    let found = resolve_sources_for_test(dir.path()).unwrap();
    assert_eq!(found, vec![log]);
}

#[test]
fn target_pointing_directly_at_event_log_file_is_returned_as_is() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("disk1_dd-events.bin");
    std::fs::write(&log, b"").unwrap();
    let found = resolve_sources_for_test(&log).unwrap();
    assert_eq!(found, vec![log]);
}
