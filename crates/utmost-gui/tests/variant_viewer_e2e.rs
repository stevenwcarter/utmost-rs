use utmost_gui::view_model::ViewModel;
use utmost_lib::events::{CarveEvent, RecoveryMethod};
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::{FileType, JpegScanInfo, JpegScanStatus};

fn run_started_minimal() -> CarveEvent {
    use utmost_lib::events::{CURRENT_FORMAT_VERSION, CliConfigSnapshot, SourceDescriptor};
    use utmost_lib::types::ExecutionEnvironment;

    CarveEvent::RunStarted {
        utmost_version: "test".into(),
        format_version: CURRENT_FORMAT_VERSION,
        started_at: "t".into(),
        command_line: vec![],
        working_directory: "/".into(),
        execution_environment: ExecutionEnvironment {
            os_sysname: String::new(),
            os_release: String::new(),
            os_version: String::new(),
            host: String::new(),
            arch: String::new(),
            uid: 0,
            start_time: String::new(),
        },
        cli_config: CliConfigSnapshot {
            output_directory: "out".into(),
            types: vec![],
            disable_builtin: false,
            config_file: None,
            concurrent_files: 1,
            disable_validation: false,
            report_only: false,
            disable_report: false,
            disable_audit: false,
            disable_export: false,
            gui_enabled: false,
            quick: false,
            block_size: 512,
            prefix_filenames: false,
            write_all: false,
            keep_incomplete_jpeg: false,
        },
        case: None,
        configured_types: vec![FileType::Jpeg],
        sources: vec![SourceDescriptor {
            source_id: 0,
            filename: "src.bin".into(),
            total_bytes: 1000,
            output_subdir: "out".into(),
        }],
        output_root: "out".into(),
    }
}

#[test]
fn open_variant_viewer_then_mark_best_persists_choice() {
    let mut vm = ViewModel::new();
    vm.apply(&run_started_minimal());

    // Partial JPEG (library file_id=10)
    let mut fo_orig = create_file_object("orig.jpg", FileType::Jpeg, 100, 0, None, 10);
    fo_orig.jpeg_scan = Some(JpegScanInfo {
        width: None,
        height: None,
        fragmentation_point_img_offset: None,
        has_restart_markers: false,
        status: JpegScanStatus::Truncated,
    });
    vm.apply(&CarveEvent::FileFound {
        source_id: 0,
        file: fo_orig,
        img_offset: 0,
        written_path: "orig.jpg".into(),
    });

    // Recovery candidate (library file_id=11)
    let fo_cand = create_file_object("orig_recovered_1.jpg", FileType::Jpeg, 200, 5000, None, 11);
    vm.apply(&CarveEvent::FileFound {
        source_id: 0,
        file: fo_cand,
        img_offset: 5000,
        written_path: "orig_recovered_1.jpg".into(),
    });
    vm.apply(&CarveEvent::RecoveryCandidate {
        original_file_id: 10,
        candidate_file_id: 11,
        rank: 1,
        method: RecoveryMethod::DirectContinuation,
        entropy_score: 7.9,
        ff_validity_score: None,
        huffman_mcu_count: None,
        continuation_img_offset: 5000,
    });

    // Set variant_viewer directly (the view-model method requires selection to
    // be the library file_id; here we exercise the state transition under test).
    vm.variant_viewer = Some(10);
    assert_eq!(vm.variant_viewer, Some(10));

    vm.open_lightbox_for_variant(11);
    assert_eq!(vm.lightbox, Some(11));

    let ev = vm.mark_as_best(10, 11);
    match ev {
        CarveEvent::MarkAsBest {
            chosen_file_id,
            original_file_id,
            ..
        } => {
            assert_eq!(chosen_file_id, 11);
            assert_eq!(original_file_id, 10);
        }
        _ => panic!("expected MarkAsBest"),
    }
    assert_eq!(vm.best_choices.get(&10), Some(&11));

    vm.close_variant_viewer();
    assert!(vm.variant_viewer.is_none());
}
