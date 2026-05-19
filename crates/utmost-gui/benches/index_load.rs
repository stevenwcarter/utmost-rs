//! Two opt-in benches for the SQLite index hot paths. Run with:
//!   UTMOST_BENCH=1 cargo bench -p utmost-gui --bench index_load
//!
//! When `UTMOST_BENCH` is unset the bench bodies are skipped (each prints a
//! short notice and returns early). This keeps cargo bench cheap in CI.

use criterion::{Criterion, criterion_group, criterion_main};
use std::sync::{Arc, Mutex};
use utmost_lib::events::{
    BincodeFileSink, CarveEvent, CaseMetadata, CliConfigSnapshot, EventSink, SourceDescriptor,
};
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::{ExecutionEnvironment, FileType};

const N_FILES: usize = 286_000;

fn run_started_event() -> CarveEvent {
    CarveEvent::RunStarted {
        utmost_version: "0".into(),
        format_version: 1,
        started_at: "2026-05-19T00:00:00+0000".into(),
        command_line: vec!["utmost".into()],
        working_directory: ".".into(),
        execution_environment: ExecutionEnvironment {
            os_sysname: "linux".into(),
            os_release: "6".into(),
            os_version: "1".into(),
            host: "h".into(),
            arch: "x86_64".into(),
            uid: 1,
            start_time: "2026-05-19T00:00:00+0000".into(),
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
        case: Some(CaseMetadata::default()),
        configured_types: vec![FileType::Jpeg],
        sources: vec![SourceDescriptor {
            source_id: 0,
            filename: "disk1.dd".into(),
            total_bytes: 4096,
            output_subdir: "output-disk1_dd".into(),
        }],
        output_root: "out".into(),
    }
}

fn write_synthetic_log(path: &std::path::Path, n: usize) {
    let sink = BincodeFileSink::create(path).unwrap();
    sink.emit(&run_started_event());
    for i in 1..=n as u64 {
        sink.emit(&CarveEvent::FileFound {
            source_id: 0,
            file: create_file_object("x.jpg", FileType::Jpeg, 0, 0, None, i),
            img_offset: 0,
            written_path: "x.jpg".into(),
        });
    }
}

fn bench_enabled() -> bool {
    std::env::var("UTMOST_BENCH").is_ok()
}

fn bench_cold(c: &mut Criterion) {
    if !bench_enabled() {
        eprintln!("skipping cold_rebuild_286k — set UTMOST_BENCH=1 to run");
        return;
    }
    let mut group = c.benchmark_group("cold_rebuild_286k");
    group.sample_size(10);
    group.bench_function("cold_rebuild", |b| {
        b.iter_batched(
            || {
                let dir = tempfile::tempdir().unwrap();
                let bin = dir.path().join("d-events.bin");
                write_synthetic_log(&bin, N_FILES);
                (dir, bin)
            },
            |(_dir, bin)| {
                let vm = Arc::new(Mutex::new(utmost_gui::view_model::ViewModel::new()));
                utmost_gui::indexer_thread::run_blocking(&bin, vm).unwrap();
            },
            criterion::BatchSize::PerIteration,
        );
    });
    group.finish();
}

fn bench_warm(c: &mut Criterion) {
    if !bench_enabled() {
        eprintln!("skipping warm_hydrate_286k — set UTMOST_BENCH=1 to run");
        return;
    }
    // Build the index once outside the timed loop.
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("d-events.bin");
    write_synthetic_log(&bin, N_FILES);
    {
        let vm = Arc::new(Mutex::new(utmost_gui::view_model::ViewModel::new()));
        utmost_gui::indexer_thread::run_blocking(&bin, vm).unwrap();
    }
    let mut group = c.benchmark_group("warm_hydrate_286k");
    group.sample_size(10);
    group.bench_function("warm_hydrate", |b| {
        b.iter(|| {
            let vm = Arc::new(Mutex::new(utmost_gui::view_model::ViewModel::new()));
            utmost_gui::indexer_thread::run_blocking(&bin, vm).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_cold, bench_warm);
criterion_main!(benches);
