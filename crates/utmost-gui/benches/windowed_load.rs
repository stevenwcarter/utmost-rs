//! Criterion benches for the windowed-files hot paths.
//!
//! Run with: `cargo bench -p utmost-gui --bench windowed_load`
//!
//! These benches don't run as part of `cargo test`/CI; they are only invoked
//! via `cargo bench`. The fixture DBs are seeded programmatically in-memory
//! (no .bin files required).
//!
//! Targets (informational):
//! * `match_ids_250k`       — `query_match_ids` over 250k rows, target <50 ms
//! * `window_fetch_2500`    — `fetch_window` for a 2500-id slice, target <10 ms
//! * `sync_tick_window`     — simplified `build_tiles`-equivalent loop, <5 ms
//! * `phase_disabled`       — `PerfRecorder::phase()` when disabled, ≤1 ns
//!
//! ## Note on `sync_tick_window`
//!
//! `UiState::sync` is tightly coupled to a live Slint `MainWindow` (it reads
//! properties off the window, writes back into `slint::VecModel`s, etc.) and
//! cannot run without an event loop. Even the `build_tiles` closure inside
//! `sync` touches `self.window`, `self.image_cache`, `self.thumbs`, and
//! `slint::Image`. To bench the *pure-Rust* hot work that runs every UI tick
//! we instead reimplement the iteration shape here: walk the windowed slice
//! of `match_ids`, look up the corresponding `FoundFile` in `vm.window`, and
//! materialise lightweight tile-equivalent data. This mirrors the cost
//! profile of `build_tiles` minus the Slint-side allocations.

use std::collections::BTreeMap;

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use turso::Value;
use utmost_lib::types::{FileObject, FileType};

use utmost_gui::index_db::models::FileStub;
use utmost_gui::index_db::queries::{fetch_window, query_match_ids};
use utmost_gui::index_db::{IndexDb, TursoPool, block_on};
use utmost_gui::telemetry::{PerfRecorder, PerfTarget};
use utmost_gui::view_model::{FilterState, FoundFile};

/// Type strings the seeder cycles through. Must match `file_type_to_db_string`
/// in `queries.rs` so the default filter (no type filter) round-trips and so
/// type-filtered benches would also work if added later.
const TYPE_CYCLE: &[&str] = &["jpeg", "png", "pdf", "gif", "bmp"];

/// Build an in-memory index DB populated with `n` file rows on a single
/// source and return its turso pool. Inserts are batched into chunks of 1k
/// inside a single transaction per chunk to keep seeding time reasonable.
fn build_fixture_db(n: usize) -> TursoPool {
    let pool = IndexDb::open_in_memory()
        .expect("open in-memory db")
        .pool()
        .clone();
    block_on(async {
        {
            let conn = pool.get().await.unwrap();
            conn.execute(
                "INSERT INTO source (source_id, filename, output_subdir, total_bytes, \
                 bytes_read, files_found, status) \
                 VALUES (1, 'fixture.img', 'fixture', 0, 0, 0, 'Finished')",
                (),
            )
            .await
            .unwrap();
        }

        const CHUNK: usize = 1000;
        let mut i: usize = 0;
        while i < n {
            let end = (i + CHUNK).min(n);
            let mut conn = pool.get().await.unwrap();
            let tx = conn.transaction().await.unwrap();
            for j in i..end {
                let suffix = TYPE_CYCLE[j % TYPE_CYCLE.len()];
                tx.execute(
                    "INSERT INTO file (file_id, source_id, filename, filesize, file_type, \
                     img_offset, written_path, byte_runs_json, preview_status) \
                     VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, '[]', 'unknown')",
                    turso::params_from_iter(vec![
                        Value::Integer((j as i64) + 1),
                        Value::Text(format!("{:08}.{}", j + 1, suffix)),
                        Value::Integer(1_000 + (j as i64) * 17),
                        Value::Text(suffix.to_string()),
                        Value::Integer((j as i64) * 4096),
                        Value::Text(format!("fixture/{:08}.{}", j + 1, suffix)),
                    ]),
                )
                .await
                .unwrap();
            }
            tx.commit().await.unwrap();
            i = end;
        }
    });
    pool
}

fn bench_match_ids_250k(c: &mut Criterion) {
    let pool = build_fixture_db(250_000);
    let filter = FilterState::default();
    c.bench_function("match_ids_250k", |b| {
        b.iter(|| {
            let stubs = query_match_ids(&pool, &filter, None).expect("query_match_ids");
            black_box(stubs.len());
        });
    });
}

fn bench_window_fetch_2500(c: &mut Criterion) {
    let pool = build_fixture_db(10_000);
    // file_ids are 1-based; pick a 2500-wide slice from the middle.
    let ids: Vec<u64> = (1u64..=2500).collect();
    c.bench_function("window_fetch_2500", |b| {
        b.iter(|| {
            let rows = fetch_window(&pool, &ids).expect("fetch_window");
            black_box(rows.len());
        });
    });
}

/// Build a synthetic `FoundFile` for the build-tiles bench. Cheap to construct
/// — no JSON parsing, no path joining beyond a `from()` — so the bench measures
/// the iteration cost, not the fixture cost.
fn fake_found_file(id: u64) -> FoundFile {
    FoundFile {
        id,
        source_id: 1,
        file: FileObject {
            file_id: id,
            filename: format!("{:08}.jpeg", id),
            filesize: 1_000 + id * 17,
            file_type: "jpeg".into(),
            byte_runs: Vec::new(),
            jpeg_scan: None,
        },
        written_path: std::path::PathBuf::from("fixture").join(format!("{:08}.jpeg", id)),
        img_offset: id * 4096,
    }
}

/// Stand-in for the `build_tiles` portion of `UiState::sync`. See module doc
/// for why we can't call the real one — it requires a live Slint window. This
/// loop mirrors the iteration shape: walk a windowed slice of `match_ids`,
/// look up each id in `vm.window`, and build a small per-tile output. The
/// Slint property writes and `SharedString` conversions in the real function
/// are roughly proportional to this work.
fn bench_sync_tick_window(c: &mut Criterion) {
    // Match-ids list (250k stubs) with a 2500-wide window populated in `vm.window`.
    let match_ids: Vec<FileStub> = (1u64..=250_000)
        .map(|id| FileStub {
            file_id: id,
            filename: format!("{:08}.jpeg", id),
            filesize: 1_000 + id * 17,
            file_type: FileType::Jpeg,
        })
        .collect();
    let window_range = 0..2500usize;
    let window: BTreeMap<u64, FoundFile> = match_ids[window_range.clone()]
        .iter()
        .map(|s| (s.file_id, fake_found_file(s.file_id)))
        .collect();

    let cols = 6usize;

    c.bench_function("sync_tick_window", |b| {
        b.iter(|| {
            let mut count = 0usize;
            for (slot_idx, stub) in match_ids[window_range.clone()].iter().enumerate() {
                let abs_idx = window_range.start + slot_idx;
                let absolute_row = (abs_idx / cols) as i32;
                let absolute_col = (abs_idx % cols) as i32;
                let (filename, filesize, file_type) = match window.get(&stub.file_id) {
                    Some(f) => (
                        f.file.filename.as_str(),
                        format!("{} B", f.file.filesize),
                        f.file.file_type.as_str().to_string(),
                    ),
                    None => (
                        stub.filename.as_str(),
                        format!("{} B", stub.filesize),
                        format!("{:?}", stub.file_type),
                    ),
                };
                black_box((
                    stub.file_id as i32,
                    absolute_row,
                    absolute_col,
                    filename,
                    filesize,
                    file_type,
                ));
                count += 1;
            }
            black_box(count);
        });
    });
}

fn bench_perf_disabled_zero_cost(c: &mut Criterion) {
    let r = PerfRecorder::new(PerfTarget::Test, false, 100_000);
    c.bench_function("phase_disabled", |b| {
        b.iter(|| {
            let g = r.phase("noop");
            black_box(&g);
        });
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench_match_ids_250k, bench_window_fetch_2500, bench_sync_tick_window, bench_perf_disabled_zero_cost
);
criterion_main!(benches);
