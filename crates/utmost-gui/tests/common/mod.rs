//! Shared helpers for `tests/index_db_writer_*.rs` integration tests.
//!
//! Cargo's test runner treats files in `tests/` as separate crates but
//! ignores subdirectories under `tests/`, so this module is imported via
//! `mod common;` from each test file that needs it. Subsequent Phase 3
//! tasks (3.3 – 3.13) reuse `run_started_event()` to seed a `run` row
//! before exercising the variant-specific event.

use std::path::Path;
use utmost_gui::index_db::{IndexDb, TursoPool, block_on};
use utmost_lib::events::{CarveEvent, CaseMetadata, CliConfigSnapshot, SourceDescriptor};
use utmost_lib::types::{ExecutionEnvironment, FileType};

/// Open (creating + migrating) the index DB at `path` and return its turso
/// pool clone for readback assertions in the post-Diesel integration tests.
#[allow(dead_code)]
pub fn open_pool(path: &Path) -> TursoPool {
    IndexDb::open(path).expect("open index db").pool().clone()
}

/// `COUNT(*)` of `table`.
#[allow(dead_code)]
pub fn count(pool: &TursoPool, table: &str) -> i64 {
    scalar_i64(pool, &format!("SELECT COUNT(*) FROM {table}"))
}

/// First column of the first row as `i64` (panics if absent/non-integer).
#[allow(dead_code)]
pub fn scalar_i64(pool: &TursoPool, sql: &str) -> i64 {
    let pool = pool.clone();
    let sql = sql.to_owned();
    block_on(async move {
        let conn = pool.get().await.unwrap();
        let mut rows = conn.query(&sql, ()).await.unwrap();
        let row = rows.next().await.unwrap().expect("expected a row");
        *row.get_value(0).unwrap().as_integer().expect("integer column")
    })
}

/// First column of the first row as `Option<i64>` (`None` when no row).
#[allow(dead_code)]
pub fn scalar_opt_i64(pool: &TursoPool, sql: &str) -> Option<i64> {
    let pool = pool.clone();
    let sql = sql.to_owned();
    block_on(async move {
        let conn = pool.get().await.unwrap();
        let mut rows = conn.query(&sql, ()).await.unwrap();
        match rows.next().await.unwrap() {
            Some(row) => row.get_value(0).unwrap().as_integer().copied(),
            None => None,
        }
    })
}

/// First column of the first row as `Option<String>` (`None` when no row or NULL).
#[allow(dead_code)]
pub fn scalar_text(pool: &TursoPool, sql: &str) -> Option<String> {
    let pool = pool.clone();
    let sql = sql.to_owned();
    block_on(async move {
        let conn = pool.get().await.unwrap();
        let mut rows = conn.query(&sql, ()).await.unwrap();
        match rows.next().await.unwrap() {
            Some(row) => row.get_value(0).unwrap().as_text().map(|s| s.to_owned()),
            None => None,
        }
    })
}

/// First column of the first row as `f64`, accepting REAL or INTEGER storage.
#[allow(dead_code)]
pub fn scalar_f64(pool: &TursoPool, sql: &str) -> f64 {
    let pool = pool.clone();
    let sql = sql.to_owned();
    block_on(async move {
        let conn = pool.get().await.unwrap();
        let mut rows = conn.query(&sql, ()).await.unwrap();
        let row = rows.next().await.unwrap().expect("expected a row");
        match row.get_value(0).unwrap() {
            turso::Value::Real(r) => r,
            turso::Value::Integer(i) => i as f64,
            other => panic!("expected real/integer, got {other:?}"),
        }
    })
}

/// Read a `meta.value` string by key.
#[allow(dead_code)]
pub fn meta_value(pool: &TursoPool, key: &str) -> Option<String> {
    scalar_text(pool, &format!("SELECT value FROM meta WHERE key = '{key}'"))
}

pub fn run_started_event() -> CarveEvent {
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
        case: Some(CaseMetadata {
            case_id: Some("C-1".into()),
            examiner: Some("E".into()),
            evidence_id: Some("EV".into()),
            notes: Some("n".into()),
        }),
        configured_types: vec![FileType::Jpeg],
        sources: vec![SourceDescriptor {
            source_id: 0,
            filename: "disk1.dd".into(),
            total_bytes: 4096,
            output_subdir: "output-disk1.dd".into(),
        }],
        output_root: "out".into(),
    }
}

/// Like `run_started_event()` but lets the test set `started_at` to make
/// distinct runs distinguishable.
#[allow(dead_code)]
pub fn run_started_event_at(started_at: &str) -> CarveEvent {
    let mut ev = run_started_event();
    if let CarveEvent::RunStarted {
        started_at: ref mut s,
        ..
    } = ev
    {
        *s = started_at.into();
    }
    ev
}
