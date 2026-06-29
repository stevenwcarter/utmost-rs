mod common;

use common::run_started_event;
use std::fs;
use turso::Value;
use utmost_gui::index_db::{IndexDb, TursoPool, block_on};
use utmost_gui::indexer_thread::{OpenAction, open_decision};
use utmost_lib::events::{BincodeFileSink, CarveEvent, EventSink};

fn make_log(dir: &std::path::Path, name: &str, events: &[CarveEvent]) -> std::path::PathBuf {
    let p = dir.join(name);
    let sink = BincodeFileSink::create(&p).unwrap();
    for e in events {
        sink.emit(e);
    }
    drop(sink);
    p
}

fn set_meta(pool: &TursoPool, key: &str, value: &str) {
    let pool = pool.clone();
    let key = key.to_owned();
    let value = value.to_owned();
    block_on(async move {
        let conn = pool.get().await.unwrap();
        conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            turso::params_from_iter(vec![Value::Text(key), Value::Text(value)]),
        )
        .await
        .unwrap();
    });
}

#[test]
fn fresh_db_is_rebuild_from_zero() {
    let dir = tempfile::tempdir().unwrap();
    let bin = make_log(dir.path(), "a-events.bin", &[run_started_event()]);
    let pool = IndexDb::open(&dir.path().join("a-index.sqlite"))
        .unwrap()
        .pool()
        .clone();
    let action = open_decision(&bin, &pool).unwrap();
    assert!(matches!(action, OpenAction::RebuildFromZero));
}

#[test]
fn different_run_started_is_wipe_and_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let bin = make_log(dir.path(), "a-events.bin", &[run_started_event()]);
    let pool = IndexDb::open(&dir.path().join("a-index.sqlite"))
        .unwrap()
        .pool()
        .clone();
    set_meta(&pool, "run_started_at", "old-timestamp");
    set_meta(&pool, "last_event_offset", "999");
    let action = open_decision(&bin, &pool).unwrap();
    assert!(matches!(action, OpenAction::WipeAndRebuild));
}

#[test]
fn equal_offset_is_hydrate_and_done() {
    let dir = tempfile::tempdir().unwrap();
    let bin = make_log(dir.path(), "a-events.bin", &[run_started_event()]);
    let size = fs::metadata(&bin).unwrap().len();
    let pool = IndexDb::open(&dir.path().join("a-index.sqlite"))
        .unwrap()
        .pool()
        .clone();
    set_meta(&pool, "run_started_at", "2026-05-19T00:00:00+0000");
    set_meta(&pool, "last_event_offset", &size.to_string());
    let action = open_decision(&bin, &pool).unwrap();
    assert!(matches!(action, OpenAction::HydrateAndDone));
}

#[test]
fn smaller_offset_is_resume() {
    let dir = tempfile::tempdir().unwrap();
    let bin = make_log(dir.path(), "a-events.bin", &[run_started_event()]);
    let pool = IndexDb::open(&dir.path().join("a-index.sqlite"))
        .unwrap()
        .pool()
        .clone();
    set_meta(&pool, "run_started_at", "2026-05-19T00:00:00+0000");
    set_meta(&pool, "last_event_offset", "1");
    let action = open_decision(&bin, &pool).unwrap();
    assert!(matches!(action, OpenAction::Resume { .. }));
}

#[test]
fn larger_offset_is_wipe_and_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let bin = make_log(dir.path(), "a-events.bin", &[run_started_event()]);
    let size = fs::metadata(&bin).unwrap().len();
    let pool = IndexDb::open(&dir.path().join("a-index.sqlite"))
        .unwrap()
        .pool()
        .clone();
    set_meta(&pool, "run_started_at", "2026-05-19T00:00:00+0000");
    set_meta(&pool, "last_event_offset", &(size + 999).to_string());
    let action = open_decision(&bin, &pool).unwrap();
    assert!(matches!(action, OpenAction::WipeAndRebuild));
}

#[test]
fn run_started_set_but_no_offset_is_rebuild_from_zero() {
    let dir = tempfile::tempdir().unwrap();
    let bin = make_log(dir.path(), "a-events.bin", &[run_started_event()]);
    let pool = IndexDb::open(&dir.path().join("a-index.sqlite"))
        .unwrap()
        .pool()
        .clone();
    set_meta(&pool, "run_started_at", "2026-05-19T00:00:00+0000");
    let action = open_decision(&bin, &pool).unwrap();
    assert!(matches!(action, OpenAction::RebuildFromZero));
}

#[test]
fn empty_log_returns_rebuild_from_zero() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("empty-events.bin");
    let _sink = BincodeFileSink::create(&bin).unwrap();
    drop(_sink);
    let pool = IndexDb::open(&dir.path().join("empty-index.sqlite"))
        .unwrap()
        .pool()
        .clone();
    let result = open_decision(&bin, &pool);
    assert!(matches!(result.unwrap(), OpenAction::RebuildFromZero));
}
