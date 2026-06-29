mod common;

use utmost_gui::index_db::IndexDb;

#[test]
fn open_fresh_path_applies_migrations() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test-index.sqlite");
    let pool = common::open_pool(&db_path);
    // After all migrations are applied, the only bootstrap meta row is the
    // preview_status_version key (seeded by 0002_preview_status). Runtime
    // keys like run_started_at / last_event_offset are written later by
    // the writer, so a fresh DB has exactly one meta row.
    assert_eq!(common::count(&pool, "meta"), 1);
}

#[test]
fn open_reapply_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test-index.sqlite");
    let _ = IndexDb::open(&db_path).unwrap();
    let _ = IndexDb::open(&db_path).unwrap();
}
