use utmost_gui::index_db::IndexDb;

#[test]
fn open_fresh_path_applies_migrations() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test-index.sqlite");
    let mut db = IndexDb::open(&db_path).unwrap();
    db.with_conn(|conn| {
        use diesel::prelude::*;
        use diesel::sql_query;
        // After all migrations are applied, the only bootstrap meta row is the
        // preview_status_version key (seeded by 0002_preview_status). Runtime
        // keys like run_started_at / last_event_offset are written later by
        // the writer, so a fresh DB has exactly one meta row.
        let n: i64 = sql_query("SELECT COUNT(*) AS n FROM meta")
            .get_result::<CountRow>(conn)
            .unwrap()
            .n;
        assert_eq!(n, 1);
        Ok::<_, diesel::result::Error>(())
    })
    .unwrap();
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    n: i64,
}

#[test]
fn open_reapply_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test-index.sqlite");
    let _ = IndexDb::open(&db_path).unwrap();
    let _ = IndexDb::open(&db_path).unwrap();
}
