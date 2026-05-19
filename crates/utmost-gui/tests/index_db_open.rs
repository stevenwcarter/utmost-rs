use utmost_gui::index_db::IndexDb;

#[test]
fn open_fresh_path_applies_migrations() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test-index.sqlite");
    let mut db = IndexDb::open(&db_path).unwrap();
    db.with_conn(|conn| {
        use diesel::prelude::*;
        use diesel::sql_query;
        let n: i64 = sql_query("SELECT COUNT(*) AS n FROM meta")
            .get_result::<CountRow>(conn)
            .unwrap()
            .n;
        assert_eq!(n, 0);
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
