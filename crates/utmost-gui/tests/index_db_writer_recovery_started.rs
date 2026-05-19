mod common;

use common::run_started_event;
use diesel::prelude::*;
use utmost_gui::index_db::{IndexDb, schema, writer::IndexDbWriter};
use utmost_lib::events::CarveEvent;

#[test]
fn apply_recovery_started_writes_recovery_run_row() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = IndexDb::open(&dir.path().join("idx.sqlite")).unwrap();
    {
        let mut w = IndexDbWriter::new(db.conn(), 100);
        w.apply(run_started_event(), 10).unwrap();
        w.apply(
            CarveEvent::RecoveryStarted {
                started_at: "2026-05-19T01:00:00+0000".into(),
                keep_candidates: 5,
                search_window: 1024 * 1024,
                block_size: 512,
                min_entropy_score: 7.0,
                huffman_validation: true,
            },
            20,
        )
        .unwrap();
        w.flush().unwrap();
    }
    db.with_conn(|conn| {
        let n: i64 = schema::recovery_run::table
            .count()
            .get_result(conn)
            .unwrap();
        assert_eq!(n, 1);
        let keep: i32 = schema::recovery_run::table
            .filter(schema::recovery_run::id.eq(1i32))
            .select(schema::recovery_run::keep_candidates)
            .first(conn)
            .unwrap();
        assert_eq!(keep, 5);
        let hv: i32 = schema::recovery_run::table
            .filter(schema::recovery_run::id.eq(1i32))
            .select(schema::recovery_run::huffman_validation)
            .first(conn)
            .unwrap();
        assert_eq!(hv, 1);
        Ok::<_, diesel::result::Error>(())
    })
    .unwrap();
}
