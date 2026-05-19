mod common;

use common::run_started_event;
use diesel::prelude::*;
use utmost_gui::index_db::{IndexDb, schema, writer::IndexDbWriter};
use utmost_lib::events::CarveEvent;

#[test]
fn apply_recovery_finished_updates_recovery_run() {
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
        w.apply(
            CarveEvent::RecoveryFinished {
                duration_ms: 1,
                partials_processed: 2,
                candidates_written: 3,
            },
            30,
        )
        .unwrap();
        w.flush().unwrap();
    }
    db.with_conn(|conn| {
        let dur: Option<i64> = schema::recovery_run::table
            .filter(schema::recovery_run::id.eq(1i32))
            .select(schema::recovery_run::finished_duration_ms)
            .first(conn)
            .unwrap();
        assert_eq!(dur, Some(1));
        let pp: Option<i32> = schema::recovery_run::table
            .filter(schema::recovery_run::id.eq(1i32))
            .select(schema::recovery_run::partials_processed)
            .first(conn)
            .unwrap();
        assert_eq!(pp, Some(2));
        let cw: Option<i32> = schema::recovery_run::table
            .filter(schema::recovery_run::id.eq(1i32))
            .select(schema::recovery_run::candidates_written)
            .first(conn)
            .unwrap();
        assert_eq!(cw, Some(3));
        Ok::<_, diesel::result::Error>(())
    })
    .unwrap();
}
