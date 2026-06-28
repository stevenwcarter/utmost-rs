use anyhow::Result;

/// Apply (or verify) the full database schema.
///
/// All DDL uses `IF NOT EXISTS` guards so the function is safe to call on an
/// already-initialised database.  The final statement seeds the
/// `preview_status_version` meta key via `INSERT OR IGNORE` — idempotent even
/// on repeat calls.
///
/// DDL is derived from the three Diesel migrations in
/// `crates/utmost-gui/migrations/` (0001_initial, 0002_preview_status,
/// 0003_preview_blob), folded into a single pass.  The `file` table already
/// contains `preview_status` (from migration 0002) and `preview_blob` is
/// present from migration 0003.  The four separate per-column `file` indexes
/// from migration 0001 (`idx_file_source`, `idx_file_type`, `idx_file_size`,
/// `idx_file_img_offset`) are reproduced exactly — each as a single-column
/// index — so that query shapes that filter or sort on one column at a time
/// continue to benefit from a tight index scan.
pub async fn create_schema(conn: &turso::Connection) -> Result<()> {
    const STMTS: &[&str] = &[
        // ── meta ─────────────────────────────────────────────────────────────
        "CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY NOT NULL,
            value TEXT NOT NULL
        )",
        // ── run ──────────────────────────────────────────────────────────────
        "CREATE TABLE IF NOT EXISTS run (
            id                    INTEGER PRIMARY KEY CHECK (id = 1),
            started_at            TEXT    NOT NULL,
            output_root           TEXT    NOT NULL,
            source_image_path     TEXT    NOT NULL,
            configured_types_json TEXT    NOT NULL,
            case_id               TEXT,
            examiner              TEXT,
            evidence_id           TEXT,
            case_notes            TEXT,
            status                TEXT    NOT NULL,
            elapsed_ms            INTEGER NOT NULL DEFAULT 0,
            total_files           INTEGER NOT NULL DEFAULT 0
        )",
        // ── source ───────────────────────────────────────────────────────────
        "CREATE TABLE IF NOT EXISTS source (
            source_id    INTEGER PRIMARY KEY NOT NULL,
            filename     TEXT    NOT NULL,
            output_subdir TEXT   NOT NULL,
            total_bytes  INTEGER NOT NULL,
            bytes_read   INTEGER NOT NULL DEFAULT 0,
            files_found  INTEGER NOT NULL DEFAULT 0,
            status       TEXT    NOT NULL,
            duration_ms  INTEGER
        )",
        // ── file (includes preview_status from migration 0002) ────────────────
        "CREATE TABLE IF NOT EXISTS file (
            file_id                    INTEGER PRIMARY KEY NOT NULL,
            source_id                  INTEGER NOT NULL REFERENCES source(source_id),
            filename                   TEXT    NOT NULL,
            filesize                   INTEGER NOT NULL,
            file_type                  TEXT    NOT NULL,
            img_offset                 INTEGER NOT NULL,
            written_path               TEXT    NOT NULL,
            byte_runs_json             TEXT    NOT NULL DEFAULT '[]',
            jpeg_status                TEXT,
            jpeg_width                 INTEGER,
            jpeg_height                INTEGER,
            jpeg_fragmentation_point   INTEGER,
            jpeg_has_restart_markers   INTEGER,
            preview_status             TEXT    NOT NULL DEFAULT 'unknown'
        )",
        // ── bookmark ─────────────────────────────────────────────────────────
        "CREATE TABLE IF NOT EXISTS bookmark (
            file_id INTEGER PRIMARY KEY NOT NULL,
            at      TEXT NOT NULL
        )",
        // ── note ─────────────────────────────────────────────────────────────
        "CREATE TABLE IF NOT EXISTS note (
            note_id INTEGER PRIMARY KEY NOT NULL,
            file_id INTEGER NOT NULL,
            text    TEXT    NOT NULL,
            at      TEXT    NOT NULL
        )",
        // ── best_choice ──────────────────────────────────────────────────────
        "CREATE TABLE IF NOT EXISTS best_choice (
            original_file_id INTEGER PRIMARY KEY NOT NULL,
            chosen_file_id   INTEGER NOT NULL,
            at               TEXT    NOT NULL
        )",
        // ── recovery_run ─────────────────────────────────────────────────────
        "CREATE TABLE IF NOT EXISTS recovery_run (
            id                    INTEGER PRIMARY KEY CHECK (id = 1),
            started_at            TEXT    NOT NULL,
            keep_candidates       INTEGER NOT NULL,
            search_window         INTEGER NOT NULL,
            block_size            INTEGER NOT NULL,
            min_entropy_score     REAL    NOT NULL,
            huffman_validation    INTEGER NOT NULL,
            finished_duration_ms  INTEGER,
            partials_processed    INTEGER,
            candidates_written    INTEGER
        )",
        // ── variant ──────────────────────────────────────────────────────────
        "CREATE TABLE IF NOT EXISTS variant (
            original_file_id       INTEGER NOT NULL,
            candidate_file_id      INTEGER NOT NULL,
            rank                   INTEGER NOT NULL,
            method                 TEXT    NOT NULL,
            entropy_score          REAL    NOT NULL,
            ff_validity_score      REAL,
            huffman_mcu_count      INTEGER,
            continuation_img_offset INTEGER NOT NULL,
            PRIMARY KEY (original_file_id, candidate_file_id)
        )",
        // ── preview_blob (migration 0003) ────────────────────────────────────
        "CREATE TABLE IF NOT EXISTS preview_blob (
            file_id INTEGER PRIMARY KEY NOT NULL,
            codec   TEXT    NOT NULL,
            width   INTEGER NOT NULL,
            height  INTEGER NOT NULL,
            bytes   BLOB    NOT NULL,
            FOREIGN KEY (file_id) REFERENCES file(file_id) ON DELETE CASCADE
        )",
        // ── indexes ──────────────────────────────────────────────────────────
        // Four single-column file indexes — reproduced exactly from migration
        // 0001 so that queries filtering or sorting on one column at a time
        // get tight index scans rather than falling back to a full table scan.
        "CREATE INDEX IF NOT EXISTS idx_file_source     ON file (source_id)",
        "CREATE INDEX IF NOT EXISTS idx_file_type       ON file (file_type)",
        "CREATE INDEX IF NOT EXISTS idx_file_size       ON file (filesize)",
        "CREATE INDEX IF NOT EXISTS idx_file_img_offset ON file (img_offset)",
        // Named exactly as in the migration files:
        "CREATE INDEX IF NOT EXISTS idx_note_file ON note (file_id)",
        "CREATE INDEX IF NOT EXISTS idx_variant_candidate ON variant (candidate_file_id)",
        "CREATE INDEX IF NOT EXISTS idx_file_preview ON file (preview_status)",
        // ── seed ─────────────────────────────────────────────────────────────
        // Mirrors the INSERT OR IGNORE from migration 0002.  Safe to repeat.
        "INSERT OR IGNORE INTO meta (key, value) VALUES ('preview_status_version', '0')",
    ];

    for s in STMTS {
        conn.execute(s, ()).await?;
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::db::{block_on, IndexDb};

    #[test]
    fn create_schema_makes_all_tables_and_is_idempotent() {
        let db = IndexDb::open_in_memory().unwrap(); // open() already ran create_schema
        let pool = db.pool().clone();
        let names: Vec<String> = block_on(async {
            // running it again must not error (idempotent)
            let conn = pool.get().await.unwrap();
            crate::db::schema_sql::create_schema(&conn).await.unwrap();
            let mut rows = conn
                .query(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
                    (),
                )
                .await
                .unwrap();
            let mut out = Vec::new();
            while let Some(r) = rows.next().await.unwrap() {
                out.push(r.get_value(0).unwrap().as_text().unwrap().to_string());
            }
            out
        });
        for t in [
            "meta",
            "run",
            "source",
            "file",
            "bookmark",
            "note",
            "best_choice",
            "recovery_run",
            "variant",
            "preview_blob",
        ] {
            assert!(names.contains(&t.to_string()), "missing table {t}");
        }

        // Verify the four original single-column file indexes are present.
        let indexes: Vec<String> = block_on(async {
            let conn = pool.get().await.unwrap();
            let mut rows = conn
                .query(
                    "SELECT name FROM sqlite_master WHERE type='index' ORDER BY name",
                    (),
                )
                .await
                .unwrap();
            let mut out = Vec::new();
            while let Some(r) = rows.next().await.unwrap() {
                out.push(r.get_value(0).unwrap().as_text().unwrap().to_string());
            }
            out
        });
        for idx in [
            "idx_file_source",
            "idx_file_type",
            "idx_file_size",
            "idx_file_img_offset",
            "idx_note_file",
            "idx_variant_candidate",
            "idx_file_preview",
        ] {
            assert!(indexes.contains(&idx.to_string()), "missing index {idx}");
        }
        // The composite index from the incorrect implementation must not exist.
        assert!(
            !indexes.contains(&"idx_file_filter".to_string()),
            "unexpected composite index idx_file_filter found"
        );
    }
}
