//! Build a [`ViewModelSnapshot`] directly from the Turso index, bypassing
//! event replay.
//!
//! [`snapshot_from_db`] reads all relevant tables in a single connection and
//! constructs a snapshot equivalent to what event-replay would produce.
//! Returns `Ok(None)` when the `run` table is empty — callers should fall
//! through to event replay in that case.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::db::{TursoPool, block_on, models};
use crate::model::{
    FileId, NoteEntry, RecoveryUiState, RunStatus, RunSummary, SourceRow as VmSourceRow,
    SourceStatus, VariantSet, ViewModelSnapshot,
};
use utmost_lib::events::CaseMetadata;
use utmost_lib::types::{FileType, JpegScanStatus};

/// Build a [`ViewModelSnapshot`] from the Turso index without replaying events.
///
/// All tables are read on a single connection.  Returns `Ok(None)` when the
/// `run` table is empty; callers should fall through to event replay in that
/// case.
pub fn snapshot_from_db(pool: &TursoPool) -> Result<Option<ViewModelSnapshot>> {
    let pool = pool.clone();
    block_on(do_snapshot_from_db(pool))
}

// ── Async implementation ──────────────────────────────────────────────────────

async fn do_snapshot_from_db(pool: TursoPool) -> Result<Option<ViewModelSnapshot>> {
    let conn = pool.get().await.context("get conn for snapshot_from_db")?;

    // ----- run (required; empty table → return None) -----
    let run_row = {
        let mut rows = conn
            .query(
                "SELECT id, started_at, output_root, source_image_path, \
                 configured_types_json, case_id, examiner, evidence_id, \
                 case_notes, status, elapsed_ms, total_files \
                 FROM run LIMIT 1",
                (),
            )
            .await
            .context("snapshot_from_db: run query")?;
        match rows.next().await? {
            Some(r) => read_run_row(&r)?,
            None => return Ok(None),
        }
    };

    // ----- source -----
    let sources_db = {
        let mut rows = conn
            .query(
                "SELECT source_id, filename, output_subdir, total_bytes, \
                 bytes_read, files_found, status, duration_ms \
                 FROM source ORDER BY source_id",
                (),
            )
            .await
            .context("snapshot_from_db: source query")?;
        let mut out: Vec<models::SourceRow> = Vec::new();
        while let Some(r) = rows.next().await? {
            out.push(read_source_row(&r)?);
        }
        out
    };

    // ----- file (for type/partial counts only; no FoundFile materialisation) -----
    let files_db = {
        let mut rows = conn
            .query(
                "SELECT file_id, source_id, filename, filesize, file_type, img_offset, \
                 written_path, byte_runs_json, jpeg_status, jpeg_width, jpeg_height, \
                 jpeg_fragmentation_point, jpeg_has_restart_markers, preview_status \
                 FROM file ORDER BY file_id",
                (),
            )
            .await
            .context("snapshot_from_db: file query")?;
        let mut out: Vec<models::FileRow> = Vec::new();
        while let Some(r) = rows.next().await? {
            out.push(read_file_row(&r)?);
        }
        out
    };

    // ----- bookmark -----
    let bookmarks_db = {
        let mut rows = conn
            .query("SELECT file_id FROM bookmark", ())
            .await
            .context("snapshot_from_db: bookmark query")?;
        let mut out: Vec<i64> = Vec::new();
        while let Some(r) = rows.next().await? {
            out.push(models::col_i64(&r, 0, "file_id")?);
        }
        out
    };

    // ----- note -----
    let notes_db = {
        let mut rows = conn
            .query(
                "SELECT note_id, file_id, text, at FROM note ORDER BY note_id",
                (),
            )
            .await
            .context("snapshot_from_db: note query")?;
        let mut out: Vec<models::NoteRow> = Vec::new();
        while let Some(r) = rows.next().await? {
            out.push(read_note_row(&r)?);
        }
        out
    };

    // ----- best_choice -----
    let best_db = {
        let mut rows = conn
            .query(
                "SELECT original_file_id, chosen_file_id FROM best_choice",
                (),
            )
            .await
            .context("snapshot_from_db: best_choice query")?;
        let mut out: Vec<(i64, i64)> = Vec::new();
        while let Some(r) = rows.next().await? {
            out.push((
                models::col_i64(&r, 0, "original_file_id")?,
                models::col_i64(&r, 1, "chosen_file_id")?,
            ));
        }
        out
    };

    // ----- variant -----
    let variants_db = {
        let mut rows = conn
            .query(
                "SELECT original_file_id, candidate_file_id, rank, method, \
                 entropy_score, ff_validity_score, huffman_mcu_count, \
                 continuation_img_offset \
                 FROM variant ORDER BY original_file_id, rank",
                (),
            )
            .await
            .context("snapshot_from_db: variant query")?;
        let mut out: Vec<models::VariantRow> = Vec::new();
        while let Some(r) = rows.next().await? {
            out.push(read_variant_row(&r)?);
        }
        out
    };

    // ----- recovery_run -----
    let recovery_db = {
        let mut rows = conn
            .query(
                "SELECT id, started_at, keep_candidates, search_window, block_size, \
                 min_entropy_score, huffman_validation, finished_duration_ms, \
                 partials_processed, candidates_written \
                 FROM recovery_run LIMIT 1",
                (),
            )
            .await
            .context("snapshot_from_db: recovery_run query")?;
        match rows.next().await? {
            Some(r) => Some(read_recovery_run_row(&r)?),
            None => None,
        }
    };

    // ── Build RunSummary ──────────────────────────────────────────────────────
    let configured_types: Vec<FileType> =
        serde_json::from_str(&run_row.configured_types_json).unwrap_or_default();
    let case = if run_row.case_id.is_none()
        && run_row.examiner.is_none()
        && run_row.evidence_id.is_none()
        && run_row.case_notes.is_none()
    {
        None
    } else {
        Some(CaseMetadata {
            case_id: run_row.case_id,
            examiner: run_row.examiner,
            evidence_id: run_row.evidence_id,
            notes: run_row.case_notes,
        })
    };
    let run = RunSummary {
        started_at: run_row.started_at,
        output_root: run_row.output_root.clone(),
        source_image_path: run_row.source_image_path,
        configured_types: configured_types.clone(),
        status: match run_row.status.as_str() {
            "Running" => RunStatus::Running,
            "Finished" => RunStatus::Finished,
            "Interrupted" => RunStatus::Interrupted,
            _ => RunStatus::Pending,
        },
        case,
        elapsed_ms: run_row.elapsed_ms as u64,
        total_files: run_row.total_files as u64,
    };

    // ── Sources ───────────────────────────────────────────────────────────────
    let sources: Vec<VmSourceRow> = sources_db
        .into_iter()
        .map(|s| VmSourceRow {
            source_id: s.source_id as u32,
            filename: s.filename,
            output_subdir: s.output_subdir,
            total_bytes: s.total_bytes as u64,
            bytes_read: s.bytes_read as u64,
            files_found: s.files_found as u64,
            status: match s.status.as_str() {
                "Running" => SourceStatus::Running,
                "Finished" => SourceStatus::Finished,
                "Interrupted" => SourceStatus::Interrupted,
                _ => SourceStatus::Pending,
            },
            duration_ms: s.duration_ms.map(|d| d as u64),
        })
        .collect();

    // ── Type / partial counts (no file materialisation) ───────────────────────
    let output_root_pb = PathBuf::from(&run_row.output_root);
    let mut type_counts: BTreeMap<FileType, u64> = BTreeMap::new();
    let mut partial_counts: BTreeMap<FileType, u64> = BTreeMap::new();
    for f in files_db {
        let found = models::file_row_to_found_file(f, &output_root_pb);
        if let Some(ft) = crate::model::parse_file_type(&found.file.file_type) {
            *type_counts.entry(ft).or_insert(0) += 1;
            let is_partial = found
                .file
                .jpeg_scan
                .as_ref()
                .map(|s| s.status != JpegScanStatus::Complete)
                .unwrap_or(false);
            if is_partial {
                *partial_counts.entry(ft).or_insert(0) += 1;
            }
        }
    }

    // ── Bookmarks ─────────────────────────────────────────────────────────────
    let bookmarks: BTreeSet<FileId> = bookmarks_db.into_iter().map(|b| b as u64).collect();

    // ── Notes ─────────────────────────────────────────────────────────────────
    let mut notes: BTreeMap<FileId, Vec<NoteEntry>> = BTreeMap::new();
    let mut next_note_id: u64 = 1;
    for n in notes_db {
        let nid = n.note_id as u64;
        notes.entry(n.file_id as u64).or_default().push(NoteEntry {
            note_id: nid,
            text: n.text,
            at: n.at,
        });
        next_note_id = next_note_id.max(nid + 1);
    }

    // ── Best choices ──────────────────────────────────────────────────────────
    let best_choices: BTreeMap<FileId, FileId> = best_db
        .into_iter()
        .map(|(orig, chosen)| (orig as u64, chosen as u64))
        .collect();

    // ── Variants ──────────────────────────────────────────────────────────────
    let mut variants: BTreeMap<FileId, VariantSet> = BTreeMap::new();
    let mut variant_of: BTreeMap<FileId, FileId> = BTreeMap::new();
    for v in variants_db {
        let entry = variants
            .entry(v.original_file_id as u64)
            .or_insert_with(|| VariantSet {
                original_id: v.original_file_id as u64,
                variant_ids: Vec::new(),
            });
        let cid = v.candidate_file_id as u64;
        if !entry.variant_ids.contains(&cid) {
            entry.variant_ids.push(cid);
        }
        variant_of.insert(cid, v.original_file_id as u64);
    }

    // ── Recovery state ────────────────────────────────────────────────────────
    let recovery_state = match (&recovery_db, !partial_counts.is_empty()) {
        (Some(r), _) if r.finished_duration_ms.is_some() => RecoveryUiState::Finished,
        (Some(_), _) => RecoveryUiState::Running,
        (None, true) => RecoveryUiState::NotRun,
        (None, false) => RecoveryUiState::Disabled,
    };

    Ok(Some(ViewModelSnapshot {
        run,
        sources,
        bookmarks,
        notes,
        best_choices,
        variants,
        variant_of,
        type_counts,
        partial_counts,
        recovery_state,
        next_note_id,
    }))
}

// ── Row readers ───────────────────────────────────────────────────────────────
// Each function maps a turso `Row` to the corresponding `models::*Row` type.
// Column indices must match the SELECT in `do_snapshot_from_db`.

fn read_run_row(row: &turso::Row) -> Result<models::RunRow> {
    Ok(models::RunRow {
        id: models::col_i64(row, 0, "id")? as i32,
        started_at: models::col_text(row, 1, "started_at")?,
        output_root: models::col_text(row, 2, "output_root")?,
        source_image_path: models::col_text(row, 3, "source_image_path")?,
        configured_types_json: models::col_text(row, 4, "configured_types_json")?,
        case_id: models::col_opt_text(row, 5)?,
        examiner: models::col_opt_text(row, 6)?,
        evidence_id: models::col_opt_text(row, 7)?,
        case_notes: models::col_opt_text(row, 8)?,
        status: models::col_text(row, 9, "status")?,
        elapsed_ms: models::col_i64(row, 10, "elapsed_ms")?,
        total_files: models::col_i64(row, 11, "total_files")?,
    })
}

fn read_source_row(row: &turso::Row) -> Result<models::SourceRow> {
    Ok(models::SourceRow {
        source_id: models::col_i64(row, 0, "source_id")? as i32,
        filename: models::col_text(row, 1, "filename")?,
        output_subdir: models::col_text(row, 2, "output_subdir")?,
        total_bytes: models::col_i64(row, 3, "total_bytes")?,
        bytes_read: models::col_i64(row, 4, "bytes_read")?,
        files_found: models::col_i64(row, 5, "files_found")?,
        status: models::col_text(row, 6, "status")?,
        duration_ms: models::col_opt_i64(row, 7)?,
    })
}

fn read_file_row(row: &turso::Row) -> Result<models::FileRow> {
    Ok(models::FileRow {
        file_id: models::col_i64(row, 0, "file_id")?,
        source_id: models::col_i64(row, 1, "source_id")? as i32,
        filename: models::col_text(row, 2, "filename")?,
        filesize: models::col_i64(row, 3, "filesize")?,
        file_type: models::col_text(row, 4, "file_type")?,
        img_offset: models::col_i64(row, 5, "img_offset")?,
        written_path: models::col_text(row, 6, "written_path")?,
        byte_runs_json: models::col_text(row, 7, "byte_runs_json")?,
        jpeg_status: models::col_opt_text(row, 8)?,
        jpeg_width: models::col_opt_i64(row, 9)?.map(|v| v as i32),
        jpeg_height: models::col_opt_i64(row, 10)?.map(|v| v as i32),
        jpeg_fragmentation_point: models::col_opt_i64(row, 11)?,
        jpeg_has_restart_markers: models::col_opt_i64(row, 12)?.map(|v| v as i32),
        preview_status: models::col_text(row, 13, "preview_status")?,
    })
}

fn read_note_row(row: &turso::Row) -> Result<models::NoteRow> {
    Ok(models::NoteRow {
        note_id: models::col_i64(row, 0, "note_id")?,
        file_id: models::col_i64(row, 1, "file_id")?,
        text: models::col_text(row, 2, "text")?,
        at: models::col_text(row, 3, "at")?,
    })
}

fn read_variant_row(row: &turso::Row) -> Result<models::VariantRow> {
    Ok(models::VariantRow {
        original_file_id: models::col_i64(row, 0, "original_file_id")?,
        candidate_file_id: models::col_i64(row, 1, "candidate_file_id")?,
        rank: models::col_i64(row, 2, "rank")? as i32,
        method: models::col_text(row, 3, "method")?,
        entropy_score: models::col_f64(row, 4, "entropy_score")?,
        ff_validity_score: models::col_opt_f64(row, 5)?,
        huffman_mcu_count: models::col_opt_i64(row, 6)?.map(|v| v as i32),
        continuation_img_offset: models::col_i64(row, 7, "continuation_img_offset")?,
    })
}

fn read_recovery_run_row(row: &turso::Row) -> Result<models::RecoveryRunRow> {
    Ok(models::RecoveryRunRow {
        id: models::col_i64(row, 0, "id")? as i32,
        started_at: models::col_text(row, 1, "started_at")?,
        keep_candidates: models::col_i64(row, 2, "keep_candidates")? as i32,
        search_window: models::col_i64(row, 3, "search_window")?,
        block_size: models::col_i64(row, 4, "block_size")? as i32,
        min_entropy_score: models::col_f64(row, 5, "min_entropy_score")?,
        huffman_validation: models::col_i64(row, 6, "huffman_validation")? as i32,
        finished_duration_ms: models::col_opt_i64(row, 7)?,
        partials_processed: models::col_opt_i64(row, 8)?.map(|v| v as i32),
        candidates_written: models::col_opt_i64(row, 9)?.map(|v| v as i32),
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{IndexDb, block_on};
    use crate::model::{RecoveryUiState, RunStatus, SourceStatus};

    fn seed_minimal_case(pool: &TursoPool) {
        block_on(async {
            let conn = pool.get().await.unwrap();
            // run
            conn.execute(
                "INSERT INTO run \
                 (id, started_at, output_root, source_image_path, \
                  configured_types_json, status, elapsed_ms, total_files) \
                 VALUES (1, '2026-05-20T10:00:00Z', '/out', '/img/disk.img', \
                         '[\"Jpeg\",\"Png\"]', 'Finished', 5000, 3)",
                (),
            )
            .await
            .unwrap();
            // source
            conn.execute(
                "INSERT INTO source \
                 (source_id, filename, output_subdir, total_bytes, bytes_read, \
                  files_found, status) \
                 VALUES (1, 'disk.img', 'disk', 1000000, 1000000, 3, 'Finished')",
                (),
            )
            .await
            .unwrap();
            // files (2 jpeg: one complete, one fragmented; 1 png)
            conn.execute(
                "INSERT INTO file \
                 (file_id, source_id, filename, filesize, file_type, img_offset, \
                  written_path, byte_runs_json, jpeg_status, preview_status) \
                 VALUES \
                 (1, 1, '00000001.jpg', 50000, 'jpeg', 0,    'disk/00000001.jpg', '[]', 'complete',    'unknown'), \
                 (2, 1, '00000002.jpg', 30000, 'jpeg', 4096, 'disk/00000002.jpg', '[]', 'fragmented',  'unknown'), \
                 (3, 1, '00000003.png', 20000, 'png',  8192, 'disk/00000003.png', '[]', NULL,          'unknown')",
                (),
            )
            .await
            .unwrap();
            // bookmark file_id 1
            conn.execute(
                "INSERT INTO bookmark (file_id, at) VALUES (1, '2026-05-20T11:00:00Z')",
                (),
            )
            .await
            .unwrap();
            // note on file_id 1
            conn.execute(
                "INSERT INTO note (note_id, file_id, text, at) \
                 VALUES (1, 1, 'interesting', '2026-05-20T11:01:00Z')",
                (),
            )
            .await
            .unwrap();
        });
    }

    #[test]
    fn snapshot_from_db_empty_run_returns_none() {
        let db = IndexDb::open_in_memory().expect("open in-memory db");
        let snap = snapshot_from_db(db.pool()).expect("snapshot");
        assert!(snap.is_none(), "empty run table must return None");
    }

    #[test]
    fn snapshot_from_db_returns_correct_run_summary() {
        let db = IndexDb::open_in_memory().expect("open in-memory db");
        seed_minimal_case(db.pool());
        let snap = snapshot_from_db(db.pool())
            .expect("snapshot")
            .expect("expected Some");

        assert_eq!(snap.run.source_image_path, "/img/disk.img");
        assert_eq!(snap.run.output_root, "/out");
        assert_eq!(snap.run.status, RunStatus::Finished);
        assert_eq!(snap.run.elapsed_ms, 5000);
        assert_eq!(snap.run.total_files, 3);
        assert_eq!(
            snap.run.configured_types,
            vec![FileType::Jpeg, FileType::Png]
        );
    }

    #[test]
    fn snapshot_from_db_sources_and_type_counts() {
        let db = IndexDb::open_in_memory().expect("open in-memory db");
        seed_minimal_case(db.pool());
        let snap = snapshot_from_db(db.pool())
            .expect("snapshot")
            .expect("expected Some");

        assert_eq!(snap.sources.len(), 1);
        assert_eq!(snap.sources[0].source_id, 1);
        assert_eq!(snap.sources[0].status, SourceStatus::Finished);
        assert_eq!(snap.sources[0].files_found, 3);

        // type_counts: 2 jpegs, 1 png.
        assert_eq!(*snap.type_counts.get(&FileType::Jpeg).unwrap_or(&0), 2);
        assert_eq!(*snap.type_counts.get(&FileType::Png).unwrap_or(&0), 1);

        // partial_counts: 1 fragmented jpeg.
        assert_eq!(*snap.partial_counts.get(&FileType::Jpeg).unwrap_or(&0), 1);
        assert_eq!(snap.partial_counts.get(&FileType::Png), None);
    }

    #[test]
    fn snapshot_from_db_bookmarks_and_notes() {
        let db = IndexDb::open_in_memory().expect("open in-memory db");
        seed_minimal_case(db.pool());
        let snap = snapshot_from_db(db.pool())
            .expect("snapshot")
            .expect("expected Some");

        assert!(
            snap.bookmarks.contains(&1),
            "file_id 1 should be bookmarked"
        );
        assert!(
            !snap.bookmarks.contains(&2),
            "file_id 2 should not be bookmarked"
        );

        let notes = snap.notes.get(&1).expect("notes for file_id 1");
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].text, "interesting");
        assert_eq!(snap.next_note_id, 2);
    }

    #[test]
    fn snapshot_from_db_recovery_state_not_run_when_partials_exist() {
        let db = IndexDb::open_in_memory().expect("open in-memory db");
        seed_minimal_case(db.pool());
        let snap = snapshot_from_db(db.pool())
            .expect("snapshot")
            .expect("expected Some");

        // partial_counts is non-empty (fragmented jpeg) but no recovery_run row.
        assert_eq!(snap.recovery_state, RecoveryUiState::NotRun);
    }

    #[test]
    fn snapshot_from_db_variants_and_best_choice() {
        let db = IndexDb::open_in_memory().expect("open in-memory db");
        seed_minimal_case(db.pool());

        // Add a variant candidate for file_id 2 and a best_choice.
        block_on(async {
            let conn = db.pool().get().await.unwrap();
            // Insert candidate file first (foreign key)
            conn.execute(
                "INSERT INTO file \
                 (file_id, source_id, filename, filesize, file_type, img_offset, \
                  written_path, byte_runs_json, preview_status) \
                 VALUES (4, 1, '00000004_candidate.jpg', 29000, 'jpeg', 4096, \
                         'disk/00000004_candidate.jpg', '[]', 'unknown')",
                (),
            )
            .await
            .unwrap();
            conn.execute(
                "INSERT INTO variant \
                 (original_file_id, candidate_file_id, rank, method, \
                  entropy_score, ff_validity_score, huffman_mcu_count, \
                  continuation_img_offset) \
                 VALUES (2, 4, 1, 'entropy', 0.95, 0.88, 120, 4096)",
                (),
            )
            .await
            .unwrap();
            conn.execute(
                "INSERT INTO best_choice (original_file_id, chosen_file_id, at) \
                 VALUES (2, 4, '2026-05-20T12:00:00Z')",
                (),
            )
            .await
            .unwrap();
        });

        let snap = snapshot_from_db(db.pool())
            .expect("snapshot")
            .expect("expected Some");

        let vs = snap.variants.get(&2).expect("variants for original 2");
        assert_eq!(vs.variant_ids, vec![4]);
        assert_eq!(snap.variant_of.get(&4), Some(&2));
        assert_eq!(snap.best_choices.get(&2), Some(&4));
    }
}
