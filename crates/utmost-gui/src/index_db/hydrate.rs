//! Build a [`ViewModelSnapshot`] directly from the SQLite index, bypassing
//! event replay. Returns `None` if the `run` table is empty — callers should
//! fall through to event replay in that case.

use anyhow::Result;
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use crate::index_db::{models::*, schema};
use crate::view_model::{
    FoundFile, NoteEntry, RecoveryUiState, RunStatus, RunSummary, SourceRow as VmSourceRow,
    SourceStatus, VariantSet, ViewModelSnapshot,
};
use utmost_lib::events::CaseMetadata;
use utmost_lib::types::{FileObject, FileType};

pub fn snapshot_from_db(conn: &mut SqliteConnection) -> Result<Option<ViewModelSnapshot>> {
    let run_row: Option<RunRow> = schema::run::table.first(conn).optional()?;
    let Some(run_row) = run_row else {
        return Ok(None);
    };

    let sources_db: Vec<SourceRow> = schema::source::table
        .order(schema::source::source_id)
        .load(conn)?;
    let files_db: Vec<FileRow> = schema::file::table
        .order(schema::file::file_id)
        .load(conn)?;
    let bookmarks_db: Vec<BookmarkRow> = schema::bookmark::table.load(conn)?;
    let notes_db: Vec<NoteRow> = schema::note::table
        .order(schema::note::note_id)
        .load(conn)?;
    let best_db: Vec<BestChoiceRow> = schema::best_choice::table.load(conn)?;
    let variants_db: Vec<VariantRow> = schema::variant::table
        .order((schema::variant::original_file_id, schema::variant::rank))
        .load(conn)?;
    let recovery_db: Option<RecoveryRunRow> = schema::recovery_run::table.first(conn).optional()?;

    // ----- Build RunSummary -----
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

    // ----- Sources -----
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

    // ----- Files -----
    let mut files: Vec<FoundFile> = Vec::with_capacity(files_db.len());
    let mut type_counts: BTreeMap<FileType, u64> = BTreeMap::new();
    let mut partial_counts: BTreeMap<FileType, u64> = BTreeMap::new();
    let output_root_pb = PathBuf::from(&run_row.output_root);
    for f in files_db.into_iter() {
        let byte_runs = serde_json::from_str(&f.byte_runs_json).unwrap_or_default();
        let jpeg_scan = build_jpeg_scan(&f);
        let file_id = f.file_id as u64;
        let fo = FileObject {
            file_id,
            filename: f.filename.clone(),
            filesize: f.filesize as u64,
            file_type: f.file_type.clone(),
            byte_runs,
            jpeg_scan,
        };
        let abs_path = output_root_pb.join(&f.written_path);
        if let Some(ft) = crate::view_model::parse_file_type_pub(&fo.file_type) {
            *type_counts.entry(ft).or_insert(0) += 1;
            let is_partial = fo
                .jpeg_scan
                .as_ref()
                .map(|s| s.status != utmost_lib::types::JpegScanStatus::Complete)
                .unwrap_or(false);
            if is_partial {
                *partial_counts.entry(ft).or_insert(0) += 1;
            }
        }
        // Task 8: FoundFile.id is the engine-allocated durable file_id.
        files.push(FoundFile {
            id: file_id,
            source_id: f.source_id as u32,
            file: fo,
            written_path: abs_path,
            img_offset: f.img_offset as u64,
        });
    }

    // ----- Bookmarks (keyed on engine file_id, matching apply() behavior) -----
    let bookmarks: BTreeSet<u64> = bookmarks_db.into_iter().map(|b| b.file_id as u64).collect();

    // ----- Notes -----
    let mut notes: BTreeMap<u64, Vec<NoteEntry>> = BTreeMap::new();
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

    // ----- Best choices -----
    let best_choices: BTreeMap<u64, u64> = best_db
        .into_iter()
        .map(|b| (b.original_file_id as u64, b.chosen_file_id as u64))
        .collect();

    // ----- Variants -----
    let mut variants: BTreeMap<u64, VariantSet> = BTreeMap::new();
    let mut variant_of: BTreeMap<u64, u64> = BTreeMap::new();
    for v in variants_db {
        let entry = variants
            .entry(v.original_file_id as u64)
            .or_insert_with(|| VariantSet {
                original_id: v.original_file_id as u64,
                variant_ids: Vec::new(),
            });
        if !entry.variant_ids.contains(&(v.candidate_file_id as u64)) {
            entry.variant_ids.push(v.candidate_file_id as u64);
        }
        variant_of.insert(v.candidate_file_id as u64, v.original_file_id as u64);
    }

    // ----- Recovery state -----
    let recovery_state = match (&recovery_db, !partial_counts.is_empty()) {
        (Some(r), _) if r.finished_duration_ms.is_some() => RecoveryUiState::Finished,
        (Some(_), _) => RecoveryUiState::Running,
        (None, true) => RecoveryUiState::NotRun,
        (None, false) => RecoveryUiState::Disabled,
    };

    Ok(Some(ViewModelSnapshot {
        run,
        sources,
        files,
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

fn build_jpeg_scan(f: &FileRow) -> Option<utmost_lib::types::JpegScanInfo> {
    let status_str = f.jpeg_status.as_ref()?;
    let status = match status_str.as_str() {
        "complete" => utmost_lib::types::JpegScanStatus::Complete,
        "truncated" => utmost_lib::types::JpegScanStatus::Truncated,
        "fragmented" => utmost_lib::types::JpegScanStatus::Fragmented,
        other => {
            tracing::warn!("unknown jpeg_status value in index: {other:?} — skipping");
            return None;
        }
    };
    Some(utmost_lib::types::JpegScanInfo {
        width: f.jpeg_width.map(|w| w as u16),
        height: f.jpeg_height.map(|h| h as u16),
        fragmentation_point_img_offset: f.jpeg_fragmentation_point.map(|o| o as u64),
        has_restart_markers: f.jpeg_has_restart_markers.unwrap_or(0) != 0,
        status,
    })
}
