//! Plain row structs and turso column mapper helpers for the per-case index DB.
//!
//! All Diesel derives have been stripped.  Field names and types are kept
//! identical to the originals in `crates/utmost-gui/src/index_db/models.rs`
//! so that the query/writer ports (Tasks 4 and 5) can map against them without
//! field-name changes.
//!
//! # `file_row_to_found_file` — deferred to Task 5
//!
//! That function depends on [`utmost_gui::view_model::FoundFile`], which has
//! not yet been moved into `utmost-index`.  [`build_jpeg_scan`] is available
//! now so Task 5 can call it without duplication.

use anyhow::{Context, Result};
use utmost_lib::types::{FileType, JpegScanInfo, JpegScanStatus};

// ── Column mapper helpers ────────────────────────────────────────────────────

/// Read an `i64` from column `idx`, with `ctx` as the error context label.
pub fn col_i64(row: &turso::Row, idx: usize, ctx: &str) -> Result<i64> {
    row.get_value(idx)?
        .as_integer()
        .copied()
        .with_context(|| format!("expected integer for {ctx}"))
}

/// Read an `Option<i64>` from column `idx`; SQL `NULL` becomes `None`.
pub fn col_opt_i64(row: &turso::Row, idx: usize) -> Result<Option<i64>> {
    Ok(row.get_value(idx)?.as_integer().copied())
}

/// Read a `String` from column `idx`, with `ctx` as the error context label.
pub fn col_text(row: &turso::Row, idx: usize, ctx: &str) -> Result<String> {
    Ok(row
        .get_value(idx)?
        .as_text()
        .with_context(|| format!("expected text for {ctx}"))?
        .to_owned())
}

/// Read an `Option<String>` from column `idx`; SQL `NULL` becomes `None`.
pub fn col_opt_text(row: &turso::Row, idx: usize) -> Result<Option<String>> {
    Ok(row.get_value(idx)?.as_text().map(|s| s.to_owned()))
}

/// Read an `f64` from column `idx`, with `ctx` as the error context label.
///
/// Accepts both `REAL` and `INTEGER` column values so that integer-stored
/// floats (e.g. `0` for `0.0`) round-trip correctly.
pub fn col_f64(row: &turso::Row, idx: usize, ctx: &str) -> Result<f64> {
    match row.get_value(idx)? {
        turso::Value::Real(r) => Ok(r),
        turso::Value::Integer(i) => Ok(i as f64),
        _ => anyhow::bail!("expected real for {ctx}"),
    }
}

/// Read a `Vec<u8>` blob from column `idx`, with `ctx` as the error context.
pub fn col_blob(row: &turso::Row, idx: usize, ctx: &str) -> Result<Vec<u8>> {
    Ok(row
        .get_value(idx)?
        .as_blob()
        .with_context(|| format!("expected blob for {ctx}"))?
        .to_vec())
}

// ── Row types ────────────────────────────────────────────────────────────────

/// Row from the `meta` key/value table.
#[derive(Debug, PartialEq, Eq)]
pub struct MetaRow {
    pub key: String,
    pub value: String,
}

/// Row from the `run` table (at most one row per database, `id = 1`).
#[derive(Debug, PartialEq, Eq)]
pub struct RunRow {
    pub id: i32,
    pub started_at: String,
    pub output_root: String,
    pub source_image_path: String,
    pub configured_types_json: String,
    pub case_id: Option<String>,
    pub examiner: Option<String>,
    pub evidence_id: Option<String>,
    pub case_notes: Option<String>,
    pub status: String,
    pub elapsed_ms: i64,
    pub total_files: i64,
}

/// Row from the `source` table (one per source image file in the run).
#[derive(Debug, PartialEq, Eq)]
pub struct SourceRow {
    pub source_id: i32,
    pub filename: String,
    pub output_subdir: String,
    pub total_bytes: i64,
    pub bytes_read: i64,
    pub files_found: i64,
    pub status: String,
    pub duration_ms: Option<i64>,
}

/// Row from the `file` table (one per carved file).
#[derive(Debug, PartialEq, Eq)]
pub struct FileRow {
    pub file_id: i64,
    pub source_id: i32,
    pub filename: String,
    pub filesize: i64,
    pub file_type: String,
    pub img_offset: i64,
    pub written_path: String,
    pub byte_runs_json: String,
    pub jpeg_status: Option<String>,
    pub jpeg_width: Option<i32>,
    pub jpeg_height: Option<i32>,
    pub jpeg_fragmentation_point: Option<i64>,
    pub jpeg_has_restart_markers: Option<i32>,
    pub preview_status: String,
}

/// Row from the `bookmark` table.
#[derive(Debug, PartialEq, Eq)]
pub struct BookmarkRow {
    pub file_id: i64,
    pub at: String,
}

/// Row from the `note` table.
#[derive(Debug, PartialEq, Eq)]
pub struct NoteRow {
    pub note_id: i64,
    pub file_id: i64,
    pub text: String,
    pub at: String,
}

/// Row from the `best_choice` table.
#[derive(Debug, PartialEq, Eq)]
pub struct BestChoiceRow {
    pub original_file_id: i64,
    pub chosen_file_id: i64,
    pub at: String,
}

/// Row from the `recovery_run` table.
#[derive(Debug, PartialEq)]
pub struct RecoveryRunRow {
    pub id: i32,
    pub started_at: String,
    pub keep_candidates: i32,
    pub search_window: i64,
    pub block_size: i32,
    pub min_entropy_score: f64,
    pub huffman_validation: i32,
    pub finished_duration_ms: Option<i64>,
    pub partials_processed: Option<i32>,
    pub candidates_written: Option<i32>,
}

/// Row from the `variant` table (recovery candidate associated with a partial file).
#[derive(Debug, PartialEq)]
pub struct VariantRow {
    pub original_file_id: i64,
    pub candidate_file_id: i64,
    pub rank: i32,
    pub method: String,
    pub entropy_score: f64,
    pub ff_validity_score: Option<f64>,
    pub huffman_mcu_count: Option<i32>,
    pub continuation_img_offset: i64,
}

/// Row from the `preview_blob` table.
#[derive(Debug, PartialEq, Eq)]
pub struct PreviewBlobRow {
    pub file_id: i64,
    pub codec: String,
    pub width: i32,
    pub height: i32,
    pub bytes: Vec<u8>,
}

/// Lightweight projection of the `file` table returned by the windowed-query
/// path.  The `file_type` field holds the parsed enum; rows with an
/// unrecognised type string are silently dropped by the query helper.
#[derive(Debug, Clone)]
pub struct FileStub {
    pub file_id: u64,
    pub filename: String,
    pub filesize: u64,
    pub file_type: FileType,
}

/// Compact row used by the picker to render a case without opening the full
/// ViewModel.  Reads only from the `run` and `meta` tables; no fold, no
/// migration.
#[derive(Debug, Clone)]
pub struct PickerMetadataRow {
    pub source_image_path: String,
    /// `"Running"` | `"Finished"` | `"Interrupted"`
    pub status: String,
    /// RFC 3339 timestamp from the `run` table.
    pub started_at: String,
    pub elapsed_ms: i64,
    pub total_files: i64,
    /// Last byte offset indexed into events.bin; `0` when absent from `meta`.
    pub last_event_offset: i64,
}

// ── JPEG helpers ─────────────────────────────────────────────────────────────

/// Reassemble a [`JpegScanInfo`] from the JPEG-related columns of a
/// [`FileRow`].
///
/// Returns `None` when `jpeg_status` is absent (the file is not a JPEG) or
/// when the stored status string is unrecognised.
pub fn build_jpeg_scan(f: &FileRow) -> Option<JpegScanInfo> {
    let status_str = f.jpeg_status.as_ref()?;
    let status = match status_str.as_str() {
        "complete" => JpegScanStatus::Complete,
        "truncated" => JpegScanStatus::Truncated,
        "fragmented" => JpegScanStatus::Fragmented,
        other => {
            tracing::warn!("unknown jpeg_status value in index: {other:?} — skipping");
            return None;
        }
    };
    Some(JpegScanInfo {
        width: f.jpeg_width.map(|w| w as u16),
        height: f.jpeg_height.map(|h| h as u16),
        fragmentation_point_img_offset: f.jpeg_fragmentation_point.map(|o| o as u64),
        has_restart_markers: f.jpeg_has_restart_markers.unwrap_or(0) != 0,
        status,
    })
}

// `file_row_to_found_file` is deferred to Task 5.
//
// It depends on `FoundFile` (currently in `utmost-gui::view_model`) and
// `serde_json` for `byte_runs_json` deserialization.  `build_jpeg_scan` is
// available above so Task 5 can call it without duplication.

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::db::{block_on, models, IndexDb};

    #[test]
    fn col_helpers_read_typed_values() {
        let db = IndexDb::open_in_memory().unwrap();
        let pool = db.pool().clone();
        block_on(async {
            let conn = pool.get().await.unwrap();
            conn.execute("INSERT INTO meta (key, value) VALUES ('k', 'v')", ())
                .await
                .unwrap();
            let mut rows = conn
                .query("SELECT key, value FROM meta WHERE key='k'", ())
                .await
                .unwrap();
            let row = rows.next().await.unwrap().unwrap();
            assert_eq!(models::col_text(&row, 0, "key").unwrap(), "k");
            assert_eq!(models::col_text(&row, 1, "value").unwrap(), "v");
        });
    }
}
