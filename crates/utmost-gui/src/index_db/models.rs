use crate::index_db::schema;
use crate::view_model::FoundFile;
use diesel::prelude::*;
use std::path::Path;
use utmost_lib::types::{FileObject, JpegScanInfo, JpegScanStatus};

#[derive(Debug, Insertable, AsChangeset)]
#[diesel(table_name = schema::meta)]
pub struct NewMeta<'a> {
    pub key: &'a str,
    pub value: &'a str,
}

#[derive(Debug, Queryable)]
pub struct MetaRow {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Insertable, AsChangeset)]
#[diesel(table_name = schema::run)]
pub struct NewRun {
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

#[derive(Debug, Queryable, PartialEq)]
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

#[derive(Debug, Insertable, AsChangeset)]
#[diesel(table_name = schema::source)]
pub struct NewSource {
    pub source_id: i32,
    pub filename: String,
    pub output_subdir: String,
    pub total_bytes: i64,
    pub bytes_read: i64,
    pub files_found: i64,
    pub status: String,
    pub duration_ms: Option<i64>,
}

#[derive(Debug, Queryable, PartialEq)]
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

#[derive(Debug, Insertable)]
#[diesel(table_name = schema::file)]
pub struct NewFile {
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

#[derive(Debug, Queryable, PartialEq)]
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

#[derive(Debug, Insertable)]
#[diesel(table_name = schema::bookmark)]
pub struct NewBookmark {
    pub file_id: i64,
    pub at: String,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct BookmarkRow {
    pub file_id: i64,
    pub at: String,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = schema::note)]
pub struct NewNote {
    pub note_id: i64,
    pub file_id: i64,
    pub text: String,
    pub at: String,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct NoteRow {
    pub note_id: i64,
    pub file_id: i64,
    pub text: String,
    pub at: String,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = schema::best_choice)]
pub struct NewBestChoice {
    pub original_file_id: i64,
    pub chosen_file_id: i64,
    pub at: String,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct BestChoiceRow {
    pub original_file_id: i64,
    pub chosen_file_id: i64,
    pub at: String,
}

#[derive(Debug, Insertable, AsChangeset)]
#[diesel(table_name = schema::recovery_run)]
pub struct NewRecoveryRun {
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

#[derive(Debug, Queryable, PartialEq)]
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

#[derive(Debug, Insertable)]
#[diesel(table_name = schema::variant)]
pub struct NewVariant {
    pub original_file_id: i64,
    pub candidate_file_id: i64,
    pub rank: i32,
    pub method: String,
    pub entropy_score: f64,
    pub ff_validity_score: Option<f64>,
    pub huffman_mcu_count: Option<i32>,
    pub continuation_img_offset: i64,
}

#[derive(Debug, Queryable, PartialEq)]
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

#[derive(diesel::Insertable, diesel::AsChangeset)]
#[diesel(table_name = crate::index_db::schema::preview_blob)]
pub struct NewPreviewBlob {
    pub file_id: i64,
    pub codec: String,
    pub width: i32,
    pub height: i32,
    pub bytes: Vec<u8>,
}

#[derive(diesel::Queryable, diesel::Selectable, Debug, PartialEq, Eq)]
#[diesel(table_name = crate::index_db::schema::preview_blob)]
pub struct PreviewBlobRow {
    pub file_id: i64,
    pub codec: String,
    pub width: i32,
    pub height: i32,
    pub bytes: Vec<u8>,
}

/// Reassemble a [`JpegScanInfo`] from the JPEG-related columns of a [`FileRow`].
/// Returns `None` when the row has no `jpeg_status` (i.e. the file is not a
/// JPEG) or when the stored status string is unrecognised.
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

/// Convert a raw [`FileRow`] into the view-model [`FoundFile`] used by the
/// GUI. `output_root` is joined with the row's stored `written_path` (which
/// is the relative path emitted by the engine in `CarveEvent::FileFound`) to
/// produce an absolute path on disk.
///
/// Shared by [`crate::index_db::hydrate::snapshot_from_db`] and the windowed
/// [`crate::index_db::queries::fetch_window`] path. Keep this the single
/// definition of how a `file` row becomes a `FoundFile`.
pub fn file_row_to_found_file(f: FileRow, output_root: &Path) -> FoundFile {
    let byte_runs = serde_json::from_str(&f.byte_runs_json).unwrap_or_default();
    let jpeg_scan = build_jpeg_scan(&f);
    let file_id = f.file_id as u64;
    let file_object = FileObject {
        file_id,
        filename: f.filename.clone(),
        filesize: f.filesize as u64,
        file_type: f.file_type.clone(),
        byte_runs,
        jpeg_scan,
    };
    let abs_path = output_root.join(&f.written_path);
    FoundFile {
        id: file_id,
        source_id: f.source_id as u32,
        file: file_object,
        written_path: abs_path,
        img_offset: f.img_offset as u64,
    }
}
