use crate::index_db::schema;
use diesel::prelude::*;

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
    pub jpeg_complete_offset: Option<i64>,
    pub jpeg_first_ff_offset: Option<i64>,
    pub jpeg_dqt_count: Option<i32>,
    pub jpeg_sos_count: Option<i32>,
    pub jpeg_dht_count: Option<i32>,
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
    pub jpeg_complete_offset: Option<i64>,
    pub jpeg_first_ff_offset: Option<i64>,
    pub jpeg_dqt_count: Option<i32>,
    pub jpeg_sos_count: Option<i32>,
    pub jpeg_dht_count: Option<i32>,
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
