//! Composable SQL queries over the per-case index database.
//!
//! All public functions are **synchronous** wrappers; the async implementation
//! lives in private `do_*` helpers bridged via [`super::block_on`].
//!
//! ## `query_match_ids` — dynamic SQL builder
//!
//! Turns a [`FilterState`] into a single `SELECT` against the `file` table,
//! returning [`FileStub`]s in the requested order.  The WHERE/ORDER clauses are
//! built dynamically at runtime; bound parameters are accumulated in a
//! `Vec<turso::Value>` and passed via [`turso::params_from_iter`].
//!
//! ## Variant-vs-original distinction
//!
//! Variants (recovery candidates) never appear in the main grid — the UI
//! surfaces them under their parent's "variants" panel via `variant_of` /
//! `variants`.  The windowed UI filters out anything in `variant_of` on the
//! Rust side when assembling the visible window, so `query_match_ids` does not
//! need to replicate that exclusion in SQL.
//!
//! ## Partial-vs-complete JPEG distinction
//!
//! `enabled_types` is the "Jpeg" chip and `enabled_partial_types` is the
//! "Partial Jpeg" chip — independent toggles.  "Jpeg only" returns complete
//! jpegs (`jpeg_status = 'complete'` OR NULL for legacy rows); "Partial Jpeg
//! only" returns truncated/fragmented jpegs; both-on returns every jpeg.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use turso::Value;

use crate::db::{block_on, TursoPool};
use crate::db::models::{self, FileStub, PickerMetadataRow, PreviewBlobRow};
use crate::model::{FilterState, FoundFile, SortDir, SortKey};
use utmost_lib::types::FileType;

// ── Previewable-types helper ──────────────────────────────────────────────────

/// Build the SQL `IN`-clause content for image-previewable file types, derived
/// from [`crate::preview::PREVIEWABLE_FILE_TYPES`] via `file_type_to_db_string`.
///
/// This is the single source of truth: adding a new image type to
/// `PREVIEWABLE_FILE_TYPES` automatically propagates to every
/// `file_type IN (…)` predicate in this module without a separate edit here.
/// The output for the current set is `'jpeg','gif','bmp','png','vjpeg'`.
fn previewable_types_in_clause() -> String {
    crate::preview::PREVIEWABLE_FILE_TYPES
        .iter()
        .map(|ft| format!("'{}'", file_type_to_db_string(*ft)))
        .collect::<Vec<_>>()
        .join(",")
}

// ── Internal param helper ─────────────────────────────────────────────────────

/// Tagged union of the bound-parameter types produced by the SQL builder.
/// Converted to [`turso::Value`] just before the query is executed.
enum Param {
    Int(i32),
    Big(i64),
    Str(String),
}

impl From<Param> for Value {
    fn from(p: Param) -> Self {
        match p {
            Param::Int(v) => Value::Integer(v as i64),
            Param::Big(v) => Value::Integer(v),
            Param::Str(v) => Value::Text(v),
        }
    }
}

// ── Public query surface ──────────────────────────────────────────────────────

/// Build and run the visible-ids query.
///
/// The result is the windowed UI's "match list": rows of the `file` table that
/// satisfy every active filter in `filter`, ordered by
/// `(bookmarked_first?, sort_key sort_dir, file_id ASC)`.
///
/// Rows with an unrecognised `file_type` string are silently dropped.
pub fn query_match_ids(pool: &TursoPool, filter: &FilterState) -> Result<Vec<FileStub>> {
    let pool = pool.clone();
    let filter = filter.clone();
    block_on(do_query_match_ids(pool, filter))
}

/// Fetch the `file` rows for `ids`, preserving the order of the input slice.
///
/// SQLite's `IN (…)` clause returns rows in natural row order, not the order
/// of the placeholders.  We reshuffle on the Rust side via a lookup map so the
/// windowed UI gets rows in the *requested* order (which already incorporates
/// the active sort from a prior [`query_match_ids`] call).
///
/// IDs that don't exist in the DB are silently skipped.  The `written_path` of
/// each returned [`FoundFile`] is absolute, resolved against `run.output_root`.
pub fn fetch_window(pool: &TursoPool, ids: &[u64]) -> Result<Vec<FoundFile>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let pool = pool.clone();
    let ids = ids.to_vec();
    block_on(do_fetch_window(pool, ids))
}

/// Read `run.output_root` for the active run.
///
/// Falls back to an empty [`PathBuf`] when the `run` table is empty (no run
/// in progress yet); in that case `FoundFile.written_path` is the relative
/// path as stored on disk, which is still safe to display.
pub fn read_output_root(pool: &TursoPool) -> Result<PathBuf> {
    let pool = pool.clone();
    block_on(do_read_output_root(pool))
}

/// Update `file.preview_status` for a single row and atomically bump the
/// `preview_status_version` meta key inside a transaction.
///
/// Same semantics as the batched
/// [`crate::db::writer::write_preview_outcomes`], scoped to one row — useful
/// for one-shot test fixtures and ad-hoc scripts.
pub fn set_preview_status(pool: &TursoPool, file_id: u64, status: &str) -> Result<()> {
    let pool = pool.clone();
    let status = status.to_owned();
    block_on(do_set_preview_status(pool, file_id, status))
}

/// Read the minimal metadata the picker needs to render a case row.
///
/// Reads only `run` (id = 1) and `meta.last_event_offset`; no fold, no
/// migration.  Returns an error when the `run` table is empty (caller should
/// fall back to reading the events.bin header).
pub fn picker_metadata_row(pool: &TursoPool) -> Result<PickerMetadataRow> {
    let pool = pool.clone();
    block_on(do_picker_metadata_row(pool))
}

/// Count `file` rows that are image types and have not yet been previewed.
///
/// "Image type" is the set defined by [`crate::preview::PREVIEWABLE_FILE_TYPES`];
/// "not yet previewed" means `preview_status = 'unknown'`.  Used by the preview
/// worker to decide whether to spin up a new batch.
pub fn count_files_without_preview(pool: &TursoPool) -> Result<usize> {
    let pool = pool.clone();
    block_on(do_count_files_without_preview(pool))
}

/// Return up to `limit` unpreviewd image files, ordered by `file_id ASC`.
///
/// Complements [`count_files_without_preview`]: the count lets the caller
/// decide *whether* to fetch; this function fetches the next batch.
pub fn get_files_without_preview(pool: &TursoPool, limit: usize) -> Result<Vec<FoundFile>> {
    let pool = pool.clone();
    block_on(do_get_files_without_preview(pool, limit))
}

/// Count files that have a `preview_blob` but no `clip_embedding` for `model`.
///
/// A file qualifies for embedding when it has an image preview (joined via
/// `preview_blob`) but the `clip_embedding` table has no row for it under the
/// given model name.
pub fn count_files_without_embedding(pool: &TursoPool, model: &str) -> Result<usize> {
    let pool = pool.clone();
    let model = model.to_owned();
    block_on(do_count_files_without_embedding(pool, model))
}

/// Return up to `limit` (file_id, preview-blob) pairs lacking a CLIP embedding
/// for `model`, ordered by `file_id ASC`.
///
/// The caller serialises `PreviewBlobRow.bytes` (little-endian f32 array) and
/// passes the result to `set_clip_embedding`.
pub fn get_files_without_embedding(
    pool: &TursoPool,
    model: &str,
    limit: usize,
) -> Result<Vec<(u64, PreviewBlobRow)>> {
    let pool = pool.clone();
    let model = model.to_owned();
    block_on(do_get_files_without_embedding(pool, model, limit))
}

// ── Async implementations ─────────────────────────────────────────────────────

async fn do_query_match_ids(pool: TursoPool, filter: FilterState) -> Result<Vec<FileStub>> {
    let conn = pool.get().await.context("get conn for query_match_ids")?;

    let mut sql = String::new();
    let mut params: Vec<Param> = Vec::new();

    // SELECT + optional LEFT JOIN for the bookmarked_first sort.
    sql.push_str(
        "SELECT f.file_id AS file_id, f.filename AS filename, \
         f.filesize AS filesize, f.file_type AS file_type FROM file f",
    );
    if filter.bookmarked_first {
        sql.push_str(" LEFT JOIN bookmark b ON b.file_id = f.file_id");
    }

    let mut wheres: Vec<String> = Vec::new();

    if let Some(sid) = filter.source_filter {
        wheres.push("f.source_id = ?".into());
        params.push(Param::Int(sid as i32));
    }

    if filter.bookmarked_only {
        wheres.push("f.file_id IN (SELECT file_id FROM bookmark)".into());
    }

    if let Some((lo, hi)) = filter.size_range {
        wheres.push("f.filesize BETWEEN ? AND ?".into());
        params.push(Param::Big(lo as i64));
        params.push(Param::Big(hi as i64));
    }

    if filter.hide_no_preview {
        wheres.push("f.preview_status != 'no_preview'".into());
    }

    // Type chips ("Jpeg") and partial chips ("Partial Jpeg") are independent
    // toggles.  One disjunct per type covers whichever of (full, partial) is
    // currently enabled.  For jpegs with NULL `jpeg_status` (legacy/test rows),
    // treat the row as complete so the "Jpeg" chip continues to surface them.
    let mut type_union: std::collections::BTreeSet<&FileType> = Default::default();
    type_union.extend(filter.enabled_types.iter());
    type_union.extend(filter.enabled_partial_types.iter());
    if !type_union.is_empty() {
        let mut clauses: Vec<String> = Vec::new();
        for ft in &type_union {
            let in_full = filter.enabled_types.contains(*ft);
            let in_partial = filter.enabled_partial_types.contains(*ft);
            let db_str = file_type_to_db_string(**ft).to_string();
            if **ft == FileType::Jpeg && in_full && !in_partial {
                clauses.push(
                    "(f.file_type = ? AND (f.jpeg_status IS NULL OR f.jpeg_status = 'complete'))"
                        .into(),
                );
                params.push(Param::Str(db_str));
            } else if **ft == FileType::Jpeg && !in_full && in_partial {
                clauses.push(
                    "(f.file_type = ? AND f.jpeg_status IN ('truncated', 'fragmented'))".into(),
                );
                params.push(Param::Str(db_str));
            } else {
                // Non-JPEG type, OR both chips on for JPEG → no status filter.
                clauses.push("f.file_type = ?".into());
                params.push(Param::Str(db_str));
            }
        }
        wheres.push(format!("({})", clauses.join(" OR ")));
    }

    if !wheres.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&wheres.join(" AND "));
    }

    // ORDER BY: bookmarked-first (DESC because NULL < non-NULL in SQLite means
    // bookmarked rows — where b.file_id IS NOT NULL — need DESC to float up),
    // then the user-selected sort, then file_id ASC as a tiebreaker.
    sql.push_str(" ORDER BY ");
    if filter.bookmarked_first {
        sql.push_str("(b.file_id IS NOT NULL) DESC, ");
    }
    let sort_col = match filter.sort_key {
        SortKey::Filename => "f.filename",
        SortKey::Size => "f.filesize",
        SortKey::FileType => "f.file_type",
        SortKey::SourceOffset => "f.img_offset",
    };
    let sort_dir = match filter.sort_dir {
        SortDir::Asc => "ASC",
        SortDir::Desc => "DESC",
    };
    sql.push_str(sort_col);
    sql.push(' ');
    sql.push_str(sort_dir);
    sql.push_str(", f.file_id ASC");

    let values: Vec<Value> = params.into_iter().map(Value::from).collect();
    let mut rows = conn
        .query(&sql, turso::params_from_iter(values))
        .await
        .context("query_match_ids: execute")?;

    let mut result = Vec::new();
    while let Some(row) = rows.next().await? {
        let file_id = models::col_i64(&row, 0, "file_id")? as u64;
        let filename = models::col_text(&row, 1, "filename")?;
        let filesize = models::col_i64(&row, 2, "filesize")? as u64;
        let file_type_str = models::col_text(&row, 3, "file_type")?;
        match crate::model::parse_file_type(&file_type_str) {
            Some(ft) => result.push(FileStub {
                file_id,
                filename,
                filesize,
                file_type: ft,
            }),
            None => {
                tracing::warn!(
                    file_id = %file_id,
                    file_type = %file_type_str,
                    "query_match_ids: skipping row with unknown file_type"
                );
            }
        }
    }
    Ok(result)
}

async fn do_fetch_window(pool: TursoPool, ids: Vec<u64>) -> Result<Vec<FoundFile>> {
    let conn = pool.get().await.context("get conn for fetch_window")?;

    // Read output_root first; rows are dropped before the next query.
    let output_root = {
        let mut rows = conn
            .query("SELECT output_root FROM run LIMIT 1", ())
            .await
            .context("fetch_window: read output_root")?;
        match rows.next().await? {
            Some(row) => PathBuf::from(models::col_text(&row, 0, "output_root")?),
            None => PathBuf::new(),
        }
    };

    // Build `IN (?, ?, …)` with one placeholder per id.
    let placeholders: Vec<&str> = ids.iter().map(|_| "?").collect();
    let sql = format!(
        "SELECT file_id, source_id, filename, filesize, file_type, img_offset, \
         written_path, byte_runs_json, jpeg_status, jpeg_width, jpeg_height, \
         jpeg_fragmentation_point, jpeg_has_restart_markers, preview_status \
         FROM file WHERE file_id IN ({})",
        placeholders.join(", ")
    );
    let params: Vec<Value> = ids.iter().map(|id| Value::Integer(*id as i64)).collect();

    let mut rows = conn
        .query(&sql, turso::params_from_iter(params))
        .await
        .context("fetch_window: execute")?;

    let mut by_id: HashMap<u64, models::FileRow> = HashMap::new();
    while let Some(row) = rows.next().await? {
        let f = row_to_file_row(&row)?;
        by_id.insert(f.file_id as u64, f);
    }

    // Reorder to match the input `ids` slice (SQL IN-clause is unordered).
    let out: Vec<FoundFile> = ids
        .iter()
        .filter_map(|id| {
            by_id
                .remove(id)
                .map(|r| models::file_row_to_found_file(r, &output_root))
        })
        .collect();
    Ok(out)
}

async fn do_read_output_root(pool: TursoPool) -> Result<PathBuf> {
    let conn = pool.get().await.context("get conn for read_output_root")?;
    let mut rows = conn
        .query("SELECT output_root FROM run LIMIT 1", ())
        .await
        .context("read_output_root: execute")?;
    match rows.next().await? {
        Some(row) => Ok(PathBuf::from(models::col_text(&row, 0, "output_root")?)),
        None => Ok(PathBuf::new()),
    }
}

async fn do_set_preview_status(pool: TursoPool, file_id: u64, status: String) -> Result<()> {
    let mut conn = pool
        .get()
        .await
        .context("get conn for set_preview_status")?;
    let tx = conn
        .transaction()
        .await
        .context("begin set_preview_status tx")?;
    tx.execute(
        "UPDATE file SET preview_status = ?1 WHERE file_id = ?2",
        (Value::Text(status), Value::Integer(file_id as i64)),
    )
    .await
    .context("set_preview_status: update file")?;
    // Atomically increment without a separate SELECT (same pattern as writer.rs).
    tx.execute(
        "UPDATE meta \
         SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) \
         WHERE key = 'preview_status_version'",
        (),
    )
    .await
    .context("set_preview_status: bump preview_status_version")?;
    tx.commit()
        .await
        .context("commit set_preview_status tx")?;
    Ok(())
}

async fn do_picker_metadata_row(pool: TursoPool) -> Result<PickerMetadataRow> {
    let conn = pool
        .get()
        .await
        .context("get conn for picker_metadata_row")?;

    let (source_image_path, status, started_at, elapsed_ms, total_files) = {
        let mut rows = conn
            .query(
                "SELECT source_image_path, status, started_at, elapsed_ms, total_files \
                 FROM run WHERE id = 1",
                (),
            )
            .await
            .context("picker_metadata_row: run query")?;
        let row = rows
            .next()
            .await?
            .context("picker_metadata_row: run table is empty")?;
        (
            models::col_text(&row, 0, "source_image_path")?,
            models::col_text(&row, 1, "status")?,
            models::col_text(&row, 2, "started_at")?,
            models::col_i64(&row, 3, "elapsed_ms")?,
            models::col_i64(&row, 4, "total_files")?,
        )
        // row and rows dropped here; conn borrow released
    };

    let last_event_offset = {
        let mut rows = conn
            .query(
                "SELECT value FROM meta WHERE key = 'last_event_offset'",
                (),
            )
            .await
            .context("picker_metadata_row: meta query")?;
        match rows.next().await? {
            Some(r) => {
                let s = models::col_text(&r, 0, "last_event_offset")?;
                s.parse::<i64>().unwrap_or(0)
            }
            None => 0,
        }
    };

    Ok(PickerMetadataRow {
        source_image_path,
        status,
        started_at,
        elapsed_ms,
        total_files,
        last_event_offset,
    })
}

async fn do_count_files_without_preview(pool: TursoPool) -> Result<usize> {
    let conn = pool
        .get()
        .await
        .context("get conn for count_files_without_preview")?;
    let sql = format!(
        "SELECT COUNT(*) FROM file \
         WHERE file_type IN ({}) AND preview_status = 'unknown'",
        previewable_types_in_clause()
    );
    let mut rows = conn
        .query(&sql, ())
        .await
        .context("count_files_without_preview: execute")?;
    match rows.next().await? {
        Some(row) => Ok(models::col_i64(&row, 0, "count")? as usize),
        None => Ok(0),
    }
}

async fn do_get_files_without_preview(pool: TursoPool, limit: usize) -> Result<Vec<FoundFile>> {
    let conn = pool
        .get()
        .await
        .context("get conn for get_files_without_preview")?;

    // Read output_root first; rows are dropped before the next query.
    let output_root = {
        let mut rows = conn
            .query("SELECT output_root FROM run LIMIT 1", ())
            .await
            .context("get_files_without_preview: read output_root")?;
        match rows.next().await? {
            Some(row) => PathBuf::from(models::col_text(&row, 0, "output_root")?),
            None => PathBuf::new(),
        }
    };

    let sql = format!(
        "SELECT file_id, source_id, filename, filesize, file_type, img_offset, \
         written_path, byte_runs_json, jpeg_status, jpeg_width, jpeg_height, \
         jpeg_fragmentation_point, jpeg_has_restart_markers, preview_status \
         FROM file WHERE file_type IN ({}) AND preview_status = 'unknown' \
         ORDER BY file_id ASC LIMIT ?1",
        previewable_types_in_clause()
    );
    let mut rows = conn
        .query(&sql, (Value::Integer(limit as i64),))
        .await
        .context("get_files_without_preview: execute")?;

    let mut result = Vec::new();
    while let Some(row) = rows.next().await? {
        let file_row = row_to_file_row(&row)?;
        result.push(models::file_row_to_found_file(file_row, &output_root));
    }
    Ok(result)
}

async fn do_count_files_without_embedding(pool: TursoPool, model: String) -> Result<usize> {
    let conn = pool
        .get()
        .await
        .context("get conn for count_files_without_embedding")?;
    let mut rows = conn
        .query(
            "SELECT COUNT(*) FROM file f \
             JOIN preview_blob pb ON pb.file_id = f.file_id \
             LEFT JOIN clip_embedding c ON c.file_id = f.file_id AND c.model = ?1 \
             WHERE c.file_id IS NULL",
            (Value::Text(model),),
        )
        .await
        .context("count_files_without_embedding: execute")?;
    match rows.next().await? {
        Some(row) => Ok(models::col_i64(&row, 0, "count")? as usize),
        None => Ok(0),
    }
}

async fn do_get_files_without_embedding(
    pool: TursoPool,
    model: String,
    limit: usize,
) -> Result<Vec<(u64, PreviewBlobRow)>> {
    let conn = pool
        .get()
        .await
        .context("get conn for get_files_without_embedding")?;
    let mut rows = conn
        .query(
            "SELECT pb.file_id, pb.codec, pb.width, pb.height, pb.bytes \
             FROM file f \
             JOIN preview_blob pb ON pb.file_id = f.file_id \
             LEFT JOIN clip_embedding c ON c.file_id = f.file_id AND c.model = ?1 \
             WHERE c.file_id IS NULL \
             ORDER BY f.file_id ASC LIMIT ?2",
            turso::params_from_iter(vec![
                Value::Text(model),
                Value::Integer(limit as i64),
            ]),
        )
        .await
        .context("get_files_without_embedding: execute")?;

    let mut result = Vec::new();
    while let Some(row) = rows.next().await? {
        let raw_id = models::col_i64(&row, 0, "file_id")?;
        let blob_row = PreviewBlobRow {
            file_id: raw_id,
            codec: models::col_text(&row, 1, "codec")?,
            width: models::col_i64(&row, 2, "width")? as i32,
            height: models::col_i64(&row, 3, "height")? as i32,
            bytes: models::col_blob(&row, 4, "bytes")?,
        };
        result.push((raw_id as u64, blob_row));
    }
    Ok(result)
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Map a [`FileType`] back to the canonical lowercase string stored in
/// `file.file_type`.  New variants must also add an arm here; the round-trip
/// property is guarded by the `file_type_string_round_trip` test.
fn file_type_to_db_string(ft: FileType) -> &'static str {
    match ft {
        FileType::Jpeg => "jpeg",
        FileType::Gif => "gif",
        FileType::Bmp => "bmp",
        FileType::Mpg => "mpg",
        FileType::Pdf => "pdf",
        FileType::Doc => "doc",
        FileType::Avi => "avi",
        FileType::Wmv => "wmv",
        FileType::Htm => "htm",
        FileType::Zip => "zip",
        FileType::Mov => "mov",
        FileType::Xls => "xls",
        FileType::Ppt => "ppt",
        FileType::Wpd => "wpd",
        FileType::Cpp => "cpp",
        FileType::Ole => "ole",
        FileType::Gzip => "gzip",
        FileType::Riff => "riff",
        FileType::Wav => "wav",
        FileType::VJpeg => "vjpeg",
        FileType::Sxw => "sxw",
        FileType::Sxc => "sxc",
        FileType::Sxi => "sxi",
        FileType::Png => "png",
        FileType::Rar => "rar",
        FileType::Exe => "exe",
        FileType::Elf => "elf",
        FileType::Reg => "reg",
        FileType::Docx => "docx",
        FileType::Xlsx => "xlsx",
        FileType::Pptx => "pptx",
        FileType::Mp4 => "mp4",
        FileType::Config => "config",
    }
}

/// Map a single turso `Row` to a [`models::FileRow`].
///
/// Column order must match the SELECT in [`do_fetch_window`] and
/// [`crate::db::hydrate::snapshot_from_db`].
fn row_to_file_row(row: &turso::Row) -> Result<models::FileRow> {
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{block_on, IndexDb};

    // ── Type cycle used by bulk-seed helpers ──────────────────────────────────

    /// Five types that cycle across bulk-seeded files. Strings must match
    /// `file_type_to_db_string` for the corresponding `FileType` variant.
    const TYPE_CYCLE: &[(&str, FileType)] = &[
        ("jpeg", FileType::Jpeg),
        ("png", FileType::Png),
        ("pdf", FileType::Pdf),
        ("gif", FileType::Gif),
        ("bmp", FileType::Bmp),
    ];

    // ── Seed helpers ─────────────────────────────────────────────────────────

    fn seed_sources(pool: &TursoPool, n: i32) {
        block_on(async {
            let conn = pool.get().await.unwrap();
            for s in 1..=n {
                conn.execute(
                    "INSERT INTO source \
                     (source_id, filename, output_subdir, total_bytes, bytes_read, \
                      files_found, status) \
                     VALUES (?1, ?2, ?3, 0, 0, 0, 'Finished')",
                    turso::params_from_iter(vec![
                        Value::Integer(s as i64),
                        Value::Text(format!("img{s}.bin")),
                        Value::Text(format!("img{s}")),
                    ]),
                )
                .await
                .unwrap();
            }
        });
    }

    /// Insert `count` files spread across `num_sources` sources, cycling
    /// through `TYPE_CYCLE` and assigning monotonically increasing filesizes.
    fn seed_files(pool: &TursoPool, count: i64, num_sources: i32) {
        block_on(async {
            let mut conn = pool.get().await.unwrap();
            let tx = conn.transaction().await.unwrap();
            for i in 0..count {
                let (suffix, _ft) = TYPE_CYCLE[(i as usize) % TYPE_CYCLE.len()];
                let source_id = (i as i32 % num_sources) + 1;
                tx.execute(
                    "INSERT INTO file \
                     (file_id, source_id, filename, filesize, file_type, img_offset, \
                      written_path, byte_runs_json, preview_status) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, '[]', 'unknown')",
                    turso::params_from_iter(vec![
                        Value::Integer(i + 1),
                        Value::Integer(source_id as i64),
                        Value::Text(format!("{:08}.{}", i + 1, suffix)),
                        Value::Integer(1_000 + i * 17),
                        Value::Text(suffix.to_owned()),
                        Value::Integer(i * 4096),
                        Value::Text(format!("img{source_id}/{:08}.{}", i + 1, suffix)),
                    ]),
                )
                .await
                .unwrap();
            }
            tx.commit().await.unwrap();
        });
    }

    fn open_db_with_fixture(n_files: i64, n_sources: i32) -> IndexDb {
        let db = IndexDb::open_in_memory().expect("open in-memory db");
        seed_sources(db.pool(), n_sources);
        seed_files(db.pool(), n_files, n_sources);
        db
    }

    /// Insert exactly one file row with explicit id/filename/size.
    /// Source 1 must already exist (call [`seed_sources`] first).
    fn seed_file(pool: &TursoPool, file_id: i64, filename: &str, filesize: i64) {
        block_on(async {
            let conn = pool.get().await.unwrap();
            conn.execute(
                "INSERT INTO file \
                 (file_id, source_id, filename, filesize, file_type, img_offset, \
                  written_path, byte_runs_json, preview_status) \
                 VALUES (?1, 1, ?2, ?3, 'jpeg', 0, ?4, '[]', 'unknown')",
                turso::params_from_iter(vec![
                    Value::Integer(file_id),
                    Value::Text(filename.to_owned()),
                    Value::Integer(filesize),
                    Value::Text(format!("img1/{filename}")),
                ]),
            )
            .await
            .unwrap();
        });
    }

    fn add_bookmark(pool: &TursoPool, file_id: i64) {
        block_on(async {
            let conn = pool.get().await.unwrap();
            conn.execute(
                "INSERT INTO bookmark (file_id, at) VALUES (?1, '2026-05-19T00:00:00Z')",
                (Value::Integer(file_id),),
            )
            .await
            .unwrap();
        });
    }

    /// Seed a DB with three jpegs (complete, truncated, fragmented) and one png.
    /// Used to exercise the partial-chip WHERE clause.
    fn seed_jpeg_status_mix(pool: &TursoPool) {
        seed_sources(pool, 1);
        let rows: &[(&str, &str, Option<&str>)] = &[
            ("jpeg-complete.jpg", "jpeg", Some("complete")),
            ("jpeg-trunc.jpg", "jpeg", Some("truncated")),
            ("jpeg-frag.jpg", "jpeg", Some("fragmented")),
            ("only.png", "png", None),
        ];
        block_on(async {
            let mut conn = pool.get().await.unwrap();
            let tx = conn.transaction().await.unwrap();
            for (i, &(name, ftype, status)) in rows.iter().enumerate() {
                let jpeg_status_val = match status {
                    Some(s) => Value::Text(s.to_owned()),
                    None => Value::Null,
                };
                tx.execute(
                    "INSERT INTO file \
                     (file_id, source_id, filename, filesize, file_type, img_offset, \
                      written_path, byte_runs_json, jpeg_status, preview_status) \
                     VALUES (?1, 1, ?2, ?3, ?4, 0, ?5, '[]', ?6, 'unknown')",
                    turso::params_from_iter(vec![
                        Value::Integer(i as i64 + 1),
                        Value::Text(name.to_owned()),
                        Value::Integer(1_000 + i as i64),
                        Value::Text(ftype.to_owned()),
                        Value::Text(format!("img1/{name}")),
                        jpeg_status_val,
                    ]),
                )
                .await
                .unwrap();
            }
            tx.commit().await.unwrap();
        });
    }

    // ── query_match_ids tests ─────────────────────────────────────────────────

    #[test]
    fn match_ids_no_filter_returns_all_in_filename_asc() {
        let db = open_db_with_fixture(1500, 3);
        let filter = FilterState::default();
        let rows = query_match_ids(db.pool(), &filter).expect("query");
        assert_eq!(rows.len(), 1500, "all rows should be returned");
        // Filenames are zero-padded `00000001.jpeg` etc, so filename order is
        // also file_id order — easy to verify monotonicity.
        for w in rows.windows(2) {
            assert!(
                w[0].filename <= w[1].filename,
                "expected filename ASC order, found {} > {}",
                w[0].filename,
                w[1].filename
            );
        }
    }

    #[test]
    fn match_ids_type_filter() {
        let db = open_db_with_fixture(1500, 2);
        let mut filter = FilterState::default();
        filter.enabled_types.insert(FileType::Jpeg);
        filter.enabled_types.insert(FileType::Png);
        let rows = query_match_ids(db.pool(), &filter).expect("query");
        assert!(!rows.is_empty(), "expected at least some matches");
        for r in &rows {
            assert!(
                matches!(r.file_type, FileType::Jpeg | FileType::Png),
                "got unexpected file_type {:?}",
                r.file_type
            );
        }
        // 5-type cycle ⇒ jpeg + png ≈ 2/5 of 1500.
        assert_eq!(rows.len(), 600);
    }

    #[test]
    fn match_ids_partial_chip_only_returns_partial_jpegs() {
        let db = IndexDb::open_in_memory().expect("open db");
        seed_jpeg_status_mix(db.pool());
        let mut filter = FilterState::default();
        filter.enabled_partial_types.insert(FileType::Jpeg);
        let rows = query_match_ids(db.pool(), &filter).expect("query");
        let names: Vec<&str> = rows.iter().map(|r| r.filename.as_str()).collect();
        assert_eq!(
            names,
            vec!["jpeg-frag.jpg", "jpeg-trunc.jpg"],
            "Partial Jpeg chip should match only truncated/fragmented jpegs"
        );
    }

    #[test]
    fn match_ids_jpeg_chip_only_returns_complete_jpegs() {
        let db = IndexDb::open_in_memory().expect("open db");
        seed_jpeg_status_mix(db.pool());
        let mut filter = FilterState::default();
        filter.enabled_types.insert(FileType::Jpeg);
        let rows = query_match_ids(db.pool(), &filter).expect("query");
        let names: Vec<&str> = rows.iter().map(|r| r.filename.as_str()).collect();
        assert_eq!(
            names,
            vec!["jpeg-complete.jpg"],
            "Jpeg chip alone should match only complete jpegs (NULL jpeg_status treated as complete)"
        );
    }

    #[test]
    fn match_ids_both_jpeg_chips_returns_every_jpeg() {
        let db = IndexDb::open_in_memory().expect("open db");
        seed_jpeg_status_mix(db.pool());
        let mut filter = FilterState::default();
        filter.enabled_types.insert(FileType::Jpeg);
        filter.enabled_partial_types.insert(FileType::Jpeg);
        let rows = query_match_ids(db.pool(), &filter).expect("query");
        let names: Vec<&str> = rows.iter().map(|r| r.filename.as_str()).collect();
        assert_eq!(
            names,
            vec!["jpeg-complete.jpg", "jpeg-frag.jpg", "jpeg-trunc.jpg"],
            "Both jpeg chips on should match every jpeg regardless of status"
        );
    }

    #[test]
    fn match_ids_non_jpeg_chip_ignores_status() {
        let db = IndexDb::open_in_memory().expect("open db");
        seed_jpeg_status_mix(db.pool());
        let mut filter = FilterState::default();
        filter.enabled_types.insert(FileType::Png);
        let rows = query_match_ids(db.pool(), &filter).expect("query");
        let names: Vec<&str> = rows.iter().map(|r| r.filename.as_str()).collect();
        assert_eq!(
            names,
            vec!["only.png"],
            "Png chip should match the png row even though jpeg_status is NULL"
        );
    }

    #[test]
    fn match_ids_size_range() {
        let db = open_db_with_fixture(1500, 2);
        let mut filter = FilterState::default();
        // Filesize for file_id = i+1 is 1_000 + i*17. Pick a slice with i in
        // [10, 19] ⇒ sizes 1170..=1323.
        let lo = 1_170u64;
        let hi = 1_323u64;
        filter.size_range = Some((lo, hi));
        let rows = query_match_ids(db.pool(), &filter).expect("query");
        assert_eq!(rows.len(), 10);
        for r in &rows {
            assert!(r.filesize >= lo && r.filesize <= hi);
        }
    }

    #[test]
    fn match_ids_bookmarked_first_puts_marked_at_top() {
        let db = open_db_with_fixture(500, 1);
        // Bookmark a few file_ids that would normally land in the middle/end.
        for fid in [100i64, 250, 499] {
            add_bookmark(db.pool(), fid);
        }
        let filter = FilterState {
            bookmarked_first: true,
            ..FilterState::default()
        };
        let rows = query_match_ids(db.pool(), &filter).expect("query");
        assert_eq!(rows.len(), 500);
        // The first three rows must be the bookmarked ones.
        let head_ids: Vec<u64> = rows.iter().take(3).map(|r| r.file_id).collect();
        let mut expected = vec![100u64, 250, 499];
        expected.sort_unstable();
        let mut got = head_ids.clone();
        got.sort_unstable();
        assert_eq!(got, expected, "first three rows must be the bookmarks");
        // And the fourth row must NOT be bookmarked.
        assert!(!head_ids.contains(&rows[3].file_id));
    }

    #[test]
    fn match_ids_sort_stable_on_file_id_for_ties() {
        // Seed 10 files all of the same type and filesize — file_id ASC
        // tiebreaker must yield a strictly increasing file_id sequence.
        let db = IndexDb::open_in_memory().expect("open db");
        seed_sources(db.pool(), 1);
        block_on(async {
            let mut conn = db.pool().get().await.unwrap();
            let tx = conn.transaction().await.unwrap();
            for i in 0..10i64 {
                tx.execute(
                    "INSERT INTO file \
                     (file_id, source_id, filename, filesize, file_type, img_offset, \
                      written_path, byte_runs_json, preview_status) \
                     VALUES (?1, 1, ?2, 4096, 'jpeg', 0, ?3, '[]', 'unknown')",
                    turso::params_from_iter(vec![
                        Value::Integer(i + 1),
                        Value::Text(format!("tied-{:02}.jpeg", i + 1)),
                        Value::Text(format!("img1/tied-{:02}.jpeg", i + 1)),
                    ]),
                )
                .await
                .unwrap();
            }
            tx.commit().await.unwrap();
        });

        let filter = FilterState {
            sort_key: SortKey::Size, // all rows tie on filesize
            ..FilterState::default()
        };
        let rows = query_match_ids(db.pool(), &filter).expect("query");
        assert_eq!(rows.len(), 10);
        let ids: Vec<u64> = rows.iter().map(|r| r.file_id).collect();
        let expected: Vec<u64> = (1..=10).collect();
        assert_eq!(
            ids, expected,
            "tiebreaker must give strictly increasing file_id"
        );
    }

    // ── fetch_window tests ────────────────────────────────────────────────────

    #[test]
    fn fetch_window_returns_rows_in_input_order() {
        let db = IndexDb::open_in_memory().expect("open in-memory db");
        seed_sources(db.pool(), 1);
        seed_file(db.pool(), 10, "a.jpg", 100);
        seed_file(db.pool(), 20, "b.jpg", 100);
        seed_file(db.pool(), 30, "c.jpg", 100);

        let ids = vec![30u64, 10, 20];
        let rows = fetch_window(db.pool(), &ids).expect("fetch_window");

        assert_eq!(
            rows.iter().map(|r| r.id).collect::<Vec<_>>(),
            vec![30, 10, 20],
            "fetch_window must reorder rows to match the input slice"
        );
    }

    #[test]
    fn fetch_window_empty_input_returns_empty() {
        let db = IndexDb::open_in_memory().expect("open in-memory db");
        let rows = fetch_window(db.pool(), &[]).expect("fetch_window");
        assert!(rows.is_empty());
    }

    // ── picker_metadata_row tests ─────────────────────────────────────────────

    #[test]
    fn picker_metadata_row_reads_run_and_last_event_offset() {
        let db = IndexDb::open_in_memory().expect("open in-memory db");
        block_on(async {
            let conn = db.pool().get().await.unwrap();
            conn.execute(
                "INSERT INTO run \
                 (id, started_at, output_root, source_image_path, \
                  configured_types_json, status, elapsed_ms, total_files) \
                 VALUES (1, '2026-05-20T00:00:00Z', '/out', '/sources/l2.img', \
                         '[]', 'Finished', 1234, 2036)",
                (),
            )
            .await
            .unwrap();
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('last_event_offset', '99999')",
                (),
            )
            .await
            .unwrap();
        });

        let row = picker_metadata_row(db.pool()).unwrap();
        assert_eq!(row.source_image_path, "/sources/l2.img");
        assert_eq!(row.status, "Finished");
        assert_eq!(row.elapsed_ms, 1234);
        assert_eq!(row.total_files, 2036);
        assert_eq!(row.last_event_offset, 99999);
    }

    #[test]
    fn picker_metadata_row_missing_meta_returns_zero_offset() {
        let db = IndexDb::open_in_memory().expect("open in-memory db");
        block_on(async {
            let conn = db.pool().get().await.unwrap();
            conn.execute(
                "INSERT INTO run \
                 (id, started_at, output_root, source_image_path, \
                  configured_types_json, status, elapsed_ms, total_files) \
                 VALUES (1, '2026-05-20T00:00:00Z', '/out', '/sources/l2.img', \
                         '[]', 'Running', 0, 0)",
                (),
            )
            .await
            .unwrap();
        });

        let row = picker_metadata_row(db.pool()).unwrap();
        assert_eq!(row.last_event_offset, 0);
    }

    // ── set_preview_status tests ──────────────────────────────────────────────

    #[test]
    fn set_preview_status_writes_and_bumps_version() {
        let db = IndexDb::open_in_memory().expect("open in-memory db");
        seed_sources(db.pool(), 1);
        seed_file(db.pool(), 1, "a.jpg", 100);

        // Migration seed: version starts at 0, status starts as "unknown".
        let (initial_status, v0) = block_on(async {
            let conn = db.pool().get().await.unwrap();
            let status = {
                let mut rows = conn
                    .query(
                        "SELECT preview_status FROM file WHERE file_id = 1",
                        (),
                    )
                    .await
                    .unwrap();
                let row = rows.next().await.unwrap().unwrap();
                models::col_text(&row, 0, "preview_status").unwrap()
            };
            let version = {
                let mut rows = conn
                    .query(
                        "SELECT value FROM meta WHERE key = 'preview_status_version'",
                        (),
                    )
                    .await
                    .unwrap();
                let row = rows.next().await.unwrap().unwrap();
                models::col_text(&row, 0, "value").unwrap()
            };
            (status, version)
        });
        assert_eq!(initial_status, "unknown");
        assert_eq!(v0, "0");

        set_preview_status(db.pool(), 1, "has_preview").expect("set_preview_status");

        let (final_status, v1) = block_on(async {
            let conn = db.pool().get().await.unwrap();
            let status = {
                let mut rows = conn
                    .query(
                        "SELECT preview_status FROM file WHERE file_id = 1",
                        (),
                    )
                    .await
                    .unwrap();
                let row = rows.next().await.unwrap().unwrap();
                models::col_text(&row, 0, "preview_status").unwrap()
            };
            let version = {
                let mut rows = conn
                    .query(
                        "SELECT value FROM meta WHERE key = 'preview_status_version'",
                        (),
                    )
                    .await
                    .unwrap();
                let row = rows.next().await.unwrap().unwrap();
                models::col_text(&row, 0, "value").unwrap()
            };
            (status, version)
        });
        assert_eq!(final_status, "has_preview");
        assert_eq!(v1, "1", "version should bump by exactly one");
    }

    // ── Seed helpers for preview/embedding tests ──────────────────────────────

    /// Insert a single file with an explicit `file_type`.
    /// Source 1 must already exist (call [`seed_sources`] first).
    fn seed_file_with_type(pool: &TursoPool, file_id: i64, file_type: &str) {
        block_on(async {
            let conn = pool.get().await.unwrap();
            conn.execute(
                "INSERT INTO file \
                 (file_id, source_id, filename, filesize, file_type, img_offset, \
                  written_path, byte_runs_json, preview_status) \
                 VALUES (?1, 1, ?2, 1024, ?3, 0, ?4, '[]', 'unknown')",
                turso::params_from_iter(vec![
                    Value::Integer(file_id),
                    Value::Text(format!("{file_id:08}.{file_type}")),
                    Value::Text(file_type.to_owned()),
                    Value::Text(format!("img1/{file_id:08}.{file_type}")),
                ]),
            )
            .await
            .unwrap();
        });
    }

    /// Insert a minimal `preview_blob` row for `file_id`.
    /// The file row must already exist.
    fn seed_preview_blob(pool: &TursoPool, file_id: i64) {
        block_on(async {
            let conn = pool.get().await.unwrap();
            conn.execute(
                "INSERT INTO preview_blob (file_id, codec, width, height, bytes) \
                 VALUES (?1, 'jpeg', 1, 1, ?2)",
                turso::params_from_iter(vec![
                    Value::Integer(file_id),
                    Value::Blob(vec![0xFF, 0xD8, 0xFF]),
                ]),
            )
            .await
            .unwrap();
        });
    }

    // ── count_files_without_preview tests ─────────────────────────────────────

    #[test]
    fn count_without_preview_counts_image_types() {
        let db = IndexDb::open_in_memory().expect("open db");
        seed_sources(db.pool(), 1);
        // 3 jpegs (image type) + 1 pdf (non-image) — only jpegs should be counted.
        seed_file_with_type(db.pool(), 1, "jpeg");
        seed_file_with_type(db.pool(), 2, "jpeg");
        seed_file_with_type(db.pool(), 3, "jpeg");
        seed_file_with_type(db.pool(), 4, "pdf");

        let count = count_files_without_preview(db.pool()).expect("count");
        assert_eq!(count, 3, "only image types should be counted");

        // Mark file 1 as has_preview → count drops to 2.
        set_preview_status(db.pool(), 1, "has_preview").expect("set_preview_status");
        let count = count_files_without_preview(db.pool()).expect("count after mark");
        assert_eq!(count, 2, "count should drop after marking one as has_preview");
    }

    // ── get_files_without_preview tests ──────────────────────────────────────

    #[test]
    fn get_without_preview_returns_limited_image_files() {
        let db = IndexDb::open_in_memory().expect("open db");
        seed_sources(db.pool(), 1);
        // 4 jpegs + 1 bmp + 1 pdf; limit 3 → first 3 jpegs only.
        seed_file_with_type(db.pool(), 1, "jpeg");
        seed_file_with_type(db.pool(), 2, "jpeg");
        seed_file_with_type(db.pool(), 3, "jpeg");
        seed_file_with_type(db.pool(), 4, "jpeg");
        seed_file_with_type(db.pool(), 5, "bmp");
        seed_file_with_type(db.pool(), 6, "pdf");

        let files = get_files_without_preview(db.pool(), 3).expect("get");
        assert_eq!(files.len(), 3, "limit should cap the result at 3");

        let previewable = ["jpeg", "gif", "bmp", "png", "vjpeg"];
        for f in &files {
            assert!(
                previewable.contains(&f.file.file_type.as_str()),
                "expected image type, got {:?}",
                f.file.file_type
            );
        }
        // ORDER BY file_id ASC → 1, 2, 3.
        let ids: Vec<u64> = files.iter().map(|f| f.id).collect();
        assert_eq!(ids, vec![1, 2, 3], "results must be in file_id order");
    }

    // ── count_files_without_embedding tests ──────────────────────────────────

    #[test]
    fn count_without_embedding_counts_preview_blobs_missing_clip_row() {
        let db = IndexDb::open_in_memory().expect("open db");
        seed_sources(db.pool(), 1);
        // 3 files; only files 1 and 2 have preview_blobs → count = 2.
        seed_file_with_type(db.pool(), 1, "jpeg");
        seed_file_with_type(db.pool(), 2, "jpeg");
        seed_file_with_type(db.pool(), 3, "jpeg");
        seed_preview_blob(db.pool(), 1);
        seed_preview_blob(db.pool(), 2);

        let count =
            count_files_without_embedding(db.pool(), "test-model").expect("count");
        assert_eq!(
            count, 2,
            "only files with a preview_blob but no embedding should count"
        );
    }

    // ── get_files_without_embedding tests ────────────────────────────────────

    #[test]
    fn get_without_embedding_returns_file_id_and_preview_blob() {
        let db = IndexDb::open_in_memory().expect("open db");
        seed_sources(db.pool(), 1);
        seed_file_with_type(db.pool(), 1, "jpeg");
        seed_file_with_type(db.pool(), 2, "jpeg");
        seed_preview_blob(db.pool(), 1);
        seed_preview_blob(db.pool(), 2);

        let pairs =
            get_files_without_embedding(db.pool(), "test-model", 10).expect("get");
        assert_eq!(pairs.len(), 2, "both files with blobs should be returned");

        let ids: Vec<u64> = pairs.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, vec![1, 2], "file_ids must be in ascending order");

        for (id, blob) in &pairs {
            assert_eq!(
                blob.file_id as u64, *id,
                "blob.file_id must match the tuple key"
            );
            assert_eq!(blob.codec, "jpeg");
        }
    }
}
