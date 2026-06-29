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
//! ### Semantic-search (KNN) branch
//!
//! When `query_embedding` is `Some` AND `filter.search_query` is `Some`,
//! `query_match_ids` switches to a `vector_distance_cos` brute-force KNN scan
//! over the `clip_embedding` table instead of the regular filter+sort path.
//! Results are ordered by ascending cosine distance; `sort_key`/`sort_dir` are
//! **overridden** for this path.  All other filters (`enabled_types`,
//! `source_filter`, `bookmarked_only`, `size_range`, `hide_no_preview`) remain
//! active via the shared [`build_filter_conditions`] helper, so a file excluded
//! by any chip/filter is also excluded from search results.
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

// ── KNN search constants ──────────────────────────────────────────────────────

/// Maximum cosine distance for a result to be included in a KNN search.
///
/// `vector_distance_cos` returns values in [0, 2]: 0 = identical, 1 =
/// orthogonal, 2 = anti-parallel.  1.3 admits any plausibly related image
/// while rejecting clearly unrelated content.
const SEARCH_DISTANCE_THRESHOLD: f32 = 1.3;

/// Maximum number of files returned by a single KNN search.
const SEARCH_RESULT_LIMIT: usize = 300;

// ── KNN helpers ───────────────────────────────────────────────────────────────

/// Serialise a `f32` slice to little-endian bytes for binding as a
/// `turso::Value::Blob` against an `F32_BLOB` column.
///
/// Non-feature-gated so that the KNN SQL path compiles even without the
/// `clip` feature — only the caller that computes embeddings needs `clip`.
fn vec_to_le_bytes(v: &[f32]) -> Vec<u8> {
    v.iter().flat_map(|f| f.to_le_bytes()).collect()
}

/// Build a brute-force cosine-distance KNN query over `clip_embedding`.
///
/// `filter_where` is either `""` or starts with `" AND "` — the same fragment
/// produced by assembling the conditions from [`build_filter_conditions`].
///
/// # Binding order
///
/// The caller must bind parameters in this order:
/// 1. `Vec<u8>` blob — the query embedding (for `vector_distance_cos(c.embedding, ?)`)
/// 2. `String` — the active model name (for `c.model = ?`)
/// 3. All filter params produced by [`build_filter_conditions`]
fn knn_query(filter_where: &str, threshold: f32, limit: usize) -> String {
    format!(
        "SELECT file_id, filename, filesize, file_type FROM (\
         SELECT f.file_id AS file_id, f.filename AS filename, \
         f.filesize AS filesize, f.file_type AS file_type, \
         vector_distance_cos(c.embedding, ?) AS distance \
         FROM file f \
         JOIN clip_embedding c ON c.file_id = f.file_id AND c.model = ? \
         WHERE 1=1{filter_where}\
         ) WHERE distance <= {threshold} \
         ORDER BY distance ASC \
         LIMIT {limit}"
    )
}

/// Extract the WHERE conditions and their bound parameters from a
/// [`FilterState`].
///
/// Returns a `(conditions, params)` pair:
/// - `conditions` — individual SQL predicate strings (each referencing `f.*`)
/// - `params` — parameters matching the placeholders in the conditions,
///   in the same order
///
/// Neither the `bookmarked_first` LEFT JOIN nor any ORDER BY clause is
/// included — those are path-specific (the KNN path orders by distance; the
/// normal path orders by sort_key).
fn build_filter_conditions(filter: &FilterState) -> (Vec<String>, Vec<Param>) {
    let mut conditions: Vec<String> = Vec::new();
    let mut params: Vec<Param> = Vec::new();

    if let Some(sid) = filter.source_filter {
        conditions.push("f.source_id = ?".into());
        params.push(Param::Int(sid as i32));
    }

    if filter.bookmarked_only {
        conditions.push("f.file_id IN (SELECT file_id FROM bookmark)".into());
    }

    if let Some((lo, hi)) = filter.size_range {
        conditions.push("f.filesize BETWEEN ? AND ?".into());
        params.push(Param::Big(lo as i64));
        params.push(Param::Big(hi as i64));
    }

    if filter.hide_no_preview {
        conditions.push("f.preview_status != 'no_preview'".into());
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
        conditions.push(format!("({})", clauses.join(" OR ")));
    }

    (conditions, params)
}

// ── Public query surface ──────────────────────────────────────────────────────

/// Build and run the visible-ids query.
///
/// ## Normal path
///
/// Returns rows of the `file` table satisfying every active filter in
/// `filter`, ordered by `(bookmarked_first?, sort_key sort_dir, file_id ASC)`.
///
/// ## Semantic-search (KNN) path
///
/// When both `query_embedding` is `Some` AND `filter.search_query` is `Some`,
/// the function switches to a `vector_distance_cos` KNN scan over the
/// `clip_embedding` table.  Results are ordered by ascending cosine distance
/// (closest first); the `sort_key`/`sort_dir` fields are overridden.  All
/// other filters (`enabled_types`, `source_filter`, …) remain in effect.
/// Files without a `clip_embedding` row for the active model are not returned.
///
/// Rows with an unrecognised `file_type` string are silently dropped on both
/// paths.
pub fn query_match_ids(
    pool: &TursoPool,
    filter: &FilterState,
    query_embedding: Option<&[f32]>,
) -> Result<Vec<FileStub>> {
    let pool = pool.clone();
    let filter = filter.clone();
    let embedding_bytes = query_embedding.map(vec_to_le_bytes);
    block_on(do_query_match_ids(pool, filter, embedding_bytes))
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

async fn do_query_match_ids(
    pool: TursoPool,
    filter: FilterState,
    query_embedding: Option<Vec<u8>>,
) -> Result<Vec<FileStub>> {
    let conn = pool.get().await.context("get conn for query_match_ids")?;

    let (conditions, filter_params) = build_filter_conditions(&filter);

    // Choose the KNN path when both a query embedding and a search text are
    // present; otherwise use the normal filter+sort path.
    let use_knn = query_embedding.is_some() && filter.search_query.is_some();

    let (sql, values) = if use_knn {
        // ── Semantic-search (KNN) path ────────────────────────────────────────
        // Results ordered by ascending cosine distance; sort_key/sort_dir are
        // overridden.  All other filters remain active via build_filter_conditions.
        let filter_where = if conditions.is_empty() {
            String::new()
        } else {
            format!(" AND {}", conditions.join(" AND "))
        };
        let sql = knn_query(&filter_where, SEARCH_DISTANCE_THRESHOLD, SEARCH_RESULT_LIMIT);

        let mut vals: Vec<Value> = Vec::new();
        // Param 1: query embedding blob (for vector_distance_cos(c.embedding, ?))
        vals.push(Value::Blob(query_embedding.expect("checked above")));
        // Param 2: model name (for c.model = ?)
        vals.push(Value::Text(crate::model::ACTIVE_MODEL_NAME.to_owned()));
        // Params 3…N: filter predicates
        vals.extend(filter_params.into_iter().map(Value::from));
        (sql, vals)
    } else {
        // ── Normal filter + sort path ─────────────────────────────────────────
        let mut sql = String::new();

        // SELECT + optional LEFT JOIN for the bookmarked_first sort.
        sql.push_str(
            "SELECT f.file_id AS file_id, f.filename AS filename, \
             f.filesize AS filesize, f.file_type AS file_type FROM file f",
        );
        if filter.bookmarked_first {
            sql.push_str(" LEFT JOIN bookmark b ON b.file_id = f.file_id");
        }

        if !conditions.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&conditions.join(" AND "));
        }

        // ORDER BY: bookmarked-first (DESC because NULL < non-NULL in SQLite
        // means bookmarked rows — where b.file_id IS NOT NULL — need DESC to
        // float up), then the user-selected sort, then file_id ASC as a
        // tiebreaker.
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

        let vals: Vec<Value> = filter_params.into_iter().map(Value::from).collect();
        (sql, vals)
    };

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
        let rows = query_match_ids(db.pool(), &filter, None).expect("query");
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
        let rows = query_match_ids(db.pool(), &filter, None).expect("query");
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
        let rows = query_match_ids(db.pool(), &filter, None).expect("query");
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
        let rows = query_match_ids(db.pool(), &filter, None).expect("query");
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
        let rows = query_match_ids(db.pool(), &filter, None).expect("query");
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
        let rows = query_match_ids(db.pool(), &filter, None).expect("query");
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
        let rows = query_match_ids(db.pool(), &filter, None).expect("query");
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
        let rows = query_match_ids(db.pool(), &filter, None).expect("query");
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
        let rows = query_match_ids(db.pool(), &filter, None).expect("query");
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

    // ── KNN semantic-search tests ─────────────────────────────────────────────
    //
    // These tests written first (TDD RED) to specify the expected behaviour of
    // the `vector_distance_cos` KNN branch in `query_match_ids`.
    //
    // Test vectors use simple unit-axis embeddings so distances are exact:
    //   dim0 = [1, 0, 0, …]   (query vector)
    //   dim1 = [0, 1, 0, …]   → distance 1.0 (orthogonal)
    //   dim2 = [0, 0, 1, …]   → distance 1.0 (orthogonal)
    //   neg0 = [-1, 0, 0, …]  → distance 2.0 (anti-parallel, > threshold 1.3)
    //   mix  = [1/√2, 1/√2, …] → distance ≈ 0.293

    /// Construct a 768-dim unit vector with `value` at `axis`, zeros elsewhere.
    fn axis_vec(axis: usize, value: f32) -> Vec<f32> {
        let mut v = vec![0.0f32; 768];
        v[axis] = value;
        v
    }

    /// Seed a `clip_embedding` row for `file_id` using the active model.
    fn seed_embedding(pool: &TursoPool, file_id: i64, embedding: &[f32]) {
        crate::db::writer::set_clip_embedding(
            pool,
            file_id as u64,
            crate::model::ACTIVE_MODEL_NAME,
            embedding,
        )
        .expect("seed_embedding");
    }

    /// Seed a file with a given `preview_status` (default is `"unknown"`).
    fn seed_file_with_preview_status(
        pool: &TursoPool,
        file_id: i64,
        filename: &str,
        preview_status: &str,
    ) {
        block_on(async {
            let conn = pool.get().await.unwrap();
            conn.execute(
                "INSERT INTO file \
                 (file_id, source_id, filename, filesize, file_type, img_offset, \
                  written_path, byte_runs_json, preview_status) \
                 VALUES (?1, 1, ?2, 1000, 'jpeg', 0, ?3, '[]', ?4)",
                turso::params_from_iter(vec![
                    Value::Integer(file_id),
                    Value::Text(filename.to_owned()),
                    Value::Text(format!("img1/{filename}")),
                    Value::Text(preview_status.to_owned()),
                ]),
            )
            .await
            .unwrap();
        });
    }

    /// Return a `FilterState` that has `search_query` set so the KNN path fires.
    fn knn_filter() -> FilterState {
        FilterState {
            search_query: Some("test query".into()),
            ..FilterState::default()
        }
    }

    #[test]
    fn knn_ordering_threshold_and_no_embedding_excluded() {
        // Scenario:
        //   file1 query = dim0 → distance 0 (closest)
        //   file2 close = (dim0+dim1)/√2 → distance ≈ 0.293
        //   file3 ortho = dim1 → distance 1.0
        //   file4 ortho = dim2 → distance 1.0
        //   file5 anti  = -dim0 → distance 2.0 — EXCLUDED (> threshold 1.3)
        //   file6 no embedding → NEVER appears
        let db = IndexDb::open_in_memory().expect("open db");
        seed_sources(db.pool(), 1);
        for id in 1..=6 {
            seed_file(db.pool(), id, &format!("f{id}.jpeg"), 1000 + id);
        }

        let v_identical = axis_vec(0, 1.0);
        let inv_sqrt2 = (0.5f32).sqrt();
        let mut v_close = vec![0.0f32; 768];
        v_close[0] = inv_sqrt2;
        v_close[1] = inv_sqrt2;
        let v_ortho1 = axis_vec(1, 1.0);
        let v_ortho2 = axis_vec(2, 1.0);
        let v_anti = axis_vec(0, -1.0);
        // file6 deliberately gets no embedding row.

        seed_embedding(db.pool(), 1, &v_identical);
        seed_embedding(db.pool(), 2, &v_close);
        seed_embedding(db.pool(), 3, &v_ortho1);
        seed_embedding(db.pool(), 4, &v_ortho2);
        seed_embedding(db.pool(), 5, &v_anti);

        let query = axis_vec(0, 1.0);
        let results = query_match_ids(db.pool(), &knn_filter(), Some(&query))
            .expect("knn search");

        // file5 (distance 2.0) and file6 (no embedding) must be absent.
        let ids: Vec<u64> = results.iter().map(|r| r.file_id).collect();
        assert!(
            !ids.contains(&5),
            "file5 (distance 2.0 > threshold 1.3) must be excluded; got {ids:?}"
        );
        assert!(
            !ids.contains(&6),
            "file6 (no embedding) must be excluded; got {ids:?}"
        );

        // files 1-4 must all appear.
        assert_eq!(
            results.len(),
            4,
            "expected 4 results (files 1-4); got {ids:?}"
        );

        // First two positions are deterministic by distance.
        assert_eq!(results[0].file_id, 1, "file1 (distance 0) must be first");
        assert_eq!(results[1].file_id, 2, "file2 (distance ≈0.293) must be second");

        // files 3 & 4 are tied at distance 1.0; both must appear in positions 2-3.
        let mut tail: Vec<u64> = results[2..].iter().map(|r| r.file_id).collect();
        tail.sort_unstable();
        assert_eq!(tail, vec![3, 4], "files 3 and 4 (distance 1.0) must be in the tail");
    }

    #[test]
    fn knn_respects_limit() {
        // Seed SEARCH_RESULT_LIMIT + 10 files all with identical embeddings to
        // the query (distance 0) and verify we get at most SEARCH_RESULT_LIMIT.
        let total = SEARCH_RESULT_LIMIT + 10;
        let db = IndexDb::open_in_memory().expect("open db");
        seed_sources(db.pool(), 1);
        let v = axis_vec(0, 1.0);
        for id in 1..=(total as i64) {
            seed_file(db.pool(), id, &format!("f{id}.jpeg"), 1000 + id);
            seed_embedding(db.pool(), id, &v);
        }
        let results = query_match_ids(db.pool(), &knn_filter(), Some(&v)).expect("knn");
        assert_eq!(
            results.len(),
            SEARCH_RESULT_LIMIT,
            "KNN results must be capped at SEARCH_RESULT_LIMIT"
        );
    }

    // ── Filter-funnel tests (one per filter type, KNN path) ───────────────────
    //
    // For each filter: seed 2 files, both with a close embedding.  Apply the
    // filter so file1 passes and file2 fails.  Assert file2 never appears.

    #[test]
    fn knn_funnel_enabled_types_chip() {
        // file1 = jpeg (passes chip), file2 = pdf (excluded by chip).
        let db = IndexDb::open_in_memory().expect("open db");
        seed_sources(db.pool(), 1);
        let v = axis_vec(0, 1.0);

        // file1: jpeg
        block_on(async {
            let conn = db.pool().get().await.unwrap();
            conn.execute(
                "INSERT INTO file (file_id, source_id, filename, filesize, file_type, \
                 img_offset, written_path, byte_runs_json, preview_status) \
                 VALUES (1, 1, 'f1.jpeg', 1000, 'jpeg', 0, 'img1/f1.jpeg', '[]', 'unknown')",
                (),
            )
            .await
            .unwrap();
        });
        // file2: pdf
        block_on(async {
            let conn = db.pool().get().await.unwrap();
            conn.execute(
                "INSERT INTO file (file_id, source_id, filename, filesize, file_type, \
                 img_offset, written_path, byte_runs_json, preview_status) \
                 VALUES (2, 1, 'f2.pdf', 1000, 'pdf', 0, 'img1/f2.pdf', '[]', 'unknown')",
                (),
            )
            .await
            .unwrap();
        });
        seed_embedding(db.pool(), 1, &v);
        seed_embedding(db.pool(), 2, &v);

        let mut filter = knn_filter();
        filter.enabled_types.insert(FileType::Jpeg);

        let results = query_match_ids(db.pool(), &filter, Some(&v)).expect("knn");
        let ids: Vec<u64> = results.iter().map(|r| r.file_id).collect();
        assert!(
            ids.contains(&1),
            "file1 (jpeg) must appear when Jpeg chip is on; got {ids:?}"
        );
        assert!(
            !ids.contains(&2),
            "file2 (pdf) must be excluded by Jpeg chip; got {ids:?}"
        );
    }

    #[test]
    fn knn_funnel_enabled_partial_types_chip() {
        // file1 = truncated jpeg (passes Partial Jpeg chip)
        // file2 = complete jpeg (excluded: Partial Jpeg chip only, no full chip)
        let db = IndexDb::open_in_memory().expect("open db");
        seed_sources(db.pool(), 1);
        let v = axis_vec(0, 1.0);

        block_on(async {
            let mut conn = db.pool().get().await.unwrap();
            let tx = conn.transaction().await.unwrap();
            tx.execute(
                "INSERT INTO file (file_id, source_id, filename, filesize, file_type, \
                 img_offset, written_path, byte_runs_json, jpeg_status, preview_status) \
                 VALUES (1, 1, 'partial.jpeg', 1000, 'jpeg', 0, 'img1/partial.jpeg', '[]', \
                         'truncated', 'unknown')",
                (),
            )
            .await
            .unwrap();
            tx.execute(
                "INSERT INTO file (file_id, source_id, filename, filesize, file_type, \
                 img_offset, written_path, byte_runs_json, jpeg_status, preview_status) \
                 VALUES (2, 1, 'complete.jpeg', 1000, 'jpeg', 0, 'img1/complete.jpeg', '[]', \
                         'complete', 'unknown')",
                (),
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
        });
        seed_embedding(db.pool(), 1, &v);
        seed_embedding(db.pool(), 2, &v);

        let mut filter = knn_filter();
        filter.enabled_partial_types.insert(FileType::Jpeg);

        let results = query_match_ids(db.pool(), &filter, Some(&v)).expect("knn");
        let ids: Vec<u64> = results.iter().map(|r| r.file_id).collect();
        assert!(
            ids.contains(&1),
            "partial jpeg must appear with Partial Jpeg chip; got {ids:?}"
        );
        assert!(
            !ids.contains(&2),
            "complete jpeg must be excluded with only Partial Jpeg chip; got {ids:?}"
        );
    }

    #[test]
    fn knn_funnel_source_filter() {
        // 2 sources; filter to source 1 only.
        let db = IndexDb::open_in_memory().expect("open db");
        seed_sources(db.pool(), 2);
        let v = axis_vec(0, 1.0);

        block_on(async {
            let mut conn = db.pool().get().await.unwrap();
            let tx = conn.transaction().await.unwrap();
            for (id, src) in [(1i64, 1i64), (2, 2)] {
                tx.execute(
                    "INSERT INTO file (file_id, source_id, filename, filesize, file_type, \
                     img_offset, written_path, byte_runs_json, preview_status) \
                     VALUES (?1, ?2, ?3, 1000, 'jpeg', 0, ?4, '[]', 'unknown')",
                    turso::params_from_iter(vec![
                        Value::Integer(id),
                        Value::Integer(src),
                        Value::Text(format!("f{id}.jpeg")),
                        Value::Text(format!("img{src}/f{id}.jpeg")),
                    ]),
                )
                .await
                .unwrap();
            }
            tx.commit().await.unwrap();
        });
        seed_embedding(db.pool(), 1, &v);
        seed_embedding(db.pool(), 2, &v);

        let mut filter = knn_filter();
        filter.source_filter = Some(1);

        let results = query_match_ids(db.pool(), &filter, Some(&v)).expect("knn");
        let ids: Vec<u64> = results.iter().map(|r| r.file_id).collect();
        assert_eq!(ids, vec![1], "only source-1 file must appear; got {ids:?}");
    }

    #[test]
    fn knn_funnel_bookmarked_only() {
        let db = IndexDb::open_in_memory().expect("open db");
        seed_sources(db.pool(), 1);
        let v = axis_vec(0, 1.0);
        seed_file(db.pool(), 1, "bookmarked.jpeg", 1000);
        seed_file(db.pool(), 2, "not-bookmarked.jpeg", 1001);
        seed_embedding(db.pool(), 1, &v);
        seed_embedding(db.pool(), 2, &v);
        add_bookmark(db.pool(), 1);

        let mut filter = knn_filter();
        filter.bookmarked_only = true;

        let results = query_match_ids(db.pool(), &filter, Some(&v)).expect("knn");
        let ids: Vec<u64> = results.iter().map(|r| r.file_id).collect();
        assert_eq!(
            ids,
            vec![1],
            "only bookmarked file must appear with bookmarked_only; got {ids:?}"
        );
    }

    #[test]
    fn knn_funnel_size_range() {
        let db = IndexDb::open_in_memory().expect("open db");
        seed_sources(db.pool(), 1);
        let v = axis_vec(0, 1.0);
        // file1: size 500 (inside range 400..=600)
        seed_file(db.pool(), 1, "small.jpeg", 500);
        // file2: size 2000 (outside range)
        seed_file(db.pool(), 2, "big.jpeg", 2000);
        seed_embedding(db.pool(), 1, &v);
        seed_embedding(db.pool(), 2, &v);

        let mut filter = knn_filter();
        filter.size_range = Some((400, 600));

        let results = query_match_ids(db.pool(), &filter, Some(&v)).expect("knn");
        let ids: Vec<u64> = results.iter().map(|r| r.file_id).collect();
        assert_eq!(
            ids,
            vec![1],
            "only in-range file must appear; got {ids:?}"
        );
    }

    #[test]
    fn knn_funnel_hide_no_preview() {
        let db = IndexDb::open_in_memory().expect("open db");
        seed_sources(db.pool(), 1);
        let v = axis_vec(0, 1.0);
        // file1: preview_status = 'has_preview' (passes filter)
        seed_file_with_preview_status(db.pool(), 1, "with-preview.jpeg", "has_preview");
        // file2: preview_status = 'no_preview' (excluded)
        seed_file_with_preview_status(db.pool(), 2, "no-preview.jpeg", "no_preview");
        seed_embedding(db.pool(), 1, &v);
        seed_embedding(db.pool(), 2, &v);

        let mut filter = knn_filter();
        filter.hide_no_preview = true;

        let results = query_match_ids(db.pool(), &filter, Some(&v)).expect("knn");
        let ids: Vec<u64> = results.iter().map(|r| r.file_id).collect();
        assert!(
            ids.contains(&1),
            "file with preview must appear; got {ids:?}"
        );
        assert!(
            !ids.contains(&2),
            "no_preview file must be excluded by hide_no_preview; got {ids:?}"
        );
    }

    #[test]
    fn knn_no_embedding_for_active_model_never_appears() {
        // Only file2 has an embedding for the active model; file1 has a row
        // under a DIFFERENT model.  Only file2 must appear.
        let db = IndexDb::open_in_memory().expect("open db");
        seed_sources(db.pool(), 1);
        let v = axis_vec(0, 1.0);
        seed_file(db.pool(), 1, "f1.jpeg", 1000);
        seed_file(db.pool(), 2, "f2.jpeg", 1001);

        // file1 gets an embedding for a *different* model.
        crate::db::writer::set_clip_embedding(
            db.pool(),
            1,
            "other-model/v1",
            &v,
        )
        .expect("embed file1 under wrong model");

        // file2 gets the active model's embedding.
        seed_embedding(db.pool(), 2, &v);

        let results = query_match_ids(db.pool(), &knn_filter(), Some(&v)).expect("knn");
        let ids: Vec<u64> = results.iter().map(|r| r.file_id).collect();
        assert!(
            !ids.contains(&1),
            "file1 (wrong model) must not appear; got {ids:?}"
        );
        assert!(
            ids.contains(&2),
            "file2 (correct model) must appear; got {ids:?}"
        );
    }

    #[test]
    fn knn_no_search_query_falls_back_to_normal_sort_path() {
        // Passing query_embedding without setting filter.search_query must NOT
        // activate the KNN path — the result should be the normal filename-ASC
        // order, not distance order.
        let db = IndexDb::open_in_memory().expect("open db");
        seed_sources(db.pool(), 1);
        // file1 embeds at anti-parallel to query (distance 2.0 — would be
        // excluded by KNN threshold); file2 identical to query (distance 0).
        let query = axis_vec(0, 1.0);
        let anti = axis_vec(0, -1.0);
        seed_file(db.pool(), 1, "a-file.jpeg", 1000); // sorts first alphabetically
        seed_file(db.pool(), 2, "z-file.jpeg", 1001);
        seed_embedding(db.pool(), 1, &anti);
        seed_embedding(db.pool(), 2, &query);

        // No search_query set → normal path.
        let filter = FilterState::default();
        let results = query_match_ids(db.pool(), &filter, Some(&query)).expect("query");

        // Normal path returns ALL files in filename-ASC order, including file1
        // which would be excluded by the KNN threshold.
        let ids: Vec<u64> = results.iter().map(|r| r.file_id).collect();
        assert_eq!(
            ids,
            vec![1, 2],
            "without search_query, normal sort path must return both files; got {ids:?}"
        );
    }
}
