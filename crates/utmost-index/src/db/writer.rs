//! Transactional writer that folds [`CarveEvent`]s into the Turso index.
//!
//! Events are buffered in memory and flushed as a single transaction. Each
//! flush also advances the `last_event_offset` / `last_event_count` /
//! `indexed_at` meta keys so the on-disk index identity stays in sync with
//! the bincode event log.

use anyhow::{Context, Result};
use turso::transaction::Transaction as Tx;
use turso::Value;
use utmost_lib::events::{CarveEvent, RecoveryMethod};

use super::models::{col_blob, col_i64, col_text, PreviewBlobRow};
use super::{block_on, TursoPool};
use crate::model::{PreviewOutcome, PreviewStatus, UiStateSnapshot};

// ── IndexDbWriter ─────────────────────────────────────────────────────────────

/// Buffered writer that folds [`CarveEvent`]s into the Turso index in batches.
///
/// The writer is sync (intended for worker threads) and bridges to the async
/// Turso API via [`block_on`].  Auto-flush fires when the pending buffer
/// reaches `batch_size`; callers must also call [`IndexDbWriter::flush`] after
/// the event stream ends to ensure no events are dropped.
pub struct IndexDbWriter {
    pool: TursoPool,
    pending: Vec<PendingEvent>,
    batch_size: usize,
    total_count: i64,
}

struct PendingEvent {
    event: CarveEvent,
    offset_after: u64,
}

impl IndexDbWriter {
    /// Create a new writer backed by `pool`.
    ///
    /// Reads `last_event_count` from `meta` to seed the running total.
    /// Any read error is silently treated as 0 so a fresh or unindexed DB
    /// does not prevent the writer from initialising.
    pub fn new(pool: TursoPool, batch_size: usize) -> Self {
        let total_count = block_on(async {
            let conn = pool.get().await.context("get conn for writer init")?;
            read_meta_i64(&conn, "last_event_count").await
        })
        .unwrap_or_default()
        .unwrap_or(0);
        Self {
            pool,
            pending: Vec::new(),
            batch_size,
            total_count,
        }
    }

    /// Buffer `event` for the next flush.
    ///
    /// `offset_after` is the `BincodeFileReader::byte_offset()` immediately
    /// after the event was decoded — i.e. the position from which the *next*
    /// event would be read.  Auto-flushes when the pending buffer reaches
    /// `batch_size`.
    pub fn apply(&mut self, event: CarveEvent, offset_after: u64) -> Result<()> {
        self.pending.push(PendingEvent { event, offset_after });
        if self.pending.len() >= self.batch_size {
            self.flush()?;
        }
        Ok(())
    }

    /// Flush all pending events as one transaction, atomically advancing
    /// `last_event_offset` and `last_event_count` together with the rows.
    pub fn flush(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let pending = std::mem::take(&mut self.pending);
        let new_offset = pending.last().unwrap().offset_after;
        let delta = pending.len() as i64;
        let new_count = self.total_count + delta;
        let pool = self.pool.clone();

        block_on(do_flush(pool, pending, new_offset, new_count))
            .context("flushing index batch")?;

        self.total_count = new_count;
        Ok(())
    }
}

async fn do_flush(
    pool: TursoPool,
    pending: Vec<PendingEvent>,
    new_offset: u64,
    new_count: i64,
) -> Result<()> {
    let mut conn = pool.get().await.context("get conn for flush")?;
    let tx = conn.transaction().await.context("begin flush tx")?;
    for p in &pending {
        apply_event_on_tx(&tx, &p.event).await?;
    }
    upsert_meta(&tx, "last_event_offset", &new_offset.to_string()).await?;
    upsert_meta(&tx, "last_event_count", &new_count.to_string()).await?;
    upsert_meta(&tx, "indexed_at", &chrono::Utc::now().to_rfc3339()).await?;
    tx.commit().await.context("commit flush tx")?;
    Ok(())
}

// ── Public write helpers ──────────────────────────────────────────────────────

/// Persist a batch of preview outcomes into `file.preview_status` and the
/// `preview_blob` table, then atomically bump `meta.preview_status_version`.
///
/// All updates run inside one transaction so a crash mid-flush leaves both
/// the row columns and the version key in their pre-flush state — readers
/// polling `preview_status_version` can use it as a reliable change marker.
///
/// Callers should batch outcomes upstream (e.g. every 100 outcomes or 500 ms)
/// so SQLite sees roughly the same write cadence as the event-fold batches.
pub fn write_preview_outcomes(pool: &TursoPool, batch: &[PreviewOutcome]) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    let pool = pool.clone();
    let batch = batch.to_vec();
    block_on(do_write_preview_outcomes(pool, batch))
}

async fn do_write_preview_outcomes(pool: TursoPool, batch: Vec<PreviewOutcome>) -> Result<()> {
    let mut conn = pool
        .get()
        .await
        .context("get conn for preview outcomes")?;
    let tx = conn
        .transaction()
        .await
        .context("begin preview outcomes tx")?;
    for outcome in &batch {
        let preview_status = match &outcome.status {
            PreviewStatus::HasPreview { .. } => "has_preview",
            PreviewStatus::NoPreview => "no_preview",
        };
        tx.execute(
            "UPDATE file SET preview_status = ?1 WHERE file_id = ?2",
            (
                Value::Text(preview_status.to_owned()),
                Value::Integer(outcome.file_id as i64),
            ),
        )
        .await
        .context("update file preview_status")?;
        if let PreviewStatus::HasPreview {
            codec,
            width,
            height,
            bytes,
        } = &outcome.status
        {
            let params: Vec<Value> = vec![
                Value::Integer(outcome.file_id as i64),
                Value::Text(codec.as_str().to_owned()),
                Value::Integer(i64::from(*width)),
                Value::Integer(i64::from(*height)),
                Value::Blob(bytes.clone()),
            ];
            tx.execute(
                "INSERT INTO preview_blob (file_id, codec, width, height, bytes) \
                 VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(file_id) DO UPDATE SET \
                   codec  = excluded.codec, \
                   width  = excluded.width, \
                   height = excluded.height, \
                   bytes  = excluded.bytes",
                turso::params_from_iter(params),
            )
            .await
            .context("upsert preview_blob")?;
        }
    }
    // Atomically increment preview_status_version without a separate SELECT;
    // readers polling this key treat any change as a cache-bust signal.
    tx.execute(
        "UPDATE meta \
         SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) \
         WHERE key = 'preview_status_version'",
        (),
    )
    .await
    .context("bump preview_status_version")?;
    tx.commit()
        .await
        .context("commit preview outcomes tx")?;
    Ok(())
}

/// Apply a single annotation event (`Bookmark`, `Note`, `MarkAsBest`) outside
/// of a batch.
///
/// Used by the live-mode path where the UI generates an annotation that needs
/// to be visible to filter/sort queries *immediately*, without waiting for the
/// journal fold at `RunFinished`.
///
/// Unlike `IndexDbWriter::flush`, this does NOT advance `last_event_offset` /
/// `last_event_count` — those keys track the engine's main `.bin` log only.
/// Annotation events still live in the journal's `.pending` queue; the fold at
/// `RunFinished` will re-apply each via `apply_event_on_tx`, which is safe
/// because every annotation variant uses an idempotent upsert.
pub fn apply_annotation_event(pool: &TursoPool, event: &CarveEvent) -> Result<()> {
    let pool = pool.clone();
    let event = event.clone();
    block_on(do_apply_annotation(pool, event))
}

async fn do_apply_annotation(pool: TursoPool, event: CarveEvent) -> Result<()> {
    let mut conn = pool.get().await.context("get conn for annotation")?;
    let tx = conn.transaction().await.context("begin annotation tx")?;
    apply_event_on_tx(&tx, &event).await?;
    tx.commit().await.context("commit annotation tx")?;
    Ok(())
}

/// Persist the [`UiStateSnapshot`] under `meta.ui_state` as a JSON blob.
///
/// Errors propagate to the caller; the query-loop thread that drives this
/// treats them as `tracing::warn!` (a UI-state save failure must not abort
/// the session).
pub fn write_ui_state(pool: &TursoPool, snapshot: &UiStateSnapshot) -> Result<()> {
    let json = serde_json::to_string(snapshot).context("serialise UiStateSnapshot")?;
    let pool = pool.clone();
    block_on(do_write_ui_state(pool, json))
}

async fn do_write_ui_state(pool: TursoPool, json: String) -> Result<()> {
    let mut conn = pool.get().await.context("get conn for write_ui_state")?;
    let tx = conn.transaction().await.context("begin ui_state tx")?;
    upsert_meta(&tx, "ui_state", &json).await?;
    tx.commit().await.context("commit ui_state tx")?;
    Ok(())
}

/// Read the persisted [`UiStateSnapshot`] from `meta.ui_state` if present.
///
/// Returns `Ok(None)` when the key is absent OR when the stored JSON fails to
/// deserialise (corrupt blob, future schema migration).  The next debounced
/// save overwrites the bad blob automatically.
pub fn read_ui_state(pool: &TursoPool) -> Result<Option<UiStateSnapshot>> {
    let pool = pool.clone();
    block_on(do_read_ui_state(pool))
}

async fn do_read_ui_state(pool: TursoPool) -> Result<Option<UiStateSnapshot>> {
    let conn = pool.get().await.context("get conn for read_ui_state")?;
    let raw = match read_meta_str(&conn, "ui_state").await? {
        Some(s) => s,
        None => return Ok(None),
    };
    match serde_json::from_str::<UiStateSnapshot>(&raw) {
        Ok(snap) => Ok(Some(snap)),
        Err(e) => {
            tracing::warn!(
                "read_ui_state: failed to deserialise ui_state blob ({e}); returning None"
            );
            Ok(None)
        }
    }
}

/// Point-lookup a cached preview blob by `file_id`.
///
/// Returns `Ok(None)` when no row exists; `Err` on schema errors (the thumb
/// worker logs and falls through to the slow render path).
pub fn preview_blob_lookup(pool: &TursoPool, file_id: u64) -> Result<Option<PreviewBlobRow>> {
    let pool = pool.clone();
    block_on(do_preview_blob_lookup(pool, file_id))
}

async fn do_preview_blob_lookup(pool: TursoPool, file_id: u64) -> Result<Option<PreviewBlobRow>> {
    let conn = pool
        .get()
        .await
        .context("get conn for preview_blob_lookup")?;
    let mut rows = conn
        .query(
            "SELECT file_id, codec, width, height, bytes \
             FROM preview_blob WHERE file_id = ?1",
            (Value::Integer(file_id as i64),),
        )
        .await
        .context("query preview_blob")?;
    match rows.next().await? {
        Some(row) => Ok(Some(PreviewBlobRow {
            file_id: col_i64(&row, 0, "file_id")?,
            codec: col_text(&row, 1, "codec")?,
            width: col_i64(&row, 2, "width")? as i32,
            height: col_i64(&row, 3, "height")? as i32,
            bytes: col_blob(&row, 4, "bytes")?,
        })),
        None => Ok(None),
    }
}

/// Upsert a CLIP embedding for `file_id` into `clip_embedding`.
///
/// `embedding` is serialised to little-endian bytes inline — a
/// feature-gate-free approach that avoids a dependency on the `clip` feature
/// flag for the write path.
///
/// # Schema note — one embedding row per `file_id`
///
/// `clip_embedding` uses `file_id` as its **sole** primary key.  Writing an
/// embedding for the same `file_id` under a **different** `model` name is
/// **destructive**: the `ON CONFLICT` upsert overwrites the existing row
/// (including its `model` column), permanently losing the previously stored
/// embedding.  If multi-model embeddings per file are ever needed the table
/// will require a `(file_id, model)` composite primary key — a breaking schema
/// migration.
pub fn set_clip_embedding(
    pool: &TursoPool,
    file_id: u64,
    model: &str,
    embedding: &[f32],
) -> Result<()> {
    let bytes: Vec<u8> = embedding.iter().flat_map(|f| f.to_le_bytes()).collect();
    let dim = embedding.len() as i64;
    let pool = pool.clone();
    let model = model.to_owned();
    block_on(do_set_clip_embedding(pool, file_id, model, dim, bytes))
}

async fn do_set_clip_embedding(
    pool: TursoPool,
    file_id: u64,
    model: String,
    dim: i64,
    bytes: Vec<u8>,
) -> Result<()> {
    let conn = pool
        .get()
        .await
        .context("get conn for set_clip_embedding")?;
    conn.execute(
        "INSERT INTO clip_embedding (file_id, model, dim, embedding) \
         VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(file_id) DO UPDATE SET \
           model     = excluded.model, \
           dim       = excluded.dim, \
           embedding = excluded.embedding",
        turso::params_from_iter(vec![
            Value::Integer(file_id as i64),
            Value::Text(model),
            Value::Integer(dim),
            Value::Blob(bytes),
        ]),
    )
    .await
    .context("upsert clip_embedding")?;
    Ok(())
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// `Transaction<'conn>` deref-targets `Connection`, so `tx.execute(...)` and
/// `tx.query(...)` call through to the underlying connection.
async fn upsert_meta(tx: &Tx<'_>, key: &str, value: &str) -> Result<()> {
    tx.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (
            Value::Text(key.to_owned()),
            Value::Text(value.to_owned()),
        ),
    )
    .await
    .with_context(|| format!("upsert meta key {key:?}"))?;
    Ok(())
}

fn val_opt_text(v: Option<String>) -> Value {
    match v {
        Some(s) => Value::Text(s),
        None => Value::Null,
    }
}

fn val_opt_i64(v: Option<i64>) -> Value {
    match v {
        Some(n) => Value::Integer(n),
        None => Value::Null,
    }
}

fn val_opt_f64(v: Option<f64>) -> Value {
    match v {
        Some(f) => Value::Real(f),
        None => Value::Null,
    }
}

async fn read_meta_str(conn: &turso::Connection, key: &str) -> Result<Option<String>> {
    let mut rows = conn
        .query(
            "SELECT value FROM meta WHERE key = ?1",
            (Value::Text(key.to_owned()),),
        )
        .await
        .context("query meta")?;
    match rows.next().await? {
        Some(row) => Ok(Some(
            row.get_value(0)?
                .as_text()
                .context("meta.value is not text")?
                .to_owned(),
        )),
        None => Ok(None),
    }
}

async fn read_meta_i64(conn: &turso::Connection, key: &str) -> Result<Option<i64>> {
    Ok(read_meta_str(conn, key)
        .await?
        .and_then(|s| s.parse::<i64>().ok()))
}

// ── apply_event_on_tx ─────────────────────────────────────────────────────────

/// Apply a single event to the database inside the given transaction.
///
/// Exhaustive over [`CarveEvent`] — adding a new variant must force an
/// explicit decision here.  `ProgressTick` updates `source.bytes_read` only;
/// it intentionally does not advance any counters used for fold resumption.
async fn apply_event_on_tx(tx: &Tx<'_>, event: &CarveEvent) -> Result<()> {
    match event {
        CarveEvent::RunStarted {
            started_at,
            output_root,
            sources,
            case,
            configured_types,
            ..
        } => {
            let source_image_path = sources
                .first()
                .map(|s| s.filename.clone())
                .unwrap_or_default();
            let configured_types_json =
                serde_json::to_string(configured_types).unwrap_or_else(|_| "[]".into());
            let params: Vec<Value> = vec![
                Value::Integer(1),
                Value::Text(started_at.clone()),
                Value::Text(output_root.clone()),
                Value::Text(source_image_path),
                Value::Text(configured_types_json),
                val_opt_text(case.as_ref().and_then(|c| c.case_id.clone())),
                val_opt_text(case.as_ref().and_then(|c| c.examiner.clone())),
                val_opt_text(case.as_ref().and_then(|c| c.evidence_id.clone())),
                val_opt_text(case.as_ref().and_then(|c| c.notes.clone())),
                Value::Text("Running".into()),
                Value::Integer(0),
                Value::Integer(0),
            ];
            tx.execute(
                "INSERT INTO run \
                 (id, started_at, output_root, source_image_path, configured_types_json, \
                  case_id, examiner, evidence_id, case_notes, status, elapsed_ms, total_files) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
                 ON CONFLICT(id) DO UPDATE SET \
                   started_at            = excluded.started_at, \
                   output_root           = excluded.output_root, \
                   source_image_path     = excluded.source_image_path, \
                   configured_types_json = excluded.configured_types_json, \
                   case_id               = excluded.case_id, \
                   examiner              = excluded.examiner, \
                   evidence_id           = excluded.evidence_id, \
                   case_notes            = excluded.case_notes, \
                   status                = excluded.status, \
                   elapsed_ms            = excluded.elapsed_ms, \
                   total_files           = excluded.total_files",
                turso::params_from_iter(params),
            )
            .await
            .context("upsert run")?;

            for s in sources {
                let src_params: Vec<Value> = vec![
                    Value::Integer(s.source_id as i64),
                    Value::Text(s.filename.clone()),
                    Value::Text(s.output_subdir.clone()),
                    Value::Integer(s.total_bytes as i64),
                    Value::Integer(0),
                    Value::Integer(0),
                    Value::Text("Pending".into()),
                    Value::Null,
                ];
                tx.execute(
                    "INSERT INTO source \
                     (source_id, filename, output_subdir, total_bytes, bytes_read, \
                      files_found, status, duration_ms) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
                     ON CONFLICT(source_id) DO UPDATE SET \
                       filename      = excluded.filename, \
                       output_subdir = excluded.output_subdir, \
                       total_bytes   = excluded.total_bytes, \
                       bytes_read    = excluded.bytes_read, \
                       files_found   = excluded.files_found, \
                       status        = excluded.status, \
                       duration_ms   = excluded.duration_ms",
                    turso::params_from_iter(src_params),
                )
                .await
                .context("upsert source")?;
            }
            upsert_meta(tx, "run_started_at", started_at).await?;
        }

        CarveEvent::SourceStarted { source_id } => {
            tx.execute(
                "UPDATE source SET status = 'Running' WHERE source_id = ?1",
                (Value::Integer(*source_id as i64),),
            )
            .await
            .context("update source status Running")?;
        }

        CarveEvent::FileFound {
            source_id,
            file,
            img_offset,
            written_path,
        } => {
            let byte_runs_json =
                serde_json::to_string(&file.byte_runs).unwrap_or_else(|_| "[]".into());
            let (
                jpeg_status,
                jpeg_width,
                jpeg_height,
                jpeg_fragmentation_point,
                jpeg_has_restart_markers,
            ) = match &file.jpeg_scan {
                Some(j) => {
                    let status_str = match j.status {
                        utmost_lib::types::JpegScanStatus::Complete => "complete",
                        utmost_lib::types::JpegScanStatus::Truncated => "truncated",
                        utmost_lib::types::JpegScanStatus::Fragmented => "fragmented",
                    };
                    (
                        Value::Text(status_str.to_owned()),
                        val_opt_i64(j.width.map(|w| w as i64)),
                        val_opt_i64(j.height.map(|h| h as i64)),
                        val_opt_i64(j.fragmentation_point_img_offset.map(|o| o as i64)),
                        Value::Integer(if j.has_restart_markers { 1 } else { 0 }),
                    )
                }
                None => (
                    Value::Null,
                    Value::Null,
                    Value::Null,
                    Value::Null,
                    Value::Null,
                ),
            };
            let params: Vec<Value> = vec![
                Value::Integer(file.file_id as i64),
                Value::Integer(*source_id as i64),
                Value::Text(file.filename.clone()),
                Value::Integer(file.filesize as i64),
                Value::Text(file.file_type.clone()),
                Value::Integer(*img_offset as i64),
                Value::Text(written_path.clone()),
                Value::Text(byte_runs_json),
                jpeg_status,
                jpeg_width,
                jpeg_height,
                jpeg_fragmentation_point,
                jpeg_has_restart_markers,
                Value::Text("unknown".into()),
            ];
            tx.execute(
                "INSERT INTO file \
                 (file_id, source_id, filename, filesize, file_type, img_offset, \
                  written_path, byte_runs_json, jpeg_status, jpeg_width, jpeg_height, \
                  jpeg_fragmentation_point, jpeg_has_restart_markers, preview_status) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                turso::params_from_iter(params),
            )
            .await
            .context("insert file")?;
            tx.execute(
                "UPDATE source SET files_found = files_found + 1 WHERE source_id = ?1",
                (Value::Integer(*source_id as i64),),
            )
            .await
            .context("increment source files_found")?;
            tx.execute(
                "UPDATE run SET total_files = total_files + 1 WHERE id = 1",
                (),
            )
            .await
            .context("increment run total_files")?;
        }

        CarveEvent::ProgressTick {
            source_id,
            bytes_read,
        } => {
            tx.execute(
                "UPDATE source SET bytes_read = ?1 WHERE source_id = ?2",
                (
                    Value::Integer(*bytes_read as i64),
                    Value::Integer(*source_id as i64),
                ),
            )
            .await
            .context("update source bytes_read")?;
        }

        CarveEvent::SourceFinished {
            source_id,
            bytes_read,
            duration_ms,
        } => {
            tx.execute(
                "UPDATE source \
                 SET status = 'Finished', bytes_read = ?1, duration_ms = ?2 \
                 WHERE source_id = ?3",
                (
                    Value::Integer(*bytes_read as i64),
                    Value::Integer(*duration_ms as i64),
                    Value::Integer(*source_id as i64),
                ),
            )
            .await
            .context("update source Finished")?;
        }

        CarveEvent::RunFinished { duration_ms, .. } => {
            tx.execute(
                "UPDATE run SET status = 'Finished', elapsed_ms = ?1 WHERE id = 1",
                (Value::Integer(*duration_ms as i64),),
            )
            .await
            .context("update run Finished")?;
        }

        CarveEvent::RecoveryStarted {
            started_at,
            keep_candidates,
            search_window,
            block_size,
            min_entropy_score,
            huffman_validation,
        } => {
            let params: Vec<Value> = vec![
                Value::Integer(1),
                Value::Text(started_at.clone()),
                Value::Integer(*keep_candidates as i64),
                Value::Integer(*search_window as i64),
                Value::Integer(*block_size as i64),
                Value::Real(*min_entropy_score),
                Value::Integer(if *huffman_validation { 1 } else { 0 }),
                Value::Null,
                Value::Null,
                Value::Null,
            ];
            tx.execute(
                "INSERT INTO recovery_run \
                 (id, started_at, keep_candidates, search_window, block_size, \
                  min_entropy_score, huffman_validation, finished_duration_ms, \
                  partials_processed, candidates_written) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
                 ON CONFLICT(id) DO UPDATE SET \
                   started_at           = excluded.started_at, \
                   keep_candidates      = excluded.keep_candidates, \
                   search_window        = excluded.search_window, \
                   block_size           = excluded.block_size, \
                   min_entropy_score    = excluded.min_entropy_score, \
                   huffman_validation   = excluded.huffman_validation, \
                   finished_duration_ms = excluded.finished_duration_ms, \
                   partials_processed   = excluded.partials_processed, \
                   candidates_written   = excluded.candidates_written",
                turso::params_from_iter(params),
            )
            .await
            .context("upsert recovery_run")?;
        }

        CarveEvent::RecoveryCandidate {
            original_file_id,
            candidate_file_id,
            rank,
            method,
            entropy_score,
            ff_validity_score,
            huffman_mcu_count,
            continuation_img_offset,
        } => {
            let method_str = match method {
                RecoveryMethod::DirectContinuation => "direct_continuation",
                RecoveryMethod::FragmentReassembly => "fragment_reassembly",
            };
            let params: Vec<Value> = vec![
                Value::Integer(*original_file_id as i64),
                Value::Integer(*candidate_file_id as i64),
                Value::Integer(*rank as i64),
                Value::Text(method_str.to_owned()),
                Value::Real(*entropy_score),
                val_opt_f64(*ff_validity_score),
                val_opt_i64(huffman_mcu_count.map(|c| c as i64)),
                Value::Integer(*continuation_img_offset as i64),
            ];
            tx.execute(
                "INSERT INTO variant \
                 (original_file_id, candidate_file_id, rank, method, entropy_score, \
                  ff_validity_score, huffman_mcu_count, continuation_img_offset) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                turso::params_from_iter(params),
            )
            .await
            .context("insert variant")?;
        }

        CarveEvent::RecoveryFinished {
            duration_ms,
            partials_processed,
            candidates_written,
        } => {
            tx.execute(
                "UPDATE recovery_run \
                 SET finished_duration_ms = ?1, \
                     partials_processed   = ?2, \
                     candidates_written   = ?3 \
                 WHERE id = 1",
                (
                    Value::Integer(*duration_ms as i64),
                    Value::Integer(*partials_processed as i64),
                    Value::Integer(*candidates_written as i64),
                ),
            )
            .await
            .context("update recovery_run Finished")?;
        }

        CarveEvent::Bookmark {
            file_id,
            bookmarked,
            at,
        } => {
            if *bookmarked {
                tx.execute(
                    "INSERT INTO bookmark (file_id, at) VALUES (?1, ?2) \
                     ON CONFLICT(file_id) DO UPDATE SET at = excluded.at",
                    (
                        Value::Integer(*file_id as i64),
                        Value::Text(at.clone()),
                    ),
                )
                .await
                .context("upsert bookmark")?;
            } else {
                tx.execute(
                    "DELETE FROM bookmark WHERE file_id = ?1",
                    (Value::Integer(*file_id as i64),),
                )
                .await
                .context("delete bookmark")?;
            }
        }

        CarveEvent::Note {
            note_id,
            file_id,
            text,
            at,
        } => {
            // Upsert on `note_id` so the row stays consistent if the same
            // event reaches `apply_event_on_tx` twice — once via the live
            // `apply_annotation_event` path (UI → indexer command) and once
            // again via the next-session `resume_from` after the journal is
            // folded into the main `.bin`.
            tx.execute(
                "INSERT INTO note (note_id, file_id, text, at) VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(note_id) DO UPDATE SET \
                   file_id = excluded.file_id, \
                   text    = excluded.text, \
                   at      = excluded.at",
                (
                    Value::Integer(*note_id as i64),
                    Value::Integer(*file_id as i64),
                    Value::Text(text.clone()),
                    Value::Text(at.clone()),
                ),
            )
            .await
            .context("upsert note")?;
        }

        CarveEvent::MarkAsBest {
            original_file_id,
            chosen_file_id,
            at,
        } => {
            tx.execute(
                "INSERT INTO best_choice (original_file_id, chosen_file_id, at) \
                 VALUES (?1, ?2, ?3) \
                 ON CONFLICT(original_file_id) DO UPDATE SET \
                   chosen_file_id = excluded.chosen_file_id, \
                   at             = excluded.at",
                (
                    Value::Integer(*original_file_id as i64),
                    Value::Integer(*chosen_file_id as i64),
                    Value::Text(at.clone()),
                ),
            )
            .await
            .context("upsert best_choice")?;
        }
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{block_on, IndexDb};
    use crate::model::{FilterStateSnapshot, PreviewCodec, UiStateSnapshot};
    use turso::Value;
    use utmost_lib::events::{CliConfigSnapshot, SourceDescriptor};
    use utmost_lib::types::ExecutionEnvironment;

    /// Build a minimal `RunStarted` event with one source.
    fn make_run_started(source_id: u32) -> CarveEvent {
        CarveEvent::RunStarted {
            utmost_version: "0.1.0".into(),
            format_version: 1,
            started_at: "2026-01-01T00:00:00Z".into(),
            command_line: vec!["utmost".into()],
            working_directory: "/tmp".into(),
            execution_environment: ExecutionEnvironment {
                os_sysname: "Linux".into(),
                os_release: "5.0".into(),
                os_version: "#1".into(),
                host: "host".into(),
                arch: "x86_64".into(),
                uid: 1000,
                start_time: "2026-01-01T00:00:00Z".into(),
            },
            cli_config: CliConfigSnapshot {
                output_directory: "/out".into(),
                types: vec![],
                disable_builtin: false,
                config_file: None,
                concurrent_files: 1,
                disable_validation: false,
                report_only: false,
                disable_report: false,
                disable_audit: false,
                disable_export: false,
                gui_enabled: false,
                quick: false,
                block_size: 512,
                prefix_filenames: false,
                write_all: false,
                keep_incomplete_jpeg: false,
            },
            case: None,
            configured_types: vec![],
            sources: vec![SourceDescriptor {
                source_id,
                filename: "test.img".into(),
                total_bytes: 1024,
                output_subdir: "out".into(),
            }],
            output_root: "/out".into(),
        }
    }

    /// Apply a `RunStarted` + `SourceStarted`, flush, then verify both rows
    /// landed in the DB with the expected status values.
    #[test]
    fn apply_flush_writes_run_started() {
        let db = IndexDb::open_in_memory().expect("open");
        let pool = db.pool().clone();

        let mut writer = IndexDbWriter::new(pool.clone(), 1000);
        writer
            .apply(make_run_started(1), 100)
            .expect("apply RunStarted");
        writer
            .apply(CarveEvent::SourceStarted { source_id: 1 }, 200)
            .expect("apply SourceStarted");
        writer.flush().expect("flush");

        block_on(async {
            let conn = pool.get().await.unwrap();

            let mut rows = conn
                .query("SELECT status FROM run WHERE id = 1", ())
                .await
                .unwrap();
            let row = rows.next().await.unwrap().expect("run row");
            assert_eq!(row.get_value(0).unwrap().as_text().unwrap(), "Running");

            let mut rows = conn
                .query("SELECT status FROM source WHERE source_id = 1", ())
                .await
                .unwrap();
            let row = rows.next().await.unwrap().expect("source row");
            assert_eq!(row.get_value(0).unwrap().as_text().unwrap(), "Running");
        });
    }

    /// `write_preview_outcomes` should update `file.preview_status`, insert a
    /// `preview_blob` row for `HasPreview` outcomes, and bump
    /// `meta.preview_status_version` on each call.
    #[test]
    fn write_preview_outcomes_bumps_version() {
        let db = IndexDb::open_in_memory().expect("open");
        let pool = db.pool().clone();

        // Seed a source and two file rows (FK: file → source).
        block_on(async {
            let conn = pool.get().await.unwrap();
            conn.execute(
                "INSERT INTO source \
                 (source_id, filename, output_subdir, total_bytes, bytes_read, files_found, status) \
                 VALUES (1, 'test.img', 'out', 1024, 0, 0, 'Running')",
                (),
            )
            .await
            .unwrap();
            conn.execute(
                "INSERT INTO file \
                 (file_id, source_id, filename, filesize, file_type, img_offset, \
                  written_path, byte_runs_json, preview_status) \
                 VALUES (42, 1, 'f0042.jpg', 1024, 'jpeg', 0, '/out/f0042.jpg', '[]', 'unknown')",
                (),
            )
            .await
            .unwrap();
            conn.execute(
                "INSERT INTO file \
                 (file_id, source_id, filename, filesize, file_type, img_offset, \
                  written_path, byte_runs_json, preview_status) \
                 VALUES (43, 1, 'f0043.pdf', 512, 'pdf', 1024, '/out/f0043.pdf', '[]', 'unknown')",
                (),
            )
            .await
            .unwrap();
        });

        let batch1 = vec![
            PreviewOutcome {
                file_id: 42,
                status: PreviewStatus::HasPreview {
                    codec: PreviewCodec::Jpeg,
                    width: 320,
                    height: 240,
                    bytes: vec![0xFF, 0xD8, 0xFF],
                },
            },
            PreviewOutcome {
                file_id: 43,
                status: PreviewStatus::NoPreview,
            },
        ];
        write_preview_outcomes(&pool, &batch1).expect("write batch1");

        block_on(async {
            let conn = pool.get().await.unwrap();

            let mut rows = conn
                .query("SELECT preview_status FROM file WHERE file_id = 42", ())
                .await
                .unwrap();
            let row = rows.next().await.unwrap().expect("file 42");
            assert_eq!(
                row.get_value(0).unwrap().as_text().unwrap(),
                "has_preview"
            );

            let mut rows = conn
                .query("SELECT preview_status FROM file WHERE file_id = 43", ())
                .await
                .unwrap();
            let row = rows.next().await.unwrap().expect("file 43");
            assert_eq!(
                row.get_value(0).unwrap().as_text().unwrap(),
                "no_preview"
            );

            let mut rows = conn
                .query("SELECT codec FROM preview_blob WHERE file_id = 42", ())
                .await
                .unwrap();
            let row = rows.next().await.unwrap().expect("preview_blob 42");
            assert_eq!(row.get_value(0).unwrap().as_text().unwrap(), "jpeg");

            let mut rows = conn
                .query(
                    "SELECT value FROM meta WHERE key = 'preview_status_version'",
                    (),
                )
                .await
                .unwrap();
            let row = rows.next().await.unwrap().expect("version row");
            assert_eq!(row.get_value(0).unwrap().as_text().unwrap(), "1");
        });

        // Second call must bump to "2".
        let batch2 = vec![PreviewOutcome {
            file_id: 42,
            status: PreviewStatus::HasPreview {
                codec: PreviewCodec::Jpeg,
                width: 640,
                height: 480,
                bytes: vec![0xFF, 0xD8, 0xFF, 0xE0],
            },
        }];
        write_preview_outcomes(&pool, &batch2).expect("write batch2");

        block_on(async {
            let conn = pool.get().await.unwrap();
            let mut rows = conn
                .query(
                    "SELECT value FROM meta WHERE key = 'preview_status_version'",
                    (),
                )
                .await
                .unwrap();
            let row = rows.next().await.unwrap().expect("version row");
            assert_eq!(row.get_value(0).unwrap().as_text().unwrap(), "2");
        });
    }

    /// Round-trip: write a snapshot, read it back, assert equality.
    #[test]
    fn write_read_ui_state_round_trips() {
        let db = IndexDb::open_in_memory().expect("open");
        let pool = db.pool().clone();

        let snap = UiStateSnapshot {
            v: 1,
            filter: FilterStateSnapshot {
                enabled_types: vec!["jpeg".into(), "pdf".into()],
                enabled_partial_types: vec![],
                bookmarked_only: true,
                source_filter: Some(2),
                sort_key: "Size".into(),
                sort_dir: "Desc".into(),
                bookmarked_first: false,
                hide_no_preview: true,
                size_range: Some((10, 1000)),
            },
            filters_visible: false,
            selected_group: Some("image".into()),
            selection_file_id: Some(42),
        };

        write_ui_state(&pool, &snap).expect("write_ui_state");
        let got = read_ui_state(&pool).expect("read_ui_state").expect("present");
        assert_eq!(got, snap);
    }

    /// When `meta.ui_state` has never been written, `read_ui_state` returns `None`.
    #[test]
    fn read_ui_state_returns_none_when_missing() {
        let db = IndexDb::open_in_memory().expect("open");
        let pool = db.pool().clone();
        assert!(read_ui_state(&pool).expect("read_ui_state").is_none());
    }

    /// A corrupt JSON blob in `meta.ui_state` must produce `Ok(None)`, not an error.
    #[test]
    fn read_ui_state_returns_none_for_corrupt_blob() {
        let db = IndexDb::open_in_memory().expect("open");
        let pool = db.pool().clone();

        block_on(async {
            let conn = pool.get().await.unwrap();
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('ui_state', '{not json')",
                (),
            )
            .await
            .unwrap();
        });

        let got = read_ui_state(&pool).expect("must not error on corrupt blob");
        assert!(got.is_none());
    }

    // ── set_clip_embedding tests ──────────────────────────────────────────────

    const LAION_MODEL: &str = "laion/CLIP-ViT-L-14-laion2B-s32B-b82K";

    /// Seed a source, `n` file rows with preview_blobs.
    fn seed_files_with_blobs(pool: &crate::db::TursoPool, n: i64) {
        block_on(async {
            let conn = pool.get().await.unwrap();
            conn.execute(
                "INSERT INTO source \
                 (source_id, filename, output_subdir, total_bytes, bytes_read, \
                  files_found, status) \
                 VALUES (1, 'test.img', 'out', 1024, 0, 0, 'Running')",
                (),
            )
            .await
            .unwrap();
            for id in 1..=n {
                conn.execute(
                    "INSERT INTO file \
                     (file_id, source_id, filename, filesize, file_type, img_offset, \
                      written_path, byte_runs_json, preview_status) \
                     VALUES (?1, 1, 'f.jpg', 1024, 'jpeg', 0, 'out/f.jpg', '[]', 'has_preview')",
                    (Value::Integer(id),),
                )
                .await
                .unwrap();
                conn.execute(
                    "INSERT INTO preview_blob (file_id, codec, width, height, bytes) \
                     VALUES (?1, 'jpeg', 1, 1, ?2)",
                    turso::params_from_iter(vec![
                        Value::Integer(id),
                        Value::Blob(vec![0xFF, 0xD8, 0xFF]),
                    ]),
                )
                .await
                .unwrap();
            }
        });
    }

    /// `set_clip_embedding` must decrease the without-embedding count to zero
    /// as each file is embedded.
    #[test]
    fn set_clip_embedding_upserts_and_count_drops_to_zero() {
        let db = IndexDb::open_in_memory().expect("open");
        let pool = db.pool().clone();
        seed_files_with_blobs(&pool, 2);

        // Both files lack embeddings → count = 2.
        let count =
            crate::db::queries::count_files_without_embedding(&pool, LAION_MODEL).expect("count");
        assert_eq!(count, 2);

        // Embed file 1 → count = 1.
        set_clip_embedding(&pool, 1, LAION_MODEL, &[0.1f32; 768]).expect("embed file 1");
        let count =
            crate::db::queries::count_files_without_embedding(&pool, LAION_MODEL).expect("count 2");
        assert_eq!(count, 1);

        // Embed file 2 → count = 0.
        set_clip_embedding(&pool, 2, LAION_MODEL, &[0.2f32; 768]).expect("embed file 2");
        let count =
            crate::db::queries::count_files_without_embedding(&pool, LAION_MODEL).expect("count 3");
        assert_eq!(count, 0);
    }

    /// Calling `set_clip_embedding` twice for the same file must not error,
    /// must leave the without-embedding count at zero (idempotent upsert), and
    /// the **second write must win** — the stored embedding bytes must equal
    /// `[0.2f32; 768]`, not the first-write value `[0.1f32; 768]`.
    #[test]
    fn set_clip_embedding_is_idempotent() {
        let db = IndexDb::open_in_memory().expect("open");
        let pool = db.pool().clone();
        seed_files_with_blobs(&pool, 1);

        set_clip_embedding(&pool, 1, LAION_MODEL, &[0.1f32; 768]).expect("first embed");
        set_clip_embedding(&pool, 1, LAION_MODEL, &[0.2f32; 768])
            .expect("second embed must not error");
        let count =
            crate::db::queries::count_files_without_embedding(&pool, LAION_MODEL).expect("count");
        assert_eq!(count, 0, "count must be 0 after two calls");

        // Read back the raw LE bytes and confirm the second write won.
        let stored = block_on(async {
            let conn = pool.get().await.unwrap();
            let mut rows = conn
                .query(
                    "SELECT embedding FROM clip_embedding WHERE file_id = 1",
                    (),
                )
                .await
                .unwrap();
            let row = rows.next().await.unwrap().expect("embedding row must exist");
            col_blob(&row, 0, "embedding").unwrap()
        });
        let floats: Vec<f32> = stored
            .chunks_exact(4)
            .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .collect();
        assert_eq!(floats.len(), 768, "expected 768 f32 values");
        for (i, &val) in floats.iter().enumerate() {
            assert!(
                (val - 0.2_f32).abs() < 1e-6,
                "float[{i}]: got {val}, expected 0.2 — second write must win"
            );
        }
    }

    /// Embedding a file under one model must not affect the missing-embedding
    /// count for a different model.
    #[test]
    fn set_clip_embedding_model_relative() {
        let db = IndexDb::open_in_memory().expect("open");
        let pool = db.pool().clone();
        seed_files_with_blobs(&pool, 1);

        let other_model = "other-model";
        // Embed file 1 under other-model only.
        set_clip_embedding(&pool, 1, other_model, &[0.5f32; 768]).expect("embed under other");

        // Count for LAION model must still be 1 (no embedding stored for it).
        let laion_count =
            crate::db::queries::count_files_without_embedding(&pool, LAION_MODEL).expect("laion");
        assert_eq!(laion_count, 1, "LAION model count should still be 1");

        // Count for other-model must be 0 (embedding was stored).
        let other_count =
            crate::db::queries::count_files_without_embedding(&pool, other_model).expect("other");
        assert_eq!(other_count, 0, "other-model count should be 0");
    }
}
