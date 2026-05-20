//! Transactional writer that folds [`CarveEvent`]s into the SQLite index.
//!
//! Events are buffered in memory and flushed as a single transaction. Each
//! flush also advances the `last_event_offset` / `last_event_count` /
//! `indexed_at` meta keys so the on-disk index identity stays in sync with
//! the bincode event log.

use anyhow::{Context, Result};
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use utmost_lib::events::CarveEvent;

use crate::index_db::models::*;
use crate::index_db::schema;
use crate::thumb_worker::{PreviewOutcome, PreviewStatus};

pub struct IndexDbWriter<'a> {
    conn: &'a mut SqliteConnection,
    pending: Vec<PendingEvent>,
    batch_size: usize,
    total_count: i64,
}

struct PendingEvent {
    event: CarveEvent,
    offset_after: u64,
}

impl<'a> IndexDbWriter<'a> {
    pub fn new(conn: &'a mut SqliteConnection, batch_size: usize) -> Self {
        let total_count = read_meta_i64(conn, "last_event_count").unwrap_or(0);
        Self {
            conn,
            pending: Vec::new(),
            batch_size,
            total_count,
        }
    }

    /// Buffer `event` for the next flush. `offset_after` is the
    /// `BincodeFileReader::byte_offset()` immediately after the event was
    /// successfully decoded — i.e. the position from which the *next* event
    /// would be read.
    pub fn apply(&mut self, event: CarveEvent, offset_after: u64) -> Result<()> {
        self.pending.push(PendingEvent {
            event,
            offset_after,
        });
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

        self.conn
            .transaction::<_, diesel::result::Error, _>(|tx| {
                for p in &pending {
                    apply_event(tx, &p.event)?;
                }
                upsert_meta(tx, "last_event_offset", &new_offset.to_string())?;
                upsert_meta(tx, "last_event_count", &new_count.to_string())?;
                upsert_meta(tx, "indexed_at", &chrono::Utc::now().to_rfc3339())?;
                Ok(())
            })
            .context("flushing index batch")?;

        self.total_count = new_count;
        Ok(())
    }
}

/// Persist a batch of preview outcomes from `ThumbWorker` into the
/// `file.preview_status` column and atomically bump the
/// `preview_status_version` meta key. Callers batch outcomes upstream
/// (every 100 outcomes or 500 ms) so SQLite sees roughly the same
/// write cadence as the event-fold batches.
///
/// All updates and the version bump run inside one transaction so a
/// crash mid-flush leaves both the rows and the version key in their
/// pre-flush state — readers polling `preview_status_version` can use
/// it as a reliable change marker.
pub fn write_preview_outcomes(
    conn: &mut SqliteConnection,
    batch: &[PreviewOutcome],
) -> diesel::QueryResult<()> {
    use crate::index_db::schema::file::dsl as f;
    use crate::index_db::schema::meta::dsl as m;
    if batch.is_empty() {
        return Ok(());
    }
    conn.transaction(|tx| {
        for outcome in batch {
            let s = match outcome.status {
                PreviewStatus::HasPreview => "has_preview",
                PreviewStatus::NoPreview => "no_preview",
            };
            diesel::update(f::file.find(outcome.file_id as i64))
                .set(f::preview_status.eq(s))
                .execute(tx)?;
        }
        let cur: String = m::meta
            .find("preview_status_version")
            .select(m::value)
            .first(tx)?;
        let next: u64 = cur.parse::<u64>().unwrap_or(0) + 1;
        diesel::update(m::meta.find("preview_status_version"))
            .set(m::value.eq(next.to_string()))
            .execute(tx)?;
        Ok(())
    })
}

fn read_meta_i64(conn: &mut SqliteConnection, key: &str) -> Option<i64> {
    schema::meta::table
        .filter(schema::meta::key.eq(key))
        .select(schema::meta::value)
        .first::<String>(conn)
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
}

fn upsert_meta(
    tx: &mut SqliteConnection,
    key: &str,
    value: &str,
) -> diesel::result::QueryResult<()> {
    // SQLite upsert via ON CONFLICT.
    diesel::sql_query(
        "INSERT INTO meta (key, value) VALUES (?, ?) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind::<diesel::sql_types::Text, _>(key)
    .bind::<diesel::sql_types::Text, _>(value)
    .execute(tx)?;
    Ok(())
}

/// Apply a single annotation event (`Bookmark`, `Note`, `MarkAsBest`) to
/// SQLite outside of a batch. Used by the live-mode path where the UI
/// generates an annotation that needs to be visible to filter/sort queries
/// *immediately*, without waiting for the journal fold at `RunFinished`.
///
/// The handler routes the event through [`apply_event`], same as the batched
/// `IndexDbWriter::flush`, so the row-level write logic stays in one place.
/// Unlike `IndexDbWriter::flush`, this function does NOT advance
/// `last_event_offset` / `last_event_count` — those keys track the engine's
/// main `.bin` log only, and these annotation events still live in the
/// journal's `.pending` until `RunFinished` folds them. The fold + next
/// session's `resume_from` will re-apply each event via `apply_event` again,
/// which is why every annotation variant's INSERT in `apply_event` uses an
/// idempotent `on_conflict` upsert.
pub fn apply_annotation_event(
    conn: &mut SqliteConnection,
    event: &CarveEvent,
) -> diesel::result::QueryResult<()> {
    conn.transaction(|tx| apply_event(tx, event))
}

fn apply_event(tx: &mut SqliteConnection, event: &CarveEvent) -> diesel::result::QueryResult<()> {
    // Exhaustive over `CarveEvent`: adding a new variant must force an
    // explicit decision here. `ProgressTick` is stream-only and is handled
    // in-place to update `source.bytes_read` without any other row writes.
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
            let new_run = NewRun {
                id: 1,
                started_at: started_at.clone(),
                output_root: output_root.clone(),
                source_image_path,
                configured_types_json: serde_json::to_string(configured_types)
                    .unwrap_or_else(|_| "[]".into()),
                case_id: case.as_ref().and_then(|c| c.case_id.clone()),
                examiner: case.as_ref().and_then(|c| c.examiner.clone()),
                evidence_id: case.as_ref().and_then(|c| c.evidence_id.clone()),
                case_notes: case.as_ref().and_then(|c| c.notes.clone()),
                status: "Running".into(),
                elapsed_ms: 0,
                total_files: 0,
            };
            diesel::insert_into(schema::run::table)
                .values(&new_run)
                .on_conflict(schema::run::id)
                .do_update()
                .set(&new_run)
                .execute(tx)?;
            for s in sources {
                let new_src = NewSource {
                    source_id: s.source_id as i32,
                    filename: s.filename.clone(),
                    output_subdir: s.output_subdir.clone(),
                    total_bytes: s.total_bytes as i64,
                    bytes_read: 0,
                    files_found: 0,
                    status: "Pending".into(),
                    duration_ms: None,
                };
                diesel::insert_into(schema::source::table)
                    .values(&new_src)
                    .on_conflict(schema::source::source_id)
                    .do_update()
                    .set(&new_src)
                    .execute(tx)?;
            }
            upsert_meta(tx, "run_started_at", started_at)?;
        }
        CarveEvent::SourceStarted { source_id } => {
            diesel::update(schema::source::table.find(*source_id as i32))
                .set(schema::source::status.eq("Running"))
                .execute(tx)?;
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
                Some(j) => (
                    Some(
                        match j.status {
                            utmost_lib::types::JpegScanStatus::Complete => "complete",
                            utmost_lib::types::JpegScanStatus::Truncated => "truncated",
                            utmost_lib::types::JpegScanStatus::Fragmented => "fragmented",
                        }
                        .to_string(),
                    ),
                    j.width.map(|w| w as i32),
                    j.height.map(|h| h as i32),
                    j.fragmentation_point_img_offset.map(|o| o as i64),
                    Some(if j.has_restart_markers { 1 } else { 0 }),
                ),
                None => (None, None, None, None, None),
            };
            let new_file = NewFile {
                file_id: file.file_id as i64,
                source_id: *source_id as i32,
                filename: file.filename.clone(),
                filesize: file.filesize as i64,
                file_type: file.file_type.clone(),
                img_offset: *img_offset as i64,
                written_path: written_path.clone(),
                byte_runs_json,
                jpeg_status,
                jpeg_width,
                jpeg_height,
                jpeg_fragmentation_point,
                jpeg_has_restart_markers,
                preview_status: "unknown".to_string(),
            };
            diesel::insert_into(schema::file::table)
                .values(&new_file)
                .execute(tx)?;
            diesel::update(schema::source::table.find(*source_id as i32))
                .set(schema::source::files_found.eq(schema::source::files_found + 1))
                .execute(tx)?;
            diesel::update(schema::run::table.find(1i32))
                .set(schema::run::total_files.eq(schema::run::total_files + 1))
                .execute(tx)?;
        }
        CarveEvent::ProgressTick {
            source_id,
            bytes_read,
        } => {
            diesel::update(schema::source::table.find(*source_id as i32))
                .set(schema::source::bytes_read.eq(*bytes_read as i64))
                .execute(tx)?;
        }
        CarveEvent::SourceFinished {
            source_id,
            bytes_read,
            duration_ms,
        } => {
            diesel::update(schema::source::table.find(*source_id as i32))
                .set((
                    schema::source::status.eq("Finished"),
                    schema::source::bytes_read.eq(*bytes_read as i64),
                    schema::source::duration_ms.eq(Some(*duration_ms as i64)),
                ))
                .execute(tx)?;
        }
        CarveEvent::RunFinished {
            duration_ms,
            total_files_written: _,
        } => {
            diesel::update(schema::run::table.find(1i32))
                .set((
                    schema::run::status.eq("Finished"),
                    schema::run::elapsed_ms.eq(*duration_ms as i64),
                ))
                .execute(tx)?;
        }
        CarveEvent::RecoveryStarted {
            started_at,
            keep_candidates,
            search_window,
            block_size,
            min_entropy_score,
            huffman_validation,
        } => {
            let new_rec = NewRecoveryRun {
                id: 1,
                started_at: started_at.clone(),
                keep_candidates: *keep_candidates as i32,
                search_window: *search_window as i64,
                block_size: *block_size as i32,
                min_entropy_score: *min_entropy_score,
                huffman_validation: if *huffman_validation { 1 } else { 0 },
                finished_duration_ms: None,
                partials_processed: None,
                candidates_written: None,
            };
            diesel::insert_into(schema::recovery_run::table)
                .values(&new_rec)
                .on_conflict(schema::recovery_run::id)
                .do_update()
                .set(&new_rec)
                .execute(tx)?;
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
                utmost_lib::events::RecoveryMethod::DirectContinuation => "direct_continuation",
                utmost_lib::events::RecoveryMethod::FragmentReassembly => "fragment_reassembly",
            };
            let new_var = NewVariant {
                original_file_id: *original_file_id as i64,
                candidate_file_id: *candidate_file_id as i64,
                rank: *rank as i32,
                method: method_str.into(),
                entropy_score: *entropy_score,
                ff_validity_score: *ff_validity_score,
                huffman_mcu_count: huffman_mcu_count.map(|c| c as i32),
                continuation_img_offset: *continuation_img_offset as i64,
            };
            diesel::insert_into(schema::variant::table)
                .values(&new_var)
                .execute(tx)?;
        }
        CarveEvent::RecoveryFinished {
            duration_ms,
            partials_processed,
            candidates_written,
        } => {
            diesel::update(schema::recovery_run::table.find(1i32))
                .set((
                    schema::recovery_run::finished_duration_ms.eq(Some(*duration_ms as i64)),
                    schema::recovery_run::partials_processed.eq(Some(*partials_processed as i32)),
                    schema::recovery_run::candidates_written.eq(Some(*candidates_written as i32)),
                ))
                .execute(tx)?;
        }
        CarveEvent::Bookmark {
            file_id,
            bookmarked,
            at,
        } => {
            if *bookmarked {
                let new_bm = NewBookmark {
                    file_id: *file_id as i64,
                    at: at.clone(),
                };
                diesel::insert_into(schema::bookmark::table)
                    .values(&new_bm)
                    .on_conflict(schema::bookmark::file_id)
                    .do_update()
                    .set(schema::bookmark::at.eq(at.clone()))
                    .execute(tx)?;
            } else {
                diesel::delete(schema::bookmark::table.find(*file_id as i64)).execute(tx)?;
            }
        }
        CarveEvent::Note {
            note_id,
            file_id,
            text,
            at,
        } => {
            let new_note = NewNote {
                note_id: *note_id as i64,
                file_id: *file_id as i64,
                text: text.clone(),
                at: at.clone(),
            };
            // Upsert on `note_id` so the row stays consistent if the same
            // event reaches `apply_event` twice — once via the live
            // [`apply_annotation_event`] path (UI → indexer command) and once
            // again via the next-session `resume_from` after the journal is
            // folded into the main `.bin`. Bookmark / MarkAsBest are already
            // idempotent (`on_conflict`); this matches them.
            diesel::insert_into(schema::note::table)
                .values(&new_note)
                .on_conflict(schema::note::note_id)
                .do_update()
                .set((
                    schema::note::file_id.eq(*file_id as i64),
                    schema::note::text.eq(text.clone()),
                    schema::note::at.eq(at.clone()),
                ))
                .execute(tx)?;
        }
        CarveEvent::MarkAsBest {
            original_file_id,
            chosen_file_id,
            at,
        } => {
            let row = NewBestChoice {
                original_file_id: *original_file_id as i64,
                chosen_file_id: *chosen_file_id as i64,
                at: at.clone(),
            };
            diesel::insert_into(schema::best_choice::table)
                .values(&row)
                .on_conflict(schema::best_choice::original_file_id)
                .do_update()
                .set((
                    schema::best_choice::chosen_file_id.eq(*chosen_file_id as i64),
                    schema::best_choice::at.eq(at.clone()),
                ))
                .execute(tx)?;
        }
    }
    Ok(())
}
