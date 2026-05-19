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

fn apply_event(tx: &mut SqliteConnection, event: &CarveEvent) -> diesel::result::QueryResult<()> {
    // Match arms for the remaining `CarveEvent` variants land in Tasks
    // 3.3 – 3.13.
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
        // Subsequent event variants added in later tasks.
        _ => {}
    }
    Ok(())
}
