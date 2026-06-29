//! Two-phase processing engine: preview rendering and CLIP embedding.
//!
//! ## Phase 1 — Previews
//!
//! For each image file whose `preview_status = 'unknown'`, render a thumbnail
//! via [`render_with_fallback`], encode it to JPEG, and persist a
//! `preview_blob` row (which also sets `file.preview_status`).  Files that
//! can't be rendered (source missing, decode error, non-image output) are
//! marked `'no_preview'` so they are not retried on subsequent runs.
//!
//! ## Phase 2 — Embeddings (`clip` feature only)
//!
//! For each file that has a `preview_blob` but no `clip_embedding` row for the
//! active model, run the embedder on the **persisted blob bytes** and persist
//! the normalised vector via [`set_clip_embedding`].
//!
//! **Load-bearing ordering guarantee:** embeddings are ALWAYS computed from the
//! persisted `preview_blob` bytes, never from re-rendered pixels.  The Previews
//! phase runs first to ensure the blob exists.
//!
//! ## Entry points
//!
//! | Function | Used by |
//! |---|---|
//! | [`run_to_completion`] | CLI `process` command |
//! | [`process_next_batch`] | GUI progress-bar worker |
//! | [`process_previews_batch`] / [`process_embeddings_batch`] | Direct / tests |

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};

use crate::db::models;
#[cfg(feature = "clip")]
use crate::db::queries::get_files_without_embedding;
use crate::db::queries::{
    count_files_without_embedding, count_files_without_preview, get_files_without_preview,
};
#[cfg(feature = "clip")]
use crate::db::writer::set_clip_embedding;
use crate::db::writer::write_preview_outcomes;
use crate::db::{TursoPool, block_on};
use crate::model::{PreviewCodec, PreviewOutcome, PreviewStatus, parse_file_type};
use crate::preview::{PreviewOutput, PreviewRegistry, encode_thumb_to_jpeg, render_with_fallback};
use crate::source_resolver::SourceResolver;

// ── Phase selector ────────────────────────────────────────────────────────────

/// Identifies which processing phase is being executed or reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessPhase {
    /// Thumbnail rendering: image files → `preview_blob` rows.
    Previews,
    /// CLIP embedding: `preview_blob` rows → `clip_embedding` rows.
    Embeddings,
}

// ── Process counts ────────────────────────────────────────────────────────────

/// Remaining work counts for both phases, supplied to progress callbacks.
pub struct ProcessCounts {
    /// Files with `preview_status = 'unknown'` still needing a thumbnail.
    pub previews_remaining: usize,
    /// Files with a `preview_blob` but no `clip_embedding` for `model`.
    pub embeddings_remaining: usize,
}

impl ProcessCounts {
    /// Load current remaining counts from the index database.
    ///
    /// `model` is forwarded to [`count_files_without_embedding`]; the SQL
    /// executes unconditionally — the result is just not acted on when the
    /// `clip` feature is disabled.
    pub fn load(pool: &TursoPool, model: &str) -> Result<Self> {
        let previews_remaining = count_files_without_preview(pool)?;
        let embeddings_remaining = count_files_without_embedding(pool, model)?;
        Ok(Self {
            previews_remaining,
            embeddings_remaining,
        })
    }
}

// ── Batch outcome ─────────────────────────────────────────────────────────────

/// Result of a single processing batch.
pub struct BatchOutcome {
    /// Number of files actually processed in this batch.
    pub processed: usize,
    /// Number of files still pending after this batch.
    pub remaining: usize,
}

// ── Preview context ───────────────────────────────────────────────────────────

/// Rendering dependencies required by the Previews phase.
///
/// Construct via [`PreviewContext::from_case`] (reads everything from the DB)
/// or via [`PreviewContext::new`] (for GUI callers that already hold a
/// `SourceResolver` and `PreviewRegistry`, or for tests).
pub struct PreviewContext {
    registry: Arc<PreviewRegistry>,
    resolver: Arc<SourceResolver>,
    /// Maps `source_id → recorded source filename` — mirrors the
    /// `SourcesByIdMap` that `ThumbWorker` maintains.
    sources_by_id: HashMap<u32, String>,
}

impl PreviewContext {
    /// Build a `PreviewContext` by reading the case's `source` table.
    ///
    /// Constructs a [`SourceResolver`] whose search locations are the
    /// recorded source filenames (absolute paths work via the resolver's
    /// "recorded path as-is" step; relative paths may not resolve).  The
    /// resolver is only consulted when a file's `written_path` does not exist
    /// on disk — i.e. report-only carves or moved output directories.
    pub fn from_case(pool: &TursoPool) -> Result<Self> {
        let pool2 = pool.clone();
        let sources_by_id = block_on(async move {
            let conn = pool2
                .get()
                .await
                .context("get conn for PreviewContext::from_case")?;

            let mut map: HashMap<u32, String> = HashMap::new();
            let mut rows = conn
                .query(
                    "SELECT source_id, filename FROM source ORDER BY source_id",
                    (),
                )
                .await
                .context("from_case: read source rows")?;
            while let Some(row) = rows.next().await? {
                let sid = models::col_i64(&row, 0, "source_id")? as u32;
                let fname = models::col_text(&row, 1, "filename")?;
                map.insert(sid, fname);
            }
            anyhow::Ok(map)
        })?;

        let search_locations: Vec<PathBuf> = sources_by_id.values().map(PathBuf::from).collect();
        let resolver = Arc::new(SourceResolver::new(search_locations, None));
        let registry = Arc::new(PreviewRegistry::with_defaults_and_jpeg());

        Ok(Self {
            registry,
            resolver,
            sources_by_id,
        })
    }

    /// Construct from explicitly supplied parts.
    ///
    /// Used by the GUI (`SlintAdapter` already holds a `PreviewRegistry` and
    /// `SourceResolver`) and by tests.
    pub fn new(
        registry: Arc<PreviewRegistry>,
        resolver: Arc<SourceResolver>,
        sources_by_id: HashMap<u32, String>,
    ) -> Self {
        Self {
            registry,
            resolver,
            sources_by_id,
        }
    }
}

// ── Phase functions ───────────────────────────────────────────────────────────

/// Render up to `batch_size` unpreviewd image files, persist outcomes, and
/// return how many were processed and how many remain.
///
/// Mirrors the `ThumbWorker` slow path exactly:
/// - `render_with_fallback` succeeds with `Image` → `encode_thumb_to_jpeg` →
///   `HasPreview` outcome.
/// - Render error, encode error, or non-`Image` output → `NoPreview` outcome
///   (file is not retried on subsequent runs).
pub fn process_previews_batch(
    pool: &TursoPool,
    ctx: &PreviewContext,
    batch_size: usize,
) -> Result<BatchOutcome> {
    let files = get_files_without_preview(pool, batch_size)?;
    if files.is_empty() {
        return Ok(BatchOutcome {
            processed: 0,
            remaining: 0,
        });
    }
    let processed = files.len();
    let mut batch: Vec<PreviewOutcome> = Vec::with_capacity(processed);

    for file in &files {
        let Some(ft) = parse_file_type(&file.file.file_type) else {
            tracing::warn!(
                file_id = %file.id,
                file_type = %file.file.file_type,
                "process_previews_batch: unrecognised file_type; marking NoPreview"
            );
            batch.push(PreviewOutcome {
                file_id: file.id,
                status: PreviewStatus::NoPreview,
            });
            continue;
        };

        let outcome = match render_with_fallback(
            &ctx.registry,
            &ctx.resolver,
            &ctx.sources_by_id,
            ft,
            &file.written_path,
            file,
        ) {
            Ok(PreviewOutput::Image(img)) => {
                let (w, h) = (img.width(), img.height());
                let pixels = img.into_raw();
                match encode_thumb_to_jpeg(&pixels, w, h) {
                    Ok(bytes) => PreviewOutcome {
                        file_id: file.id,
                        status: PreviewStatus::HasPreview {
                            codec: PreviewCodec::Jpeg,
                            width: w,
                            height: h,
                            bytes,
                        },
                    },
                    Err(e) => {
                        // Decode succeeded but encode failed.  This intentionally
                        // diverges from `ThumbWorker`: the interactive GUI emits
                        // *no* outcome on encode failure, leaving
                        // `preview_status = 'unknown'` so the file is retried on
                        // the next case open (once the encoder is fixed the image
                        // appears automatically).  A batch engine cannot afford
                        // that policy — it would re-drain every encode failure on
                        // every run.  Emitting `NoPreview` here stops re-processing
                        // at the cost of a manual DB cleanup
                        // (`UPDATE file SET preview_status='unknown' WHERE
                        // preview_status='no_preview'`) if the encoder is later
                        // fixed.  Log at warn so operators can track regressions.
                        tracing::warn!(
                            file_id = %file.id,
                            "process_previews_batch: encode_thumb_to_jpeg failed: {e:#}; \
                             marking NoPreview (decode succeeded; blob not persisted)"
                        );
                        PreviewOutcome {
                            file_id: file.id,
                            status: PreviewStatus::NoPreview,
                        }
                    }
                }
            }
            // Non-image output (Icon, Text, HexDump) or render error.
            Ok(_) => PreviewOutcome {
                file_id: file.id,
                status: PreviewStatus::NoPreview,
            },
            Err(e) => {
                tracing::debug!(
                    file_id = %file.id,
                    "process_previews_batch: render_with_fallback failed: {e:#}; marking NoPreview"
                );
                PreviewOutcome {
                    file_id: file.id,
                    status: PreviewStatus::NoPreview,
                }
            }
        };
        batch.push(outcome);
    }

    write_preview_outcomes(pool, &batch)?;
    let remaining = count_files_without_preview(pool)?;
    Ok(BatchOutcome {
        processed,
        remaining,
    })
}

/// Embed up to `batch_size` files that have a preview blob but no CLIP
/// embedding for `model`.
///
/// **Load-bearing contract:** the embedder receives `preview_blob.bytes` (the
/// persisted JPEG thumbnail), never re-rendered pixels.  Call
/// [`process_previews_batch`] to completion before calling this.
#[cfg(feature = "clip")]
pub fn process_embeddings_batch(
    pool: &TursoPool,
    embedder: &dyn crate::clip::EmbedFn,
    model: &str,
    batch_size: usize,
) -> Result<BatchOutcome> {
    let pairs = get_files_without_embedding(pool, model, batch_size)?;
    if pairs.is_empty() {
        return Ok(BatchOutcome {
            processed: 0,
            remaining: 0,
        });
    }
    let processed = pairs.len();

    for (file_id, blob) in &pairs {
        let raw = embedder
            .embed_image(&blob.bytes)
            .with_context(|| format!("embed_image for file_id={file_id}"))?;
        let normalized = crate::clip::normalize_vector(&raw);
        set_clip_embedding(pool, *file_id, model, &normalized)
            .with_context(|| format!("set_clip_embedding for file_id={file_id}"))?;
    }

    let remaining = count_files_without_embedding(pool, model)?;
    Ok(BatchOutcome {
        processed,
        remaining,
    })
}

// ── Orchestration ─────────────────────────────────────────────────────────────

/// Processing options for [`run_to_completion`].
pub struct ProcessOpts {
    /// Maximum files to process per batch.
    pub batch_size: usize,
    /// When `true` and the `clip` feature is enabled and an `embedder` is
    /// supplied, run the Embeddings phase after Previews.
    pub embeddings: bool,
}

/// Dispatch one batch for the requested phase and return the outcome.
///
/// When the `clip` feature is disabled, the [`ProcessPhase::Embeddings`] arm
/// is a no-op that returns `processed = 0, remaining = 0`.
///
/// **`#[cfg(feature = "clip")]` call-site requirement:** `embedder` and `model`
/// are absent from the signature when the `clip` feature is disabled; callers
/// (CLI `process`, GUI worker) must gate those arguments with the same
/// `#[cfg(feature = "clip")]` attribute at every call site.
pub fn process_next_batch(
    pool: &TursoPool,
    ctx: Option<&PreviewContext>,
    #[cfg(feature = "clip")] embedder: Option<&dyn crate::clip::EmbedFn>,
    #[cfg(feature = "clip")] model: &str,
    phase: ProcessPhase,
    batch_size: usize,
) -> Result<BatchOutcome> {
    match phase {
        ProcessPhase::Previews => {
            let ctx = ctx.context("process_next_batch(Previews) requires a PreviewContext")?;
            process_previews_batch(pool, ctx, batch_size)
        }
        ProcessPhase::Embeddings => {
            #[cfg(feature = "clip")]
            {
                match embedder {
                    Some(emb) => process_embeddings_batch(pool, emb, model, batch_size),
                    None => Ok(BatchOutcome {
                        processed: 0,
                        remaining: count_files_without_embedding(pool, model)?,
                    }),
                }
            }
            #[cfg(not(feature = "clip"))]
            {
                Ok(BatchOutcome {
                    processed: 0,
                    remaining: 0,
                })
            }
        }
    }
}

/// Run both processing phases to completion.
///
/// Calls `progress(phase, counts)` before each batch, where `counts` reflects
/// the state at the start of that batch.  Processing stops as soon as each
/// phase is drained.
///
/// ```text
/// Phase 1: loop { if previews_remaining == 0 { break }
///                 progress(Previews, counts);
///                 process_previews_batch(…); }
/// Phase 2: loop { if embeddings_remaining == 0 { break }
///                 progress(Embeddings, counts);
///                 process_embeddings_batch(…); }
/// ```
///
/// Phase 2 only runs when **all** of the following hold:
/// - `opts.embeddings` is `true`
/// - The `clip` feature is enabled
/// - `embedder` is `Some`
///
/// **`#[cfg(feature = "clip")]` call-site requirement:** `embedder` and `model`
/// are absent from the signature when the `clip` feature is disabled; callers
/// (CLI `process`, GUI worker) must gate those arguments with the same
/// `#[cfg(feature = "clip")]` attribute at every call site.
pub fn run_to_completion(
    pool: &TursoPool,
    ctx: &PreviewContext,
    #[cfg(feature = "clip")] embedder: Option<&dyn crate::clip::EmbedFn>,
    #[cfg(feature = "clip")] model: &str,
    opts: ProcessOpts,
    progress: &mut dyn FnMut(ProcessPhase, ProcessCounts),
) -> Result<()> {
    // Model string for ProcessCounts::load — uses the actual model when clip is
    // enabled so the `embeddings_remaining` value in progress callbacks is
    // meaningful.  Falls back to an empty string when the clip feature is off
    // (the embeddings count is still computed but never acted on).
    #[cfg(feature = "clip")]
    let model_for_count = model;
    #[cfg(not(feature = "clip"))]
    let model_for_count = "";

    // Phase 1: Previews.
    loop {
        let counts = ProcessCounts::load(pool, model_for_count)?;
        if counts.previews_remaining == 0 {
            break;
        }
        progress(ProcessPhase::Previews, counts);
        process_previews_batch(pool, ctx, opts.batch_size)?;
    }

    // Phase 2: Embeddings — only when clip feature is compiled in, embeddings
    // are requested, and an embedder is available.
    #[cfg(feature = "clip")]
    if opts.embeddings
        && let Some(emb) = embedder
    {
        loop {
            let counts = ProcessCounts::load(pool, model)?;
            if counts.embeddings_remaining == 0 {
                break;
            }
            progress(ProcessPhase::Embeddings, counts);
            process_embeddings_batch(pool, emb, model, opts.batch_size)?;
        }
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{IndexDb, block_on};
    use turso::Value;

    // ── Seed helpers ──────────────────────────────────────────────────────────

    /// Insert a minimal `run` row.  `output_root` affects how
    /// `get_files_without_preview` constructs `FoundFile.written_path`
    /// (via `output_root.join(written_path_col)`).  Pass `""` to make the
    /// `written_path` column value the effective path (absolute paths stored
    /// in the column are preserved via `PathBuf::join` semantics).
    fn seed_run(pool: &TursoPool, output_root: &str) {
        block_on(async {
            pool.get()
                .await
                .unwrap()
                .execute(
                    "INSERT INTO run \
                     (id, started_at, output_root, source_image_path, \
                      configured_types_json, status, elapsed_ms, total_files) \
                     VALUES (1, '2026-01-01T00:00:00Z', ?1, 'src.img', '[]', \
                             'Finished', 0, 0)",
                    (Value::Text(output_root.to_owned()),),
                )
                .await
                .unwrap();
        });
    }

    /// Insert a `source` row.
    fn seed_source(pool: &TursoPool, source_id: i64, filename: &str) {
        block_on(async {
            pool.get()
                .await
                .unwrap()
                .execute(
                    "INSERT INTO source \
                     (source_id, filename, output_subdir, total_bytes, \
                      bytes_read, files_found, status) \
                     VALUES (?1, ?2, 'out', 0, 0, 0, 'Finished')",
                    turso::params_from_iter(vec![
                        Value::Integer(source_id),
                        Value::Text(filename.to_owned()),
                    ]),
                )
                .await
                .unwrap();
        });
    }

    /// Insert a JPEG `file` row with `preview_status = 'unknown'`.
    ///
    /// `written_path` should be an absolute path to a file on disk when the
    /// test needs `render_with_fallback` to succeed via the path-based route.
    fn seed_jpeg_file_unknown(pool: &TursoPool, file_id: i64, written_path: &str) {
        block_on(async {
            pool.get()
                .await
                .unwrap()
                .execute(
                    "INSERT INTO file \
                     (file_id, source_id, filename, filesize, file_type, img_offset, \
                      written_path, byte_runs_json, preview_status) \
                     VALUES (?1, 1, ?2, 1024, 'jpeg', 0, ?3, '[]', 'unknown')",
                    turso::params_from_iter(vec![
                        Value::Integer(file_id),
                        Value::Text(format!("{file_id:08}.jpeg")),
                        Value::Text(written_path.to_owned()),
                    ]),
                )
                .await
                .unwrap();
        });
    }

    /// A `PreviewContext` with no source-byte fallback.  Sufficient for tests
    /// that put the JPEG file at a real on-disk path so the path-based render
    /// route succeeds without needing source-bytes resolution.
    fn minimal_ctx() -> PreviewContext {
        PreviewContext::new(
            Arc::new(PreviewRegistry::with_defaults_and_jpeg()),
            Arc::new(SourceResolver::new(vec![], None)),
            HashMap::new(),
        )
    }

    // ── Previews phase ────────────────────────────────────────────────────────

    /// Previews phase processes all qualifying files and then becomes a no-op.
    #[test]
    fn previews_phase_drains_to_zero_then_is_idempotent() {
        let db = IndexDb::open_in_memory().expect("open in-memory db");
        let pool = db.pool();

        let tmp = tempfile::tempdir().unwrap();
        let jpeg_bytes = include_bytes!("../tests/fixtures/tiny_2x2.jpg");
        let jpeg_path = tmp.path().join("00000001.jpeg");
        std::fs::write(&jpeg_path, jpeg_bytes).unwrap();

        // output_root="" → join("") + abs path → abs path preserved.
        seed_run(pool, "");
        seed_source(pool, 1, "src.img");
        seed_jpeg_file_unknown(pool, 1, jpeg_path.to_str().unwrap());

        let ctx = minimal_ctx();

        let counts = ProcessCounts::load(pool, "m").unwrap();
        assert_eq!(counts.previews_remaining, 1, "one file should be pending");

        // First batch: processes the file, remaining drops to 0.
        let out = process_previews_batch(pool, &ctx, 10).unwrap();
        assert_eq!(out.processed, 1);
        assert_eq!(out.remaining, 0);

        // Second run: idempotent — nothing to process.
        let out2 = process_previews_batch(pool, &ctx, 10).unwrap();
        assert_eq!(out2.processed, 0, "re-running must be a no-op");
        assert_eq!(out2.remaining, 0);
    }

    /// A file whose on-disk path doesn't exist and has no source-resolver
    /// mapping is marked `NoPreview` so it isn't retried forever.
    #[test]
    fn previews_phase_marks_no_preview_for_unresolvable_file() {
        let db = IndexDb::open_in_memory().expect("open in-memory db");
        let pool = db.pool();

        seed_run(pool, "");
        seed_source(pool, 1, "src.img");
        seed_jpeg_file_unknown(pool, 1, "/does/not/exist/00000001.jpeg");

        let ctx = minimal_ctx();

        let out = process_previews_batch(pool, &ctx, 10).unwrap();
        assert_eq!(out.processed, 1, "file was attempted");
        assert_eq!(out.remaining, 0, "file is gone from the pending queue");

        let counts = ProcessCounts::load(pool, "m").unwrap();
        assert_eq!(
            counts.previews_remaining, 0,
            "NoPreview removes it from the queue"
        );
    }

    /// `from_case` constructs a context from the DB without error.
    #[test]
    fn preview_context_from_case_builds_from_db() {
        let db = IndexDb::open_in_memory().expect("open db");
        let pool = db.pool();

        // from_case only reads the source table; an empty table is fine.
        let _ctx = PreviewContext::from_case(pool).expect("from_case must succeed");
    }

    /// `from_case` populates `sources_by_id` from the `source` table.
    #[test]
    fn preview_context_from_case_populates_sources_by_id() {
        let db = IndexDb::open_in_memory().expect("open db");
        let pool = db.pool();

        seed_source(pool, 1, "/mnt/evidence/disk.img");
        seed_source(pool, 2, "/mnt/evidence/usb.img");

        let ctx = PreviewContext::from_case(pool).expect("from_case");
        assert_eq!(
            ctx.sources_by_id.get(&1).map(String::as_str),
            Some("/mnt/evidence/disk.img")
        );
        assert_eq!(
            ctx.sources_by_id.get(&2).map(String::as_str),
            Some("/mnt/evidence/usb.img")
        );
    }

    // ── Embeddings phase ──────────────────────────────────────────────────────

    #[cfg(feature = "clip")]
    mod clip_tests {
        use super::*;
        use std::sync::{Arc, Mutex};

        /// Insert a JPEG `file` row with `preview_status = 'has_preview'`.
        fn seed_file_has_preview(pool: &TursoPool, file_id: i64) {
            block_on(async {
                pool.get()
                    .await
                    .unwrap()
                    .execute(
                        "INSERT INTO file \
                         (file_id, source_id, filename, filesize, file_type, img_offset, \
                          written_path, byte_runs_json, preview_status) \
                         VALUES (?1, 1, ?2, 1024, 'jpeg', 0, '/dev/null', '[]', 'has_preview')",
                        turso::params_from_iter(vec![
                            Value::Integer(file_id),
                            Value::Text(format!("{file_id:08}.jpeg")),
                        ]),
                    )
                    .await
                    .unwrap();
            });
        }

        /// Insert a `preview_blob` row.  The `file` row must already exist.
        fn seed_blob_row(pool: &TursoPool, file_id: i64, bytes: Vec<u8>) {
            block_on(async {
                pool.get()
                    .await
                    .unwrap()
                    .execute(
                        "INSERT INTO preview_blob (file_id, codec, width, height, bytes) \
                         VALUES (?1, 'jpeg', 1, 1, ?2)",
                        turso::params_from_iter(vec![Value::Integer(file_id), Value::Blob(bytes)]),
                    )
                    .await
                    .unwrap();
            });
        }

        /// Constant fake embedder — always returns `vec![0.1; ACTIVE_DIM]`.
        struct FakeEmbed;
        impl crate::clip::EmbedFn for FakeEmbed {
            fn embed_image(&self, _b: &[u8]) -> anyhow::Result<Vec<f32>> {
                Ok(vec![0.1; crate::clip::ACTIVE_DIM])
            }
        }

        /// Recording embedder — captures every byte slice passed to it and
        /// returns a unit vector (dim 0 = 1.0, rest = 0.0; already normalised).
        struct RecordingEmbed(Arc<Mutex<Vec<Vec<u8>>>>);
        impl crate::clip::EmbedFn for RecordingEmbed {
            fn embed_image(&self, b: &[u8]) -> anyhow::Result<Vec<f32>> {
                self.0.lock().unwrap().push(b.to_vec());
                let mut v = vec![0.0f32; crate::clip::ACTIVE_DIM];
                v[0] = 1.0; // unit vector — already L2-normalised
                Ok(v)
            }
        }

        /// Embeddings phase processes all eligible files then becomes a no-op.
        #[test]
        fn embeddings_phase_drains_to_zero_then_is_idempotent() {
            let db = IndexDb::open_in_memory().expect("open db");
            let pool = db.pool();

            seed_source(pool, 1, "src.img");
            seed_file_has_preview(pool, 1);
            seed_blob_row(pool, 1, vec![0xAA, 0xBB]);
            seed_file_has_preview(pool, 2);
            seed_blob_row(pool, 2, vec![0xCC, 0xDD]);

            let model = crate::clip::ACTIVE_MODEL;
            let counts = ProcessCounts::load(pool, model).unwrap();
            assert_eq!(counts.embeddings_remaining, 2);

            let out = process_embeddings_batch(pool, &FakeEmbed, model, 10).unwrap();
            assert_eq!(out.processed, 2);
            assert_eq!(out.remaining, 0);

            // Idempotent.
            let out2 = process_embeddings_batch(pool, &FakeEmbed, model, 10).unwrap();
            assert_eq!(out2.processed, 0, "re-running must be a no-op");
            assert_eq!(out2.remaining, 0);
        }

        /// LOAD-BEARING: the embedder receives `preview_blob.bytes` verbatim —
        /// not re-rendered pixels.  Ensures future refactors cannot silently
        /// switch to re-rendering, which would break semantic search consistency
        /// (two runs would produce embeddings from different image bytes).
        #[test]
        fn embedding_receives_preview_blob_bytes_not_re_rendered() {
            let db = IndexDb::open_in_memory().expect("open db");
            let pool = db.pool();

            seed_source(pool, 1, "src.img");
            seed_file_has_preview(pool, 1);

            // Use bytes that no image renderer would produce.
            let sentinel: Vec<u8> = (0u8..32).collect();
            seed_blob_row(pool, 1, sentinel.clone());

            let recorded: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
            let embedder = RecordingEmbed(recorded.clone());

            let out =
                process_embeddings_batch(pool, &embedder, crate::clip::ACTIVE_MODEL, 10).unwrap();
            assert_eq!(out.processed, 1);

            let calls = recorded.lock().unwrap();
            assert_eq!(
                calls.len(),
                1,
                "embedder must be called exactly once per file"
            );
            assert_eq!(
                calls[0], sentinel,
                "embedder must receive the preview_blob bytes, not re-rendered pixels"
            );
        }

        /// Embedding produces a normalised `ACTIVE_DIM`-length vector stored
        /// in `clip_embedding` (verified by reading back the row from the DB).
        #[test]
        fn embedding_stores_normalised_active_dim_vector() {
            use crate::clip::{ACTIVE_DIM, ACTIVE_MODEL};

            let db = IndexDb::open_in_memory().expect("open db");
            let pool = db.pool();

            seed_source(pool, 1, "src.img");
            seed_file_has_preview(pool, 1);
            seed_blob_row(pool, 1, vec![0x00, 0x01, 0x02]);

            let out = process_embeddings_batch(pool, &FakeEmbed, ACTIVE_MODEL, 10).unwrap();
            assert_eq!(out.processed, 1);

            // Verify that the DB row has the expected dimension and byte length.
            block_on(async {
                let conn = pool.get().await.unwrap();
                let mut rows = conn
                    .query(
                        "SELECT dim, length(embedding) FROM clip_embedding WHERE file_id = 1",
                        (),
                    )
                    .await
                    .unwrap();
                let row = rows
                    .next()
                    .await
                    .unwrap()
                    .expect("clip_embedding row must exist");
                let dim = *row.get_value(0).unwrap().as_integer().unwrap();
                let byte_len = *row.get_value(1).unwrap().as_integer().unwrap();
                assert_eq!(dim, ACTIVE_DIM as i64, "dim must equal ACTIVE_DIM");
                assert_eq!(
                    byte_len,
                    (ACTIVE_DIM * 4) as i64,
                    "embedding must be ACTIVE_DIM × 4 bytes (f32 LE)"
                );
            });
        }

        /// Re-embedding a file already in `clip_embedding` is idempotent — the
        /// count stays at 0 and no error is returned.
        #[test]
        fn re_embedding_is_idempotent() {
            use crate::clip::ACTIVE_MODEL;

            let db = IndexDb::open_in_memory().expect("open db");
            let pool = db.pool();

            seed_source(pool, 1, "src.img");
            seed_file_has_preview(pool, 1);
            seed_blob_row(pool, 1, vec![0x01, 0x02]);

            // First pass — embeds file 1.
            process_embeddings_batch(pool, &FakeEmbed, ACTIVE_MODEL, 10).unwrap();
            assert_eq!(
                ProcessCounts::load(pool, ACTIVE_MODEL)
                    .unwrap()
                    .embeddings_remaining,
                0
            );

            // Second pass — nothing to embed.
            let out = process_embeddings_batch(pool, &FakeEmbed, ACTIVE_MODEL, 10).unwrap();
            assert_eq!(out.processed, 0, "second pass must be a no-op");
        }

        /// `run_to_completion` runs Previews then Embeddings, calling the
        /// progress callback at least once for each phase that has work.
        #[test]
        fn run_to_completion_calls_progress_for_both_phases() {
            use crate::clip::ACTIVE_MODEL;

            let db = IndexDb::open_in_memory().expect("open db");
            let pool = db.pool();

            let tmp = tempfile::tempdir().unwrap();
            let jpeg_bytes = include_bytes!("../tests/fixtures/tiny_2x2.jpg");
            let jpeg_path = tmp.path().join("00000001.jpeg");
            std::fs::write(&jpeg_path, jpeg_bytes).unwrap();

            seed_run(pool, "");
            seed_source(pool, 1, "src.img");
            seed_jpeg_file_unknown(pool, 1, jpeg_path.to_str().unwrap());

            let ctx = minimal_ctx();
            let mut preview_calls = 0usize;
            let mut embed_calls = 0usize;

            run_to_completion(
                pool,
                &ctx,
                Some(&FakeEmbed),
                ACTIVE_MODEL,
                ProcessOpts {
                    batch_size: 10,
                    embeddings: true,
                },
                &mut |phase, _counts| match phase {
                    ProcessPhase::Previews => preview_calls += 1,
                    ProcessPhase::Embeddings => embed_calls += 1,
                },
            )
            .unwrap();

            assert!(
                preview_calls >= 1,
                "progress must fire at least once for Previews"
            );
            assert!(
                embed_calls >= 1,
                "progress must fire at least once for Embeddings"
            );

            // After completion both queues must be empty.
            let counts = ProcessCounts::load(pool, ACTIVE_MODEL).unwrap();
            assert_eq!(counts.previews_remaining, 0);
            assert_eq!(counts.embeddings_remaining, 0);
        }
    }
}
