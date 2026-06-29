//! Decode JPEG (and future format) thumbnails off the Slint thread.
//! Posts back to the Slint event loop via `slint::invoke_from_event_loop`.
//!
//! The cache stores `SharedPixelBuffer<Rgba8Pixel>` (which is `Send + Sync`)
//! rather than `slint::Image` (which is not `Send`). The adapter converts a
//! cached buffer into an `Image` on demand from the UI thread.

use crossbeam_channel::{Receiver, Sender, unbounded};
use lru::LruCache;
use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use utmost_lib::types::FileType;

use crate::preview::{PreviewRegistry, render_with_fallback};
use crate::source_resolver::SourceResolver;
use crate::view_model::{FileId, FoundFile};

/// Quality factor for the persisted thumbnail. ~80 keeps thumbs visually
/// indistinguishable from the RGBA source at 256-px max edge while
/// landing each blob in the 5-15 KB range.
const JPEG_QUALITY: u8 = 80;

/// Encode a decoded RGBA8 thumbnail to JPEG bytes for persistence in the
/// `preview_blob` table. The alpha channel is discarded — JPEG has no
/// alpha support. Runs on the decode worker thread so encoding
/// parallelism scales with the worker pool. Quality is fixed at
/// [`JPEG_QUALITY`]; codec/quality choice is encoded in the
/// `preview_blob.codec` column so future encoders can be added without a
/// schema migration.
pub fn encode_thumb_to_jpeg(rgba: &[u8], width: u32, height: u32) -> anyhow::Result<Vec<u8>> {
    use image::ExtendedColorType;
    use image::codecs::jpeg::JpegEncoder;
    let expected = (width as usize) * (height as usize) * 4;
    if rgba.len() != expected {
        anyhow::bail!(
            "encode_thumb_to_jpeg: buffer len {} != width*height*4 = {}",
            rgba.len(),
            expected
        );
    }
    // Convert RGBA8 to RGB8 by dropping the alpha channel.
    let rgb: Vec<u8> = rgba
        .chunks_exact(4)
        .flat_map(|chunk| [chunk[0], chunk[1], chunk[2]])
        .collect();
    // JPEG at q80 is roughly 5-15 KB for a 256-px thumb; ~1/16 of raw RGBA
    // is a reasonable starting capacity that avoids a few early grow events
    // without overshooting.
    let mut out: Vec<u8> = Vec::with_capacity(rgba.len() / 16);
    JpegEncoder::new_with_quality(&mut out, JPEG_QUALITY).encode(
        &rgb,
        width,
        height,
        ExtendedColorType::Rgb8,
    )?;
    Ok(out)
}

pub type ThumbBuffer = slint::SharedPixelBuffer<slint::Rgba8Pixel>;
pub type ThumbCache = Arc<Mutex<LruCache<FileId, ThumbBuffer>>>;
/// Negative-cache of file ids whose preview rendering produced no image
/// (decode error or non-image fallback output). Prevents the worker from
/// retrying deterministic failures on every sync tick.
pub type FailedSet = Arc<Mutex<HashSet<FileId>>>;
pub type SourcesByIdMap = Arc<RwLock<HashMap<u32, String>>>;

// The preview outcome/codec/status types now live in `utmost_index::model`
// (Diesel→turso migration). Re-export them so the GUI's existing
// `crate::thumb_worker::Preview*` paths keep resolving unchanged.
pub use utmost_index::model::{PreviewCodec, PreviewOutcome, PreviewStatus};

pub struct ThumbWorker {
    tx: Sender<ThumbRequest>,
    pub cache: ThumbCache,
    failed: FailedSet,
    pub sources_by_id: SourcesByIdMap,
}

struct ThumbRequest {
    id: FileId,
    file_type: FileType,
    path: PathBuf,
    file: FoundFile,
}

impl ThumbWorker {
    /// Spawn `workers` decode threads that pull `ThumbRequest`s and produce
    /// `SharedPixelBuffer<Rgba8Pixel>` thumbnails in the LRU cache.
    ///
    /// When `sqlite_path` is `Some`, the worker:
    ///   1. Hydrates `failed` from `preview_status='no_preview'` rows at
    ///      construction time so previously-failed files are not re-decoded.
    ///   2. Opens one read-only SQLite connection per worker thread for the
    ///      fast-path `preview_blob_lookup` — a hit decodes the cached JPEG
    ///      (~1 ms) instead of re-running `render_with_fallback` against the
    ///      source image (~tens of ms). The fast path does NOT emit a
    ///      `PreviewOutcome` because `preview_status` is already correct
    ///      on disk.
    ///
    /// When `sqlite_path` is `None`, the persistent cache is disabled —
    /// the worker decodes every request from source bytes and the LRU is
    /// the only memoization. Used by tests that don't need a per-case
    /// sqlite.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        registry: Arc<PreviewRegistry>,
        resolver: Arc<SourceResolver>,
        capacity: usize,
        workers: usize,
        on_complete: Arc<dyn Fn(FileId) + Send + Sync>,
        outcomes_tx: Option<Sender<PreviewOutcome>>,
        shutdown_signal: Arc<AtomicBool>,
        sqlite_path: Option<PathBuf>,
    ) -> Self {
        let cache: ThumbCache = Arc::new(Mutex::new(LruCache::new(
            NonZeroUsize::new(capacity.max(1)).unwrap(),
        )));
        let failed: FailedSet = Arc::new(Mutex::new(HashSet::new()));
        let sources_by_id: SourcesByIdMap = Arc::new(RwLock::new(HashMap::new()));

        // Hydrate `failed` from preview_status='no_preview' rows so we
        // don't re-attempt deterministic failures on every case reopen.
        if let Some(path) = sqlite_path.as_ref() {
            match hydrate_failed_from_sqlite(path) {
                Ok(ids) => {
                    failed.lock().unwrap().extend(ids);
                }
                Err(e) => {
                    tracing::warn!(
                        "thumb worker: hydrate_failed_from_sqlite({}) failed: {e:#}; \
                         starting with empty failed set",
                        path.display()
                    );
                }
            }
        }

        // One shared turso pool per case for the blob fast-path lookups; each
        // worker thread gets a cheap clone. `None` when no per-case sqlite was
        // provided (tests) — the worker then always takes the slow path.
        let pool: Option<crate::index_db::TursoPool> =
            sqlite_path
                .as_ref()
                .and_then(|p| match crate::index_db::TursoPool::open(p) {
                    Ok(pool) => Some(pool),
                    Err(e) => {
                        tracing::warn!(
                            "thumb worker: opening turso pool for {} failed: {e:#}; \
                         blob fast-path disabled this session",
                            p.display()
                        );
                        None
                    }
                });

        let (tx, rx) = unbounded::<ThumbRequest>();
        for _ in 0..workers.max(1) {
            let rx: Receiver<ThumbRequest> = rx.clone();
            let cache = cache.clone();
            let failed = failed.clone();
            let registry = registry.clone();
            let resolver = resolver.clone();
            let sources_by_id = sources_by_id.clone();
            let on_complete = on_complete.clone();
            let outcomes_tx = outcomes_tx.clone();
            let shutdown = shutdown_signal.clone();
            // Cheap clone of the shared turso pool for blob fast-path lookups.
            // WAL mode on the per-case DB lets N readers + 1 writer proceed in
            // parallel.
            let pool = pool.clone();
            thread::spawn(move || {
                while let Ok(req) = rx.recv() {
                    // Bail before any work if `close_case` (or the window-close
                    // path) has asked us to stop. Without this check, workers
                    // would chew through the entire queued backlog of decode
                    // requests, holding the last clones of `outcomes_tx` and
                    // blocking `preview_writer_thread.join()` on the UI thread.
                    if shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    if cache.lock().unwrap().contains(&req.id) {
                        continue;
                    }
                    if failed.lock().unwrap().contains(&req.id) {
                        continue;
                    }
                    // FAST PATH: serve from preview_blob if present. A hit skips the
                    // source-bytes decode entirely. We do NOT emit a PreviewOutcome here
                    // because preview_status='has_preview' is already on disk and the
                    // preview_status_version meta key is unchanged.
                    if let Some(p) = pool.as_ref() {
                        let lookup = crate::index_db::writer::preview_blob_lookup(p, req.id);
                        let decoded = match lookup {
                            Ok(Some(row)) => {
                                let img = image::ImageReader::new(std::io::Cursor::new(&row.bytes))
                                    .with_guessed_format()
                                    .ok()
                                    .and_then(|r| r.decode().ok());
                                if img.is_none() {
                                    tracing::warn!(
                                        "thumb worker: cached preview_blob for file_id={} \
                                         failed to decode ({} bytes); falling through to slow \
                                         path (slow path will overwrite the bad blob on success)",
                                        req.id,
                                        row.bytes.len()
                                    );
                                }
                                img
                            }
                            Ok(None) => None,
                            Err(e) => {
                                tracing::warn!(
                                    "thumb worker: preview_blob_lookup({}) errored: {e}; \
                                     falling through to slow path",
                                    req.id
                                );
                                None
                            }
                        };
                        if let Some(dyn_img) = decoded {
                            let rgba = dyn_img.to_rgba8();
                            let (w, h) = (rgba.width(), rgba.height());
                            let pixels: Vec<u8> = rgba.into_raw();
                            let buf =
                                slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
                                    &pixels, w, h,
                                );
                            cache.lock().unwrap().put(req.id, buf);
                            let cb = on_complete.clone();
                            let id = req.id;
                            let _ = slint::invoke_from_event_loop(move || cb(id));
                            continue;
                        }
                        // Lookup miss, lookup error, or decode failure → fall through to
                        // slow path. If a bad blob caused the decode failure, the slow
                        // path's INSERT OR REPLACE in write_preview_outcomes overwrites
                        // it on success.
                    }

                    // SLOW PATH — same as the existing `start` worker body.
                    let snap = sources_by_id.read().unwrap().clone();
                    let out = render_with_fallback(
                        &registry,
                        &resolver,
                        &snap,
                        req.file_type,
                        &req.path,
                        &req.file,
                    );
                    // Post-Task-8 unification, `req.id` already equals
                    // `req.file.file.file_id` — but read the inner value
                    // explicitly here so the outcome record stays correct
                    // even if future code paths construct requests by
                    // some other path.
                    let durable_file_id: u64 = req.file.file.file_id;
                    match out {
                        Ok(crate::preview::PreviewOutput::Image(img)) => {
                            let (w, h) = (img.width(), img.height());
                            let pixels: Vec<u8> = img.into_raw();
                            let buf =
                                slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
                                    &pixels, w, h,
                                );
                            cache.lock().unwrap().put(req.id, buf);
                            let cb = on_complete.clone();
                            let id = req.id;
                            let _ = slint::invoke_from_event_loop(move || cb(id));
                            if let Some(tx) = &outcomes_tx {
                                match encode_thumb_to_jpeg(&pixels, w, h) {
                                    Ok(bytes) => {
                                        let _ = tx.send(PreviewOutcome {
                                            file_id: durable_file_id,
                                            status: PreviewStatus::HasPreview {
                                                codec: PreviewCodec::Jpeg,
                                                width: w,
                                                height: h,
                                                bytes,
                                            },
                                        });
                                    }
                                    Err(e) => {
                                        // The decode succeeded — the RGBA buffer is already in the
                                        // LRU and on_complete has fired. The encode is the only step
                                        // that failed; do NOT mark the file as NoPreview, because
                                        // that would blacklist a successfully-decoded file
                                        // permanently. Leaving preview_status='unknown' means the
                                        // file will be re-decoded (and re-encoded) on the next case
                                        // open.
                                        tracing::warn!(
                                            "thumb worker: encode_thumb_to_jpeg failed for file_id={}: {}; \
                                             in-memory thumb cached, but no preview_blob will be persisted \
                                             this session",
                                            durable_file_id,
                                            e
                                        );
                                    }
                                }
                            }
                        }
                        // Either a non-image preview (text/hex/icon) or a decode
                        // error: deterministically reproduces, so remember it
                        // and skip future requests for the same id.
                        _ => {
                            failed.lock().unwrap().insert(req.id);
                            if let Some(tx) = &outcomes_tx {
                                let _ = tx.send(PreviewOutcome {
                                    file_id: durable_file_id,
                                    status: PreviewStatus::NoPreview,
                                });
                            }
                        }
                    }
                }
            });
        }
        Self {
            tx,
            cache,
            failed,
            sources_by_id,
        }
    }

    pub fn request(&self, id: FileId, file_type: FileType, path: PathBuf, file: FoundFile) {
        // Skip enqueuing when we already have a definitive result (positive or
        // negative). Saves channel traffic from the per-tick sync loop, which
        // calls `request()` for every visible tile lacking a UI-thread image.
        if self.cache.lock().unwrap().contains(&id) {
            return;
        }
        if self.failed.lock().unwrap().contains(&id) {
            return;
        }
        let _ = self.tx.send(ThumbRequest {
            id,
            file_type,
            path,
            file,
        });
    }

    /// Returns true if the worker has already attempted to render a preview for
    /// this file id and produced no image. Used by the UI adapter to avoid
    /// repeated lookups on the per-tick sync loop.
    pub fn has_failed(&self, id: FileId) -> bool {
        self.failed.lock().unwrap().contains(&id)
    }

    /// Returns a freshly-built `slint::Image` for the cached buffer, if any.
    /// Must be called from the UI thread (where `slint::Image` may live).
    pub fn get_image(&self, id: FileId) -> Option<slint::Image> {
        self.cache
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .map(slint::Image::from_rgba8)
    }

    /// Returns the cached pixel buffer for a file id, if the worker has
    /// finished decoding it. Cheap clone — the underlying buffer is
    /// reference-counted. The UI adapter uses this to memoize a stable
    /// `slint::Image` per file id so Slint doesn't see a property change
    /// (and re-upload the texture) on every sync tick.
    pub fn get_buffer(&self, id: FileId) -> Option<ThumbBuffer> {
        self.cache.lock().unwrap().get(&id).cloned()
    }
}

/// Read all `file.file_id`s whose `preview_status` is `'no_preview'`.
/// Used at [`ThumbWorker::start`] construction to hydrate `failed` from
/// durable state. WAL mode + busy_timeout are applied per-connection by the
/// turso pool manager, so the read coexists with the case's writer.
fn hydrate_failed_from_sqlite(path: &std::path::Path) -> anyhow::Result<Vec<FileId>> {
    use crate::index_db::{TursoPool, block_on};
    let pool = TursoPool::open(path)?;
    block_on(async move {
        let conn = pool.get().await?;
        let mut rows = conn
            .query(
                "SELECT file_id FROM file WHERE preview_status = 'no_preview'",
                (),
            )
            .await?;
        let mut ids: Vec<FileId> = Vec::new();
        while let Some(row) = rows.next().await? {
            let id = row.get_value(0)?.as_integer().copied().unwrap_or(0);
            ids.push(id as FileId);
        }
        anyhow::Ok(ids)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preview::PreviewRegistry;
    use crate::source_resolver::SourceResolver;
    use crate::view_model::FoundFile;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;
    use utmost_lib::reporting::create_file_object;
    use utmost_lib::types::{ByteRun, FileObject};

    fn dummy_file(file_id: u64) -> FoundFile {
        FoundFile {
            id: file_id,
            source_id: 0,
            file: create_file_object("a.jpg", FileType::Jpeg, 1024, 0, None, file_id),
            written_path: std::path::PathBuf::from("/nowhere/a.jpg"),
            img_offset: 0,
        }
    }

    /// Open (creating + migrating) the per-case sqlite at `db_path` and return
    /// a turso pool clone for seeding test fixtures.
    fn open_seeded_db(db_path: &std::path::Path) -> crate::index_db::TursoPool {
        crate::index_db::IndexDb::open(db_path)
            .expect("open sqlite")
            .pool()
            .clone()
    }

    /// Insert a `source` row (source_id only; the rest are fixed stubs).
    fn seed_source(pool: &crate::index_db::TursoPool, source_id: i64) {
        crate::index_db::block_on(async {
            let conn = pool.get().await.unwrap();
            conn.execute(
                "INSERT INTO source (source_id, filename, output_subdir, total_bytes, \
                 bytes_read, files_found, status) VALUES (?1, 'x.dd', 'x', 0, 0, 0, 'Running')",
                (turso::Value::Integer(source_id),),
            )
            .await
            .unwrap();
        });
    }

    /// Insert a `file` row with the given `preview_status`.
    fn seed_file(
        pool: &crate::index_db::TursoPool,
        file_id: i64,
        source_id: i64,
        preview_status: &str,
    ) {
        let preview_status = preview_status.to_owned();
        crate::index_db::block_on(async move {
            let conn = pool.get().await.unwrap();
            conn.execute(
                "INSERT INTO file (file_id, source_id, filename, filesize, file_type, \
                 img_offset, written_path, byte_runs_json, preview_status) \
                 VALUES (?1, ?2, 'a.jpg', 1, 'jpeg', 0, '/dev/null', '[]', ?3)",
                turso::params_from_iter(vec![
                    turso::Value::Integer(file_id),
                    turso::Value::Integer(source_id),
                    turso::Value::Text(preview_status),
                ]),
            )
            .await
            .unwrap();
        });
    }

    /// Insert a `preview_blob` row.
    fn seed_preview_blob(
        pool: &crate::index_db::TursoPool,
        file_id: i64,
        width: i64,
        height: i64,
        bytes: Vec<u8>,
    ) {
        crate::index_db::block_on(async move {
            let conn = pool.get().await.unwrap();
            conn.execute(
                "INSERT INTO preview_blob (file_id, codec, width, height, bytes) \
                 VALUES (?1, 'jpeg', ?2, ?3, ?4)",
                turso::params_from_iter(vec![
                    turso::Value::Integer(file_id),
                    turso::Value::Integer(width),
                    turso::Value::Integer(height),
                    turso::Value::Blob(bytes),
                ]),
            )
            .await
            .unwrap();
        });
    }

    /// When the shutdown signal is set, thumb workers must exit promptly
    /// without draining queued requests. Mirrors the symptom that caused
    /// the GUI to freeze on back-to-picker: workers held the last clones
    /// of `preview_outcomes_tx`, and `close_case`'s preview-writer join
    /// waited for them to chew through the entire decode queue.
    #[test]
    fn workers_exit_on_shutdown_without_processing_queued_requests() {
        let shutdown = Arc::new(AtomicBool::new(true));
        let (otx, orx) = unbounded::<PreviewOutcome>();
        let registry = Arc::new(PreviewRegistry::with_defaults_and_jpeg());
        let resolver = Arc::new(SourceResolver::new(vec![], None));
        let on_complete: Arc<dyn Fn(FileId) + Send + Sync> = Arc::new(|_| {});

        let worker = ThumbWorker::start(
            registry,
            resolver,
            256,
            2,
            on_complete,
            Some(otx),
            shutdown.clone(),
            None,
        );

        for i in 0..50u64 {
            worker.request(
                i as FileId,
                FileType::Jpeg,
                std::path::PathBuf::from("/nowhere/a.jpg"),
                dummy_file(i),
            );
        }

        drop(worker);

        // With shutdown asserted, both worker threads must skip every queued
        // request and drop their outcomes_tx clone almost immediately. The
        // channel disconnect arrives well within 500ms; if shutdown is
        // *not* honored, the workers would emit ~50 PreviewOutcomes first.
        match orx.recv_timeout(Duration::from_millis(500)) {
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {}
            Ok(o) => panic!(
                "workers processed a request despite shutdown=true: got {:?}",
                o
            ),
            Err(e) => panic!("unexpected channel error waiting for disconnect: {e:?}"),
        }
    }

    /// Sanity check: with shutdown=false, queued requests *are* processed
    /// (worker emits at least one outcome). This makes sure the shutdown
    /// path is what's gating processing, not some unrelated regression.
    #[test]
    fn workers_process_queued_requests_when_not_shutdown() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let (otx, orx) = unbounded::<PreviewOutcome>();
        let registry = Arc::new(PreviewRegistry::with_defaults_and_jpeg());
        let resolver = Arc::new(SourceResolver::new(vec![], None));
        let on_complete: Arc<dyn Fn(FileId) + Send + Sync> = Arc::new(|_| {});

        let worker = ThumbWorker::start(
            registry,
            resolver,
            256,
            2,
            on_complete,
            Some(otx),
            shutdown.clone(),
            None,
        );

        worker.request(
            1,
            FileType::Jpeg,
            std::path::PathBuf::from("/nowhere/a.jpg"),
            dummy_file(1),
        );

        // The path doesn't exist and there's no source resolver mapping,
        // so render_with_fallback errors out → worker emits NoPreview.
        let _ = orx
            .recv_timeout(Duration::from_secs(2))
            .expect("worker should have produced a PreviewOutcome");

        drop(worker);
    }

    /// On a successful slow-path decode, the worker must send a HasPreview
    /// outcome that carries the JPEG-encoded thumbnail bytes (not an empty
    /// vec). This is the on-the-wire payload that `write_preview_outcomes`
    /// turns into a `preview_blob` row.
    #[test]
    fn worker_emits_jpeg_bytes_in_has_preview_outcome() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let (otx, orx) = unbounded::<PreviewOutcome>();
        let registry = Arc::new(PreviewRegistry::with_defaults_and_jpeg());

        // Resolve a temp source so the slow path can actually decode.
        let tmp = tempfile::tempdir().unwrap();
        let src_path = tmp.path().join("src.dd");
        let jpeg_bytes: &[u8] = include_bytes!("../tests/fixtures/tiny_2x2.jpg");
        std::fs::write(&src_path, jpeg_bytes).unwrap();
        let resolver = Arc::new(crate::source_resolver::SourceResolver::new(
            vec![src_path.clone()],
            None,
        ));
        let on_complete: Arc<dyn Fn(FileId) + Send + Sync> = Arc::new(|_| {});

        let worker = ThumbWorker::start(
            registry,
            resolver,
            16,
            1,
            on_complete,
            Some(otx),
            shutdown.clone(),
            None,
        );

        // sources_by_id needs the entry so render_with_fallback can resolve.
        worker
            .sources_by_id
            .write()
            .unwrap()
            .insert(0u32, src_path.to_string_lossy().into_owned());

        // Build a FoundFile that points at the source bytes (path-based
        // path won't work — the file at the dummy path doesn't exist —
        // so render_with_fallback drops into render_from_bytes).
        let f = FoundFile {
            id: 99,
            source_id: 0,
            file: FileObject {
                file_id: 99,
                filename: "x.jpg".into(),
                filesize: jpeg_bytes.len() as u64,
                file_type: "jpeg".into(),
                byte_runs: vec![ByteRun {
                    offset: 0,
                    img_offset: 0,
                    len: jpeg_bytes.len() as u64,
                }],
                jpeg_scan: None,
            },
            written_path: tmp.path().join("does-not-exist.jpg"),
            img_offset: 0,
        };
        worker.request(
            99 as FileId,
            FileType::Jpeg,
            f.written_path.clone(),
            f.clone(),
        );

        let outcome = orx
            .recv_timeout(Duration::from_secs(5))
            .expect("worker emitted an outcome");
        assert_eq!(outcome.file_id, 99);
        match outcome.status {
            PreviewStatus::HasPreview {
                codec,
                width,
                height,
                bytes,
            } => {
                assert_eq!(codec, PreviewCodec::Jpeg);
                assert!(width > 0 && height > 0);
                assert!(!bytes.is_empty(), "bytes must contain the JPEG payload");
                assert!(
                    bytes[0] == 0xFF && bytes[1] == 0xD8,
                    "bytes must start with JPEG SOI marker, got {:02x}{:02x}",
                    bytes[0],
                    bytes[1]
                );
            }
            PreviewStatus::NoPreview => panic!("expected HasPreview"),
        }
        drop(worker);
    }

    /// At case-open, the worker must hydrate its `failed` set from sqlite
    /// rows with preview_status='no_preview' so previously-failed files
    /// don't get re-decoded on the next session.
    #[test]
    fn worker_hydrates_failed_set_from_no_preview_rows_on_open() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("case-index.sqlite");

        // Seed the on-disk sqlite with one file_id known to be NoPreview.
        {
            let pool = open_seeded_db(&db_path);
            seed_source(&pool, 1);
            seed_file(&pool, 123, 1, "no_preview");
        }

        let shutdown = Arc::new(AtomicBool::new(false));
        let (otx, _orx) = unbounded::<PreviewOutcome>();
        let registry = Arc::new(PreviewRegistry::with_defaults_and_jpeg());
        let resolver = Arc::new(crate::source_resolver::SourceResolver::new(vec![], None));
        let on_complete: Arc<dyn Fn(FileId) + Send + Sync> = Arc::new(|_| {});

        let worker = ThumbWorker::start(
            registry,
            resolver,
            16,
            1,
            on_complete,
            Some(otx),
            shutdown.clone(),
            Some(db_path),
        );
        assert!(
            worker.has_failed(123),
            "worker should have hydrated file_id=123 into the failed set"
        );
        drop(worker);
    }

    /// With a pre-populated preview_blob row in sqlite, requesting that
    /// file_id must:
    ///   1. Populate the in-memory LRU cache with the decoded bytes.
    ///   2. Invoke on_complete with the file id.
    ///   3. NOT send a PreviewOutcome (status is already on disk).
    ///
    /// Uses `PreviewRegistry::empty()` so any fall-through to the slow
    /// path would error — proving the fast path actually ran.
    #[test]
    fn worker_fast_path_serves_from_preview_blob() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("case-index.sqlite");

        // Pre-populate a preview_blob row for file_id=200 with a real JPEG.
        let jpeg_bytes: Vec<u8> = include_bytes!("../tests/fixtures/tiny_2x2.jpg").to_vec();
        {
            let pool = open_seeded_db(&db_path);
            seed_source(&pool, 1);
            seed_file(&pool, 200, 1, "has_preview");
            seed_preview_blob(&pool, 200, 2, 2, jpeg_bytes.clone());
        }

        let shutdown = Arc::new(AtomicBool::new(false));
        let (otx, orx) = unbounded::<PreviewOutcome>();
        // Empty registry → slow path would error → if a PreviewOutcome
        // arrives, it would be NoPreview, NOT a fast-path silent fill.
        let registry = Arc::new(PreviewRegistry::empty());
        let resolver = Arc::new(crate::source_resolver::SourceResolver::new(vec![], None));

        let completed: Arc<Mutex<Vec<FileId>>> = Arc::new(Mutex::new(Vec::new()));
        let completed_for_cb = completed.clone();
        let on_complete: Arc<dyn Fn(FileId) + Send + Sync> = Arc::new(move |id| {
            completed_for_cb.lock().unwrap().push(id);
        });

        let worker = ThumbWorker::start(
            registry,
            resolver,
            16,
            1,
            on_complete,
            Some(otx),
            shutdown.clone(),
            Some(db_path),
        );

        worker.request(
            200 as FileId,
            FileType::Jpeg,
            std::path::PathBuf::from("/does-not-exist.jpg"),
            dummy_file(200),
        );

        // Drain — fast path should NOT emit a PreviewOutcome. Anything
        // arriving within 500 ms is a regression.
        match orx.recv_timeout(Duration::from_millis(500)) {
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => { /* expected */ }
            Err(e) => panic!("unexpected channel error: {e:?}"),
            Ok(o) => panic!(
                "fast path must not emit a PreviewOutcome, got {:?}",
                o.status
            ),
        }

        // The LRU cache should now hold the decoded buffer.
        assert!(
            worker.get_buffer(200 as FileId).is_some(),
            "fast path must populate the in-memory LRU"
        );

        drop(worker);
    }

    /// If the cached preview_blob row contains undecodable bytes, the
    /// worker must fall through to the slow path. With a real
    /// PreviewRegistry and a working source, that means a HasPreview
    /// outcome will arrive (and the slow path's INSERT OR REPLACE will
    /// heal the bad blob on the writer side).
    #[test]
    fn worker_fast_path_falls_through_on_corrupt_blob() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("case-index.sqlite");

        // Real source bytes so the slow path can succeed.
        let src_path = tmp.path().join("src.dd");
        let jpeg_bytes: &[u8] = include_bytes!("../tests/fixtures/tiny_2x2.jpg");
        std::fs::write(&src_path, jpeg_bytes).unwrap();

        // Seed sqlite with: source row, file row in 'has_preview' state,
        // and a preview_blob with GARBAGE bytes (won't decode).
        {
            let pool = open_seeded_db(&db_path);
            seed_source(&pool, 0);
            seed_file(&pool, 300, 0, "has_preview");
            seed_preview_blob(&pool, 300, 1, 1, b"not actually a jpeg".to_vec());
        }

        let shutdown = Arc::new(AtomicBool::new(false));
        let (otx, orx) = unbounded::<PreviewOutcome>();
        let registry = Arc::new(PreviewRegistry::with_defaults_and_jpeg());
        let resolver = Arc::new(crate::source_resolver::SourceResolver::new(
            vec![src_path.clone()],
            None,
        ));
        let on_complete: Arc<dyn Fn(FileId) + Send + Sync> = Arc::new(|_| {});

        let worker = ThumbWorker::start(
            registry,
            resolver,
            16,
            1,
            on_complete,
            Some(otx),
            shutdown.clone(),
            Some(db_path),
        );
        worker
            .sources_by_id
            .write()
            .unwrap()
            .insert(0u32, src_path.to_string_lossy().into_owned());

        // Build a FoundFile that points at the source bytes.
        use utmost_lib::types::{ByteRun, FileObject};
        let f = FoundFile {
            id: 300,
            source_id: 0,
            file: FileObject {
                file_id: 300,
                filename: "a.jpg".into(),
                filesize: jpeg_bytes.len() as u64,
                file_type: "jpeg".into(),
                byte_runs: vec![ByteRun {
                    offset: 0,
                    img_offset: 0,
                    len: jpeg_bytes.len() as u64,
                }],
                jpeg_scan: None,
            },
            written_path: tmp.path().join("does-not-exist.jpg"),
            img_offset: 0,
        };
        worker.request(300 as FileId, FileType::Jpeg, f.written_path.clone(), f);

        // Slow path should run and emit HasPreview (with real bytes).
        let outcome = orx
            .recv_timeout(Duration::from_secs(5))
            .expect("slow path must run after corrupt-blob fast-path failure");
        assert_eq!(outcome.file_id, 300);
        match outcome.status {
            PreviewStatus::HasPreview { bytes, .. } => {
                assert!(
                    !bytes.is_empty() && bytes[0] == 0xFF && bytes[1] == 0xD8,
                    "slow path must emit a real JPEG, not the garbage from the cache"
                );
            }
            other => panic!("expected HasPreview from slow path, got {:?}", other),
        }
        drop(worker);
    }

    #[test]
    fn encode_thumb_to_jpeg_round_trips_dimensions() {
        // A 4×3 RGBA gradient encodes to JPEG bytes, and decoding those
        // bytes recovers the same dimensions.
        let w: u32 = 4;
        let h: u32 = 3;
        let rgba: Vec<u8> = (0..(w * h * 4))
            .map(|i| if i % 4 == 3 { 255 } else { (i % 256) as u8 })
            .collect();

        let encoded = super::encode_thumb_to_jpeg(&rgba, w, h).expect("encode");
        assert!(
            encoded.len() > 2 && encoded[0] == 0xFF && encoded[1] == 0xD8,
            "must start with JPEG SOI marker"
        );

        // Decode-back round trip via the `image` crate.
        let decoded = image::ImageReader::new(std::io::Cursor::new(encoded))
            .with_guessed_format()
            .expect("guess")
            .decode()
            .expect("decode jpeg");
        assert_eq!(decoded.width(), w);
        assert_eq!(decoded.height(), h);
    }
}
