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

/// Terminal outcome of a single preview-decode attempt, broadcast to a
/// background indexer so the per-file `preview_status` column in the
/// SQLite index can be updated and the `preview_status_version` meta key
/// bumped. The `HasPreview` variant carries the encoded thumbnail bytes
/// so the writer can persist them into `preview_blob` in the same
/// transaction as the `preview_status` update.
#[derive(Debug, Clone)]
pub enum PreviewStatus {
    HasPreview {
        codec: PreviewCodec,
        width: u32,
        height: u32,
        bytes: Vec<u8>,
    },
    NoPreview,
}

/// Encoding format of a persisted thumbnail. Only `Jpeg` is produced by
/// the worker today; the variant exists so the on-disk `preview_blob.codec`
/// column can grow new values (e.g. `Webp`) without a schema migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewCodec {
    Jpeg,
}

impl PreviewCodec {
    /// On-disk string representation stored in `preview_blob.codec`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Jpeg => "jpeg",
        }
    }
}

/// Pairing of an engine-allocated file id with the terminal preview
/// outcome the worker produced for it. Carries `u64` (not `FileId`) so
/// downstream consumers — including SQLite, which stores `file_id` as
/// `BIGINT` — can use it without re-wrapping.
#[derive(Debug, Clone)]
pub struct PreviewOutcome {
    pub file_id: u64,
    pub status: PreviewStatus,
}

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
    pub fn start(
        registry: Arc<PreviewRegistry>,
        resolver: Arc<SourceResolver>,
        capacity: usize,
        workers: usize,
        on_complete: Arc<dyn Fn(FileId) + Send + Sync>,
        outcomes_tx: Option<Sender<PreviewOutcome>>,
        shutdown_signal: Arc<AtomicBool>,
    ) -> Self {
        let cache: ThumbCache = Arc::new(Mutex::new(LruCache::new(
            NonZeroUsize::new(capacity.max(1)).unwrap(),
        )));
        let failed: FailedSet = Arc::new(Mutex::new(HashSet::new()));
        let sources_by_id: SourcesByIdMap = Arc::new(RwLock::new(HashMap::new()));
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
                    // Snapshot the sources map for this request.
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
                                // Encode the RGBA buffer to JPEG on this worker thread so encoding
                                // parallelism scales with the worker pool. On encode failure, fall
                                // back to NoPreview — re-decoding from source is the next-best
                                // recourse on the next case open.
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
                                        // that would (once T9's failed-set hydration lands) blacklist
                                        // a successfully-decoded file permanently. Leaving
                                        // preview_status='unknown' means the file will be re-decoded
                                        // (and re-encoded) on the next case open.
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
