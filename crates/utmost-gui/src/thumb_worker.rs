//! Decode JPEG (and future format) thumbnails off the Slint thread.
//! Posts back to the Slint event loop via `slint::invoke_from_event_loop`.
//!
//! The cache stores `SharedPixelBuffer<Rgba8Pixel>` (which is `Send + Sync`)
//! rather than `slint::Image` (which is not `Send`). The adapter converts a
//! cached buffer into an `Image` on demand from the UI thread.

use crossbeam_channel::{Receiver, Sender, unbounded};
use lru::LruCache;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use utmost_lib::types::FileType;

use crate::preview::{PreviewRegistry, render_with_fallback};
use crate::source_resolver::SourceResolver;
use crate::view_model::{FileId, FoundFile};

pub type ThumbBuffer = slint::SharedPixelBuffer<slint::Rgba8Pixel>;
pub type ThumbCache = Arc<Mutex<LruCache<FileId, ThumbBuffer>>>;
pub type SourcesByIdMap = Arc<RwLock<HashMap<u32, String>>>;

pub struct ThumbWorker {
    tx: Sender<ThumbRequest>,
    pub cache: ThumbCache,
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
    ) -> Self {
        let cache: ThumbCache = Arc::new(Mutex::new(LruCache::new(
            NonZeroUsize::new(capacity.max(1)).unwrap(),
        )));
        let sources_by_id: SourcesByIdMap = Arc::new(RwLock::new(HashMap::new()));
        let (tx, rx) = unbounded::<ThumbRequest>();
        for _ in 0..workers.max(1) {
            let rx: Receiver<ThumbRequest> = rx.clone();
            let cache = cache.clone();
            let registry = registry.clone();
            let resolver = resolver.clone();
            let sources_by_id = sources_by_id.clone();
            let on_complete = on_complete.clone();
            thread::spawn(move || {
                while let Ok(req) = rx.recv() {
                    if cache.lock().unwrap().contains(&req.id) {
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
                    if let Ok(crate::preview::PreviewOutput::Image(img)) = out {
                        let (w, h) = (img.width(), img.height());
                        let pixels: Vec<u8> = img.into_raw();
                        let buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
                            &pixels, w, h,
                        );
                        cache.lock().unwrap().put(req.id, buf);
                        let cb = on_complete.clone();
                        let id = req.id;
                        let _ = slint::invoke_from_event_loop(move || cb(id));
                    }
                }
            });
        }
        Self {
            tx,
            cache,
            sources_by_id,
        }
    }

    pub fn request(&self, id: FileId, file_type: FileType, path: PathBuf, file: FoundFile) {
        let _ = self.tx.send(ThumbRequest {
            id,
            file_type,
            path,
            file,
        });
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
