//! CLIP embedding wrapper for the `clip` feature.
//!
//! Uses the `clipper` crate to load the LAION ViT-L/14 model from HuggingFace
//! and produce L2-normalised embedding vectors for images and text queries.
//! The model is loaded lazily on a background thread via [`Embedder::start_loading`].

use std::sync::{Arc, OnceLock};

use anyhow::Result;

// ── Constants ─────────────────────────────────────────────────────────────────

/// The CLIP model used for semantic search (LAION ViT-L/14, 768-d).
///
/// Delegates to [`crate::model::ACTIVE_MODEL_NAME`] — the single source of truth
/// shared with the KNN search read path — so a model bump only requires editing
/// one constant.
pub const ACTIVE_MODEL: &str = crate::model::ACTIVE_MODEL_NAME;

/// Embedding dimension produced by [`ACTIVE_MODEL`].
pub const ACTIVE_DIM: usize = 768;

// ── Pure helpers ──────────────────────────────────────────────────────────────

/// L2-normalise a vector in-place semantics, returning a new allocation.
///
/// Returns the input unchanged (as a clone) when the magnitude is zero to
/// avoid a divide-by-zero — callers should treat a zero vector as degenerate.
pub fn normalize_vector(v: &[f32]) -> Vec<f32> {
    let magnitude: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if magnitude == 0.0 {
        return v.to_vec();
    }
    v.iter().map(|x| x / magnitude).collect()
}

/// Serialise an `f32` slice to little-endian bytes — the wire format used for
/// vector columns in SQLite / libSQL (`F32_BLOB`).
pub fn to_le_bytes(v: &[f32]) -> Vec<u8> {
    v.iter().flat_map(|f| f.to_le_bytes()).collect()
}

// ── Embedding entry points ────────────────────────────────────────────────────

/// Embed a single image from raw bytes (PNG, JPEG, …) using an already-loaded
/// model.  Calls [`clipper::ClipEmbedder::get_image_embedding_from_bytes`].
pub fn embed_image_from_bytes(embedder: &clipper::ClipEmbedder, bytes: &[u8]) -> Result<Vec<f32>> {
    embedder.get_image_embedding_from_bytes(bytes)
}

/// Embed a text query string using an already-loaded model.
/// Calls [`clipper::ClipEmbedder::get_text_embedding`].
pub fn embed_text(embedder: &clipper::ClipEmbedder, text: &str) -> Result<Vec<f32>> {
    embedder.get_text_embedding(text)
}

// ── EmbedFn trait (test injection seam) ──────────────────────────────────────

/// Abstraction over single-image embedding that allows test doubles to replace
/// the real `ClipEmbedder` without touching the model-loading path.
pub trait EmbedFn {
    fn embed_image(&self, bytes: &[u8]) -> Result<Vec<f32>>;
}

impl EmbedFn for clipper::ClipEmbedder {
    fn embed_image(&self, bytes: &[u8]) -> Result<Vec<f32>> {
        self.get_image_embedding_from_bytes(bytes)
    }
}

// ── Lazy background loader ────────────────────────────────────────────────────

/// A handle to a [`clipper::ClipEmbedder`] that is loaded on a background thread.
///
/// Cheap to clone — the inner `Arc` is reference-counted and the `OnceLock`
/// ensures the model is initialised at most once regardless of how many clones
/// call [`Embedder::start_loading`].
#[derive(Clone)]
pub struct Embedder {
    inner: Arc<OnceLock<clipper::ClipEmbedder>>,
}

impl Embedder {
    /// Create a handle that has not yet started loading.
    pub fn new() -> Self {
        Embedder {
            inner: Arc::new(OnceLock::new()),
        }
    }

    /// Spawn a background thread that downloads (cached after first run) and
    /// loads [`ACTIVE_MODEL`] from HuggingFace, storing it in the inner
    /// `OnceLock`.  If the model is already loaded (or a load thread is already
    /// in flight and has raced to populate the lock), this is a no-op — no
    /// redundant ~1.5 GB load is started.
    pub fn start_loading(&self) {
        if self.inner.get().is_some() {
            return; // already loaded; don't spawn a redundant ~1.5 GB load
        }
        let lock = Arc::clone(&self.inner);
        std::thread::spawn(
            move || match clipper::ClipEmbedder::from_model(ACTIVE_MODEL, false) {
                Ok(e) => {
                    let _ = lock.set(e);
                    tracing::info!("CLIP model loaded: {ACTIVE_MODEL}");
                }
                Err(err) => tracing::error!("CLIP model load failed: {err:#}"),
            },
        );
    }

    /// Returns `true` once the model has finished loading and is ready to use.
    pub fn is_ready(&self) -> bool {
        self.inner.get().is_some()
    }

    /// Borrow the loaded embedder, or `None` if it has not finished loading yet.
    pub fn get(&self) -> Option<&clipper::ClipEmbedder> {
        self.inner.get()
    }
}

impl Default for Embedder {
    fn default() -> Self {
        Self::new()
    }
}

/// Load the active CLIP model synchronously, blocking the calling thread.
///
/// Downloads the model from HuggingFace on the first run (~1.5 GB) and caches
/// it locally.  Intended for CLI callers; prefer [`Embedder::start_loading`]
/// in the GUI to keep the UI responsive.
pub fn load_active_model_sync() -> Result<impl EmbedFn + Send + Sync> {
    clipper::ClipEmbedder::from_model(ACTIVE_MODEL, false)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards that the clip write-path constant and the model.rs read-path constant
    /// remain in sync.  A model bump editing only one of them would cause embeddings
    /// written under one name to be queried under another, silently returning zero rows.
    #[test]
    fn active_model_matches_canonical_name() {
        assert_eq!(
            ACTIVE_MODEL,
            crate::model::ACTIVE_MODEL_NAME,
            "clip::ACTIVE_MODEL and model::ACTIVE_MODEL_NAME must stay in sync"
        );
    }

    #[test]
    fn normalize_vector_is_unit_length() {
        let v = super::normalize_vector(&[3.0, 4.0]);
        let mag: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((mag - 1.0).abs() < 1e-6);
    }

    #[test]
    fn to_le_bytes_roundtrips() {
        let v = vec![1.0f32, -2.5, 0.0];
        let b = super::to_le_bytes(&v);
        assert_eq!(b.len(), 12);
        let back: Vec<f32> = b
            .chunks(4)
            .map(|c| f32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        assert_eq!(back, v);
    }

    /// Downloads ~1.5 GB from HuggingFace on the first run (cached thereafter).
    /// Run manually: `cargo test -p utmost-index -- --ignored clip::tests::loads_active_model_and_embeds_text`
    #[test]
    #[ignore = "downloads ~1.5 GB from HuggingFace; run manually with `-- --ignored`"]
    fn loads_active_model_and_embeds_text() {
        let embedder = clipper::ClipEmbedder::from_model(ACTIVE_MODEL, false).expect("model load");
        let embedding = embed_text(&embedder, "a photograph of a cat").expect("text embedding");
        assert_eq!(embedding.len(), ACTIVE_DIM);
        let mag: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!(mag > 0.0, "embedding must be non-zero");
    }
}
