//! Domain types shared between the indexer write surface and the GUI layer.
//!
//! These types are stripped of all Slint dependencies so they can live in
//! `utmost-index` without pulling in `utmost-gui`.  Field names and serde
//! representations are kept identical to the originals in
//! `crates/utmost-gui/src/{thumb_worker,view_model}.rs`.

// ── Preview types ─────────────────────────────────────────────────────────────

/// Codec used to encode a preview thumbnail in the `preview_blob` table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewCodec {
    Jpeg,
}

impl PreviewCodec {
    /// Canonical string name stored in `preview_blob.codec`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Jpeg => "jpeg",
        }
    }
}

/// Outcome of a thumbnail decode attempt for a single carved file.
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

/// A decoded (or failed) preview result, ready to be persisted via
/// [`crate::db::writer::write_preview_outcomes`].
#[derive(Debug, Clone)]
pub struct PreviewOutcome {
    pub file_id: u64,
    pub status: PreviewStatus,
}

// ── UI-state snapshot types ───────────────────────────────────────────────────

/// Persisted snapshot of the per-case UI state stored in `meta.ui_state`.
///
/// Version field `v` is at `1`.  Per-field `#[serde(default)]` allows additive
/// forward-compatibility: a future task can add fields without bumping `v`.
/// Non-additive changes require bumping the version and adding a migration arm
/// in `UiStateSnapshot::into_runtime` (in `utmost-gui`).
#[derive(Debug, Clone, PartialEq, Default, serde::Serialize, serde::Deserialize)]
pub struct UiStateSnapshot {
    #[serde(default)]
    pub v: u32,
    #[serde(default)]
    pub filter: FilterStateSnapshot,
    #[serde(default)]
    pub filters_visible: bool,
    #[serde(default)]
    pub selected_group: Option<String>,
    #[serde(default)]
    pub selection_file_id: Option<u64>,
}

/// Persisted snapshot of the filter/sort state within a case detail view.
#[derive(Debug, Clone, PartialEq, Default, serde::Serialize, serde::Deserialize)]
pub struct FilterStateSnapshot {
    #[serde(default)]
    pub enabled_types: Vec<String>,
    #[serde(default)]
    pub enabled_partial_types: Vec<String>,
    #[serde(default)]
    pub bookmarked_only: bool,
    #[serde(default)]
    pub source_filter: Option<u32>,
    #[serde(default)]
    pub sort_key: String,
    #[serde(default)]
    pub sort_dir: String,
    #[serde(default)]
    pub bookmarked_first: bool,
    #[serde(default)]
    pub hide_no_preview: bool,
    #[serde(default)]
    pub size_range: Option<(u64, u64)>,
}
