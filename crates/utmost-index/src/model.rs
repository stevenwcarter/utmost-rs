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

// ── View-model types ──────────────────────────────────────────────────────────
//
// Plain-data copies of types defined in `utmost-gui::view_model`.  Reproduced
// here (without Slint dependencies) so the read surface (`queries`, `hydrate`)
// can return them without depending on `utmost-gui`.  Field names, types, and
// derives are kept identical to the originals.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use utmost_lib::events::CaseMetadata;
use utmost_lib::types::{FileObject, FileType};

/// Canonical stable identifier for a carved file, matching `FileObject.file_id`.
pub type FileId = u64;

/// Status of the overall carve run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunStatus {
    Pending,
    Running,
    Finished,
    Interrupted,
}

/// Status of a single source image within a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceStatus {
    Pending,
    Running,
    Finished,
    Interrupted,
}

/// Primary sort key for the file grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortKey {
    #[default]
    Filename,
    Size,
    FileType,
    SourceOffset,
}

/// Sort direction for the file grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortDir {
    #[default]
    Asc,
    Desc,
}

/// High-level summary of the carve run, populated from the `run` table.
#[derive(Debug, Clone)]
pub struct RunSummary {
    pub started_at: String,
    pub output_root: String,
    pub source_image_path: String,
    pub configured_types: Vec<FileType>,
    pub status: RunStatus,
    pub case: Option<CaseMetadata>,
    pub elapsed_ms: u64,
    pub total_files: u64,
}

/// View-model row for a single source image.
///
/// Named `SourceRow` to match `utmost-gui::view_model::SourceRow`; note that
/// `crate::db::models::SourceRow` is the lower-level raw DB row type.
#[derive(Debug, Clone)]
pub struct SourceRow {
    pub source_id: u32,
    pub filename: String,
    pub output_subdir: String,
    pub total_bytes: u64,
    pub bytes_read: u64,
    pub files_found: u64,
    pub status: SourceStatus,
    pub duration_ms: Option<u64>,
}

/// A single carved file as returned by [`crate::db::queries::fetch_window`].
#[derive(Debug, Clone)]
pub struct FoundFile {
    pub id: FileId,
    pub source_id: u32,
    pub file: FileObject,
    pub written_path: PathBuf,
    pub img_offset: u64,
}

/// Runtime filter/sort state for the file grid.
///
/// `enabled_types` and `enabled_partial_types` are each a set of
/// [`FileType`]s: the full-chip set and the partial-chip set respectively.
/// Both empty → no type filter (all files returned).
///
/// `search_query` is **transient** — it is never persisted in
/// [`FilterStateSnapshot`] and is not serialised.  It serves as the signal
/// that a semantic search is active; the caller computes the corresponding
/// embedding and passes it to `query_match_ids` separately.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FilterState {
    pub enabled_types: BTreeSet<FileType>,
    pub enabled_partial_types: BTreeSet<FileType>,
    pub bookmarked_only: bool,
    pub source_filter: Option<u32>,
    pub sort_key: SortKey,
    pub sort_dir: SortDir,
    pub bookmarked_first: bool,
    pub hide_no_preview: bool,
    pub size_range: Option<(u64, u64)>,
    /// The raw text query typed by the user.  Transient — not persisted.
    /// When `Some`, `query_match_ids` uses the semantic-search (KNN) path
    /// instead of the filter+sort path, provided a query embedding is also
    /// supplied.
    pub search_query: Option<String>,
}

/// CLIP model identifier used for embedding storage and KNN lookup.
///
/// Non-feature-gated so that a `--no-default-features` build (without the
/// `clip` feature) can still compile the KNN search SQL path and read an
/// embedding cache written by a `clip`-enabled build.
pub const ACTIVE_MODEL_NAME: &str = "laion/CLIP-ViT-L-14-laion2B-s32B-b82K";

/// Whether a fragmentation-recovery run has been executed for this case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecoveryUiState {
    /// No partial JPEGs in the case — recovery is not applicable.
    #[default]
    Disabled,
    /// Partial JPEGs exist but recovery has not been run.
    NotRun,
    /// Recovery is currently in progress.
    Running,
    /// Recovery has completed.
    Finished,
}

/// Recovery candidates associated with a single partial file.
#[derive(Debug, Clone)]
pub struct VariantSet {
    pub original_id: FileId,
    /// Variant ids in rank order (rank 1 first).
    pub variant_ids: Vec<FileId>,
}

/// A single user annotation on a carved file.
#[derive(Debug, Clone)]
pub struct NoteEntry {
    pub note_id: u64,
    pub text: String,
    pub at: String,
}

/// Plain-data snapshot of all ViewModel state that can be hydrated from the
/// SQLite index without replaying the event log.
///
/// The file list itself is NOT included — the caller posts a `Requery` /
/// `FetchWindow` to the indexer thread to populate it after hydration.
#[derive(Debug)]
pub struct ViewModelSnapshot {
    pub run: RunSummary,
    pub sources: Vec<SourceRow>,
    pub bookmarks: BTreeSet<FileId>,
    pub notes: BTreeMap<FileId, Vec<NoteEntry>>,
    pub best_choices: BTreeMap<FileId, FileId>,
    pub variants: BTreeMap<FileId, VariantSet>,
    pub variant_of: BTreeMap<FileId, FileId>,
    pub type_counts: BTreeMap<FileType, u64>,
    pub partial_counts: BTreeMap<FileType, u64>,
    pub recovery_state: RecoveryUiState,
    pub next_note_id: u64,
}

// ── File-type helpers ─────────────────────────────────────────────────────────

/// Parse the lowercase string stored in `file.file_type` back into a
/// [`FileType`] enum variant.  Returns `None` for unrecognised strings.
///
/// Inverse of `file_type_to_db_string` in `crate::db::queries`.
///
/// `parse_file_type_pub` is a stable public alias kept for compatibility with
/// code that previously referenced `utmost_gui::view_model::parse_file_type_pub`.
pub fn parse_file_type_pub(s: &str) -> Option<FileType> {
    parse_file_type(s)
}

pub fn parse_file_type(s: &str) -> Option<FileType> {
    match s {
        "jpeg" => Some(FileType::Jpeg),
        "gif" => Some(FileType::Gif),
        "bmp" => Some(FileType::Bmp),
        "mpg" => Some(FileType::Mpg),
        "pdf" => Some(FileType::Pdf),
        "doc" => Some(FileType::Doc),
        "avi" => Some(FileType::Avi),
        "wmv" => Some(FileType::Wmv),
        "htm" => Some(FileType::Htm),
        "zip" => Some(FileType::Zip),
        "mov" => Some(FileType::Mov),
        "xls" => Some(FileType::Xls),
        "ppt" => Some(FileType::Ppt),
        "wpd" => Some(FileType::Wpd),
        "cpp" => Some(FileType::Cpp),
        "ole" => Some(FileType::Ole),
        "gzip" => Some(FileType::Gzip),
        "riff" => Some(FileType::Riff),
        "wav" => Some(FileType::Wav),
        "vjpeg" => Some(FileType::VJpeg),
        "sxw" => Some(FileType::Sxw),
        "sxc" => Some(FileType::Sxc),
        "sxi" => Some(FileType::Sxi),
        "png" => Some(FileType::Png),
        "rar" => Some(FileType::Rar),
        "exe" => Some(FileType::Exe),
        "elf" => Some(FileType::Elf),
        "reg" => Some(FileType::Reg),
        "docx" => Some(FileType::Docx),
        "xlsx" => Some(FileType::Xlsx),
        "pptx" => Some(FileType::Pptx),
        "mp4" => Some(FileType::Mp4),
        "config" => Some(FileType::Config),
        _ => None,
    }
}
