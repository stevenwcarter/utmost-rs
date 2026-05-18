//! Pure-Rust view-model that consumes CarveEvents. No Slint imports.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use utmost_lib::events::{CarveEvent, CaseMetadata};
use utmost_lib::types::{FileObject, FileType};

pub type FileId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunStatus { Pending, Running, Finished, Interrupted }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceStatus { Pending, Running, Finished, Interrupted }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey { Filename, Size }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDir { Asc, Desc }

#[derive(Debug, Clone)]
pub struct RunSummary {
    pub started_at: String,
    pub output_root: String,
    pub configured_types: Vec<FileType>,
    pub status: RunStatus,
    pub case: Option<CaseMetadata>,
    pub elapsed_ms: u64,
    pub total_files: u64,
}

impl Default for RunSummary {
    fn default() -> Self {
        Self {
            started_at: String::new(),
            output_root: String::new(),
            configured_types: Vec::new(),
            status: RunStatus::Pending,
            case: None,
            elapsed_ms: 0,
            total_files: 0,
        }
    }
}

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

#[derive(Debug, Clone)]
pub struct FoundFile {
    pub id: FileId,
    pub source_id: u32,
    pub file: FileObject,
    pub written_path: PathBuf,
    pub img_offset: u64,
}

#[derive(Debug, Clone)]
pub struct FilterState {
    pub enabled_types: BTreeSet<FileType>,
    pub source_filter: Option<u32>,
    pub sort_key: SortKey,
    pub sort_dir: SortDir,
}

impl Default for FilterState {
    fn default() -> Self {
        Self {
            enabled_types: BTreeSet::new(),
            source_filter: None,
            sort_key: SortKey::Filename,
            sort_dir: SortDir::Asc,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct ViewModel {
    pub run: RunSummary,
    pub sources: Vec<SourceRow>,
    pub files: Vec<FoundFile>,
    pub type_counts: BTreeMap<FileType, u64>,
    pub filter: FilterState,
    pub selection: Option<FileId>,
    pub visible_files: Vec<FileId>,
    next_file_id: FileId,
}

impl ViewModel {
    pub fn new() -> Self { Self::default() }

    /// To be implemented in Task 25.
    pub fn apply(&mut self, _event: &CarveEvent) {
        unimplemented!("ViewModel::apply implemented in Task 25")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_view_model_is_empty() {
        let vm = ViewModel::new();
        assert_eq!(vm.sources.len(), 0);
        assert_eq!(vm.files.len(), 0);
        assert_eq!(vm.run.status, RunStatus::Pending);
        assert!(vm.selection.is_none());
    }
}
