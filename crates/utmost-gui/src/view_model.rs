//! Pure-Rust view-model that consumes CarveEvents. No Slint imports.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use utmost_lib::events::{CarveEvent, CaseMetadata};
use utmost_lib::types::{FileObject, FileType};

pub type FileId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunStatus {
    Pending,
    Running,
    Finished,
    Interrupted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceStatus {
    Pending,
    Running,
    Finished,
    Interrupted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortKey {
    #[default]
    Filename,
    Size,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortDir {
    #[default]
    Asc,
    Desc,
}

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

#[derive(Debug, Clone, Default)]
pub struct FilterState {
    pub enabled_types: BTreeSet<FileType>,
    pub enabled_partial_types: BTreeSet<FileType>,
    pub bookmarked_only: bool,
    pub source_filter: Option<u32>,
    pub sort_key: SortKey,
    pub sort_dir: SortDir,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LightboxView {
    pub zoom: f32,
    pub fit: bool,
}

impl Default for LightboxView {
    fn default() -> Self {
        Self {
            zoom: 1.0,
            fit: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecoveryUiState {
    #[default]
    Disabled,
    NotRun,
    Running,
    Finished,
}

#[derive(Debug, Clone)]
pub struct VariantSet {
    pub original_id: FileId,
    /// Variant ids in rank order (rank 1 first).
    pub variant_ids: Vec<FileId>,
}

#[derive(Debug, Clone)]
pub struct NoteEntry {
    pub note_id: u64,
    pub text: String,
    pub at: String,
}

#[derive(Debug, Clone)]
pub struct NoteInputState {
    pub target: FileId,
    pub draft: String,
}

#[derive(Debug, Default, Clone)]
pub struct ViewModel {
    // ── existing fields, unchanged ──
    pub run: RunSummary,
    pub sources: Vec<SourceRow>,
    pub files: Vec<FoundFile>,
    pub type_counts: BTreeMap<FileType, u64>,
    pub filter: FilterState,
    pub selection: Option<FileId>,
    pub visible_files: Vec<FileId>,
    pub lightbox: Option<FileId>,
    pub lightbox_view: LightboxView,
    next_file_id: FileId,

    // ── NEW ──
    pub variants: BTreeMap<FileId, VariantSet>,
    pub variant_of: BTreeMap<FileId, FileId>,
    pub bookmarks: BTreeSet<FileId>,
    pub notes: BTreeMap<FileId, Vec<NoteEntry>>,
    pub best_choices: BTreeMap<FileId, FileId>,
    pub partial_counts: BTreeMap<FileType, u64>,
    pub recovery_state: RecoveryUiState,
    pub variant_viewer: Option<FileId>,
    pub note_input: Option<NoteInputState>,
    #[allow(dead_code)] // used by Task 11's add_note method
    pub(crate) next_note_id: u64,
}

impl ViewModel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn recompute_visible(&mut self) {
        let mut ids: Vec<FileId> = self
            .files
            .iter()
            .filter(|f| {
                // Variants never appear in the main grid.
                if self.variant_of.contains_key(&f.file.file_id) {
                    return false;
                }
                if let Some(sid) = self.filter.source_filter
                    && f.source_id != sid
                {
                    return false;
                }
                if self.filter.bookmarked_only && !self.bookmarks.contains(&f.file.file_id) {
                    return false;
                }
                if let Some(ft) = parse_file_type(&f.file.file_type) {
                    let is_partial = f
                        .file
                        .jpeg_scan
                        .as_ref()
                        .map(|s| s.status != utmost_lib::types::JpegScanStatus::Complete)
                        .unwrap_or(false);
                    if is_partial {
                        self.filter.enabled_partial_types.contains(&ft)
                    } else {
                        self.filter.enabled_types.contains(&ft)
                    }
                } else {
                    true
                }
            })
            .map(|f| f.id)
            .collect();
        let by_id: BTreeMap<FileId, &FoundFile> = self.files.iter().map(|f| (f.id, f)).collect();
        ids.sort_by(|a, b| {
            let fa = by_id[a];
            let fb = by_id[b];
            let cmp = match self.filter.sort_key {
                SortKey::Filename => fa.file.filename.cmp(&fb.file.filename),
                SortKey::Size => fa.file.filesize.cmp(&fb.file.filesize),
            };
            match self.filter.sort_dir {
                SortDir::Asc => cmp,
                SortDir::Desc => cmp.reverse(),
            }
        });
        self.visible_files = ids;
    }

    pub fn apply(&mut self, event: &CarveEvent) {
        match event {
            CarveEvent::RunStarted {
                started_at,
                output_root,
                configured_types,
                case,
                sources,
                ..
            } => {
                self.run.started_at = started_at.clone();
                self.run.output_root = output_root.clone();
                self.run.configured_types = configured_types.clone();
                self.run.case = case.clone();
                self.run.status = RunStatus::Running;
                self.sources = sources
                    .iter()
                    .map(|s| SourceRow {
                        source_id: s.source_id,
                        filename: s.filename.clone(),
                        output_subdir: s.output_subdir.clone(),
                        total_bytes: s.total_bytes,
                        bytes_read: 0,
                        files_found: 0,
                        status: SourceStatus::Pending,
                        duration_ms: None,
                    })
                    .collect();
                self.filter.enabled_types = configured_types.iter().copied().collect();
            }
            CarveEvent::SourceStarted { source_id } => {
                if let Some(row) = self.sources.iter_mut().find(|r| r.source_id == *source_id) {
                    row.status = SourceStatus::Running;
                }
            }
            CarveEvent::FileFound {
                source_id,
                file,
                img_offset,
                written_path,
            } => {
                let id = self.next_file_id;
                self.next_file_id += 1;
                let abs_path: PathBuf = PathBuf::from(&self.run.output_root).join(written_path);
                let ft = parse_file_type(&file.file_type);
                if let Some(ft) = ft {
                    *self.type_counts.entry(ft).or_insert(0) += 1;
                    if self.run.configured_types.is_empty() {
                        self.filter.enabled_types.insert(ft);
                    }
                }
                let is_partial = file
                    .jpeg_scan
                    .as_ref()
                    .map(|s| s.status != utmost_lib::types::JpegScanStatus::Complete)
                    .unwrap_or(false);
                if is_partial && let Some(ft) = ft {
                    *self.partial_counts.entry(ft).or_insert(0) += 1;
                }
                self.files.push(FoundFile {
                    id,
                    source_id: *source_id,
                    file: file.clone(),
                    written_path: abs_path,
                    img_offset: *img_offset,
                });
                if let Some(row) = self.sources.iter_mut().find(|r| r.source_id == *source_id) {
                    row.files_found += 1;
                }
                self.run.total_files += 1;
            }
            CarveEvent::ProgressTick {
                source_id,
                bytes_read,
            } => {
                if let Some(row) = self.sources.iter_mut().find(|r| r.source_id == *source_id) {
                    row.bytes_read = *bytes_read;
                }
            }
            CarveEvent::SourceFinished {
                source_id,
                bytes_read,
                duration_ms,
            } => {
                if let Some(row) = self.sources.iter_mut().find(|r| r.source_id == *source_id) {
                    row.status = SourceStatus::Finished;
                    row.bytes_read = *bytes_read;
                    row.duration_ms = Some(*duration_ms);
                }
            }
            CarveEvent::RunFinished {
                duration_ms,
                total_files_written: _,
            } => {
                self.run.status = RunStatus::Finished;
                self.run.elapsed_ms = *duration_ms;
                if !self.partial_counts.is_empty()
                    && self.recovery_state == RecoveryUiState::Disabled
                {
                    self.recovery_state = RecoveryUiState::NotRun;
                }
            }
            CarveEvent::RecoveryStarted { .. } => {
                self.recovery_state = RecoveryUiState::Running;
            }
            CarveEvent::RecoveryFinished { .. } => {
                self.recovery_state = RecoveryUiState::Finished;
            }
            CarveEvent::RecoveryCandidate {
                original_file_id,
                candidate_file_id,
                ..
            } => {
                let entry = self
                    .variants
                    .entry(*original_file_id)
                    .or_insert_with(|| VariantSet {
                        original_id: *original_file_id,
                        variant_ids: Vec::new(),
                    });
                if !entry.variant_ids.contains(candidate_file_id) {
                    entry.variant_ids.push(*candidate_file_id);
                }
                self.variant_of
                    .insert(*candidate_file_id, *original_file_id);
                self.recompute_visible();
            }
            CarveEvent::Bookmark {
                file_id,
                bookmarked,
                ..
            } => {
                if *bookmarked {
                    self.bookmarks.insert(*file_id);
                } else {
                    self.bookmarks.remove(file_id);
                }
            }
            CarveEvent::Note {
                note_id,
                file_id,
                text,
                at,
            } => {
                self.notes.entry(*file_id).or_default().push(NoteEntry {
                    note_id: *note_id,
                    text: text.clone(),
                    at: at.clone(),
                });
                self.next_note_id = self.next_note_id.max(*note_id + 1);
            }
            CarveEvent::MarkAsBest {
                original_file_id,
                chosen_file_id,
                ..
            } => {
                self.best_choices.insert(*original_file_id, *chosen_file_id);
            }
        }
    }

    pub fn open_lightbox(&mut self) {
        if let Some(id) = self.selection {
            self.lightbox = Some(id);
            self.lightbox_view = LightboxView::default();
        }
    }

    pub fn close_lightbox(&mut self) {
        self.lightbox = None;
    }

    pub fn lightbox_next(&mut self) {
        self.lightbox_step(1);
    }

    pub fn lightbox_prev(&mut self) {
        self.lightbox_step(-1);
    }

    pub fn deselect(&mut self) {
        self.selection = None;
        self.lightbox = None;
    }

    pub fn close_or_deselect(&mut self) {
        if self.lightbox.is_some() {
            self.lightbox = None;
        } else {
            self.selection = None;
        }
    }

    pub fn zoom_set(&mut self, z: f32) {
        self.lightbox_view.zoom = z.clamp(0.1, 8.0);
        self.lightbox_view.fit = false;
    }

    pub fn zoom_fit(&mut self) {
        self.lightbox_view = LightboxView::default();
    }

    pub fn toggle_bookmark(&mut self, file_id: FileId) -> CarveEvent {
        let was = self.bookmarks.contains(&file_id);
        let bookmarked = !was;
        if bookmarked {
            self.bookmarks.insert(file_id);
        } else {
            self.bookmarks.remove(&file_id);
        }
        CarveEvent::Bookmark {
            file_id,
            bookmarked,
            at: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn add_note(&mut self, file_id: FileId, text: String) -> CarveEvent {
        self.next_note_id = self.next_note_id.max(1);
        let note_id = self.next_note_id;
        self.next_note_id += 1;
        let at = chrono::Utc::now().to_rfc3339();
        self.notes.entry(file_id).or_default().push(NoteEntry {
            note_id,
            text: text.clone(),
            at: at.clone(),
        });
        CarveEvent::Note {
            note_id,
            file_id,
            text,
            at,
        }
    }

    pub fn mark_as_best(&mut self, original_file_id: FileId, chosen_file_id: FileId) -> CarveEvent {
        self.best_choices.insert(original_file_id, chosen_file_id);
        CarveEvent::MarkAsBest {
            original_file_id,
            chosen_file_id,
            at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Opens the variant viewer for the currently selected file.
    ///
    /// # ID-space caveat
    ///
    /// `self.selection` must hold a library-level `FileObject.file_id` for the
    /// `self.variants.contains_key` lookup to succeed, because `variants` is
    /// keyed by `FileObject.file_id`. If the GUI has stored the VM-internal
    /// `FoundFile.id` in `selection` instead, this check will silently fail.
    /// Callers (Tasks 16/17/18) must either (a) store the library `file_id` in
    /// `selection`, or (b) resolve it via
    /// `vm.files.iter().find(|f| f.id == sel).map(|f| f.file.file_id)` before
    /// calling this method.
    pub fn open_variant_viewer(&mut self) {
        if let Some(sel) = self.selection
            && self.variants.contains_key(&sel)
        {
            self.variant_viewer = Some(sel);
        }
    }

    pub fn close_variant_viewer(&mut self) {
        self.variant_viewer = None;
    }

    pub fn open_lightbox_for_variant(&mut self, variant_id: FileId) {
        self.lightbox = Some(variant_id);
        self.lightbox_view = LightboxView::default();
    }

    fn lightbox_step(&mut self, delta: isize) {
        let Some(cur) = self.lightbox else { return };
        let n = self.visible_files.len();
        if n == 0 {
            return;
        }
        let Some(idx) = self.visible_files.iter().position(|id| *id == cur) else {
            return;
        };
        let next_idx = ((idx as isize + delta).rem_euclid(n as isize)) as usize;
        self.lightbox = Some(self.visible_files[next_idx]);
        self.lightbox_view = LightboxView::default();
    }
}

pub fn parse_file_type_pub(s: &str) -> Option<FileType> {
    parse_file_type(s)
}

fn parse_file_type(s: &str) -> Option<FileType> {
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

    use utmost_lib::events::*;
    use utmost_lib::reporting::create_file_object;
    use utmost_lib::types::{ExecutionEnvironment, FileType};

    fn empty_env() -> ExecutionEnvironment {
        ExecutionEnvironment {
            os_sysname: String::new(),
            os_release: String::new(),
            os_version: String::new(),
            host: String::new(),
            arch: String::new(),
            uid: 0,
            start_time: String::new(),
        }
    }
    fn empty_cli() -> CliConfigSnapshot {
        CliConfigSnapshot {
            output_directory: "out".into(),
            types: vec![],
            disable_builtin: false,
            config_file: None,
            concurrent_files: 1,
            disable_validation: false,
            report_only: false,
            disable_report: false,
            disable_audit: false,
            disable_export: false,
            gui_enabled: false,
            quick: false,
            block_size: 512,
            prefix_filenames: false,
            write_all: false,
            keep_incomplete_jpeg: false,
        }
    }

    fn run_started_with_sources(ids: &[u32]) -> CarveEvent {
        CarveEvent::RunStarted {
            utmost_version: "test".into(),
            format_version: CURRENT_FORMAT_VERSION,
            started_at: "t".into(),
            command_line: vec![],
            working_directory: "/".into(),
            execution_environment: empty_env(),
            cli_config: empty_cli(),
            case: None,
            configured_types: vec![FileType::Jpeg],
            sources: ids
                .iter()
                .map(|i| SourceDescriptor {
                    source_id: *i,
                    filename: format!("src{i}.bin"),
                    total_bytes: 1000,
                    output_subdir: format!("output-{i}"),
                })
                .collect(),
            output_root: "out".into(),
        }
    }

    #[test]
    fn run_started_populates_run_and_sources() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0, 1]));
        assert_eq!(vm.sources.len(), 2);
        assert_eq!(vm.sources[0].source_id, 0);
        assert_eq!(vm.run.status, RunStatus::Running);
        assert_eq!(vm.run.output_root, "out");
        assert_eq!(vm.run.configured_types, vec![FileType::Jpeg]);
    }

    #[test]
    fn source_started_sets_source_running() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        vm.apply(&CarveEvent::SourceStarted { source_id: 0 });
        assert_eq!(vm.sources[0].status, SourceStatus::Running);
    }

    #[test]
    fn file_found_adds_file_and_increments_counts() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        let fo = create_file_object("a.jpg", FileType::Jpeg, 1024, 0, None, 1);
        vm.apply(&CarveEvent::FileFound {
            source_id: 0,
            file: fo,
            img_offset: 0,
            written_path: "a.jpg".into(),
        });
        assert_eq!(vm.files.len(), 1);
        assert_eq!(vm.type_counts.get(&FileType::Jpeg), Some(&1));
        assert_eq!(vm.sources[0].files_found, 1);
        assert_eq!(vm.run.total_files, 1);
    }

    #[test]
    fn progress_tick_updates_source_bytes_read() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        vm.apply(&CarveEvent::ProgressTick {
            source_id: 0,
            bytes_read: 500,
        });
        assert_eq!(vm.sources[0].bytes_read, 500);
    }

    #[test]
    fn source_finished_flips_status_and_records_duration() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        vm.apply(&CarveEvent::SourceFinished {
            source_id: 0,
            bytes_read: 1000,
            duration_ms: 42,
        });
        assert_eq!(vm.sources[0].status, SourceStatus::Finished);
        assert_eq!(vm.sources[0].duration_ms, Some(42));
        assert_eq!(vm.sources[0].bytes_read, 1000);
    }

    #[test]
    fn run_finished_flips_run_status() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        vm.apply(&CarveEvent::RunFinished {
            duration_ms: 100,
            total_files_written: 3,
        });
        assert_eq!(vm.run.status, RunStatus::Finished);
        assert_eq!(vm.run.elapsed_ms, 100);
    }

    #[test]
    fn file_found_before_known_source_still_inserted() {
        let mut vm = ViewModel::new();
        // Skip RunStarted entirely
        let fo = create_file_object("a.jpg", FileType::Jpeg, 1, 0, None, 1);
        vm.apply(&CarveEvent::FileFound {
            source_id: 99,
            file: fo,
            img_offset: 0,
            written_path: "a.jpg".into(),
        });
        assert_eq!(vm.files.len(), 1);
    }

    fn add_file(vm: &mut ViewModel, sid: u32, name: &str, ft: FileType, sz: u64) {
        let fo = create_file_object(name, ft, sz, 0, None, 0);
        vm.apply(&CarveEvent::FileFound {
            source_id: sid,
            file: fo,
            img_offset: 0,
            written_path: name.into(),
        });
    }

    #[test]
    fn visible_files_includes_only_enabled_types() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 100);
        add_file(&mut vm, 0, "b.pdf", FileType::Pdf, 200);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.recompute_visible();
        assert_eq!(vm.visible_files.len(), 1);
    }

    #[test]
    fn sort_by_filename_asc() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "z.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.sort_key = SortKey::Filename;
        vm.filter.sort_dir = SortDir::Asc;
        vm.recompute_visible();
        let first = vm
            .files
            .iter()
            .find(|f| f.id == vm.visible_files[0])
            .unwrap();
        assert_eq!(first.file.filename, "a.jpg");
    }

    #[test]
    fn sort_by_size_desc() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "x.jpg", FileType::Jpeg, 100);
        add_file(&mut vm, 0, "y.jpg", FileType::Jpeg, 999);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.sort_key = SortKey::Size;
        vm.filter.sort_dir = SortDir::Desc;
        vm.recompute_visible();
        let first = vm
            .files
            .iter()
            .find(|f| f.id == vm.visible_files[0])
            .unwrap();
        assert_eq!(first.file.filesize, 999);
    }

    #[test]
    fn source_filter_limits_to_one_source() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0, 1]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 1, "b.jpg", FileType::Jpeg, 1);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.filter.source_filter = Some(1);
        vm.recompute_visible();
        assert_eq!(vm.visible_files.len(), 1);
        let f = vm
            .files
            .iter()
            .find(|f| f.id == vm.visible_files[0])
            .unwrap();
        assert_eq!(f.source_id, 1);
    }

    #[test]
    fn new_view_model_has_lightbox_closed() {
        let vm = ViewModel::new();
        assert!(vm.lightbox.is_none());
        assert!(vm.lightbox_view.fit);
        assert!((vm.lightbox_view.zoom - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn open_lightbox_uses_current_selection() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        vm.recompute_visible();
        let id = vm.visible_files[0];
        vm.selection = Some(id);
        vm.open_lightbox();
        assert_eq!(vm.lightbox, Some(id));
        // Fit/zoom reset on open.
        assert!(vm.lightbox_view.fit);
        assert!((vm.lightbox_view.zoom - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn open_lightbox_noop_without_selection() {
        let mut vm = ViewModel::new();
        vm.selection = None;
        vm.open_lightbox();
        assert!(vm.lightbox.is_none());
    }

    #[test]
    fn close_lightbox_clears_lightbox_keeps_selection() {
        let mut vm = ViewModel::new();
        vm.selection = Some(7);
        vm.lightbox = Some(7);
        vm.close_lightbox();
        assert_eq!(vm.selection, Some(7));
        assert!(vm.lightbox.is_none());
    }

    #[test]
    fn lightbox_next_wraps_at_end() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 0, "b.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 0, "c.jpg", FileType::Jpeg, 1);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.recompute_visible();
        let ids = vm.visible_files.clone();
        vm.selection = Some(ids[2]);
        vm.open_lightbox();
        vm.lightbox_next();
        assert_eq!(vm.lightbox, Some(ids[0])); // wrapped
    }

    #[test]
    fn lightbox_prev_wraps_at_start() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 0, "b.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 0, "c.jpg", FileType::Jpeg, 1);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.recompute_visible();
        let ids = vm.visible_files.clone();
        vm.selection = Some(ids[0]);
        vm.open_lightbox();
        vm.lightbox_prev();
        assert_eq!(vm.lightbox, Some(ids[2])); // wrapped to end
    }

    #[test]
    fn lightbox_next_on_empty_visible_is_noop() {
        let mut vm = ViewModel::new();
        // No files added; visible_files is empty.
        vm.lightbox = None;
        vm.lightbox_next();
        assert!(vm.lightbox.is_none());
    }

    #[test]
    fn lightbox_next_resets_zoom_to_fit() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        add_file(&mut vm, 0, "a.jpg", FileType::Jpeg, 1);
        add_file(&mut vm, 0, "b.jpg", FileType::Jpeg, 1);
        vm.filter.enabled_types = [FileType::Jpeg].into_iter().collect();
        vm.recompute_visible();
        let ids = vm.visible_files.clone();
        vm.selection = Some(ids[0]);
        vm.open_lightbox();
        vm.lightbox_view.fit = false;
        vm.lightbox_view.zoom = 2.5;
        vm.lightbox_next();
        assert!(vm.lightbox_view.fit);
        assert!((vm.lightbox_view.zoom - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn deselect_clears_selection_and_lightbox() {
        let mut vm = ViewModel::new();
        vm.selection = Some(3);
        vm.lightbox = Some(3);
        vm.deselect();
        assert!(vm.selection.is_none());
        assert!(vm.lightbox.is_none());
    }

    #[test]
    fn close_or_deselect_closes_lightbox_first() {
        let mut vm = ViewModel::new();
        vm.selection = Some(3);
        vm.lightbox = Some(3);
        vm.close_or_deselect();
        // Lightbox closed, selection kept.
        assert_eq!(vm.selection, Some(3));
        assert!(vm.lightbox.is_none());
        // Second press clears selection.
        vm.close_or_deselect();
        assert!(vm.selection.is_none());
        assert!(vm.lightbox.is_none());
    }

    #[test]
    fn close_or_deselect_with_nothing_is_noop() {
        let mut vm = ViewModel::new();
        vm.close_or_deselect();
        assert!(vm.selection.is_none());
        assert!(vm.lightbox.is_none());
    }

    #[test]
    fn zoom_set_clamps_and_disables_fit() {
        let mut vm = ViewModel::new();
        vm.zoom_set(2.0);
        assert!((vm.lightbox_view.zoom - 2.0).abs() < f32::EPSILON);
        assert!(!vm.lightbox_view.fit);

        // Below 0.1 clamps to 0.1.
        vm.zoom_set(0.05);
        assert!((vm.lightbox_view.zoom - 0.1).abs() < f32::EPSILON);

        // Above 8.0 clamps to 8.0.
        vm.zoom_set(20.0);
        assert!((vm.lightbox_view.zoom - 8.0).abs() < f32::EPSILON);
    }

    #[test]
    fn zoom_fit_flips_fit_on_and_resets_zoom() {
        let mut vm = ViewModel::new();
        vm.lightbox_view.fit = false;
        vm.lightbox_view.zoom = 3.0;
        vm.zoom_fit();
        assert!(vm.lightbox_view.fit);
        assert!((vm.lightbox_view.zoom - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn apply_recovery_candidate_populates_variants() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));

        // Set up an original partial JPEG (file_id 10) and a candidate (file_id 11)
        let mut fo_orig = create_file_object("orig.jpg", FileType::Jpeg, 100, 0, None, 10);
        fo_orig.jpeg_scan = Some(utmost_lib::types::JpegScanInfo {
            width: None,
            height: None,
            fragmentation_point_img_offset: None,
            has_restart_markers: false,
            status: utmost_lib::types::JpegScanStatus::Truncated,
        });
        vm.apply(&CarveEvent::FileFound {
            source_id: 0,
            file: fo_orig,
            img_offset: 0,
            written_path: "orig.jpg".into(),
        });

        let fo_cand =
            create_file_object("orig_recovered_1.jpg", FileType::Jpeg, 200, 5000, None, 11);
        vm.apply(&CarveEvent::FileFound {
            source_id: 0,
            file: fo_cand,
            img_offset: 5000,
            written_path: "orig_recovered_1.jpg".into(),
        });

        vm.apply(&CarveEvent::RecoveryCandidate {
            original_file_id: 10,
            candidate_file_id: 11,
            rank: 1,
            method: utmost_lib::events::RecoveryMethod::DirectContinuation,
            entropy_score: 7.9,
            ff_validity_score: Some(0.97),
            huffman_mcu_count: Some(412),
            continuation_img_offset: 5000,
        });

        let vs = vm.variants.get(&10).expect("variant set");
        assert_eq!(vs.variant_ids, vec![11]);
        assert_eq!(vm.variant_of.get(&11), Some(&10));
    }

    #[test]
    fn recovery_started_finished_toggle_recovery_state() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        vm.recovery_state = RecoveryUiState::NotRun;

        vm.apply(&CarveEvent::RecoveryStarted {
            started_at: "t".into(),
            keep_candidates: 5,
            search_window: 50_000_000,
            block_size: 512,
            min_entropy_score: 7.0,
            huffman_validation: true,
        });
        assert_eq!(vm.recovery_state, RecoveryUiState::Running);

        vm.apply(&CarveEvent::RecoveryFinished {
            duration_ms: 100,
            partials_processed: 1,
            candidates_written: 1,
        });
        assert_eq!(vm.recovery_state, RecoveryUiState::Finished);
    }

    #[test]
    fn new_view_model_has_empty_annotation_state() {
        let vm = ViewModel::new();
        assert!(vm.variants.is_empty());
        assert!(vm.variant_of.is_empty());
        assert!(vm.bookmarks.is_empty());
        assert!(vm.notes.is_empty());
        assert!(vm.best_choices.is_empty());
        assert!(vm.partial_counts.is_empty());
        assert_eq!(vm.recovery_state, RecoveryUiState::Disabled);
        assert!(vm.variant_viewer.is_none());
        assert!(vm.note_input.is_none());
    }

    #[test]
    fn apply_bookmark_toggles_membership() {
        let mut vm = ViewModel::new();
        vm.apply(&CarveEvent::Bookmark {
            file_id: 7,
            bookmarked: true,
            at: "t".into(),
        });
        assert!(vm.bookmarks.contains(&7));
        vm.apply(&CarveEvent::Bookmark {
            file_id: 7,
            bookmarked: false,
            at: "t".into(),
        });
        assert!(!vm.bookmarks.contains(&7));
    }

    #[test]
    fn apply_note_appends_chronologically_and_tracks_next_id() {
        let mut vm = ViewModel::new();
        vm.apply(&CarveEvent::Note {
            note_id: 1,
            file_id: 7,
            text: "a".into(),
            at: "t1".into(),
        });
        vm.apply(&CarveEvent::Note {
            note_id: 2,
            file_id: 7,
            text: "b".into(),
            at: "t2".into(),
        });
        let entries = vm.notes.get(&7).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].text, "a");
        assert_eq!(entries[1].text, "b");
        assert_eq!(vm.next_note_id, 3);
    }

    #[test]
    fn recompute_visible_excludes_variants_from_main_grid() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        vm.filter.enabled_types.insert(FileType::Jpeg);

        // VM assigns internal ids sequentially from 0: a.jpg → 0, b.jpg → 1.
        // FileObject file_ids (1 and 2) are used as the RecoveryCandidate ids.
        let fo_a = create_file_object("a.jpg", FileType::Jpeg, 100, 0, None, 1);
        let fo_b = create_file_object("b.jpg", FileType::Jpeg, 100, 0, None, 2);
        vm.apply(&CarveEvent::FileFound {
            source_id: 0,
            file: fo_a,
            img_offset: 0,
            written_path: "a.jpg".into(),
        });
        vm.apply(&CarveEvent::FileFound {
            source_id: 0,
            file: fo_b,
            img_offset: 0,
            written_path: "b.jpg".into(),
        });

        // Mark b.jpg (file_id=2) as a recovery candidate of a.jpg (file_id=1).
        vm.apply(&CarveEvent::RecoveryCandidate {
            original_file_id: 1,
            candidate_file_id: 2,
            rank: 1,
            method: utmost_lib::events::RecoveryMethod::DirectContinuation,
            entropy_score: 7.5,
            ff_validity_score: None,
            huffman_mcu_count: None,
            continuation_img_offset: 0,
        });

        // VM internal id 0 = a.jpg (not a variant) → visible.
        // VM internal id 1 = b.jpg (variant of a.jpg) → excluded.
        assert_eq!(vm.visible_files, vec![0]);
    }

    #[test]
    fn partial_chip_is_independent_of_normal_chip() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));

        // VM internal id 0 = c.jpg (complete), id 1 = p.jpg (partial).
        let mut fo_complete = create_file_object("c.jpg", FileType::Jpeg, 100, 0, None, 1);
        fo_complete.jpeg_scan = Some(utmost_lib::types::JpegScanInfo {
            width: None,
            height: None,
            fragmentation_point_img_offset: None,
            has_restart_markers: false,
            status: utmost_lib::types::JpegScanStatus::Complete,
        });
        let mut fo_partial = create_file_object("p.jpg", FileType::Jpeg, 100, 0, None, 2);
        fo_partial.jpeg_scan = Some(utmost_lib::types::JpegScanInfo {
            width: None,
            height: None,
            fragmentation_point_img_offset: None,
            has_restart_markers: false,
            status: utmost_lib::types::JpegScanStatus::Truncated,
        });
        vm.apply(&CarveEvent::FileFound {
            source_id: 0,
            file: fo_complete,
            img_offset: 0,
            written_path: "c.jpg".into(),
        });
        vm.apply(&CarveEvent::FileFound {
            source_id: 0,
            file: fo_partial,
            img_offset: 0,
            written_path: "p.jpg".into(),
        });

        // Only "Partial JPG" enabled — should show only p.jpg (VM id 1).
        vm.filter.enabled_types.clear();
        vm.filter.enabled_partial_types.insert(FileType::Jpeg);
        vm.recompute_visible();
        assert_eq!(vm.visible_files, vec![1]);

        // Only "JPG" enabled — should show only c.jpg (VM id 0).
        vm.filter.enabled_types.insert(FileType::Jpeg);
        vm.filter.enabled_partial_types.clear();
        vm.recompute_visible();
        assert_eq!(vm.visible_files, vec![0]);

        // Both enabled — both visible.
        vm.filter.enabled_partial_types.insert(FileType::Jpeg);
        vm.recompute_visible();
        assert_eq!(vm.visible_files, vec![0, 1]);
    }

    #[test]
    fn bookmarked_only_filter_narrows_grid() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));
        vm.filter.enabled_types.insert(FileType::Jpeg);

        // VM internal id 0 = a.jpg, id 1 = b.jpg.
        let fo_a = create_file_object("a.jpg", FileType::Jpeg, 100, 0, None, 1);
        let fo_b = create_file_object("b.jpg", FileType::Jpeg, 100, 0, None, 2);
        vm.apply(&CarveEvent::FileFound {
            source_id: 0,
            file: fo_a,
            img_offset: 0,
            written_path: "a.jpg".into(),
        });
        vm.apply(&CarveEvent::FileFound {
            source_id: 0,
            file: fo_b,
            img_offset: 0,
            written_path: "b.jpg".into(),
        });

        // Bookmark b.jpg by its library file_id (2).
        vm.apply(&CarveEvent::Bookmark {
            file_id: 2,
            bookmarked: true,
            at: "t".into(),
        });
        vm.filter.bookmarked_only = true;
        vm.recompute_visible();
        assert_eq!(vm.visible_files, vec![1]);
    }

    #[test]
    fn apply_mark_as_best_is_last_writer_wins() {
        let mut vm = ViewModel::new();
        vm.apply(&CarveEvent::MarkAsBest {
            original_file_id: 10,
            chosen_file_id: 11,
            at: "t1".into(),
        });
        vm.apply(&CarveEvent::MarkAsBest {
            original_file_id: 10,
            chosen_file_id: 12,
            at: "t2".into(),
        });
        assert_eq!(vm.best_choices.get(&10), Some(&12));
    }

    #[test]
    fn toggle_bookmark_returns_event_and_updates_state() {
        let mut vm = ViewModel::new();
        let ev = vm.toggle_bookmark(7);
        match ev {
            CarveEvent::Bookmark {
                file_id,
                bookmarked,
                ..
            } => {
                assert_eq!(file_id, 7);
                assert!(bookmarked);
            }
            _ => panic!("expected Bookmark"),
        }
        assert!(vm.bookmarks.contains(&7));

        // Toggle again → un-bookmark
        let ev2 = vm.toggle_bookmark(7);
        match ev2 {
            CarveEvent::Bookmark { bookmarked, .. } => assert!(!bookmarked),
            _ => panic!(),
        }
        assert!(!vm.bookmarks.contains(&7));
    }

    #[test]
    fn add_note_allocates_monotonic_ids_and_returns_event() {
        let mut vm = ViewModel::new();
        let e1 = vm.add_note(7, "first".into());
        let e2 = vm.add_note(7, "second".into());
        let id1 = match e1 {
            CarveEvent::Note { note_id, .. } => note_id,
            _ => panic!(),
        };
        let id2 = match e2 {
            CarveEvent::Note { note_id, .. } => note_id,
            _ => panic!(),
        };
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(vm.notes.get(&7).unwrap().len(), 2);
    }

    #[test]
    fn mark_as_best_returns_event_and_records_choice() {
        let mut vm = ViewModel::new();
        let ev = vm.mark_as_best(10, 11);
        match ev {
            CarveEvent::MarkAsBest {
                original_file_id,
                chosen_file_id,
                ..
            } => {
                assert_eq!(original_file_id, 10);
                assert_eq!(chosen_file_id, 11);
            }
            _ => panic!(),
        }
        assert_eq!(vm.best_choices.get(&10), Some(&11));
    }

    #[test]
    fn file_found_increments_partial_counts_for_partial_jpegs() {
        let mut vm = ViewModel::new();
        vm.apply(&run_started_with_sources(&[0]));

        let mut fo = create_file_object("part.jpg", FileType::Jpeg, 100, 0, None, 1);
        fo.jpeg_scan = Some(utmost_lib::types::JpegScanInfo {
            width: None,
            height: None,
            fragmentation_point_img_offset: None,
            has_restart_markers: false,
            status: utmost_lib::types::JpegScanStatus::Truncated,
        });
        vm.apply(&CarveEvent::FileFound {
            source_id: 0,
            file: fo,
            img_offset: 0,
            written_path: "part.jpg".into(),
        });

        assert_eq!(*vm.partial_counts.get(&FileType::Jpeg).unwrap(), 1);
    }
}
