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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    Filename,
    Size,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDir {
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

#[derive(Debug, Default, Clone)]
pub struct ViewModel {
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
                if let Some(sid) = self.filter.source_filter
                    && f.source_id != sid
                {
                    return false;
                }
                if let Some(ft) = parse_file_type(&f.file.file_type) {
                    self.filter.enabled_types.contains(&ft)
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
            }
        }
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
        let fo = create_file_object("a.jpg", FileType::Jpeg, 1024, 0, None);
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
        let fo = create_file_object("a.jpg", FileType::Jpeg, 1, 0, None);
        vm.apply(&CarveEvent::FileFound {
            source_id: 99,
            file: fo,
            img_offset: 0,
            written_path: "a.jpg".into(),
        });
        assert_eq!(vm.files.len(), 1);
    }

    fn add_file(vm: &mut ViewModel, sid: u32, name: &str, ft: FileType, sz: u64) {
        let fo = create_file_object(name, ft, sz, 0, None);
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
}
