//! Event stream for live and replayable carve runs.
//!
//! See `docs/superpowers/specs/2026-05-17-utmost-gui-design.md` for the
//! versioned binary format.

use serde::{Deserialize, Serialize};

pub const CURRENT_FORMAT_VERSION: u32 = 1;
pub const MAGIC: [u8; 4] = *b"UTMS";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileHeader {
    pub magic: [u8; 4],
    pub format_version: u32,
}

impl Default for FileHeader {
    fn default() -> Self {
        Self {
            magic: MAGIC,
            format_version: CURRENT_FORMAT_VERSION,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceDescriptor {
    pub source_id: u32,
    pub filename: String,
    pub total_bytes: u64,
    pub output_subdir: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CaseMetadata {
    #[serde(default)]
    pub case_id: Option<String>,
    #[serde(default)]
    pub examiner: Option<String>,
    #[serde(default)]
    pub evidence_id: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

impl CaseMetadata {
    pub fn is_empty(&self) -> bool {
        self.case_id.is_none()
            && self.examiner.is_none()
            && self.evidence_id.is_none()
            && self.notes.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliConfigSnapshot {
    pub output_directory: String,
    pub types: Vec<String>,
    pub disable_builtin: bool,
    pub config_file: Option<String>,
    pub concurrent_files: usize,
    pub disable_validation: bool,
    pub report_only: bool,
    pub disable_report: bool,
    pub disable_audit: bool,
    pub disable_export: bool,
    pub gui_enabled: bool,
    pub quick: bool,
    pub block_size: usize,
    pub prefix_filenames: bool,
    pub write_all: bool,
    pub keep_incomplete_jpeg: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_header_round_trips_through_bincode() {
        let header = FileHeader {
            magic: *b"UTMS",
            format_version: CURRENT_FORMAT_VERSION,
        };
        let bytes = bincode::serialize(&header).unwrap();
        let decoded: FileHeader = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.magic, *b"UTMS");
        assert_eq!(decoded.format_version, CURRENT_FORMAT_VERSION);
    }

    #[test]
    fn source_descriptor_round_trips() {
        let s = SourceDescriptor {
            source_id: 7,
            filename: "disk.dd".into(),
            total_bytes: 1024,
            output_subdir: "output-disk_dd".into(),
        };
        let bytes = bincode::serialize(&s).unwrap();
        let decoded: SourceDescriptor = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded, s);
    }

    #[test]
    fn case_metadata_round_trips_with_partial_fields() {
        let c = CaseMetadata {
            case_id: Some("CASE-1".into()),
            examiner: None,
            evidence_id: Some("E-9".into()),
            notes: None,
        };
        let bytes = bincode::serialize(&c).unwrap();
        let decoded: CaseMetadata = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded, c);
    }

    #[test]
    fn cli_config_snapshot_round_trips() {
        let cfg = CliConfigSnapshot {
            output_directory: "out".into(),
            types: vec!["jpeg".into()],
            disable_builtin: false,
            config_file: None,
            concurrent_files: 4,
            disable_validation: false,
            report_only: false,
            disable_report: false,
            disable_audit: false,
            disable_export: false,
            gui_enabled: true,
            quick: false,
            block_size: 512,
            prefix_filenames: false,
            write_all: false,
            keep_incomplete_jpeg: false,
        };
        let bytes = bincode::serialize(&cfg).unwrap();
        let decoded: CliConfigSnapshot = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded, cfg);
    }
}
