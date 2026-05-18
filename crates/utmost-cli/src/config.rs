//! User configuration loaded from `~/.config/utmost/config.toml`.
#![allow(dead_code)]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use utmost_lib::events::CaseMetadata;

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq)]
pub struct UserConfig {
    #[serde(default)]
    pub gui: GuiConfig,
    #[serde(default)]
    pub export: ExportConfig,
    #[serde(default)]
    pub case: CaseConfig,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq)]
pub struct GuiConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ExportConfig {
    pub enabled: bool,
}
impl Default for ExportConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq)]
pub struct CaseConfig {
    #[serde(default)]
    pub case_id: Option<String>,
    #[serde(default)]
    pub examiner: Option<String>,
    #[serde(default)]
    pub evidence_id: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

impl CaseConfig {
    pub fn to_metadata(&self) -> CaseMetadata {
        CaseMetadata {
            case_id: self.case_id.clone(),
            examiner: self.examiner.clone(),
            evidence_id: self.evidence_id.clone(),
            notes: self.notes.clone(),
        }
    }
}

/// Returns the default config path, or `None` on platforms with no XDG dir.
pub fn default_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("utmost").join("config.toml"))
}

/// Load config from `path`. Missing file → returns `Ok(UserConfig::default())`.
/// Malformed TOML → returns `Err`.
pub fn load_from(path: &std::path::Path) -> Result<UserConfig> {
    match std::fs::read_to_string(path) {
        Ok(s) => toml::from_str(&s).with_context(|| format!("parsing {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(UserConfig::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn missing_file_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let r = load_from(&dir.path().join("nope.toml")).unwrap();
        assert_eq!(r, UserConfig::default());
        assert!(r.export.enabled);
        assert!(!r.gui.enabled);
    }

    #[test]
    fn malformed_file_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bad.toml");
        std::fs::File::create(&p)
            .unwrap()
            .write_all(b"this is not toml = =")
            .unwrap();
        assert!(load_from(&p).is_err());
    }

    #[test]
    fn loads_gui_enabled_true() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ok.toml");
        std::fs::File::create(&p)
            .unwrap()
            .write_all(b"[gui]\nenabled = true\n")
            .unwrap();
        let r = load_from(&p).unwrap();
        assert!(r.gui.enabled);
    }

    #[test]
    fn loads_case_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("case.toml");
        std::fs::File::create(&p)
            .unwrap()
            .write_all(b"[case]\nexaminer = \"Jane\"\ncase_id = \"C-1\"\n")
            .unwrap();
        let r = load_from(&p).unwrap();
        assert_eq!(r.case.examiner.as_deref(), Some("Jane"));
        assert_eq!(r.case.case_id.as_deref(), Some("C-1"));
    }
}
