//! Helpers for assembling EventSinks for a carve run.
#![allow(dead_code)]

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use utmost_lib::events::{BincodeFileSink, EventSink, FanoutSink};

/// Derive the filename stem used for the event log, sqlite index, and
/// pending sidecar of a source. Wraps `clean_filename` (the same helper
/// `output_layout::derive_subdir` uses) with a single fallback so an
/// empty input still produces a usable stem.
pub fn log_stem(source_path: &str) -> String {
    let base = utmost_lib::types::clean_filename(source_path, 32);
    if base.is_empty() {
        "source".to_string()
    } else {
        base
    }
}

/// Build the event sink for a single source. `stem` is used to name the
/// on-disk event log (`<stem>-events.bin`). When `export_enabled=false`
/// and no extra sinks are supplied, returns `None`.
pub fn build_source_sink(
    output_dir: &Path,
    stem: &str,
    export_enabled: bool,
    extra: Vec<Arc<dyn EventSink>>,
) -> Result<Option<Arc<dyn EventSink>>> {
    let mut sinks: Vec<Arc<dyn EventSink>> = Vec::new();
    if export_enabled {
        let path = output_dir.join(format!("{stem}-events.bin"));
        let s = BincodeFileSink::create(&path)
            .with_context(|| format!("creating event log at {}", path.display()))?;
        sinks.push(Arc::new(s));
    }
    sinks.extend(extra);
    if sinks.is_empty() {
        Ok(None)
    } else if sinks.len() == 1 {
        Ok(Some(sinks.into_iter().next().unwrap()))
    } else {
        Ok(Some(Arc::new(FanoutSink::new(sinks))))
    }
}

/// Compute the output directory for a single carve thread.
/// `subdir.is_empty()` means the source uses the flat single-source layout.
pub fn source_output_dir(root: &Path, subdir: &str) -> PathBuf {
    if subdir.is_empty() {
        root.to_path_buf()
    } else {
        root.join(subdir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_subdir_returns_root() {
        assert_eq!(source_output_dir(Path::new("/o"), ""), PathBuf::from("/o"));
    }
    #[test]
    fn nonempty_subdir_is_joined() {
        assert_eq!(
            source_output_dir(Path::new("/o"), "output-foo"),
            PathBuf::from("/o/output-foo")
        );
    }

    #[test]
    fn build_with_no_options_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let r = build_source_sink(dir.path(), "disk1_dd", false, vec![]).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn build_with_export_creates_stem_events_file_and_returns_sink() {
        let dir = tempfile::tempdir().unwrap();
        let r = build_source_sink(dir.path(), "disk1_dd", true, vec![]).unwrap();
        assert!(r.is_some());
        assert!(dir.path().join("disk1_dd-events.bin").exists());
        assert!(!dir.path().join("carve_events.bin").exists());
    }

    #[test]
    fn log_stem_for_normal_filename() {
        // clean_filename lowercases and joins stem+extension with `_`.
        assert_eq!(super::log_stem("/path/disk1.dd"), "disk1_dd");
    }

    #[test]
    fn log_stem_for_filename_with_spaces() {
        // clean_filename collapses non-alphanumerics
        let s = super::log_stem("/path/my disk.dd");
        assert!(!s.is_empty());
        assert!(!s.contains(' '));
    }

    #[test]
    fn log_stem_for_empty_input() {
        assert_eq!(super::log_stem(""), "source");
    }
}
