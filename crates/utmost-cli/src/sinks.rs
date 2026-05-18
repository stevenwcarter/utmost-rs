//! Helpers for assembling EventSinks for a carve run.
#![allow(dead_code)]

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use utmost_lib::events::{BincodeFileSink, EventSink, FanoutSink};

/// Build the event sink for a single source. `export_enabled=false` returns None
/// when no other sinks are present, or a Fanout containing only the extra sinks.
pub fn build_source_sink(
    output_dir: &Path,
    export_enabled: bool,
    extra: Vec<Arc<dyn EventSink>>,
) -> Result<Option<Arc<dyn EventSink>>> {
    let mut sinks: Vec<Arc<dyn EventSink>> = Vec::new();
    if export_enabled {
        let path = output_dir.join("carve_events.bin");
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
        let r = build_source_sink(dir.path(), false, vec![]).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn build_with_export_creates_file_and_returns_sink() {
        let dir = tempfile::tempdir().unwrap();
        let r = build_source_sink(dir.path(), true, vec![]).unwrap();
        assert!(r.is_some());
        assert!(dir.path().join("carve_events.bin").exists());
    }
}
