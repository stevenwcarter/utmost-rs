//! Per-input-file output subdirectory derivation for multi-source runs.

use anyhow::{Result, bail};
use std::collections::BTreeSet;
use utmost_lib::types::clean_filename;

const MAX_SUBDIR_NAME: usize = 32;
const MAX_COLLISION_SUFFIX: u32 = 1000;

/// Derive a unique output-XX/ subdirectory name for `input_path`, avoiding any
/// names already in `taken`. Returns just the basename (no leading slash).
pub fn derive_subdir(input_path: &str, taken: &BTreeSet<String>) -> Result<String> {
    let base = clean_filename(input_path, MAX_SUBDIR_NAME);
    let base = if base.is_empty() {
        "source".to_string()
    } else {
        base
    };
    let candidate = format!("output-{}", base);
    if !taken.contains(&candidate) {
        return Ok(candidate);
    }
    for i in 1..=MAX_COLLISION_SUFFIX {
        let next = format!("output-{}-{}", base, i);
        if !taken.contains(&next) {
            return Ok(next);
        }
    }
    bail!("collision suffix exhausted for input: {input_path}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_derivation_uses_clean_filename() {
        let taken = BTreeSet::new();
        let r = derive_subdir("/path/disk_image.dd", &taken).unwrap();
        assert_eq!(r, "output-disk_image_dd");
    }

    #[test]
    fn collision_appends_suffix() {
        let mut taken = BTreeSet::new();
        taken.insert("output-foo".to_string());
        let r = derive_subdir("/path/foo", &taken).unwrap();
        assert_eq!(r, "output-foo-1");
    }

    #[test]
    fn two_distinct_inputs_collide_after_cleaning() {
        let mut taken = BTreeSet::new();
        let a = derive_subdir("file---one", &taken).unwrap();
        taken.insert(a.clone());
        let b = derive_subdir("file___one", &taken).unwrap();
        assert_ne!(a, b);
        assert!(b.ends_with("-1"));
    }

    #[test]
    fn empty_filename_falls_back_to_source() {
        let taken = BTreeSet::new();
        let r = derive_subdir("", &taken).unwrap();
        assert_eq!(r, "output-source");
    }

    #[test]
    fn collision_bound_is_enforced() {
        let mut taken = BTreeSet::new();
        taken.insert("output-x".to_string());
        for i in 1..=MAX_COLLISION_SUFFIX {
            taken.insert(format!("output-x-{}", i));
        }
        let err = derive_subdir("x", &taken).unwrap_err();
        assert!(format!("{err}").contains("collision"));
    }

    #[test]
    fn truncation_clips_at_32_chars() {
        let taken = BTreeSet::new();
        let long = "a".repeat(100);
        let r = derive_subdir(&long, &taken).unwrap();
        // "output-" prefix + 32 chars max
        assert!(r.len() <= "output-".len() + MAX_SUBDIR_NAME);
    }
}
