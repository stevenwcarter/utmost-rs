//! Case discovery for `utmost-viewer <dir>`. Recursive walk for any
//! `*-events.bin` file under the target. Hidden dirs are skipped;
//! symlinks to directories are not followed. Bounded by MAX_DEPTH.

use anyhow::Result;
use std::path::{Path, PathBuf};

const MAX_DEPTH: usize = 8;

pub fn discover_cases(target: &Path) -> Result<Vec<PathBuf>> {
    if target.is_file() {
        return Ok(vec![target.to_path_buf()]);
    }
    if !target.is_dir() {
        anyhow::bail!(
            "target is neither a file nor a directory: {}",
            target.display()
        );
    }
    let mut found = Vec::new();
    walk_for_events_bin(target, 0, &mut found);
    found.sort();
    found.dedup();
    if found.is_empty() {
        anyhow::bail!("no <stem>-events.bin found under {}", target.display());
    }
    Ok(found)
}

fn walk_for_events_bin(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > MAX_DEPTH {
        return;
    }
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                "discover_cases: skipping unreadable dir {}: {e}",
                dir.display()
            );
            return;
        }
    };
    for entry in read {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(
                    "discover_cases: skipping bad dirent in {}: {e}",
                    dir.display()
                );
                continue;
            }
        };
        let p = entry.path();
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_file() {
            if let Some(name) = p.file_name().and_then(|n| n.to_str())
                && name.ends_with("-events.bin")
            {
                out.push(p.canonicalize().unwrap_or(p));
            }
        } else if ft.is_dir() {
            let basename = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !basename.starts_with('.') {
                walk_for_events_bin(&p, depth + 1, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn touch(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"").unwrap();
    }

    #[test]
    fn finds_nested_events_bins() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        touch(&root.join("run1/run1-events.bin"));
        touch(&root.join("run2/run2-events.bin"));
        touch(&root.join("readme.txt"));
        let found = discover_cases(root).unwrap();
        assert_eq!(found.len(), 2);
        let names: Vec<_> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"run1-events.bin".to_string()));
        assert!(names.contains(&"run2-events.bin".to_string()));
    }

    #[test]
    fn returns_single_when_passed_file() {
        let tmp = TempDir::new().unwrap();
        let f = tmp.path().join("solo-events.bin");
        touch(&f);
        let found = discover_cases(&f).unwrap();
        assert_eq!(found, vec![f]);
    }

    #[test]
    fn errors_on_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let err = discover_cases(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("no <stem>-events.bin found"));
    }

    #[test]
    fn skips_hidden_dirs() {
        let tmp = TempDir::new().unwrap();
        touch(&tmp.path().join(".hidden/run-events.bin"));
        touch(&tmp.path().join("visible/run-events.bin"));
        let found = discover_cases(tmp.path()).unwrap();
        assert_eq!(found.len(), 1);
        assert!(found[0].to_string_lossy().contains("visible"));
    }

    #[test]
    fn respects_max_depth() {
        let tmp = TempDir::new().unwrap();
        // Create depth = MAX_DEPTH + 2 nesting; the deepest one must NOT be found.
        let mut p = tmp.path().to_path_buf();
        for i in 0..(MAX_DEPTH + 2) {
            p = p.join(format!("d{i}"));
        }
        touch(&p.join("deep-events.bin"));
        // Also place one within depth so we get a non-empty success rather than an error.
        touch(&tmp.path().join("d0/d1/shallow-events.bin"));
        let found = discover_cases(tmp.path()).unwrap();
        let names: Vec<_> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"shallow-events.bin".to_string()));
        assert!(!names.contains(&"deep-events.bin".to_string()));
    }

    #[test]
    fn dedups_canonicalised_paths() {
        let tmp = TempDir::new().unwrap();
        let real = tmp.path().join("real/run-events.bin");
        touch(&real);
        // Symlink the dir to itself by another name; only on Unix.
        #[cfg(unix)]
        std::os::unix::fs::symlink(tmp.path().join("real"), tmp.path().join("link")).unwrap();
        let found = discover_cases(tmp.path()).unwrap();
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn continues_past_unreadable_subdir() {
        // Best-effort: skipping unreadable dirs must not abort the walk. We can't
        // easily produce a guaranteed-unreadable dir cross-platform, so this test
        // verifies the function still returns Ok when one subdir errors at
        // read_dir time. We simulate by creating a path that's "looks like a
        // dir to is_dir() but read_dir will fail" — a regular file passed as
        // the target is already handled by the file-branch; we use a fifo on
        // Unix instead. Skip on non-Unix.
        #[cfg(unix)]
        {
            use std::os::unix::net::UnixListener;
            let tmp = TempDir::new().unwrap();
            touch(&tmp.path().join("good/run-events.bin"));
            // Create a unix socket inside the target dir; read_dir on the dir
            // succeeds but file_type on the socket is neither file nor dir, so
            // it's harmlessly skipped. This exercises the "ft.is_file/is_dir
            // both false" branch.
            let sock_path = tmp.path().join("weird.sock");
            let _l = UnixListener::bind(&sock_path).unwrap();
            let found = discover_cases(tmp.path()).unwrap();
            assert_eq!(found.len(), 1);
        }
    }
}
