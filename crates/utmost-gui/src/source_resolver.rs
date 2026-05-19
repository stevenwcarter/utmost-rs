//! Locate the original source image referenced by a recorded event log.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub struct SourceResolver {
    search_locations: Vec<PathBuf>,
    event_log_path: Option<PathBuf>,
    cache: Mutex<HashMap<u32, Option<PathBuf>>>,
}

impl SourceResolver {
    pub fn new(search_locations: Vec<PathBuf>, event_log_path: Option<PathBuf>) -> Self {
        Self {
            search_locations,
            event_log_path,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn resolve(&self, source_id: u32, recorded_filename: &str) -> Option<PathBuf> {
        // Lock is intentionally dropped between check and insert; concurrent races
        // produce identical results so harmless duplicate filesystem walks are fine.
        if let Some(hit) = self.cache.lock().unwrap().get(&source_id) {
            return hit.clone();
        }
        let resolved = self.resolve_uncached(recorded_filename);
        self.cache
            .lock()
            .unwrap()
            .insert(source_id, resolved.clone());
        resolved
    }

    fn resolve_uncached(&self, recorded_filename: &str) -> Option<PathBuf> {
        let basename = Path::new(recorded_filename).file_name()?.to_owned();

        // 1. User-supplied search locations.
        for loc in &self.search_locations {
            if loc.is_file() {
                if loc.file_name() == Some(basename.as_os_str()) {
                    return Some(loc.clone());
                }
            } else if loc.is_dir() {
                let candidate = loc.join(&basename);
                if candidate.exists() {
                    return Some(candidate);
                }
            }
        }

        // 2. Recorded path as-is.
        let recorded = PathBuf::from(recorded_filename);
        if recorded.exists() {
            return Some(recorded);
        }

        // 3. Parent of the event log's directory + basename.
        //    log path = /run/output/carve_events.bin
        //    parent          = /run/output
        //    parent.parent   = /run
        //    join(basename)  = /run/source.dd
        if let Some(log_path) = &self.event_log_path
            && let Some(log_parent_parent) = log_path.parent().and_then(|p| p.parent())
        {
            let candidate = log_parent_parent.join(&basename);
            if candidate.exists() {
                return Some(candidate);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn touch(path: &Path) {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p).unwrap();
        }
        std::fs::write(path, b"").unwrap();
    }

    #[test]
    fn resolves_to_supplied_file_when_basename_matches() {
        let tmp = TempDir::new().unwrap();
        let source_file = tmp.path().join("evidence.dd");
        touch(&source_file);

        let resolver = SourceResolver::new(vec![source_file.clone()], None);
        let got = resolver.resolve(0, "/old/path/evidence.dd");
        assert_eq!(got, Some(source_file));
    }

    #[test]
    fn resolves_to_search_dir_when_file_present() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("images");
        let target = dir.join("disk.dd");
        touch(&target);

        let resolver = SourceResolver::new(vec![dir.clone()], None);
        let got = resolver.resolve(0, "/old/disk.dd");
        assert_eq!(got, Some(target));
    }

    #[test]
    fn falls_back_to_recorded_path_when_supplied_locations_miss() {
        let tmp = TempDir::new().unwrap();
        let recorded = tmp.path().join("recorded.dd");
        touch(&recorded);

        // Search location pointing at a nonexistent dir.
        let bogus = tmp.path().join("does-not-exist");
        let resolver = SourceResolver::new(vec![bogus], None);
        let got = resolver.resolve(0, recorded.to_str().unwrap());
        assert_eq!(got, Some(recorded));
    }

    #[test]
    fn falls_back_to_parent_of_event_log_dir() {
        let tmp = TempDir::new().unwrap();
        // /tmp/run/output/carve_events.bin
        let output_dir = tmp.path().join("run").join("output");
        std::fs::create_dir_all(&output_dir).unwrap();
        let log = output_dir.join("carve_events.bin");
        touch(&log);
        // /tmp/run/source.dd
        let source = tmp.path().join("run").join("source.dd");
        touch(&source);

        let resolver = SourceResolver::new(vec![], Some(log));
        let got = resolver.resolve(0, "/old/path/source.dd");
        assert_eq!(got, Some(source));
    }

    #[test]
    fn returns_none_when_nothing_resolves() {
        let resolver = SourceResolver::new(vec![], None);
        let got = resolver.resolve(0, "/totally/missing/file.dd");
        assert_eq!(got, None);
    }

    #[test]
    fn cache_returns_same_result_on_second_call() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("a.dd");
        touch(&source);

        let resolver = SourceResolver::new(vec![source.clone()], None);
        let first = resolver.resolve(0, "/x/a.dd");
        // Delete the file after first resolve — second call should still hit cache.
        std::fs::remove_file(&source).unwrap();
        let second = resolver.resolve(0, "/x/a.dd");
        assert_eq!(first, second);
        assert_eq!(second, Some(source));
    }

    #[test]
    fn search_locations_walked_in_order() {
        let tmp = TempDir::new().unwrap();
        let dir_a = tmp.path().join("a");
        let dir_b = tmp.path().join("b");
        let in_a = dir_a.join("img.dd");
        let in_b = dir_b.join("img.dd");
        touch(&in_a);
        touch(&in_b);

        // dir_a listed first → its hit wins.
        let resolver = SourceResolver::new(vec![dir_a, dir_b], None);
        let got = resolver.resolve(0, "/x/img.dd");
        assert_eq!(got, Some(in_a));
    }

    #[test]
    fn search_file_with_mismatching_basename_is_skipped() {
        let tmp = TempDir::new().unwrap();
        // Supplied search location is a real file, but its basename doesn't match
        // what the recording references. Resolver should fall through.
        let unrelated_file = tmp.path().join("unrelated.bin");
        touch(&unrelated_file);

        let resolver = SourceResolver::new(vec![unrelated_file], None);
        let got = resolver.resolve(0, "/x/wanted.dd");
        assert_eq!(got, None);
    }

    #[test]
    fn distinct_source_ids_resolve_independently() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("images");
        let one = dir.join("one.dd");
        let two = dir.join("two.dd");
        touch(&one);
        touch(&two);

        let resolver = SourceResolver::new(vec![dir], None);
        let r1 = resolver.resolve(1, "/x/one.dd");
        let r2 = resolver.resolve(2, "/x/two.dd");
        assert_eq!(r1, Some(one));
        assert_eq!(r2, Some(two));
    }
}
