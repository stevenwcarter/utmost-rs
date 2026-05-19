# Source-byte Thumbnails + Always-track Partials Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land three coordinated changes: (a) always record partial JPEGs in the event log regardless of `--keep-incomplete-jpeg`; (b) generate thumbnails by reading source bytes when the carved file is absent; (c) accept repeatable `--source` paths in `utmost-viewer` for resolving the original image.

**Architecture:** Engine change is contained to `crates/utmost-lib/src/engine.rs` and threads a new `was_written` flag through one tuple to keep `audit_log.txt` aligned with on-disk state. GUI changes add a new `source_resolver` module, two new bytes-based methods on `PreviewRenderer`, and a `render_with_fallback` orchestrator that tries on-disk first and falls back to a byte-range read. The viewer CLI gains a repeatable `--source` that the resolver consumes.

**Tech Stack:** Rust 1.95, Cargo workspace (`utmost-lib`, `utmost-cli`, `utmost-gui`, `utmost-viewer`), Slint 1.10, `image` crate for decoding, `clap` for CLI, `anyhow` for errors.

**Reference spec:** `docs/superpowers/specs/2026-05-18-source-bytes-thumbs-and-partials-design.md`

**Pre-flight:** Confirm `cargo build --release` and `cargo test` are green on the current branch tip before starting Task 1. Branch off `feature/utmost-gui-slint` (or wherever HEAD is).

---

## File Map

| File | Change | Why |
|---|---|---|
| `crates/utmost-lib/src/engine.rs` | Refactor `extract_basic_file` return shape; remove extraction-time partial-skip; add write-skip in `write_to_disk`. | Section 2. |
| `crates/utmost-gui/src/source_resolver.rs` | **New module.** `SourceResolver` struct + cache. | Section 1c. |
| `crates/utmost-gui/src/preview/mod.rs` | Trait gains `render_from_bytes` / `render_full_from_bytes` (default Err); registry gains dispatch helpers; new `render_with_fallback` + `render_full_with_fallback`. | Sections 1a, 1d. |
| `crates/utmost-gui/src/preview/jpeg.rs` | Implement byte-based decoders. | Section 1b. |
| `crates/utmost-gui/src/thumb_worker.rs` | Carry the resolver + sources map; call `render_with_fallback`. | Section 1d. |
| `crates/utmost-gui/src/slint_adapter.rs` | Construct sources_by_id each sync; thread resolver into worker + full-res path; call `render_full_with_fallback`. | Section 1d. |
| `crates/utmost-gui/src/lib.rs` | `run_from_file` signature gains `Vec<PathBuf>`; `launch_ui_with_journal` likewise. | Section 3. |
| `crates/utmost-viewer/src/main.rs` | Add repeatable `--source` CLI flag. | Section 3. |
| `crates/utmost-gui/tests/source_bytes_fallback.rs` | **New integration test.** End-to-end report-only carve → viewer thumb. | Section 1. |

---

## Task 1: Refactor `extract_basic_file` return tuple to carry `was_written`

**Files:**
- Modify: `crates/utmost-lib/src/engine.rs`

### Background

`extract_basic_file` currently returns `(extracted_size, needs_bridge, opt_file_id)`. The caller at `engine.rs:649-656` uses `extracted_size > 0` as the signal to (a) call `audit_entry`, (b) call `increment_fileswritten`, and (c) call `increment_found_count`. After Task 2 we'll need to distinguish "detected" (event emitted; chip increments) from "written" (audit + fileswritten increment). This task is a no-op refactor to make room for that distinction.

- [ ] **Step 1: Locate the function and its callers**

In `crates/utmost-lib/src/engine.rs`, find:
- The function definition (it's the only `fn` returning `Result<(usize, bool, Option<u64>)>` — grep for `Ok((0, false, None))` to land on it; the signature comment near line 765 mentions "Returns `(extracted_size, needs_bridge, file_id)`").
- Every return site: lines 797, 856, 882, 894 (`Some(file_id)`), 896.
- Every caller: lines 638 (the main caller, then audit log at 649-656 + write_all branch at 658-681), 1325 (test), 1902 (test).

- [ ] **Step 2: Change the return type to a 4-tuple**

Change the function signature's return type from `Result<(usize, bool, Option<u64>)>` to `Result<(usize, bool, bool, Option<u64>)>`. The third bool is `was_written`.

Update each return site:

- Line ~797 (`Ok((0, true, None))`) → `Ok((0, true, false, None))`. (Bridge-needed: nothing was written.)
- Line ~856 (the existing partial-jpeg skip, will be deleted in Task 2 but for now): `Ok((0, false, false, None))`.
- Line ~882 (validation failure): `Ok((0, false, false, None))`.
- Line ~894 (`Ok((file_size, false, Some(file_id)))`) → `Ok((file_size, false, true, Some(file_id)))`. Today this is the only "actually wrote a file" path.
- Line ~896 (final `Ok((0, false, None))`) → `Ok((0, false, false, None))`.

- [ ] **Step 3: Update the doc comment**

The function's doc comment near line 765 says "Returns `(extracted_size, needs_bridge, file_id)`". Update to `(extracted_size, needs_bridge, was_written, file_id)` with a sentence:

```rust
/// Returns `(extracted_size, needs_bridge, was_written, file_id)`. `extracted_size`
/// advances the read position past the detected file. `was_written` is true only
/// when a file actually landed on disk (false for validation failures, report-only,
/// and — once Task 2 lands — partial-jpeg skips).
```

- [ ] **Step 4: Update the caller pattern at engine.rs:638**

Change:

```rust
let (extracted_size, needs_bridge, opt_file_id) = extract_basic_file(
```

to:

```rust
let (extracted_size, needs_bridge, was_written, opt_file_id) = extract_basic_file(
```

The body of the caller block (lines 649-682) currently does:

```rust
if extracted_size > 0 {
    let new_file_number = state.increment_fileswritten();
    let filename = format!("{}.{}", new_file_number, spec.suffix);
    let file_id = opt_file_id.expect("extracted_size > 0 implies a file_id was allocated");
    state.audit_entry(&format!(
        "[fid={:<5}] {:<5} {:<30} {:<15} {:<15} {}",
        file_id, new_file_number, filename, extracted_size, absolute_offset, spec.comment
    ))?;
    state.increment_found_count(spec.file_type);
}
```

For this refactor, no behavior change yet. Keep the gate as `extracted_size > 0`. Suppress the unused warning on `was_written` for now:

```rust
let _ = was_written;
if extracted_size > 0 {
    // ... unchanged body ...
}
```

The Task 2 step will tighten this.

- [ ] **Step 5: Update the write-all branch at engine.rs:658-681**

That block calls `write_to_disk` directly (header-dump mode) and emits its own audit entry. No tuple to update there. Leave alone.

- [ ] **Step 6: Update tests at engine.rs:1325 and 1902**

Both destructure the 3-tuple. Change:

```rust
let (extracted_size, _needs_bridge, _file_id) = size.unwrap();
```

to:

```rust
let (extracted_size, _needs_bridge, _was_written, _file_id) = size.unwrap();
```

(Search for both lines exactly to confirm the form; the trailing identifier name may vary.)

- [ ] **Step 7: Build + clippy + test**

```
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

Expected: all green. This is a pure refactor — no test behavior changes.

- [ ] **Step 8: Commit**

```
git add crates/utmost-lib/src/engine.rs
git commit -m "$(cat <<'EOF'
refactor(lib): thread was_written through extract_basic_file

No behavior change. Makes room for Task 2's distinction between
"detected" (FileFound event + chip increment) and "written"
(audit_log + fileswritten counter).

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Always emit FileFound for partial JPEGs; skip only the disk write

**Files:**
- Modify: `crates/utmost-lib/src/engine.rs`
- Test: `crates/utmost-lib/src/engine.rs` (new tests in the existing `mod tests` block)

### Background

Today partial JPEGs return early at `engine.rs:846-857` before any event is emitted. Move the gate into `write_to_disk` so the `FileFound` event is always emitted but the disk write is conditional. Tighten the caller at `engine.rs:649-682` to gate `audit_entry` and `increment_fileswritten` on `was_written` (introduced in Task 1) while still incrementing `found_count` for any detected file.

- [ ] **Step 1: Write failing tests first**

In the existing `mod tests` block in `crates/utmost-lib/src/engine.rs`, add four new tests. Pick a spot near `test_write_to_disk_report_only` (around line 2245).

```rust
#[test]
fn partial_jpeg_emits_file_found_when_flag_off() {
    let (state, _tmp) = create_test_state_with_partial_jpeg(false /* keep */, false /* write_all */);
    let events = drive_test_carve_collect_events(&state);
    let partials: Vec<_> = events.iter()
        .filter_map(|e| if let crate::events::CarveEvent::FileFound { file, .. } = e { Some(file) } else { None })
        .filter(|fo| fo.jpeg_scan.as_ref().is_some_and(|j| j.status != crate::types::JpegScanStatus::Complete))
        .collect();
    assert_eq!(partials.len(), 1, "exactly one partial-jpeg event expected");
}

#[test]
fn partial_jpeg_does_not_write_to_disk_when_flag_off() {
    let (state, tmp) = create_test_state_with_partial_jpeg(false, false);
    let _ = drive_test_carve_collect_events(&state);
    let entries: Vec<_> = std::fs::read_dir(tmp.path()).unwrap().collect();
    let jpgs: Vec<_> = entries.iter()
        .filter_map(|e| e.as_ref().ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "jpg"))
        .collect();
    assert_eq!(jpgs.len(), 0, "no .jpg file should be written for a partial when flag is off");
}

#[test]
fn partial_jpeg_writes_to_disk_when_flag_on() {
    let (state, tmp) = create_test_state_with_partial_jpeg(true /* keep */, false);
    let _ = drive_test_carve_collect_events(&state);
    let jpgs: Vec<_> = std::fs::read_dir(tmp.path()).unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "jpg"))
        .collect();
    assert_eq!(jpgs.len(), 1, "one .jpg file should be written for a partial when flag is on");
}

#[test]
fn partial_jpeg_writes_to_disk_when_write_all_is_on() {
    let (state, tmp) = create_test_state_with_partial_jpeg(false, true /* write_all */);
    let _ = drive_test_carve_collect_events(&state);
    let jpgs: Vec<_> = std::fs::read_dir(tmp.path()).unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "jpg"))
        .collect();
    assert_eq!(jpgs.len(), 1, "write_all should also force the disk write");
}
```

These tests use two helpers that don't exist yet — write them inside the same `mod tests` block:

```rust
fn create_test_state_with_partial_jpeg(
    keep_incomplete_jpeg: bool,
    write_all: bool,
) -> (State, TempDir) {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config = StateConfig {
        output_directory: temp_dir.path().to_string_lossy().to_string(),
        debug: false,
        prefix_filenames: false,
        chunk_size: Some(1),
        block_size: Some(512),
        skip: Some(0),
        disable_validation: false,
        report_only: false,
        disable_report: false,
        disable_audit: false,
        quick: false,
        write_all,
        keep_incomplete_jpeg,
    };
    let state = State::new(config).expect("Failed to create state");
    (state, temp_dir)
}

/// Synthesises a tiny in-memory JPEG header with no EOI marker (i.e. a
/// truncated/fragmented jpeg) and drives `process_buffer` on it, returning
/// the events that were emitted via a collecting `EventSink`.
fn drive_test_carve_collect_events(state: &State) -> Vec<crate::events::CarveEvent> {
    use std::sync::{Arc, Mutex};
    let collected: Arc<Mutex<Vec<crate::events::CarveEvent>>> = Arc::new(Mutex::new(Vec::new()));
    struct CollectSink(Arc<Mutex<Vec<crate::events::CarveEvent>>>);
    impl crate::events::EventSink for CollectSink {
        fn emit(&self, event: &crate::events::CarveEvent) {
            self.0.lock().unwrap().push(event.clone());
        }
    }
    // Use ARC interior mutability — set_event_sink takes &mut self, so we need a path.
    // The existing test infrastructure in this file uses State::set_event_sink directly.
    // If unavailable, the implementer should adapt by exposing or replacing the sink in place.
    let mut state = state.clone(); // State derives Clone in this codebase; confirm and replace if not.
    state.set_event_sink(Arc::new(CollectSink(collected.clone())));

    // SOI(FFD8) + APP0/JFIF header + SOF0 16x16 + SOS marker (no scan data, no EOI).
    // The engine sees a JPEG header with no recognisable end and tags it Truncated.
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&[0xFF, 0xD8]); // SOI
    bytes.extend_from_slice(&[
        0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    ]); // JFIF APP0
    bytes.extend_from_slice(&[
        0xFF, 0xC0, 0x00, 0x11, 0x08, 0x00, 0x10, 0x00, 0x10, 0x03, 0x01, 0x22,
        0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01,
    ]); // SOF0 16x16
    bytes.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x0C, 0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00]); // SOS
    bytes.resize(1024, 0x00); // padding, no EOI

    let specs = crate::search_specs::init_all_search_specs(&state.config);
    let jpeg_spec = specs.iter().find(|s| s.file_type == crate::types::FileType::Jpeg)
        .expect("jpeg spec must exist").clone();

    let file_info = crate::types::FileInfo {
        filename: "test_source.bin".to_string(),
        file_size: bytes.len() as u64,
        bytes_read: 0,
    };

    let mut buf = bytes.clone();
    let _ = crate::engine::process_buffer(
        &state,
        &[jpeg_spec],
        &mut buf,
        0, // absolute_offset
        &file_info,
        1, // total_input_files
    );

    let events = collected.lock().unwrap().clone();
    events
}
```

NOTES on the helper:
- `State::clone` may or may not be derived. If it's not, the implementer should use a `RefCell`/`Mutex` wrapper around the sink-set step, or use a different injection mechanism. Whatever they do, the test must be able to register a collecting sink before driving the carve.
- `process_buffer` is the existing entry point for chunk processing in `engine.rs`. If its name/visibility differs from what's used here, the implementer should adapt — the goal is to drive one detection event from a synthetic buffer and read what came out.

Run the tests:

```
cargo test -p utmost-lib partial_jpeg
```

Expected: FAIL on `partial_jpeg_emits_file_found_when_flag_off` (no event emitted today). The disk-not-written tests will pass coincidentally (because nothing is detected today either, so nothing is written), and the writes-when-flag-on test will pass (existing behavior).

- [ ] **Step 2: Remove the extraction-time skip**

In `crates/utmost-lib/src/engine.rs:846-857`, delete:

```rust
// Skip incomplete JPEGs by default to avoid flooding output with
// max-size junk files.  Both --keep-incomplete-jpeg and --write-all
// opt back in to writing them.
if status != JpegScanStatus::Complete
    && !state.config.keep_incomplete_jpeg
    && !state.config.write_all
{
    debug!(
        "Skipping incomplete JPEG ({:?}) at offset {} (would be {} bytes)",
        status, abs_offset, size
    );
    return Ok((0, false, false, None));
}
```

(After Task 1 the tuple is already 4-wide; that's why this snippet shows the new shape.)

- [ ] **Step 3: Add the write-time skip in `write_to_disk`**

Find the report-only branch at `engine.rs:1032-1041` and the FileFound emit just above it (lines 1018-1030). Extend the branch so partials with the flag off are also caught here.

The current code is:

```rust
// (around 1018-1030: emit FileFound)
state.emit(crate::events::CarveEvent::FileFound { ... });

// If report-only mode, skip actual file writing
if state.config.report_only {
    info!("Found {} ({} bytes) at offset {} [report-only mode]", filename, data.len(), offset);
    return Ok(file_id);
}
```

Change to:

```rust
// (FileFound emit unchanged)

let is_partial = matches!(
    jpeg_scan_info,
    Some(ref info) if info.status != JpegScanStatus::Complete
);
let skip_partial_write = is_partial
    && !state.config.keep_incomplete_jpeg
    && !state.config.write_all;

if state.config.report_only || skip_partial_write {
    info!(
        "Found {} ({} bytes) at offset {} [{}]",
        filename,
        data.len(),
        offset,
        if state.config.report_only { "report-only" } else { "partial-skip" },
    );
    return Ok(file_id);
}
```

`write_to_disk` already returns `file_id` here, so the caller's `opt_file_id` is `Some(_)`. But the caller currently treats `extracted_size > 0` as "was_written"; we'll fix that in the next step.

- [ ] **Step 4: Distinguish written from detected at the caller**

`write_to_disk` returns `Ok(file_id)` whether or not the file was actually written. Today the caller at engine.rs:885-894 receives `file_id` and returns `Ok((file_size, false, Some(file_id)))` from `extract_basic_file`. We need a way to know whether `write_to_disk` actually wrote.

Refactor `write_to_disk` to return `Result<(u64, bool)>` — `(file_id, was_written)`. Update its callsite in `extract_basic_file` (around line 885) to capture both, and pass `was_written` up the tuple:

In `extract_basic_file`:

```rust
let (file_id, was_written) = write_to_disk(
    state,
    spec,
    candidate_data,
    abs_offset,
    file_info,
    total_input_files,
    jpeg_scan_info,
)?;
Ok((file_size, false, was_written, Some(file_id)))
```

In `write_to_disk`'s short-circuits:

```rust
// report-only or partial-skip:
return Ok((file_id, false));

// at the end after writing successfully:
return Ok((file_id, true));
```

The header-dump branch at line 664-672 currently calls `write_to_disk` and discards the result (well, captures it as `file_id`). Update to capture `(file_id, _)`:

```rust
let (file_id, _was_written) = write_to_disk(...)?;
```

That branch unconditionally calls `audit_entry` itself, so `_was_written` is fine.

- [ ] **Step 5: Gate audit_entry and increment_fileswritten on was_written**

Back in `extract_basic_file`'s caller at engine.rs:649-682, change:

```rust
let _ = was_written;
if extracted_size > 0 {
    let new_file_number = state.increment_fileswritten();
    let filename = format!("{}.{}", new_file_number, spec.suffix);
    let file_id = opt_file_id.expect("extracted_size > 0 implies a file_id was allocated");
    state.audit_entry(&format!(
        "[fid={:<5}] {:<5} {:<30} {:<15} {:<15} {}",
        file_id, new_file_number, filename, extracted_size, absolute_offset, spec.comment
    ))?;
    state.increment_found_count(spec.file_type);
}
```

to:

```rust
if extracted_size > 0 {
    // Always increment the "detected" counter (drives the GUI's "Partial JPEG" chip
    // and the type-count statistics in the report).
    state.increment_found_count(spec.file_type);

    if was_written {
        let new_file_number = state.increment_fileswritten();
        let filename = format!("{}.{}", new_file_number, spec.suffix);
        let file_id = opt_file_id.expect("was_written implies a file_id was allocated");
        state.audit_entry(&format!(
            "[fid={:<5}] {:<5} {:<30} {:<15} {:<15} {}",
            file_id, new_file_number, filename, extracted_size, absolute_offset, spec.comment
        ))?;
    }
}
```

- [ ] **Step 6: Run the new tests**

```
cargo test -p utmost-lib partial_jpeg
```

Expected: all four PASS.

- [ ] **Step 7: Run the full suite**

```
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

Expected: all green. If existing tests in `engine.rs` or `engine_events.rs` fail because they asserted "no partial entries appear in events", inspect each — they need to be updated to reflect the new behavior. Do not silently delete tests; if a test's intent was "default-flag carve produces no events for partials," that intent is now wrong and the assertion should be updated to "partial events are present and `jpeg_scan.status != Complete`."

The `test_write_to_disk_report_only` test at engine.rs:2245 should still pass — it asserts no `.pdf` files written in report-only mode, which is unchanged.

The `incomplete_jpegs` count printed by `utmost-cli/src/main.rs:779` comes from the recovery pipeline reading `report.fileobjects`, so the count remains correct.

- [ ] **Step 8: Commit**

```
git add crates/utmost-lib/src/engine.rs
git commit -m "$(cat <<'EOF'
feat(lib): always emit FileFound for partial JPEGs

Previously the extraction-time guard returned early when
--keep-incomplete-jpeg and --write-all were both off, so no event
was emitted and the GUI never saw partials. The guard is now in
write_to_disk, so the FileFound event is always emitted (including
its jpeg_scan.status field, which already distinguishes Complete
from Truncated/Fragmented). The disk write is still gated.

audit_log.txt and the "files written" counter remain aligned with
on-disk state via a new was_written signal threaded from
write_to_disk through extract_basic_file. The detected-file counter
(increment_found_count) is unconditional so the GUI's partial chip
populates correctly.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: New `source_resolver.rs` module with TDD unit tests

**Files:**
- Create: `crates/utmost-gui/src/source_resolver.rs`
- Modify: `crates/utmost-gui/src/lib.rs` (declare the new module)

### Background

Pure logic, no IO beyond `Path::exists()`, `Path::is_file()`, `Path::is_dir()`. The resolver:
1. Walks user-supplied search locations (files match by basename; dirs match by basename inside).
2. Falls back to the recorded path as-is.
3. Falls back to `<parent of event-log dir>/<basename>`.
Returns `None` if nothing resolves. Cached per `source_id`.

- [ ] **Step 1: Write failing tests**

Create `crates/utmost-gui/src/source_resolver.rs` with both implementation skeleton and tests at the bottom. Start by writing the tests so they compile against the planned API. Note: the implementation will be `unimplemented!()` initially.

```rust
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
        unimplemented!()
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
}
```

Also add to `crates/utmost-gui/src/lib.rs` (near other `mod` declarations like `mod journal;` or `pub mod preview;`):

```rust
pub mod source_resolver;
```

If `tempfile` is not in `[dev-dependencies]` for `utmost-gui`, add it:

```
cargo add --dev --package utmost-gui tempfile
```

Check first — `crates/utmost-gui/Cargo.toml` likely already has it (the existing tests use it).

- [ ] **Step 2: Confirm tests fail to compile**

```
cargo test -p utmost-gui source_resolver
```

Expected: tests don't compile, or compile and panic at `unimplemented!()`.

- [ ] **Step 3: Implement `resolve`**

Replace the `unimplemented!()` body:

```rust
pub fn resolve(&self, source_id: u32, recorded_filename: &str) -> Option<PathBuf> {
    if let Some(hit) = self.cache.lock().unwrap().get(&source_id) {
        return hit.clone();
    }
    let resolved = self.resolve_uncached(recorded_filename);
    self.cache.lock().unwrap().insert(source_id, resolved.clone());
    resolved
}

fn resolve_uncached(&self, recorded_filename: &str) -> Option<PathBuf> {
    let basename = Path::new(recorded_filename).file_name()?.to_owned();

    // 1. User-supplied search locations.
    for loc in &self.search_locations {
        if loc.is_file() {
            if loc.file_name() == Some(basename.as_os_str()) && loc.exists() {
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

    // 3. Parent of the event log's directory.
    if let Some(log_path) = &self.event_log_path {
        if let Some(log_parent_parent) = log_path.parent().and_then(|p| p.parent()) {
            let candidate = log_parent_parent.join(&basename);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    None
}
```

- [ ] **Step 4: Run tests**

```
cargo test -p utmost-gui source_resolver
```

Expected: all 7 tests PASS.

- [ ] **Step 5: fmt + clippy + full test**

```
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

All green.

- [ ] **Step 6: Commit**

```
git add crates/utmost-gui/src/source_resolver.rs crates/utmost-gui/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(gui): SourceResolver maps source_id -> on-disk path

Walks user-supplied search locations (files match by basename, dirs
match by basename inside), falls back to the recorded path, then to
the parent of the event-log directory. Cached per source_id.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Bytes-based decode on `PreviewRenderer` (trait + JPEG override)

**Files:**
- Modify: `crates/utmost-gui/src/preview/mod.rs` (trait + default impls)
- Modify: `crates/utmost-gui/src/preview/jpeg.rs` (JPEG override + test)

### Background

Add `render_from_bytes` and `render_full_from_bytes` to `PreviewRenderer`. Default `Err`. `JpegPreview` implements both via `image::ImageReader::new(Cursor::new(bytes))`.

- [ ] **Step 1: Write failing tests**

In `crates/utmost-gui/src/preview/jpeg.rs`, add at the bottom (if there's no `mod tests` block yet, create one):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::view_model::FoundFile;
    use std::path::PathBuf;
    use utmost_lib::types::{ByteRun, FileObject};

    /// A tiny 2x2 JPEG (red/blue/green/white pixels) encoded inline.
    /// Generated once with `image` and embedded here so the test has no I/O.
    const TINY_JPEG: &[u8] = include_bytes!("../../tests/fixtures/tiny_2x2.jpg");

    fn dummy_found_file() -> FoundFile {
        FoundFile {
            id: 1,
            source_id: 0,
            file: FileObject {
                file_id: 1,
                filename: "x.jpg".into(),
                filesize: TINY_JPEG.len() as u64,
                file_type: "jpeg".into(),
                byte_runs: vec![ByteRun { offset: 0, img_offset: 0, len: TINY_JPEG.len() as u64 }],
                jpeg_scan: None,
            },
            written_path: PathBuf::new(),
            img_offset: 0,
        }
    }

    #[test]
    fn jpeg_renders_from_bytes() {
        let renderer = JpegPreview;
        let f = dummy_found_file();
        let out = renderer.render_from_bytes(TINY_JPEG, &f).expect("decode");
        match out {
            PreviewOutput::Image(img) => {
                assert_eq!(img.width(), 2);
                assert_eq!(img.height(), 2);
            }
            other => panic!("expected Image, got {other:?}"),
        }
    }

    #[test]
    fn jpeg_renders_full_from_bytes() {
        let renderer = JpegPreview;
        let f = dummy_found_file();
        let out = renderer.render_full_from_bytes(TINY_JPEG, &f).expect("decode");
        assert!(matches!(out, PreviewOutput::Image(_)));
    }

    #[test]
    fn jpeg_render_from_bytes_returns_err_on_garbage() {
        let renderer = JpegPreview;
        let f = dummy_found_file();
        let garbage = b"not a jpeg at all";
        assert!(renderer.render_from_bytes(garbage, &f).is_err());
    }
}
```

The fixture `tests/fixtures/tiny_2x2.jpg` doesn't exist yet — generate it with a one-shot helper. Add a separate small bin or use `cargo test` to invoke it; simplest is to commit a 2×2 JPEG you generate locally. The implementer can produce it via:

```rust
// scratch program, do not commit:
use image::{ImageBuffer, Rgb};
let mut img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::new(2, 2);
img.put_pixel(0, 0, Rgb([255, 0, 0]));
img.put_pixel(1, 0, Rgb([0, 0, 255]));
img.put_pixel(0, 1, Rgb([0, 255, 0]));
img.put_pixel(1, 1, Rgb([255, 255, 255]));
img.save("crates/utmost-gui/tests/fixtures/tiny_2x2.jpg").unwrap();
```

Place the fixture file at `crates/utmost-gui/tests/fixtures/tiny_2x2.jpg` and check it in.

Run:

```
cargo test -p utmost-gui jpeg_render
```

Expected: tests don't compile (`render_from_bytes` doesn't exist on the trait yet).

- [ ] **Step 2: Add the trait methods in `preview/mod.rs`**

In `crates/utmost-gui/src/preview/mod.rs`, the existing `PreviewRenderer` trait is around line 54-62. Add two new methods with default impls:

```rust
pub trait PreviewRenderer: Send + Sync {
    fn supports(&self, ft: FileType) -> bool;

    fn render(&self, path: &Path, file: &FoundFile) -> Result<PreviewOutput>;

    fn render_full(&self, path: &Path, file: &FoundFile) -> Result<PreviewOutput> {
        self.render(path, file)
    }

    fn render_side_panel_metadata(&self, file: &FoundFile) -> Vec<(String, String)>;

    /// Byte-based decode for cases where no on-disk file exists (report-only
    /// carves, moved output dirs). Default impl returns `Err`; renderers that
    /// can decode in-memory override this.
    fn render_from_bytes(&self, _bytes: &[u8], _file: &FoundFile) -> Result<PreviewOutput> {
        anyhow::bail!("byte-based decode not supported for this renderer")
    }

    fn render_full_from_bytes(&self, bytes: &[u8], file: &FoundFile) -> Result<PreviewOutput> {
        self.render_from_bytes(bytes, file)
    }
}
```

- [ ] **Step 3: Implement the JPEG override**

In `crates/utmost-gui/src/preview/jpeg.rs`, add the bytes-decoder helper and impl methods. The existing file starts at line 1 with `use anyhow::{Context, Result};` and so on. Add near `decode_image`:

```rust
fn decode_image_from_bytes(bytes: &[u8]) -> Result<image::DynamicImage> {
    ImageReader::new(std::io::Cursor::new(bytes))
        .with_guessed_format()
        .context("guess format from bytes")?
        .decode()
        .context("decode bytes")
}
```

In the `impl PreviewRenderer for JpegPreview` block (existing methods unchanged), add:

```rust
fn render_from_bytes(&self, bytes: &[u8], _file: &FoundFile) -> Result<PreviewOutput> {
    let img = decode_image_from_bytes(bytes)?;
    let (w, h) = (img.width(), img.height());
    let scale = (MAX_EDGE as f32 / w.max(h) as f32).min(1.0);
    let (nw, nh) = ((w as f32 * scale) as u32, (h as f32 * scale) as u32);
    let resized = if scale < 1.0 {
        img.resize(nw.max(1), nh.max(1), FilterType::Triangle).to_rgba8()
    } else {
        img.to_rgba8()
    };
    Ok(PreviewOutput::Image(resized))
}

fn render_full_from_bytes(&self, bytes: &[u8], _file: &FoundFile) -> Result<PreviewOutput> {
    Ok(PreviewOutput::Image(decode_image_from_bytes(bytes)?.to_rgba8()))
}
```

- [ ] **Step 4: Run the JPEG tests**

```
cargo test -p utmost-gui jpeg_render
```

Expected: all 3 tests PASS.

- [ ] **Step 5: fmt + clippy + full test**

```
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

All green.

- [ ] **Step 6: Commit**

```
git add crates/utmost-gui/src/preview/mod.rs \
        crates/utmost-gui/src/preview/jpeg.rs \
        crates/utmost-gui/tests/fixtures/tiny_2x2.jpg
git commit -m "$(cat <<'EOF'
feat(gui): PreviewRenderer gains byte-based decode methods

Default impls return Err for renderers that can't decode from
memory. JpegPreview overrides both render_from_bytes and
render_full_from_bytes. Pairs a tiny 2x2 jpeg fixture for the tests.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: `PreviewRegistry` dispatch helpers + `render_with_fallback`

**Files:**
- Modify: `crates/utmost-gui/src/preview/mod.rs`
- Test: same file (the existing `#[cfg(test)] mod tests` block)

### Background

`PreviewRegistry` currently has `render_for(ft, path, file)` and `render_full_for(ft, path, file)`. Add byte-based dispatch helpers and a public orchestrator that tries the on-disk path first and falls back to a byte-range read.

- [ ] **Step 1: Write failing tests**

In `crates/utmost-gui/src/preview/mod.rs`'s test module (look for `#[cfg(test)] mod tests` around line 150+), add:

```rust
#[test]
fn render_with_fallback_uses_path_when_present() {
    use std::path::PathBuf;
    let tmp = tempfile::TempDir::new().unwrap();
    // Write a real jpeg to disk via the fixture bytes.
    let bytes = include_bytes!("../../tests/fixtures/tiny_2x2.jpg");
    let path = tmp.path().join("on-disk.jpg");
    std::fs::write(&path, bytes).unwrap();

    let registry = PreviewRegistry::with_defaults_and_jpeg();
    let resolver = Arc::new(crate::source_resolver::SourceResolver::new(vec![], None));
    let mut sources_by_id = HashMap::new();
    sources_by_id.insert(0u32, String::from("ignored.dd"));

    let file = FoundFile {
        id: 1,
        source_id: 0,
        file: FileObject {
            file_id: 1,
            filename: "on-disk.jpg".into(),
            filesize: bytes.len() as u64,
            file_type: "jpeg".into(),
            byte_runs: vec![ByteRun { offset: 0, img_offset: 0, len: bytes.len() as u64 }],
            jpeg_scan: None,
        },
        written_path: path.clone(),
        img_offset: 0,
    };

    let out = render_with_fallback(
        &registry, &resolver, &sources_by_id,
        utmost_lib::types::FileType::Jpeg, &path, &file,
    ).expect("render");
    assert!(matches!(out, PreviewOutput::Image(_)));
}

#[test]
fn render_with_fallback_uses_bytes_when_path_missing() {
    use std::path::PathBuf;
    let tmp = tempfile::TempDir::new().unwrap();

    // Source image is a real jpeg on disk; the "written" path doesn't exist.
    let bytes = include_bytes!("../../tests/fixtures/tiny_2x2.jpg");
    let source_path = tmp.path().join("source.dd");
    std::fs::write(&source_path, bytes).unwrap();

    let registry = PreviewRegistry::with_defaults_and_jpeg();
    let resolver = Arc::new(crate::source_resolver::SourceResolver::new(
        vec![source_path.clone()],
        None,
    ));
    let mut sources_by_id = HashMap::new();
    sources_by_id.insert(0u32, source_path.to_str().unwrap().to_string());

    let nonexistent_written = tmp.path().join("output").join("missing.jpg");
    let file = FoundFile {
        id: 1,
        source_id: 0,
        file: FileObject {
            file_id: 1,
            filename: "missing.jpg".into(),
            filesize: bytes.len() as u64,
            file_type: "jpeg".into(),
            byte_runs: vec![ByteRun { offset: 0, img_offset: 0, len: bytes.len() as u64 }],
            jpeg_scan: None,
        },
        written_path: nonexistent_written.clone(),
        img_offset: 0,
    };

    let out = render_with_fallback(
        &registry, &resolver, &sources_by_id,
        utmost_lib::types::FileType::Jpeg, &nonexistent_written, &file,
    ).expect("render");
    assert!(matches!(out, PreviewOutput::Image(_)));
}

#[test]
fn render_with_fallback_concatenates_multiple_byte_runs() {
    // Split the fixture into two halves; the second byte_run should append
    // and produce a decodable image.
    let bytes = include_bytes!("../../tests/fixtures/tiny_2x2.jpg");
    let half = bytes.len() / 2;
    let head = &bytes[..half];
    let tail = &bytes[half..];

    let tmp = tempfile::TempDir::new().unwrap();
    let source = tmp.path().join("source.dd");
    // Lay out source as: [padding 16 bytes][head][padding 16 bytes][tail]
    let mut buf = vec![0u8; 16];
    buf.extend_from_slice(head);
    let head_end = buf.len();
    buf.extend_from_slice(&[0u8; 16]);
    let tail_start = buf.len();
    buf.extend_from_slice(tail);
    std::fs::write(&source, &buf).unwrap();

    let registry = PreviewRegistry::with_defaults_and_jpeg();
    let resolver = Arc::new(crate::source_resolver::SourceResolver::new(
        vec![source.clone()],
        None,
    ));
    let mut sources_by_id = HashMap::new();
    sources_by_id.insert(0u32, source.to_str().unwrap().to_string());

    let file = FoundFile {
        id: 1,
        source_id: 0,
        file: FileObject {
            file_id: 1,
            filename: "x.jpg".into(),
            filesize: bytes.len() as u64,
            file_type: "jpeg".into(),
            byte_runs: vec![
                ByteRun { offset: 0, img_offset: 16, len: head.len() as u64 },
                ByteRun { offset: head.len() as u64, img_offset: tail_start as u64, len: tail.len() as u64 },
            ],
            jpeg_scan: None,
        },
        written_path: tmp.path().join("missing.jpg"),
        img_offset: 16,
    };

    let out = render_with_fallback(
        &registry, &resolver, &sources_by_id,
        utmost_lib::types::FileType::Jpeg, &file.written_path, &file,
    ).expect("render");
    assert!(matches!(out, PreviewOutput::Image(_)));
}

#[test]
fn render_with_fallback_returns_err_when_neither_works() {
    let tmp = tempfile::TempDir::new().unwrap();
    let registry = PreviewRegistry::with_defaults_and_jpeg();
    let resolver = Arc::new(crate::source_resolver::SourceResolver::new(vec![], None));
    let sources_by_id = HashMap::new();

    let file = FoundFile {
        id: 1,
        source_id: 0,
        file: FileObject {
            file_id: 1,
            filename: "x.jpg".into(),
            filesize: 0,
            file_type: "jpeg".into(),
            byte_runs: vec![],
            jpeg_scan: None,
        },
        written_path: tmp.path().join("nope.jpg"),
        img_offset: 0,
    };

    let out = render_with_fallback(
        &registry, &resolver, &sources_by_id,
        utmost_lib::types::FileType::Jpeg, &file.written_path, &file,
    );
    assert!(out.is_err());
}
```

The tests reference imports that may not be in the test module yet. Add at the top of the `mod tests` block:

```rust
use super::*;
use crate::view_model::FoundFile;
use std::collections::HashMap;
use std::sync::Arc;
use utmost_lib::types::{ByteRun, FileObject};
```

Run:

```
cargo test -p utmost-gui render_with_fallback
```

Expected: compile error — `render_with_fallback`, `render_from_bytes_for`, `render_full_from_bytes_for` don't exist.

- [ ] **Step 2: Add dispatch helpers on `PreviewRegistry`**

In `crates/utmost-gui/src/preview/mod.rs` near the existing `render_for` and `render_full_for` methods (around line 90-117):

```rust
pub fn render_from_bytes_for(
    &self,
    file_type: FileType,
    bytes: &[u8],
    file: &FoundFile,
) -> Result<PreviewOutput> {
    for r in &self.renderers {
        if r.supports(file_type) {
            return r.render_from_bytes(bytes, file);
        }
    }
    anyhow::bail!("no renderer for file type {:?}", file_type)
}

pub fn render_full_from_bytes_for(
    &self,
    file_type: FileType,
    bytes: &[u8],
    file: &FoundFile,
) -> Result<PreviewOutput> {
    for r in &self.renderers {
        if r.supports(file_type) {
            return r.render_full_from_bytes(bytes, file);
        }
    }
    anyhow::bail!("no renderer for file type {:?}", file_type)
}
```

- [ ] **Step 3: Add the `render_with_fallback` orchestrator**

Still in `preview/mod.rs`, as a free function (not on the registry):

```rust
use std::io::{Read, Seek, SeekFrom};

pub fn render_with_fallback(
    registry: &PreviewRegistry,
    resolver: &crate::source_resolver::SourceResolver,
    sources_by_id: &std::collections::HashMap<u32, String>,
    file_type: FileType,
    path: &Path,
    file: &FoundFile,
) -> Result<PreviewOutput> {
    // 1. On-disk path first.
    if path.exists() {
        match registry.render_for(file_type, path, file) {
            Ok(out) => return Ok(out),
            Err(e) => tracing::debug!(
                "path-based render failed for {}: {}; falling back to source bytes",
                path.display(), e
            ),
        }
    }

    // 2. Byte-range fallback.
    let bytes = read_source_bytes(resolver, sources_by_id, file)?;
    registry.render_from_bytes_for(file_type, &bytes, file)
}

pub fn render_full_with_fallback(
    registry: &PreviewRegistry,
    resolver: &crate::source_resolver::SourceResolver,
    sources_by_id: &std::collections::HashMap<u32, String>,
    file_type: FileType,
    path: &Path,
    file: &FoundFile,
) -> Result<PreviewOutput> {
    if path.exists() {
        match registry.render_full_for(file_type, path, file) {
            Ok(out) => return Ok(out),
            Err(e) => tracing::debug!(
                "path-based full render failed for {}: {}; falling back to source bytes",
                path.display(), e
            ),
        }
    }
    let bytes = read_source_bytes(resolver, sources_by_id, file)?;
    registry.render_full_from_bytes_for(file_type, &bytes, file)
}

fn read_source_bytes(
    resolver: &crate::source_resolver::SourceResolver,
    sources_by_id: &std::collections::HashMap<u32, String>,
    file: &FoundFile,
) -> Result<Vec<u8>> {
    if file.file.byte_runs.is_empty() {
        anyhow::bail!("file has no byte_runs");
    }
    let recorded = sources_by_id.get(&file.source_id)
        .ok_or_else(|| anyhow::anyhow!("no recorded source filename for source_id {}", file.source_id))?;
    let src_path = resolver.resolve(file.source_id, recorded)
        .ok_or_else(|| anyhow::anyhow!("source not resolvable for source_id {}", file.source_id))?;

    let mut f = std::fs::File::open(&src_path)
        .with_context(|| format!("open source {}", src_path.display()))?;
    let total_len: u64 = file.file.byte_runs.iter().map(|r| r.len).sum();
    let mut buf = Vec::with_capacity(total_len as usize);
    for run in &file.file.byte_runs {
        f.seek(SeekFrom::Start(run.img_offset))
            .with_context(|| format!("seek to {:#x} in {}", run.img_offset, src_path.display()))?;
        let mut chunk = vec![0u8; run.len as usize];
        let n = f.read(&mut chunk).with_context(|| "read source bytes")?;
        chunk.truncate(n);
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}
```

If `tracing` isn't already imported at the top of `preview/mod.rs`, add `use tracing;` or fully qualify the call (`tracing::debug!(...)`).

- [ ] **Step 4: Run tests**

```
cargo test -p utmost-gui render_with_fallback
```

Expected: all 4 tests PASS.

- [ ] **Step 5: fmt + clippy + full test**

```
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

All green.

- [ ] **Step 6: Commit**

```
git add crates/utmost-gui/src/preview/mod.rs
git commit -m "$(cat <<'EOF'
feat(gui): render_with_fallback orchestrator + bytes-based registry dispatch

render_with_fallback tries the on-disk path first; on miss or decode
failure it reads byte_runs from the resolved source image and calls
render_from_bytes. Multi-run files (recovered jpegs with a header
fragment + continuation) are concatenated into one buffer.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Wire fallback into thumb worker + slint adapter

**Files:**
- Modify: `crates/utmost-gui/src/thumb_worker.rs`
- Modify: `crates/utmost-gui/src/slint_adapter.rs`

### Background

`ThumbWorker::start` builds the worker threads holding a `PreviewRegistry`. It needs to also hold the `SourceResolver` and the per-sync `sources_by_id` map. The cleanest split: the resolver is owned per-worker (cloned via Arc); the map is a `Arc<RwLock<HashMap<u32, String>>>` updated by the adapter each sync and read by the worker per request.

- [ ] **Step 1: Add a shared sources map to ThumbWorker**

In `crates/utmost-gui/src/thumb_worker.rs`:

a. Add fields and imports at the top:

```rust
use std::collections::HashMap;
use std::sync::RwLock;

use crate::source_resolver::SourceResolver;
use crate::preview::render_with_fallback;
```

b. Change the struct:

```rust
pub type SourcesByIdMap = Arc<RwLock<HashMap<u32, String>>>;

pub struct ThumbWorker {
    tx: Sender<ThumbRequest>,
    pub cache: ThumbCache,
    pub sources_by_id: SourcesByIdMap,
}
```

c. Update `ThumbWorker::start` to accept the resolver and create the sources map:

```rust
pub fn start(
    registry: Arc<PreviewRegistry>,
    resolver: Arc<SourceResolver>,
    capacity: usize,
    workers: usize,
    on_complete: Arc<dyn Fn(FileId) + Send + Sync>,
) -> Self {
    let cache: ThumbCache = Arc::new(Mutex::new(LruCache::new(
        NonZeroUsize::new(capacity.max(1)).unwrap(),
    )));
    let sources_by_id: SourcesByIdMap = Arc::new(RwLock::new(HashMap::new()));
    let (tx, rx) = unbounded::<ThumbRequest>();
    for _ in 0..workers.max(1) {
        let rx: Receiver<ThumbRequest> = rx.clone();
        let cache = cache.clone();
        let registry = registry.clone();
        let resolver = resolver.clone();
        let sources_by_id = sources_by_id.clone();
        let on_complete = on_complete.clone();
        thread::spawn(move || {
            while let Ok(req) = rx.recv() {
                if cache.lock().unwrap().contains(&req.id) {
                    continue;
                }
                // Snapshot the sources map for this request.
                let snap: HashMap<u32, String> = sources_by_id.read().unwrap().clone();
                let out = render_with_fallback(
                    &registry, &resolver, &snap,
                    req.file_type, &req.path, &req.file,
                );
                if let Ok(crate::preview::PreviewOutput::Image(img)) = out {
                    let (w, h) = (img.width(), img.height());
                    let pixels: Vec<u8> = img.into_raw();
                    let buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
                        &pixels, w, h,
                    );
                    cache.lock().unwrap().put(req.id, buf);
                    let cb = on_complete.clone();
                    let id = req.id;
                    let _ = slint::invoke_from_event_loop(move || cb(id));
                }
            }
        });
    }
    Self { tx, cache, sources_by_id }
}
```

- [ ] **Step 2: Update the adapter to construct/own the resolver and update the sources map**

In `crates/utmost-gui/src/slint_adapter.rs`:

a. Add an `Arc<SourceResolver>` field to the adapter struct (search for the struct that holds `thumbs: ThumbWorker` — that's the one). E.g. `pub resolver: Arc<SourceResolver>`.

b. Wherever the adapter is constructed (search for `ThumbWorker::start`), pass in the new resolver from outside:

```rust
let resolver = Arc::new(SourceResolver::new(source_search_locations, event_log_path));
let thumbs = ThumbWorker::start(registry.clone(), resolver.clone(), 512, 4, on_complete);
```

(The exact thumb-worker capacity/workers values may already be wired — preserve them; only add the `resolver` argument.) The `source_search_locations: Vec<PathBuf>` and `event_log_path: Option<PathBuf>` come from upstream (Task 7).

c. In `sync()`, before the tile loop, update the sources map from `vm.sources`:

```rust
{
    let mut map = self.thumbs.sources_by_id.write().unwrap();
    map.clear();
    for s in &vm.sources {
        map.insert(s.source_id, s.filename.clone());
    }
}
```

Place this right after the chips and selected_id block, before the tile loop builds `FileTileData`.

d. The `full_res_image` function around line 504 currently calls `self.registry.render_full_for(ft, &f.written_path, f)`. Replace with `render_full_with_fallback`:

```rust
fn full_res_image(&self, f: &crate::view_model::FoundFile) -> Option<slint::Image> {
    let mut ic = self.image_cache_full.borrow_mut();
    if let Some(img) = ic.get(&f.id) {
        return Some(img.clone());
    }
    let ft = parse_file_type_pub(&f.file.file_type)?;
    let snap = self.thumbs.sources_by_id.read().unwrap().clone();
    match crate::preview::render_full_with_fallback(
        &self.registry, &self.resolver, &snap, ft, &f.written_path, f,
    ) {
        Ok(crate::preview::PreviewOutput::Image(rgba)) => {
            let (w, h) = (rgba.width(), rgba.height());
            let mut buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::new(w, h);
            buf.make_mut_bytes().copy_from_slice(&rgba);
            let img = slint::Image::from_rgba8(buf);
            ic.insert(f.id, img.clone());
            Some(img)
        }
        Ok(_) => None,
        Err(e) => {
            eprintln!(
                "full-res preview decode failed for {}: {}",
                f.written_path.display(), e
            );
            None
        }
    }
}
```

- [ ] **Step 3: Update the adapter constructor signature**

The adapter is constructed somewhere in `lib.rs`. Find the construction site (search for `Adapter::new` or similar — match the codebase pattern). Add `source_search_locations: Vec<PathBuf>` and `event_log_path: Option<PathBuf>` as constructor args.

For now, pass empty `vec![]` and `None` from `lib.rs` so the project compiles. Task 7 wires the real values.

- [ ] **Step 4: Verify build + tests**

```
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

All green. The thumb-worker tests should still pass (the new fallback path is exercised by Task 5's tests at the orchestrator level; this task is integration only).

- [ ] **Step 5: Commit**

```
git add crates/utmost-gui/src/thumb_worker.rs crates/utmost-gui/src/slint_adapter.rs
git commit -m "$(cat <<'EOF'
feat(gui): thumb worker + adapter use render_with_fallback

ThumbWorker now owns the SourceResolver and a shared sources_by_id
map updated each sync from vm.sources. Both the worker thread (for
thumbnails) and the adapter's full_res_image (for the lightbox)
route through render_with_fallback, so the byte-range fallback fires
whenever the on-disk file is missing.

Resolver's search locations are empty for now; Task 7 wires the
viewer CLI's --source values through.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Viewer `--source` CLI + `run_from_file` signature

**Files:**
- Modify: `crates/utmost-viewer/src/main.rs`
- Modify: `crates/utmost-gui/src/lib.rs`

### Background

Repeat `--source` to add a search location. Thread `Vec<PathBuf>` through `run_from_file` and `launch_ui_with_journal` to the adapter constructor (Task 6 already accepts it).

- [ ] **Step 1: Update the viewer CLI**

`crates/utmost-viewer/src/main.rs`:

```rust
use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about = "Replay a utmost carve event log")]
struct Args {
    /// Path to either a directory or a carve_events.bin file.
    target: PathBuf,

    /// Search location for the original source image. May be a file (used
    /// directly if its basename matches a recorded source) or a directory
    /// (scanned by basename). May be repeated; entries are tried left to
    /// right. If omitted, the viewer falls back to the path recorded in
    /// the event log and then to the parent of the log's directory.
    #[arg(long, action = clap::ArgAction::Append)]
    source: Vec<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    utmost_gui::run_from_file(&args.target, args.source)
}
```

- [ ] **Step 2: Update `run_from_file` in utmost-gui**

`crates/utmost-gui/src/lib.rs`, the existing function around line 17:

```rust
pub fn run_from_file(target: &Path, source_search_locations: Vec<PathBuf>) -> Result<()> {
    // existing body — locate the events.bin file path, compute event_log_path = Some(...)
    // existing body — build the vm + journal
    launch_ui_with_journal(vm, journal, source_search_locations, event_log_path)
}
```

`event_log_path` is the canonical path to the loaded `carve_events.bin` (which the function already knows internally). Make sure it's captured before delegating.

For the journal-recovery code path around line 90 (the `else` branch), do the same: pass `source_search_locations` and the relevant `event_log_path`.

- [ ] **Step 3: Update `launch_ui_with_journal`**

Around line 93 of `lib.rs`:

```rust
fn launch_ui_with_journal(
    vm: ViewModel,
    journal: Journal,
    source_search_locations: Vec<PathBuf>,
    event_log_path: Option<PathBuf>,
) -> Result<()> {
    // ... existing body ...
    // wherever the adapter is constructed, pass these through
}
```

The exact adapter-construction site varies — find it by searching for `Adapter::new` or `SlintAdapter::new` or similar, and add the two new args.

- [ ] **Step 4: Update internal callers**

If anything inside `utmost-gui` calls `run_from_file` (some `examples/` or tests might), pass `vec![]`. Search:

```
grep -rn "run_from_file" /Users/steve/src/utmost
```

- [ ] **Step 5: Build + clippy + test**

```
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

All green.

- [ ] **Step 6: Manual smoke check**

```
cargo run -p utmost-viewer -- --help
```

Expected: the help text shows the new `--source <SOURCE>` argument and mentions it can be repeated.

- [ ] **Step 7: Commit**

```
git add crates/utmost-viewer/src/main.rs crates/utmost-gui/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(viewer): repeatable --source flag plumbed to the source resolver

utmost-viewer now accepts --source <path> (file or directory),
repeatable, and threads the list through run_from_file ->
launch_ui_with_journal -> Adapter -> SourceResolver.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: End-to-end integration test (report-only → viewer thumb)

**Files:**
- Create: `crates/utmost-gui/tests/source_bytes_fallback.rs`

### Background

A library-level integration test that:
1. Constructs a synthetic source image containing a tiny JPEG at a known offset.
2. Drives `utmost-lib`'s engine in `report-only` mode against that source (no files written).
3. Builds a `ViewModel` from the resulting bincoded events.
4. Calls `render_with_fallback` directly with the JPEG `FoundFile` and asserts an Image comes back.

This is *not* a Slint integration test (the GUI itself doesn't run in CI cleanly). The test verifies the data flow up to the renderer, which is the value-add.

- [ ] **Step 1: Write the test**

Create `crates/utmost-gui/tests/source_bytes_fallback.rs`:

```rust
//! End-to-end: report-only carve → SourceResolver → render_with_fallback.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;
use utmost_gui::preview::{PreviewOutput, PreviewRegistry, render_with_fallback};
use utmost_gui::source_resolver::SourceResolver;
use utmost_gui::view_model::FoundFile;
use utmost_lib::types::{ByteRun, FileObject, FileType};

#[test]
fn report_only_carve_thumbnails_via_source_bytes() {
    // 1. Synthesise a source image: [64 bytes padding][tiny jpeg][64 bytes padding].
    let jpeg_bytes = include_bytes!("fixtures/tiny_2x2.jpg");
    let mut source: Vec<u8> = vec![0u8; 64];
    let jpeg_offset = source.len() as u64;
    source.extend_from_slice(jpeg_bytes);
    source.extend_from_slice(&[0u8; 64]);

    let tmp = TempDir::new().unwrap();
    let source_path = tmp.path().join("test_source.dd");
    std::fs::write(&source_path, &source).unwrap();

    // 2. Build a FoundFile as if a report-only carve had emitted it.
    let mut sources_by_id = HashMap::new();
    sources_by_id.insert(0u32, source_path.to_str().unwrap().to_string());

    let file = FoundFile {
        id: 1,
        source_id: 0,
        file: FileObject {
            file_id: 1,
            filename: "001-64.jpg".into(),
            filesize: jpeg_bytes.len() as u64,
            file_type: "jpeg".into(),
            byte_runs: vec![ByteRun {
                offset: 0,
                img_offset: jpeg_offset,
                len: jpeg_bytes.len() as u64,
            }],
            jpeg_scan: None,
        },
        // The would-be written path — never actually created.
        written_path: tmp.path().join("output").join("001-64.jpg"),
        img_offset: jpeg_offset,
    };

    // 3. SourceResolver knows about the source via --source-equivalent.
    let resolver = Arc::new(SourceResolver::new(vec![source_path.clone()], None));

    // 4. Render via the fallback orchestrator.
    let registry = PreviewRegistry::with_defaults_and_jpeg();
    let out = render_with_fallback(
        &registry,
        &resolver,
        &sources_by_id,
        FileType::Jpeg,
        &file.written_path, // nonexistent
        &file,
    )
    .expect("fallback should decode the embedded jpeg");

    match out {
        PreviewOutput::Image(img) => {
            assert_eq!(img.width(), 2);
            assert_eq!(img.height(), 2);
        }
        other => panic!("expected Image, got {other:?}"),
    }
}

#[test]
fn fallback_uses_recorded_path_when_no_search_locations() {
    let jpeg_bytes = include_bytes!("fixtures/tiny_2x2.jpg");
    let tmp = TempDir::new().unwrap();
    let source_path = tmp.path().join("recorded.dd");
    std::fs::write(&source_path, jpeg_bytes).unwrap();

    let mut sources_by_id = HashMap::new();
    sources_by_id.insert(0u32, source_path.to_str().unwrap().to_string());

    let file = FoundFile {
        id: 1,
        source_id: 0,
        file: FileObject {
            file_id: 1,
            filename: "x.jpg".into(),
            filesize: jpeg_bytes.len() as u64,
            file_type: "jpeg".into(),
            byte_runs: vec![ByteRun {
                offset: 0,
                img_offset: 0,
                len: jpeg_bytes.len() as u64,
            }],
            jpeg_scan: None,
        },
        written_path: tmp.path().join("missing.jpg"),
        img_offset: 0,
    };

    let resolver = Arc::new(SourceResolver::new(vec![], None));
    let registry = PreviewRegistry::with_defaults_and_jpeg();
    let out = render_with_fallback(
        &registry, &resolver, &sources_by_id,
        FileType::Jpeg, &file.written_path, &file,
    ).expect("recorded path should resolve");
    assert!(matches!(out, PreviewOutput::Image(_)));
}
```

The test imports `utmost_gui::preview::render_with_fallback` and `utmost_gui::source_resolver::SourceResolver`. Both modules must be re-exported in `utmost-gui/src/lib.rs`. Check that `pub mod preview;` and `pub mod source_resolver;` are present, and that `view_model` and `preview` already export `FoundFile`, `PreviewOutput`, `PreviewRegistry`. If `render_with_fallback` isn't pub from `preview/mod.rs`, mark it `pub`.

- [ ] **Step 2: Run the integration test**

```
cargo test -p utmost-gui --test source_bytes_fallback
```

Expected: both tests PASS.

- [ ] **Step 3: fmt + clippy + full test**

```
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

All green.

- [ ] **Step 4: Commit**

```
git add crates/utmost-gui/tests/source_bytes_fallback.rs
git commit -m "$(cat <<'EOF'
test(gui): integration test for report-only → byte-range thumbnail

Synthesises a source image with a tiny jpeg at a known offset, sets
up a FoundFile that points at it via byte_runs, and verifies that
render_with_fallback decodes the image without any on-disk carved
file.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Final verification

After Task 8:

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

All four must succeed. Then a manual end-to-end check:

```
# Carve in report-only mode against a real disk image with embedded jpegs
cargo run -p utmost-cli --release -- --report-only -t jpeg /path/to/image.dd

# Launch the viewer pointed at the output, with --source
cargo run -p utmost-viewer --release -- ./output --source /path/to/image.dd

# Confirm: gallery shows JPEG thumbnails even though ./output has no .jpg files.
```

And a partial-tracking check:

```
# Default flags (no --keep-incomplete-jpeg)
cargo run -p utmost-cli --release -- -t jpeg /path/to/image.with.partials.dd
cargo run -p utmost-viewer --release -- ./output

# Confirm: "Partial JPEG (N)" filter chip appears and is populated. Partial
# thumbnails render via the source-byte fallback (no .jpg files on disk for
# the partials).
```

## Out-of-scope follow-ups (from the spec)

- "Source missing" UI badge or banner.
- Per-source-id explicit mapping (`--source <id>=<path>`).
- Multiple bincoded event logs in one viewer session.
- A pre-warm-thumbnails CLI mode.
- Bytes-decoding for non-JPEG image types.
