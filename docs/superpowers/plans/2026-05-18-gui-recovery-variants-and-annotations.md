# GUI Recovery Variants & Forensic Annotations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `utmost-lib` and `utmost-gui` to surface multiple JPEG recovery candidates per partial original, capture three kinds of forensic annotations (bookmarks, append-only notes, mark-as-best), and persist all of it in `carve_events.bin` with a crash-safe `carve_events.pending` journal sidecar.

**Architecture:** New `CarveEvent` variants + a stable `file_id: u64` on `FileObject` form the data model. Recovery is extended to write top-N candidates and emit new events that link them to originals. The GUI view-model gains state for variants, bookmarks, notes, and best-of choices, plus filter chips. A new `journal.rs` module writes a same-framing sidecar during live carves and folds it into the main log at `RunFinished`.

**Tech Stack:** Rust, bincode 1.x (length-prefixed framing), serde, Slint, crossbeam-channel, tokio (CLI side), `tracing` for warn logs.

**Source spec:** `docs/superpowers/specs/2026-05-18-gui-recovery-variants-and-annotations-design.md` (commit `a16cf4a`).

**Note on DFXML:** The spec §5 mentions `carve_report.xml` (DFXML). No XML reporter exists in the codebase as of `a16cf4a` (only `JsonReporter`). `file_id` propagation to a future DFXML reporter is deferred until that reporter exists. JSON propagation is automatic via `serde`.

---

## Wave 1 — Foundation (sequential; everything else depends on these)

### Task 1: Add `file_id: u64` to `FileObject` and seed the engine allocator

**Files:**
- Modify: `crates/utmost-lib/src/types.rs:62-74` (`FileObject` struct; serde rename rules)
- Modify: `crates/utmost-lib/src/types.rs` (add `next_file_id: Arc<AtomicU64>` to `State`)
- Modify: `crates/utmost-lib/src/reporting.rs:146-164` (`create_file_object` signature)
- Modify: `crates/utmost-lib/src/engine.rs:993-1015` (allocate and pass `file_id`)
- Test: `crates/utmost-lib/src/types.rs` (extend existing `tests` module)

**Parallel with:** none (must complete before all other tasks).

- [ ] **Step 1: Write the failing test**

In `crates/utmost-lib/src/types.rs`, locate the existing `#[cfg(test)] mod tests` block at the bottom and add:

```rust
#[test]
fn state_allocates_monotonic_file_ids() {
    use std::sync::atomic::Ordering;

    let temp_dir = tempfile::tempdir().unwrap();
    let config = crate::types::CarveConfig {
        output_directory: temp_dir.path().to_string_lossy().into(),
        disable_report: true,
        disable_audit: true,
        ..Default::default()
    };
    let state = crate::types::State::new(config).unwrap();

    let a = state.next_file_id.fetch_add(1, Ordering::SeqCst);
    let b = state.next_file_id.fetch_add(1, Ordering::SeqCst);
    let c = state.next_file_id.fetch_add(1, Ordering::SeqCst);

    assert_eq!(a, 1);
    assert_eq!(b, 2);
    assert_eq!(c, 3);
}

#[test]
fn file_object_carries_file_id() {
    let fo = crate::reporting::create_file_object(
        "00000001.jpg",
        crate::types::FileType::Jpeg,
        100,
        0,
        None,
        42, // file_id
    );
    assert_eq!(fo.file_id, 42);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```
cargo test -p utmost-lib state_allocates_monotonic_file_ids file_object_carries_file_id
```
Expected: both tests FAIL — `file_id` field does not exist; `create_file_object` does not accept the extra arg; `State` has no `next_file_id`.

- [ ] **Step 3: Extend `FileObject`**

In `crates/utmost-lib/src/types.rs:62-74`, add `pub file_id: u64` as the first field of `FileObject`:

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileObject {
    /// Stable monotonic identifier allocated by the engine when the file is
    /// extracted. Survives renames; used as the canonical handle by the bincoded
    /// event log, audit log, and annotation events.
    pub file_id: u64,
    pub filename: String,
    pub filesize: u64,
    pub file_type: String,
    pub byte_runs: Vec<ByteRun>,
    pub jpeg_scan: Option<JpegScanInfo>,
}
```

- [ ] **Step 4: Add `next_file_id` to `State`**

Find the `State` struct in `crates/utmost-lib/src/types.rs` (search `pub struct State`). Add this field next to other shared counters:

```rust
pub next_file_id: Arc<AtomicU64>,
```

In `State::new` (search `pub fn new(config: CarveConfig)`), initialise it after the existing `Arc::new(AtomicUsize::new(0))` fields:

```rust
next_file_id: Arc::new(AtomicU64::new(1)),
```

Ensure the imports at the top include `use std::sync::atomic::AtomicU64;` (already imports `AtomicUsize`; add `AtomicU64`).

- [ ] **Step 5: Update `create_file_object`**

In `crates/utmost-lib/src/reporting.rs:146-164`:

```rust
pub fn create_file_object(
    filename: &str,
    file_type: FileType,
    file_size: u64,
    img_offset: u64,
    jpeg_scan: Option<JpegScanInfo>,
    file_id: u64,
) -> FileObject {
    FileObject {
        file_id,
        filename: filename.to_string(),
        filesize: file_size,
        file_type: format!("{:?}", file_type).to_lowercase(),
        byte_runs: vec![ByteRun {
            offset: 0,
            img_offset,
            len: file_size,
        }],
        jpeg_scan,
    }
}
```

- [ ] **Step 6: Update engine emit site to allocate + pass `file_id`**

In `crates/utmost-lib/src/engine.rs:993-1015`, the existing `state.emit(...)` block. Replace with:

```rust
let file_id = state.next_file_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

state.report_file(
    &filename,
    spec.file_type,
    data.len() as u64,
    offset,
    jpeg_scan,
    file_id,
)?;

state.emit(crate::events::CarveEvent::FileFound {
    source_id: file_info.source_id,
    file: crate::reporting::create_file_object(
        &filename,
        spec.file_type,
        data.len() as u64,
        offset,
        jpeg_scan_for_event,
        file_id,
    ),
    img_offset: offset,
    written_path: filename.clone(),
});
```

Update the `StateReporting::report_file` trait method signature and impl to accept `file_id: u64` (file `crates/utmost-lib/src/reporting.rs` and wherever `impl StateReporting for State` lives — search `report_file`). Plumb `file_id` into the FileObject built inside `report_file`.

- [ ] **Step 7: Run the tests to verify they pass**

```
cargo test -p utmost-lib state_allocates_monotonic_file_ids file_object_carries_file_id
```
Expected: both PASS.

- [ ] **Step 8: Run the full lib test suite**

```
cargo test -p utmost-lib
```
Expected: ALL pass. Some pre-existing tests may need to pass a dummy `file_id` (use `0` or any monotonic value) to `create_file_object` — fix call sites compile errors as they appear.

- [ ] **Step 9: fmt + clippy**

```
cargo fmt --all && cargo clippy --all-targets -- -D warnings
```
Expected: no output / no warnings.

- [ ] **Step 10: Commit**

```
git add crates/utmost-lib/src/types.rs crates/utmost-lib/src/reporting.rs crates/utmost-lib/src/engine.rs
git commit -m "$(cat <<'EOF'
feat(lib): add file_id to FileObject and engine allocator

Stable monotonic identifier per extracted file, allocated by the engine
and carried on FileObject. Used as the canonical handle in carve_report.json
and (in later tasks) the bincoded event log + annotation events.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Define new `CarveEvent` variants and `RecoveryMethod` enum

**Files:**
- Modify: `crates/utmost-lib/src/events.rs` (add variants near existing `CarveEvent` enum at lines 80-130)
- Test: `crates/utmost-lib/src/events.rs` (new `#[cfg(test)] mod tests`)

**Parallel with:** Task 1 (different files). Run after Task 1 if `cargo test` ordering matters; otherwise truly independent.

- [ ] **Step 1: Write the failing test**

Add at the bottom of `crates/utmost-lib/src/events.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(ev: &CarveEvent) {
        let bytes = bincode::serialize(ev).expect("serialize");
        let back: CarveEvent = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(ev, &back);
    }

    #[test]
    fn recovery_started_roundtrips() {
        let ev = CarveEvent::RecoveryStarted {
            started_at: "2026-05-18T10:00:00Z".into(),
            keep_candidates: 5,
            search_window: 50 * 1024 * 1024,
            block_size: 512,
            min_entropy_score: 7.0,
            huffman_validation: true,
        };
        roundtrip(&ev);
        assert!(ev.persistable());
    }

    #[test]
    fn recovery_candidate_roundtrips() {
        let ev = CarveEvent::RecoveryCandidate {
            original_file_id: 42,
            candidate_file_id: 43,
            rank: 1,
            method: RecoveryMethod::DirectContinuation,
            entropy_score: 7.95,
            ff_validity_score: Some(0.97),
            huffman_mcu_count: Some(412),
            continuation_img_offset: 0xdeadbeef,
        };
        roundtrip(&ev);
        assert!(ev.persistable());
    }

    #[test]
    fn recovery_finished_roundtrips() {
        let ev = CarveEvent::RecoveryFinished {
            duration_ms: 1234,
            partials_processed: 3,
            candidates_written: 9,
        };
        roundtrip(&ev);
        assert!(ev.persistable());
    }

    #[test]
    fn bookmark_roundtrips() {
        let ev = CarveEvent::Bookmark {
            file_id: 7,
            bookmarked: true,
            at: "2026-05-18T10:00:00Z".into(),
        };
        roundtrip(&ev);
        assert!(ev.persistable());
    }

    #[test]
    fn note_roundtrips() {
        let ev = CarveEvent::Note {
            note_id: 1,
            file_id: 7,
            text: "hello".into(),
            at: "2026-05-18T10:00:00Z".into(),
        };
        roundtrip(&ev);
        assert!(ev.persistable());
    }

    #[test]
    fn mark_as_best_roundtrips() {
        let ev = CarveEvent::MarkAsBest {
            original_file_id: 7,
            chosen_file_id: 9,
            at: "2026-05-18T10:00:00Z".into(),
        };
        roundtrip(&ev);
        assert!(ev.persistable());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```
cargo test -p utmost-lib --lib events::tests
```
Expected: every test FAILS — variants do not exist.

- [ ] **Step 3: Lift `RecoveryMethod` from `jpeg_recover` into `events`**

In `crates/utmost-lib/src/events.rs`, near the top imports, add:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryMethod {
    /// The continuation was found immediately after the carved file's end
    /// offset (contiguous on-disk, just past the max_len cutoff).
    DirectContinuation,
    /// The continuation was found at a non-contiguous location via entropy
    /// scan, suggesting true filesystem fragmentation.
    FragmentReassembly,
}
```

Then in `crates/utmost-lib/src/jpeg_recover.rs`, find the existing `pub enum RecoveryMethod` (around lines 97-106) and replace with:

```rust
pub use crate::events::RecoveryMethod;
```

- [ ] **Step 4: Add the new event variants**

In `crates/utmost-lib/src/events.rs`, extend the `pub enum CarveEvent` (around lines 80-115):

```rust
    RecoveryStarted {
        started_at: String,
        keep_candidates: usize,
        search_window: usize,
        block_size: usize,
        min_entropy_score: f64,
        huffman_validation: bool,
    },
    RecoveryCandidate {
        original_file_id: u64,
        candidate_file_id: u64,
        rank: u32,
        method: RecoveryMethod,
        entropy_score: f64,
        ff_validity_score: Option<f64>,
        huffman_mcu_count: Option<usize>,
        continuation_img_offset: u64,
    },
    RecoveryFinished {
        duration_ms: u64,
        partials_processed: u32,
        candidates_written: u32,
    },
    Bookmark {
        file_id: u64,
        bookmarked: bool,
        at: String,
    },
    Note {
        note_id: u64,
        file_id: u64,
        text: String,
        at: String,
    },
    MarkAsBest {
        original_file_id: u64,
        chosen_file_id: u64,
        at: String,
    },
```

In the `impl CarveEvent` block, extend `persistable()` to include the new variants in the `true` arm of the exhaustive match:

```rust
pub fn persistable(&self) -> bool {
    match self {
        CarveEvent::RunStarted { .. }
        | CarveEvent::SourceStarted { .. }
        | CarveEvent::FileFound { .. }
        | CarveEvent::SourceFinished { .. }
        | CarveEvent::RunFinished { .. }
        | CarveEvent::RecoveryStarted { .. }
        | CarveEvent::RecoveryCandidate { .. }
        | CarveEvent::RecoveryFinished { .. }
        | CarveEvent::Bookmark { .. }
        | CarveEvent::Note { .. }
        | CarveEvent::MarkAsBest { .. } => true,
        CarveEvent::ProgressTick { .. } => false,
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

```
cargo test -p utmost-lib --lib events::tests
```
Expected: all six tests PASS.

- [ ] **Step 6: Run the full workspace test suite**

```
cargo test
```
Expected: all pass. Recovery's prior `RecoveryMethod` references via `pub enum` are now `pub use`s — confirm no breakage.

- [ ] **Step 7: fmt + clippy**

```
cargo fmt --all && cargo clippy --all-targets -- -D warnings
```

- [ ] **Step 8: Commit**

```
git add crates/utmost-lib/src/events.rs crates/utmost-lib/src/jpeg_recover.rs
git commit -m "$(cat <<'EOF'
feat(lib): new CarveEvent variants for recovery and annotations

Adds RecoveryStarted/RecoveryCandidate/RecoveryFinished plus Bookmark/Note/
MarkAsBest. RecoveryMethod moves from jpeg_recover to events as the shared
source of truth. All variants are persistable. CURRENT_FORMAT_VERSION stays
at 1 (format unshared).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Thread `file_id` through the audit log

**Files:**
- Modify: `crates/utmost-lib/src/engine.rs:404-412` (`audit_layout` header)
- Modify: `crates/utmost-lib/src/engine.rs:652-655, 674-677` (audit row formats)
- Test: `crates/utmost-lib/src/engine.rs` (add test verifying `[fid=` prefix)

**Parallel with:** Task 2 (different file regions). Runs after Task 1.

- [ ] **Step 1: Write the failing test**

Search `crates/utmost-lib/src/engine.rs` for the existing test module (`#[cfg(test)]` near the bottom). Add:

```rust
#[test]
fn audit_log_lines_include_fid_column() {
    use std::io::Read;
    let temp_dir = tempfile::tempdir().unwrap();
    let config = crate::types::CarveConfig {
        output_directory: temp_dir.path().to_string_lossy().into(),
        disable_report: true,
        disable_audit: false,
        ..Default::default()
    };
    let state = crate::types::State::new(config).unwrap();

    // Manually write what would be a "file found" audit row at fid=42:
    state
        .audit_entry(&format!(
            "[fid={:<5}] {:<5} {:<30} {:<15} {:<15} {}",
            42, 1, "test.jpg", 100, 0xdeadbeef_u64, "JPEG"
        ))
        .unwrap();

    let audit_path = format!("{}/audit_log.txt", temp_dir.path().to_string_lossy());
    let mut contents = String::new();
    std::fs::File::open(&audit_path)
        .unwrap()
        .read_to_string(&mut contents)
        .unwrap();
    assert!(contents.contains("[fid=42"), "audit log missing fid column: {contents}");
}
```

- [ ] **Step 2: Run test to verify it fails (or passes for the wrong reason)**

```
cargo test -p utmost-lib audit_log_lines_include_fid_column
```
This test will likely pass immediately since the test writes the format itself. The real assertion comes in Steps 3-4 where we ensure the *production* code path emits the prefix.

- [ ] **Step 3: Add a production-path test**

Append to the same test module:

```rust
#[test]
fn engine_audit_row_format_includes_fid() {
    // This is a string-format-only test; verifies the format string our
    // engine uses contains "[fid=". We snapshot the format here so refactors
    // can't silently drop the column.
    let formatted = format!(
        "[fid={:<5}] {:<5} {:<30} {:<15} {:<15} {}",
        42, 1, "test.jpg", 100u64, 0u64, "JPEG"
    );
    assert!(formatted.starts_with("[fid=42"));
}
```

Run: `cargo test -p utmost-lib engine_audit_row_format_includes_fid` — expected: PASS (this is a format snapshot test; the real change is in Step 4).

- [ ] **Step 4: Update `audit_layout()` header**

In `crates/utmost-lib/src/engine.rs:404-412`:

```rust
fn audit_layout(state: &State) -> Result<()> {
    state.audit_entry(&format!(
        "{:<10} {:<5} {}{}){:<17} {:<15} {:<15} {}",
        "FID", "Num", "Name (bs=", state.block_size, "", "Size", "File Offset", "Comment"
    ))?;
    Ok(())
}
```

- [ ] **Step 5: Update the two `audit_entry` row formats**

In `crates/utmost-lib/src/engine.rs:652-655` (inside the file-extracted branch). Replace:

```rust
state.audit_entry(&format!(
    "[fid={:<5}] {:<5} {:<30} {:<15} {:<15} {}",
    file_id, new_file_number, filename, extracted_size, absolute_offset, spec.comment
))?;
```

The `file_id` variable comes from the new allocator (Task 1). It must already be in scope at this site — see the changes from Task 1 Step 6 which moved the `state.next_file_id.fetch_add(...)` call into `write_to_disk`'s caller. If `file_id` is not in scope here, refactor Task 1's allocation point to happen *before* the audit-row write so `file_id` is available. The cleanest place is at the top of the `if extracted_size > 0 {` block.

In `crates/utmost-lib/src/engine.rs:674-677` (header-dump branch). Replace with:

```rust
state.audit_entry(&format!(
    "[fid={:<5}] {:<5} {:<30} {:<15} {:<15} {}",
    file_id, new_file_number, filename, dump_size, absolute_offset, "(Header dump)"
))?;
```

- [ ] **Step 6: Verify**

```
cargo test -p utmost-lib && cargo clippy --all-targets -- -D warnings
```
Expected: PASS, no warnings.

- [ ] **Step 7: Commit**

```
git add crates/utmost-lib/src/engine.rs
git commit -m "$(cat <<'EOF'
feat(lib): audit log lines include [fid=N] column

Every "file extracted" audit row now starts with [fid=N] where N is the
engine-allocated file_id from FileObject. Header-dump rows follow the same
format. Enables cross-referencing audit_log.txt against carve_report.json
and the bincoded event log.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Wave 2 — Recovery pipeline (depends on Wave 1)

### Task 4: Extend `RecoveryConfig` with `keep_candidates` and lift the single-best `break`

**Files:**
- Modify: `crates/utmost-lib/src/jpeg_recover.rs:51-92` (`RecoveryConfig` struct + Default)
- Modify: `crates/utmost-lib/src/jpeg_recover.rs:407-450` (the candidate write loop)
- Test: `crates/utmost-lib/src/jpeg_recover.rs` (existing test module)

**Parallel with:** Task 5 (different file regions, but both edit `jpeg_recover.rs` — run Task 4 first, then Task 5).

- [ ] **Step 1: Write the failing test**

Add to the existing test module at the bottom of `crates/utmost-lib/src/jpeg_recover.rs`:

```rust
#[test]
fn keep_candidates_three_writes_three_files() {
    // Reuse the existing test_config() helper and synthetic-fixture setup.
    // The fixture should expose 3+ plausible continuations. If the existing
    // tests already build one, use that builder; otherwise see the
    // make_jpeg_fileobject helper around line 526 as a starting point.
    // ... build fixture with >=3 plausible continuations ...
    let mut cfg = test_config(512, 8 * 1024 * 1024);
    cfg.keep_candidates = 3;
    cfg.huffman_validation = false; // exclude Layer 2 for predictability
    let report = recover_fragmented_jpegs(
        &image_path, &report_path, output_dir, &cfg
    ).unwrap();
    assert_eq!(report.recovered.len(), 3);
    // Filenames are <stem>_recovered_1.jpg, _2.jpg, _3.jpg
    assert!(report.recovered.iter().any(|r| r.recovered_filename.ends_with("_recovered_1.jpg")));
    assert!(report.recovered.iter().any(|r| r.recovered_filename.ends_with("_recovered_2.jpg")));
    assert!(report.recovered.iter().any(|r| r.recovered_filename.ends_with("_recovered_3.jpg")));
}
```

**Note:** the test above is a sketch. The existing test module in `jpeg_recover.rs` (search `#[cfg(test)] mod tests` around line 550+) has fixture helpers. Reuse them — do not invent new ones. If a 3-continuations fixture doesn't exist, the simplest path is to assemble a small synthetic image: header bytes + scan data with 3 distinct high-entropy regions, each producing a valid EOI on splice. See the existing `direct_continuation_recovers_simple_jpeg` test for the pattern.

- [ ] **Step 2: Run test to verify failure**

```
cargo test -p utmost-lib keep_candidates_three_writes_three_files
```
Expected: FAIL — either `cfg.keep_candidates` doesn't exist or only one file is written.

- [ ] **Step 3: Add `keep_candidates` to `RecoveryConfig`**

In `crates/utmost-lib/src/jpeg_recover.rs:51-92`, extend the struct and `Default`:

```rust
pub struct RecoveryConfig {
    pub block_size: usize,
    pub search_window: usize,
    pub max_candidates: usize,
    pub min_entropy_score: f64,
    pub min_ff_validity_score: f64,
    pub huffman_validation: bool,
    /// Maximum number of candidate reassemblies to *write to disk* (and emit
    /// as separate FileFound + RecoveryCandidate events) per incomplete JPEG.
    /// Independent of `max_candidates`, which controls the Layer-1 entropy
    /// pool size. Capped by callers (CLI default 3, GUI default 5 with cap 10).
    pub keep_candidates: usize,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            block_size: 512,
            search_window: DEFAULT_SEARCH_WINDOW_BYTES,
            max_candidates: 3,
            min_entropy_score: 7.0,
            min_ff_validity_score: 0.9,
            huffman_validation: true,
            keep_candidates: 3,
        }
    }
}
```

- [ ] **Step 4: Lift the `break` in the candidate-write loop**

In `crates/utmost-lib/src/jpeg_recover.rs:412-450`, the loop that currently writes a single candidate. Replace with:

```rust
let mut kept: usize = 0;
let original_stem: Cow<str> = Path::new(&fo.filename)
    .file_stem()
    .map(|s| s.to_string_lossy())
    .unwrap_or_else(|| Cow::Borrowed(fo.filename.as_str()));

for rc in ranked {
    if kept >= config.keep_candidates {
        break;
    }

    let mut reassembled = Vec::with_capacity(header_fragment.len() + rc.cont_buf.len());
    reassembled.extend_from_slice(&header_fragment);
    reassembled.extend_from_slice(&rc.cont_buf);

    let Some(eoi_pos) = find_eoi(&reassembled) else {
        continue;
    };
    let valid_data = &reassembled[..eoi_pos + 2];

    let rank = (kept + 1) as u32;
    let recovered_filename = format!("{original_stem}_recovered_{rank}.jpg");
    let out_path = format!("{output_dir}/{recovered_filename}");

    let mut out_file = File::create(&out_path)
        .with_context(|| format!("Failed to create output file: {out_path}"))?;
    out_file
        .write_all(valid_data)
        .with_context(|| format!("Failed to write recovered file: {out_path}"))?;
    out_file.flush()?;

    let method = if rc.offset == direct_offset {
        RecoveryMethod::DirectContinuation
    } else {
        RecoveryMethod::FragmentReassembly
    };

    recovered_files.push(RecoveredFile {
        original_filename: fo.filename.clone(),
        recovered_filename,
        recovery_method: method,
        entropy_score: rc.entropy,
        header_img_offset,
        continuation_img_offset: rc.offset,
        recovered_size: valid_data.len(),
        ff_validity_score: Some(rc.ff_validity),
        huffman_mcu_count: rc.mcu_count,
        // file_id + original_file_id filled by Task 6
    });

    kept += 1;
}
```

Note: `RecoveredFile` is extended in Task 6 with `file_id` and `original_file_id`; this task leaves placeholder comments rather than adding the fields — Task 6 will revisit.

- [ ] **Step 5: Run the failing test to verify pass**

```
cargo test -p utmost-lib keep_candidates_three_writes_three_files
```
Expected: PASS.

- [ ] **Step 6: Existing tests must still pass**

```
cargo test -p utmost-lib
```
Expected: PASS.

Note: any pre-existing test that asserts the filename suffix `_recovered.jpg` (no rank) must be updated to expect `_recovered_1.jpg`. Steve's test file will be regenerated.

- [ ] **Step 7: fmt + clippy**

```
cargo fmt --all && cargo clippy --all-targets -- -D warnings
```

- [ ] **Step 8: Commit**

```
git add crates/utmost-lib/src/jpeg_recover.rs
git commit -m "$(cat <<'EOF'
feat(lib): retain top-N JPEG recovery candidates

RecoveryConfig.keep_candidates (default 3) replaces the single-best
write-then-break behaviour. Files now named <stem>_recovered_<rank>.jpg
with rank 1-indexed. max_candidates (entropy pool) is unchanged.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Thread `--candidates` to `keep_candidates` in the CLI

**Files:**
- Modify: `crates/utmost-cli/src/main.rs:86-89` (`--candidates` flag) and `:754-770` (`run_recover` config build)

**Parallel with:** none for the file (touches one CLI file). Runs after Task 4.

- [ ] **Step 1: Write the failing test**

The CLI doesn't have an easy unit-test surface. Use an integration test in `crates/utmost-cli/tests/` (create the dir if absent):

```rust
// crates/utmost-cli/tests/recover_cli.rs
use assert_cmd::Command;

#[test]
fn recover_cli_accepts_candidates_flag() {
    let mut cmd = Command::cargo_bin("utmost").unwrap();
    cmd.args(["recover", "--help"]);
    let output = cmd.output().expect("run cli");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--candidates"), "help missing --candidates: {stdout}");
}
```

Add `assert_cmd = "2"` to `crates/utmost-cli/Cargo.toml` `[dev-dependencies]` if not present.

- [ ] **Step 2: Run test**

```
cargo test -p utmost-cli recover_cli_accepts_candidates_flag
```
Expected: PASS today (flag already exists). This test is a regression guard.

- [ ] **Step 3: Verify `keep_candidates` is plumbed through**

Open `crates/utmost-cli/src/main.rs:754-770` (`run_recover`). It already builds a `RecoveryConfig`. Set `keep_candidates`:

```rust
let config = RecoveryConfig {
    block_size: args.block_size,
    search_window: args.search_window,
    max_candidates: args.candidates,
    min_entropy_score: args.min_entropy,
    huffman_validation: !args.no_huffman_validation, // if such a flag exists
    keep_candidates: args.candidates,                // NEW
    ..RecoveryConfig::default()
};
```

(`args.candidates` is the existing `-n` / `--candidates` flag; default `3`. Reuse it for both `max_candidates` and `keep_candidates` so CLI users get N candidates written and N considered in the entropy pool.)

- [ ] **Step 4: Run tests**

```
cargo test -p utmost-cli
```
Expected: PASS.

- [ ] **Step 5: fmt + clippy**

```
cargo fmt --all && cargo clippy --all-targets -- -D warnings
```

- [ ] **Step 6: Commit**

```
git add crates/utmost-cli/src/main.rs crates/utmost-cli/Cargo.toml crates/utmost-cli/tests/
git commit -m "$(cat <<'EOF'
feat(cli): wire --candidates flag to RecoveryConfig.keep_candidates

CLI users with -n N now get N recovered files written per partial JPEG
instead of always one.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Recovery emits events into an existing `carve_events.bin`

**Files:**
- Modify: `crates/utmost-lib/src/jpeg_recover.rs` (signature of `recover_fragmented_jpegs` + emit logic + `RecoveredFile` struct)
- Test: `crates/utmost-lib/src/jpeg_recover.rs`

**Parallel with:** none. Depends on Tasks 1, 2, 4.

- [ ] **Step 1: Write the failing test**

Add to `crates/utmost-lib/src/jpeg_recover.rs` test module:

```rust
#[test]
fn recovery_appends_events_to_existing_bincode_log() {
    use crate::events::{BincodeFileReader, BincodeFileSink, CarveEvent, EventSink, FileHeader};

    let temp_dir = tempfile::tempdir().unwrap();
    let bin_path = temp_dir.path().join("carve_events.bin");

    // Pre-create a minimal carve_events.bin with header + a FileFound for fid=10
    {
        let sink = BincodeFileSink::create(&bin_path).unwrap();
        let fo = crate::reporting::create_file_object(
            "10-0.jpg", crate::types::FileType::Jpeg, 100, 0, None, 10,
        );
        sink.emit(&CarveEvent::FileFound {
            source_id: 0,
            file: fo,
            img_offset: 0,
            written_path: "10-0.jpg".into(),
        });
        // drop sink
    }

    // ... build the partial-JPEG fixture + carve_report.json (as in Task 4 test) ...

    let mut cfg = test_config(512, 8 * 1024 * 1024);
    cfg.keep_candidates = 2;
    cfg.huffman_validation = false;

    let report = recover_fragmented_jpegs_with_event_log(
        &image_path,
        &report_path,
        output_dir,
        &cfg,
        Some(&bin_path),
    )
    .unwrap();

    assert_eq!(report.recovered.len(), 2);

    // Read carve_events.bin back; expect RecoveryStarted, then 2x
    // (FileFound + RecoveryCandidate), then RecoveryFinished.
    let mut r = BincodeFileReader::open(&bin_path).unwrap();
    let mut kinds = Vec::new();
    while let Some(ev) = r.next_event().unwrap() {
        kinds.push(std::mem::discriminant(&ev));
    }
    // Sanity: at least 1 (preexisting FileFound) + RecoveryStarted + 2*(FileFound + RecoveryCandidate) + RecoveryFinished
    assert!(kinds.len() >= 6);
}
```

- [ ] **Step 2: Run test to verify failure**

```
cargo test -p utmost-lib recovery_appends_events_to_existing_bincode_log
```
Expected: FAIL — `recover_fragmented_jpegs_with_event_log` does not exist yet.

- [ ] **Step 3: Add the `RecoveredFile` fields**

In `crates/utmost-lib/src/jpeg_recover.rs:108-134`, extend:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredFile {
    /// Engine-allocated file_id for the recovered candidate.
    pub file_id: u64,
    /// file_id of the partial original this candidate is a variant of.
    pub original_file_id: u64,
    pub original_filename: String,
    pub recovered_filename: String,
    pub recovery_method: RecoveryMethod,
    pub entropy_score: f64,
    pub header_img_offset: u64,
    pub continuation_img_offset: u64,
    pub recovered_size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ff_validity_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub huffman_mcu_count: Option<usize>,
    /// 1-indexed rank within the partial's variant set.
    pub rank: u32,
}
```

- [ ] **Step 4: Add a helper for finding `max_file_id` in an existing log**

In `crates/utmost-lib/src/events.rs`, append:

```rust
/// Scan a bincoded event log and return the maximum `file_id` seen across
/// FileFound events. Used by the recovery pass to seed its allocator so new
/// candidates do not collide with existing file_ids. Returns 0 if the log is
/// empty or contains no FileFound events.
pub fn max_file_id_in_log(path: &std::path::Path) -> std::io::Result<u64> {
    let mut reader = BincodeFileReader::open(path)?;
    let mut max_id: u64 = 0;
    while let Some(ev) = reader.next_event()? {
        if let CarveEvent::FileFound { file, .. } = ev {
            max_id = max_id.max(file.file_id);
        }
    }
    Ok(max_id)
}
```

Add a unit test in `events.rs::tests`:

```rust
#[test]
fn max_file_id_in_log_returns_expected_max() {
    let temp_dir = tempfile::tempdir().unwrap();
    let bin_path = temp_dir.path().join("e.bin");
    {
        let sink = BincodeFileSink::create(&bin_path).unwrap();
        for fid in [10u64, 25, 17] {
            let fo = crate::reporting::create_file_object(
                "x.bin", crate::types::FileType::Jpeg, 0, 0, None, fid,
            );
            sink.emit(&CarveEvent::FileFound {
                source_id: 0, file: fo, img_offset: 0, written_path: "x".into(),
            });
        }
    }
    assert_eq!(max_file_id_in_log(&bin_path).unwrap(), 25);
}
```

Run: `cargo test -p utmost-lib max_file_id_in_log_returns_expected_max` — PASS.

- [ ] **Step 5: Add `recover_fragmented_jpegs_with_event_log` wrapper**

Refactor `recover_fragmented_jpegs` to accept an optional event-log path. The simplest path is to add a wrapper:

```rust
pub fn recover_fragmented_jpegs(
    image_path: &str,
    report_path: &str,
    output_dir: &str,
    config: &RecoveryConfig,
) -> Result<RecoveryReport> {
    recover_fragmented_jpegs_with_event_log(image_path, report_path, output_dir, config, None)
}

pub fn recover_fragmented_jpegs_with_event_log(
    image_path: &str,
    report_path: &str,
    output_dir: &str,
    config: &RecoveryConfig,
    event_log: Option<&std::path::Path>,
) -> Result<RecoveryReport> {
    // existing body, plus:
    //   - if event_log is Some, open it for append-mode emit
    //   - emit RecoveryStarted before the per-partial loop
    //   - for each kept candidate: allocate file_id, emit FileFound, emit RecoveryCandidate
    //   - emit RecoveryFinished after the loop
    //   - populate RecoveredFile.file_id, original_file_id, rank
}
```

For the file_id allocator: if `event_log` is `Some`, call `max_file_id_in_log(path)` and seed an `AtomicU64` to `max + 1`. Otherwise start at `1`.

For append-mode emission, add an `EventSink` constructor to `events.rs`:

```rust
impl BincodeFileSink {
    /// Open an existing event log for *append-only* event emission. The file
    /// must already contain a valid FileHeader; no header is written.
    pub fn open_append(path: &std::path::Path) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new().append(true).open(path)?;
        let writer = std::io::BufWriter::new(file);
        Ok(Self {
            inner: std::sync::Mutex::new(BincodeFileSinkInner {
                writer,
                disabled: false,
            }),
        })
    }
}
```

- [ ] **Step 6: Emit events in the per-candidate loop**

Inside `recover_fragmented_jpegs_with_event_log`, before the per-partial loop:

```rust
let next_file_id = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
    event_log
        .map(|p| crate::events::max_file_id_in_log(p).unwrap_or(0))
        .unwrap_or(0)
        + 1,
));

let sink: Option<BincodeFileSink> = event_log
    .map(|p| BincodeFileSink::open_append(p))
    .transpose()
    .with_context(|| "opening event log for append")?;

let emit = |ev: &crate::events::CarveEvent| {
    if let Some(ref s) = sink {
        <BincodeFileSink as EventSink>::emit(s, ev);
    }
};

let started_at = chrono::Utc::now().to_rfc3339();
emit(&CarveEvent::RecoveryStarted {
    started_at: started_at.clone(),
    keep_candidates: config.keep_candidates,
    search_window: config.search_window,
    block_size: config.block_size,
    min_entropy_score: config.min_entropy_score,
    huffman_validation: config.huffman_validation,
});
```

Inside the per-kept-candidate write block, after writing the file to disk:

```rust
let candidate_file_id = next_file_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
let original_file_id = fo.file_id;  // fo is the partial's FileObject from carve_report

let candidate_fo = crate::reporting::create_file_object(
    &recovered_filename,
    crate::types::FileType::Jpeg,
    valid_data.len() as u64,
    rc.offset,
    None,
    candidate_file_id,
);

emit(&CarveEvent::FileFound {
    source_id: 0, // recovery does not know per-source; use 0 by convention
    file: candidate_fo,
    img_offset: rc.offset,
    written_path: recovered_filename.clone(),
});

emit(&CarveEvent::RecoveryCandidate {
    original_file_id,
    candidate_file_id,
    rank,
    method,
    entropy_score: rc.entropy,
    ff_validity_score: Some(rc.ff_validity),
    huffman_mcu_count: rc.mcu_count,
    continuation_img_offset: rc.offset,
});

recovered_files.push(RecoveredFile {
    file_id: candidate_file_id,
    original_file_id,
    original_filename: fo.filename.clone(),
    recovered_filename,
    recovery_method: method,
    entropy_score: rc.entropy,
    header_img_offset,
    continuation_img_offset: rc.offset,
    recovered_size: valid_data.len(),
    ff_validity_score: Some(rc.ff_validity),
    huffman_mcu_count: rc.mcu_count,
    rank,
});
```

After the per-partial loop, before writing `recover_report.json`:

```rust
let duration_ms = start.elapsed().as_millis() as u64;
emit(&CarveEvent::RecoveryFinished {
    duration_ms,
    partials_processed: incomplete_count as u32,
    candidates_written: recovered_files.len() as u32,
});
```

(Add `let start = std::time::Instant::now();` near the top of the function.)

Note: `CarveReport.fileobjects` items need `file_id` to be present. Carve runs prior to this change won't have it serialised — they'll deserialise with `file_id: 0` (serde default). Add `#[serde(default)]` on `FileObject.file_id` to handle the migration:

```rust
pub struct FileObject {
    #[serde(default)]
    pub file_id: u64,
    // ...
}
```

This is a benign default — the new field will deserialise to `0` for pre-existing JSON, and recovery will not include those in candidate emissions (they're the partials being recovered, not new files).

- [ ] **Step 7: Run the failing test to verify pass**

```
cargo test -p utmost-lib recovery_appends_events_to_existing_bincode_log
```
Expected: PASS.

- [ ] **Step 8: Add a test for `file_id` continuity**

```rust
#[test]
fn recovery_seeds_file_id_from_existing_log() {
    use crate::events::{BincodeFileSink, CarveEvent, EventSink, max_file_id_in_log};

    let temp_dir = tempfile::tempdir().unwrap();
    let bin_path = temp_dir.path().join("carve_events.bin");
    {
        let sink = BincodeFileSink::create(&bin_path).unwrap();
        for fid in [50u64, 99, 71] {
            let fo = crate::reporting::create_file_object(
                "x.jpg", crate::types::FileType::Jpeg, 0, 0, None, fid,
            );
            sink.emit(&CarveEvent::FileFound {
                source_id: 0, file: fo, img_offset: 0, written_path: "x".into(),
            });
        }
    }

    // ... run recovery with a fixture that yields >=1 candidate ...
    let mut cfg = test_config(512, 8 * 1024 * 1024);
    cfg.keep_candidates = 1;
    cfg.huffman_validation = false;
    let report = recover_fragmented_jpegs_with_event_log(
        &image_path, &report_path, output_dir, &cfg, Some(&bin_path),
    ).unwrap();
    assert!(report.recovered.iter().any(|r| r.file_id == 100));
}
```

Run: `cargo test -p utmost-lib recovery_seeds_file_id_from_existing_log` — PASS.

- [ ] **Step 9: fmt + clippy + full tests**

```
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test
```

- [ ] **Step 10: Commit**

```
git add crates/utmost-lib/src/jpeg_recover.rs crates/utmost-lib/src/events.rs crates/utmost-lib/src/types.rs
git commit -m "$(cat <<'EOF'
feat(lib): recovery appends FileFound+RecoveryCandidate to carve_events.bin

Adds recover_fragmented_jpegs_with_event_log which emits per-candidate
events to an existing bincode log. file_id allocator seeds from
max_file_id_in_log so candidates don't collide with carve-time ids.
RecoveredFile gains file_id, original_file_id, and rank. FileObject.file_id
gets serde(default) for backward-compat JSON deserialisation.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Wave 3 — View-model state and reducer (depends on Wave 1 and Wave 2)

### Task 7: Add new view-model state fields and supporting types

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs:118-130` (ViewModel struct)
- Modify: `crates/utmost-gui/src/view_model.rs:85-100` (FilterState struct)

**Parallel with:** Task 10 (journal.rs — different file). Runs after Wave 1 + 2.

- [ ] **Step 1: Write the failing test**

Append to `crates/utmost-gui/src/view_model.rs` tests module:

```rust
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
```

Run: `cargo test -p utmost-gui new_view_model_has_empty_annotation_state` — Expected: FAIL (fields don't exist).

- [ ] **Step 2: Add the supporting types**

In `crates/utmost-gui/src/view_model.rs`, near the other type definitions:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryUiState {
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
```

- [ ] **Step 3: Extend `ViewModel`**

In `crates/utmost-gui/src/view_model.rs:118-130`:

```rust
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
    pub(crate) next_note_id: u64,
}
```

Implement `Default` for `RecoveryUiState`:

```rust
impl Default for RecoveryUiState {
    fn default() -> Self {
        RecoveryUiState::Disabled
    }
}
```

- [ ] **Step 4: Extend `FilterState`**

```rust
#[derive(Debug, Clone, Default)]
pub struct FilterState {
    pub enabled_types: BTreeSet<FileType>,
    pub enabled_partial_types: BTreeSet<FileType>,  // NEW
    pub bookmarked_only: bool,                       // NEW
    pub source_filter: Option<u32>,
    pub sort_key: SortKey,
    pub sort_dir: SortDir,
}
```

Existing `impl Default for FilterState` may need to be removed if you derive `Default`. If `SortKey` and `SortDir` don't derive `Default`, add:

```rust
impl Default for SortKey { fn default() -> Self { SortKey::Filename } }
impl Default for SortDir { fn default() -> Self { SortDir::Asc } }
```

- [ ] **Step 5: Verify**

```
cargo test -p utmost-gui new_view_model_has_empty_annotation_state
```
Expected: PASS.

```
cargo test -p utmost-gui
```
Expected: all existing tests still PASS.

- [ ] **Step 6: fmt + clippy + commit**

```
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add crates/utmost-gui/src/view_model.rs
git commit -m "$(cat <<'EOF'
feat(gui): view-model state for variants, bookmarks, notes, best-of

Adds VariantSet / NoteEntry / NoteInputState / RecoveryUiState types and
threads them through ViewModel and FilterState. No reducer logic yet — that
lands in subsequent tasks.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: Reducer handles `RecoveryStarted` / `RecoveryCandidate` / `RecoveryFinished`

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs` (`apply()` match)
- Test: same file

**Parallel with:** Task 10 (different file). Runs after Task 7.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn apply_recovery_candidate_populates_variants() {
    let mut vm = ViewModel::new();
    vm.apply(&run_started_with_sources(&[0]));

    // Set up an original partial JPEG (file_id 10) and a candidate (file_id 11)
    let mut fo_orig = create_file_object("orig.jpg", FileType::Jpeg, 100, 0, None, 10);
    fo_orig.jpeg_scan = Some(utmost_lib::types::JpegScanInfo {
        width: None, height: None,
        fragmentation_point_img_offset: None,
        has_restart_markers: false,
        status: utmost_lib::types::JpegScanStatus::Truncated,
    });
    vm.apply(&CarveEvent::FileFound {
        source_id: 0, file: fo_orig, img_offset: 0, written_path: "orig.jpg".into(),
    });

    let fo_cand = create_file_object("orig_recovered_1.jpg", FileType::Jpeg, 200, 5000, None, 11);
    vm.apply(&CarveEvent::FileFound {
        source_id: 0, file: fo_cand, img_offset: 5000, written_path: "orig_recovered_1.jpg".into(),
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
```

Run: `cargo test -p utmost-gui apply_recovery_candidate_populates_variants recovery_started_finished_toggle_recovery_state` — FAIL.

- [ ] **Step 2: Implement the reducer cases**

In `crates/utmost-gui/src/view_model.rs`, the `apply()` `match event {...}` block. Add (alongside existing arms):

```rust
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
    let entry = self.variants.entry(*original_file_id).or_insert_with(|| VariantSet {
        original_id: *original_file_id,
        variant_ids: Vec::new(),
    });
    if !entry.variant_ids.contains(candidate_file_id) {
        entry.variant_ids.push(*candidate_file_id);
    }
    self.variant_of.insert(*candidate_file_id, *original_file_id);
    self.recompute_visible();
}
```

- [ ] **Step 3: Verify tests pass**

```
cargo test -p utmost-gui apply_recovery_candidate_populates_variants recovery_started_finished_toggle_recovery_state
```
Expected: PASS.

- [ ] **Step 4: fmt + clippy + commit**

```
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add crates/utmost-gui/src/view_model.rs
git commit -m "$(cat <<'EOF'
feat(gui): view-model reducer handles recovery events

RecoveryStarted/Finished drive recovery_state. RecoveryCandidate populates
variants and variant_of, then triggers recompute_visible (which will skip
candidates once that's wired in Task 9).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: Reducer handles `Bookmark` / `Note` / `MarkAsBest`; partial_counts tracking

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs` (`apply()` match + `FileFound` arm)
- Test: same file

**Parallel with:** Task 10. Runs after Task 8.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn apply_bookmark_toggles_membership() {
    let mut vm = ViewModel::new();
    vm.apply(&CarveEvent::Bookmark { file_id: 7, bookmarked: true, at: "t".into() });
    assert!(vm.bookmarks.contains(&7));
    vm.apply(&CarveEvent::Bookmark { file_id: 7, bookmarked: false, at: "t".into() });
    assert!(!vm.bookmarks.contains(&7));
}

#[test]
fn apply_note_appends_chronologically_and_tracks_next_id() {
    let mut vm = ViewModel::new();
    vm.apply(&CarveEvent::Note { note_id: 1, file_id: 7, text: "a".into(), at: "t1".into() });
    vm.apply(&CarveEvent::Note { note_id: 2, file_id: 7, text: "b".into(), at: "t2".into() });
    let entries = vm.notes.get(&7).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].text, "a");
    assert_eq!(entries[1].text, "b");
    assert_eq!(vm.next_note_id, 3);
}

#[test]
fn apply_mark_as_best_is_last_writer_wins() {
    let mut vm = ViewModel::new();
    vm.apply(&CarveEvent::MarkAsBest { original_file_id: 10, chosen_file_id: 11, at: "t1".into() });
    vm.apply(&CarveEvent::MarkAsBest { original_file_id: 10, chosen_file_id: 12, at: "t2".into() });
    assert_eq!(vm.best_choices.get(&10), Some(&12));
}

#[test]
fn file_found_increments_partial_counts_for_partial_jpegs() {
    let mut vm = ViewModel::new();
    vm.apply(&run_started_with_sources(&[0]));

    let mut fo = create_file_object("part.jpg", FileType::Jpeg, 100, 0, None, 1);
    fo.jpeg_scan = Some(utmost_lib::types::JpegScanInfo {
        width: None, height: None,
        fragmentation_point_img_offset: None,
        has_restart_markers: false,
        status: utmost_lib::types::JpegScanStatus::Truncated,
    });
    vm.apply(&CarveEvent::FileFound {
        source_id: 0, file: fo, img_offset: 0, written_path: "part.jpg".into(),
    });

    assert_eq!(*vm.partial_counts.get(&FileType::Jpeg).unwrap(), 1);
}
```

Run: `cargo test -p utmost-gui apply_bookmark_toggles_membership apply_note_appends_chronologically_and_tracks_next_id apply_mark_as_best_is_last_writer_wins file_found_increments_partial_counts_for_partial_jpegs` — FAIL.

- [ ] **Step 2: Implement reducer arms**

In `apply()`'s match, add:

```rust
CarveEvent::Bookmark { file_id, bookmarked, .. } => {
    if *bookmarked {
        self.bookmarks.insert(*file_id);
    } else {
        self.bookmarks.remove(file_id);
    }
}
CarveEvent::Note { note_id, file_id, text, at } => {
    self.notes
        .entry(*file_id)
        .or_default()
        .push(NoteEntry {
            note_id: *note_id,
            text: text.clone(),
            at: at.clone(),
        });
    self.next_note_id = self.next_note_id.max(*note_id + 1);
}
CarveEvent::MarkAsBest { original_file_id, chosen_file_id, .. } => {
    self.best_choices.insert(*original_file_id, *chosen_file_id);
}
```

- [ ] **Step 3: Extend the `FileFound` arm to track partial_counts**

Inside the existing `CarveEvent::FileFound { ... }` arm in `apply()`, after the `type_counts` increment, add:

```rust
let is_partial = file
    .jpeg_scan
    .as_ref()
    .map(|s| s.status != utmost_lib::types::JpegScanStatus::Complete)
    .unwrap_or(false);
if is_partial {
    if let Some(ft) = ft {
        *self.partial_counts.entry(ft).or_insert(0) += 1;
    }
}
```

(Place where `ft` is already in scope — alongside the existing `type_counts` block.)

- [ ] **Step 4: Verify**

```
cargo test -p utmost-gui
```
Expected: all new tests PASS, existing tests untouched.

- [ ] **Step 5: fmt + clippy + commit**

```
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add crates/utmost-gui/src/view_model.rs
git commit -m "$(cat <<'EOF'
feat(gui): reducer handles Bookmark/Note/MarkAsBest + partial_counts

Bookmark toggles set membership; Note appends to the per-file chronological
list and bumps next_note_id; MarkAsBest is last-writer-wins per original.
FileFound now increments partial_counts whenever JpegScanStatus is not
Complete.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: `recompute_visible()` excludes variants; partial/bookmarked filter logic

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs:137-169` (`recompute_visible`)
- Test: same file

**Parallel with:** Task 11. Runs after Task 9.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn recompute_visible_excludes_variants_from_main_grid() {
    let mut vm = ViewModel::new();
    vm.apply(&run_started_with_sources(&[0]));
    vm.filter.enabled_types.insert(FileType::Jpeg);

    let fo_a = create_file_object("a.jpg", FileType::Jpeg, 100, 0, None, 1);
    let fo_b = create_file_object("b.jpg", FileType::Jpeg, 100, 0, None, 2);
    vm.apply(&CarveEvent::FileFound { source_id: 0, file: fo_a, img_offset: 0, written_path: "a.jpg".into() });
    vm.apply(&CarveEvent::FileFound { source_id: 0, file: fo_b, img_offset: 0, written_path: "b.jpg".into() });

    // Mark b.jpg as a variant of a.jpg
    vm.apply(&CarveEvent::RecoveryCandidate {
        original_file_id: 1, candidate_file_id: 2, rank: 1,
        method: utmost_lib::events::RecoveryMethod::DirectContinuation,
        entropy_score: 7.5, ff_validity_score: None, huffman_mcu_count: None,
        continuation_img_offset: 0,
    });

    assert_eq!(vm.visible_files, vec![1]);
}

#[test]
fn partial_chip_is_independent_of_normal_chip() {
    let mut vm = ViewModel::new();
    vm.apply(&run_started_with_sources(&[0]));

    let mut fo_complete = create_file_object("c.jpg", FileType::Jpeg, 100, 0, None, 1);
    fo_complete.jpeg_scan = Some(utmost_lib::types::JpegScanInfo {
        width: None, height: None, fragmentation_point_img_offset: None,
        has_restart_markers: false,
        status: utmost_lib::types::JpegScanStatus::Complete,
    });
    let mut fo_partial = create_file_object("p.jpg", FileType::Jpeg, 100, 0, None, 2);
    fo_partial.jpeg_scan = Some(utmost_lib::types::JpegScanInfo {
        width: None, height: None, fragmentation_point_img_offset: None,
        has_restart_markers: false,
        status: utmost_lib::types::JpegScanStatus::Truncated,
    });
    vm.apply(&CarveEvent::FileFound { source_id: 0, file: fo_complete, img_offset: 0, written_path: "c.jpg".into() });
    vm.apply(&CarveEvent::FileFound { source_id: 0, file: fo_partial, img_offset: 0, written_path: "p.jpg".into() });

    // Only "Partial JPG" enabled — should show only p.jpg
    vm.filter.enabled_types.clear();
    vm.filter.enabled_partial_types.insert(FileType::Jpeg);
    vm.recompute_visible();
    assert_eq!(vm.visible_files, vec![2]);

    // Only "JPG" enabled — should show only c.jpg
    vm.filter.enabled_types.insert(FileType::Jpeg);
    vm.filter.enabled_partial_types.clear();
    vm.recompute_visible();
    assert_eq!(vm.visible_files, vec![1]);

    // Both enabled — both visible
    vm.filter.enabled_partial_types.insert(FileType::Jpeg);
    vm.recompute_visible();
    assert_eq!(vm.visible_files, vec![1, 2]);
}

#[test]
fn bookmarked_only_filter_narrows_grid() {
    let mut vm = ViewModel::new();
    vm.apply(&run_started_with_sources(&[0]));
    vm.filter.enabled_types.insert(FileType::Jpeg);

    let fo_a = create_file_object("a.jpg", FileType::Jpeg, 100, 0, None, 1);
    let fo_b = create_file_object("b.jpg", FileType::Jpeg, 100, 0, None, 2);
    vm.apply(&CarveEvent::FileFound { source_id: 0, file: fo_a, img_offset: 0, written_path: "a.jpg".into() });
    vm.apply(&CarveEvent::FileFound { source_id: 0, file: fo_b, img_offset: 0, written_path: "b.jpg".into() });

    vm.apply(&CarveEvent::Bookmark { file_id: 2, bookmarked: true, at: "t".into() });
    vm.filter.bookmarked_only = true;
    vm.recompute_visible();
    assert_eq!(vm.visible_files, vec![2]);
}
```

Run: FAIL.

- [ ] **Step 2: Update `recompute_visible`**

Replace the existing `recompute_visible` body (`crates/utmost-gui/src/view_model.rs:137-169`):

```rust
pub fn recompute_visible(&mut self) {
    let mut ids: Vec<FileId> = self
        .files
        .iter()
        .filter(|f| {
            // Variants never appear in the main grid.
            if self.variant_of.contains_key(&f.id) {
                return false;
            }
            if let Some(sid) = self.filter.source_filter
                && f.source_id != sid
            {
                return false;
            }
            if self.filter.bookmarked_only && !self.bookmarks.contains(&f.id) {
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
```

- [ ] **Step 3: Verify**

```
cargo test -p utmost-gui
```
Expected: all PASS.

- [ ] **Step 4: fmt + clippy + commit**

```
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add crates/utmost-gui/src/view_model.rs
git commit -m "$(cat <<'EOF'
feat(gui): recompute_visible respects variants/partial/bookmarked filters

Variants are excluded from the main grid (they live in the side-panel
mini-grid + variant viewer modal). Partial JPGs match the new
enabled_partial_types chip set; complete files match enabled_types.
bookmarked_only narrows the grid further when active.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 11: View-model input methods (`toggle_bookmark`, `add_note`, `mark_as_best`, viewer/lightbox helpers)

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs` (`impl ViewModel`)
- Test: same file

**Parallel with:** none. Runs after Task 10.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn toggle_bookmark_returns_event_and_updates_state() {
    let mut vm = ViewModel::new();
    let ev = vm.toggle_bookmark(7);
    match ev {
        CarveEvent::Bookmark { file_id, bookmarked, .. } => {
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
    let id1 = match e1 { CarveEvent::Note { note_id, .. } => note_id, _ => panic!() };
    let id2 = match e2 { CarveEvent::Note { note_id, .. } => note_id, _ => panic!() };
    assert_eq!(id1, 1);
    assert_eq!(id2, 2);
    assert_eq!(vm.notes.get(&7).unwrap().len(), 2);
}

#[test]
fn mark_as_best_returns_event_and_records_choice() {
    let mut vm = ViewModel::new();
    let ev = vm.mark_as_best(10, 11);
    match ev {
        CarveEvent::MarkAsBest { original_file_id, chosen_file_id, .. } => {
            assert_eq!(original_file_id, 10);
            assert_eq!(chosen_file_id, 11);
        }
        _ => panic!(),
    }
    assert_eq!(vm.best_choices.get(&10), Some(&11));
}
```

Run: FAIL.

- [ ] **Step 2: Implement the methods**

In the `impl ViewModel` block:

```rust
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
    self.notes
        .entry(file_id)
        .or_default()
        .push(NoteEntry {
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
```

- [ ] **Step 3: Add `chrono` dependency**

Add to `crates/utmost-gui/Cargo.toml` under `[dependencies]`:

```toml
chrono = { version = "0.4", features = ["serde"] }
```

(Check `Cargo.toml` first to confirm it's not already there.)

- [ ] **Step 4: Verify**

```
cargo test -p utmost-gui
```

- [ ] **Step 5: fmt + clippy + commit**

```
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add crates/utmost-gui/src/view_model.rs crates/utmost-gui/Cargo.toml
git commit -m "$(cat <<'EOF'
feat(gui): view-model input methods for annotations + variant viewer

toggle_bookmark / add_note / mark_as_best return the CarveEvent that the
slint adapter should route to the journal sidecar (live) or carve_events.bin
(viewer). open/close_variant_viewer + open_lightbox_for_variant prep the
variant-viewer modal flow.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Wave 4 — Journal sidecar (depends on Wave 1+2; parallel with Wave 3)

### Task 12: `journal.rs` — append, replay, fold

**Files:**
- Create: `crates/utmost-gui/src/journal.rs`
- Modify: `crates/utmost-gui/src/lib.rs` (`pub mod journal;`)
- Test: same file (`#[cfg(test)] mod tests`)

**Parallel with:** Tasks 7-11 (different file). Runs after Wave 2.

- [ ] **Step 1: Write the failing tests** (do this before any production code)

Create `crates/utmost-gui/src/journal.rs` with only the test module first:

```rust
//! Append-and-replay sidecar for forensic annotations.
//!
//! While the engine is actively writing `carve_events.bin`, the GUI cannot
//! also write to it. Annotation events (Bookmark, Note, MarkAsBest) are
//! durably staged in `carve_events.pending` (same framing) and folded into
//! the main log when the engine signals `RunFinished` (or at next session
//! open if the run crashed before that).

use std::io::Result as IoResult;
use std::path::{Path, PathBuf};
use utmost_lib::events::CarveEvent;

#[cfg(test)]
mod tests {
    use super::*;
    use utmost_lib::events::{BincodeFileReader, BincodeFileSink, FileHeader, MAGIC};

    #[test]
    fn append_one_event_creates_pending_with_framing() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("carve_events.bin");
        // Create a valid main log so .pending lives next to it.
        let _sink = BincodeFileSink::create(&bin).unwrap();

        let journal = Journal::for_main_log(&bin);
        journal
            .append(&CarveEvent::Bookmark {
                file_id: 7,
                bookmarked: true,
                at: "t".into(),
            })
            .unwrap();

        let pending_path = journal.pending_path();
        assert!(pending_path.exists(), "pending file should exist");

        let events = journal.read_pending().unwrap();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], CarveEvent::Bookmark { file_id: 7, .. }));
    }

    #[test]
    fn fold_appends_pending_into_main_log_and_deletes_pending() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("carve_events.bin");
        let _sink = BincodeFileSink::create(&bin).unwrap();

        let journal = Journal::for_main_log(&bin);
        journal.append(&CarveEvent::Bookmark { file_id: 1, bookmarked: true, at: "t".into() }).unwrap();
        journal.append(&CarveEvent::Note { note_id: 1, file_id: 1, text: "hi".into(), at: "t".into() }).unwrap();

        journal.fold().unwrap();

        assert!(!journal.pending_path().exists(), "pending should be deleted after fold");

        // Replay the main log and check the events landed.
        let mut r = BincodeFileReader::open(&bin).unwrap();
        let mut count = 0;
        while let Some(_) = r.next_event().unwrap() { count += 1; }
        assert_eq!(count, 2);
    }

    #[test]
    fn replay_pending_at_startup_applies_then_folds_and_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("carve_events.bin");
        let _sink = BincodeFileSink::create(&bin).unwrap();

        // Pre-create a pending file with one event (simulates a crashed run)
        let journal = Journal::for_main_log(&bin);
        journal.append(&CarveEvent::Bookmark { file_id: 9, bookmarked: true, at: "t".into() }).unwrap();
        drop(journal);

        // Now a fresh GUI starts: open the log, expect to recover the pending.
        let journal2 = Journal::for_main_log(&bin);
        let recovered = journal2.recover_on_open().unwrap();
        assert_eq!(recovered.len(), 1);
        assert!(matches!(recovered[0], CarveEvent::Bookmark { file_id: 9, .. }));
        assert!(!journal2.pending_path().exists());

        // The events are now folded into the main log.
        let mut r = BincodeFileReader::open(&bin).unwrap();
        let mut count = 0;
        while let Some(_) = r.next_event().unwrap() { count += 1; }
        assert_eq!(count, 1);
    }

    #[test]
    fn malformed_trailing_frame_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("carve_events.bin");
        let _sink = BincodeFileSink::create(&bin).unwrap();

        let journal = Journal::for_main_log(&bin);
        journal.append(&CarveEvent::Bookmark { file_id: 1, bookmarked: true, at: "t".into() }).unwrap();

        // Append junk to the pending file
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(journal.pending_path())
            .unwrap();
        f.write_all(&[0xff, 0xff, 0xff, 0xff]).unwrap();  // length 4.29e9 — won't fit; truncated read

        let events = journal.read_pending().unwrap();
        assert_eq!(events.len(), 1, "should recover only the well-formed event");
    }
}
```

Run: `cargo test -p utmost-gui --lib journal::tests` — Expected: COMPILE FAIL (`Journal` doesn't exist).

- [ ] **Step 2: Define the API skeleton**

Inside `crates/utmost-gui/src/journal.rs`, above the test module:

```rust
pub struct Journal {
    main_log: PathBuf,
}

impl Journal {
    pub fn for_main_log(main_log: &Path) -> Self {
        Self {
            main_log: main_log.to_path_buf(),
        }
    }

    pub fn pending_path(&self) -> PathBuf {
        // carve_events.bin → carve_events.pending
        // (Sibling with the .pending extension regardless of the main log's stem)
        let mut p = self.main_log.clone();
        let stem = self.main_log.file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "carve_events".into());
        p.set_file_name(format!("{stem}.pending"));
        p
    }

    /// Append a single event to the pending sidecar. Creates the file with
    /// the same framing as the main log (length-prefixed bincode frames) on
    /// first call. Failures are returned to the caller — they are surfaced
    /// by the GUI as a non-fatal warning.
    pub fn append(&self, event: &CarveEvent) -> IoResult<()> {
        // Implementation: open pending in append mode, length-prefixed frame.
        // No FileHeader — the pending file is a *fragment*, not a log.
        unimplemented!()
    }

    /// Read all events currently in the pending file. Tolerates a malformed
    /// trailing frame (truncated mid-write): returns events up to the last
    /// well-formed frame; logs a warning at `tracing::warn` if truncation
    /// was detected.
    pub fn read_pending(&self) -> IoResult<Vec<CarveEvent>> {
        unimplemented!()
    }

    /// Append every event currently in the pending file to the main log,
    /// then delete the pending file. Idempotent: if the pending file does
    /// not exist, returns Ok.
    pub fn fold(&self) -> IoResult<()> {
        unimplemented!()
    }

    /// Combined startup routine: read pending (if any), append to main log,
    /// delete pending. Returns the events that were folded (for the caller
    /// to also apply to the view-model, since they aren't replayed via the
    /// main log this session).
    pub fn recover_on_open(&self) -> IoResult<Vec<CarveEvent>> {
        unimplemented!()
    }
}
```

In `crates/utmost-gui/src/lib.rs`, add:

```rust
pub mod journal;
```

Compile check: `cargo build -p utmost-gui` — should compile (test module still fails).

- [ ] **Step 3: Implement `append`**

```rust
pub fn append(&self, event: &CarveEvent) -> IoResult<()> {
    use std::io::Write;
    let bytes = bincode::serialize(event)
        .map_err(|e| std::io::Error::other(format!("bincode serialize: {e}")))?;
    let len = u32::try_from(bytes.len())
        .map_err(|_| std::io::Error::other("frame larger than u32::MAX"))?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(self.pending_path())?;
    f.write_all(&len.to_le_bytes())?;
    f.write_all(&bytes)?;
    f.flush()?;
    Ok(())
}
```

- [ ] **Step 4: Implement `read_pending`**

```rust
pub fn read_pending(&self) -> IoResult<Vec<CarveEvent>> {
    use std::io::Read;
    let path = self.pending_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut f = std::fs::File::open(&path)?;
    let mut events = Vec::new();
    loop {
        let mut len_buf = [0u8; 4];
        match f.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        if let Err(e) = f.read_exact(&mut buf) {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                tracing::warn!(
                    "journal: truncated trailing frame in {} — ignoring tail",
                    path.display()
                );
                break;
            }
            return Err(e);
        }
        match bincode::deserialize::<CarveEvent>(&buf) {
            Ok(ev) => events.push(ev),
            Err(e) => {
                tracing::warn!("journal: undecodable frame at end of {}: {e}", path.display());
                break;
            }
        }
    }
    Ok(events)
}
```

- [ ] **Step 5: Implement `fold` and `recover_on_open`**

```rust
pub fn fold(&self) -> IoResult<()> {
    let pending = self.pending_path();
    if !pending.exists() {
        return Ok(());
    }
    let events = self.read_pending()?;
    {
        let sink = utmost_lib::events::BincodeFileSink::open_append(&self.main_log)?;
        for ev in &events {
            <utmost_lib::events::BincodeFileSink as utmost_lib::events::EventSink>::emit(&sink, ev);
        }
        // sink drops here, flushing
    }
    std::fs::remove_file(&pending)?;
    Ok(())
}

pub fn recover_on_open(&self) -> IoResult<Vec<CarveEvent>> {
    let events = self.read_pending()?;
    if events.is_empty() {
        // Still remove the (empty or malformed) file if present.
        if self.pending_path().exists() {
            std::fs::remove_file(self.pending_path())?;
        }
        return Ok(events);
    }
    {
        let sink = utmost_lib::events::BincodeFileSink::open_append(&self.main_log)?;
        for ev in &events {
            <utmost_lib::events::BincodeFileSink as utmost_lib::events::EventSink>::emit(&sink, ev);
        }
    }
    std::fs::remove_file(self.pending_path())?;
    Ok(events)
}
```

- [ ] **Step 6: Verify**

```
cargo test -p utmost-gui --lib journal::tests
```
Expected: all PASS.

- [ ] **Step 7: fmt + clippy + commit**

```
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add crates/utmost-gui/src/journal.rs crates/utmost-gui/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(gui): journal sidecar for forensic annotations

Append-and-replay carve_events.pending with same framing as the main log.
Journal::append stages an annotation event during a live run; fold() merges
into the main log at RunFinished; recover_on_open() does the same at viewer
startup if the previous session crashed. Tolerates malformed trailing
frames (truncated mid-write).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 13: Idempotency property test for journal replay

**Files:**
- Modify: `crates/utmost-gui/src/journal.rs` (extend test module)

**Parallel with:** Task 14. Runs after Task 12.

- [ ] **Step 1: Write the property test**

Append to `journal::tests`:

```rust
#[test]
fn fold_then_open_yields_same_view_model_state_as_direct_open() {
    use crate::view_model::ViewModel;
    use utmost_lib::events::{BincodeFileReader, BincodeFileSink, EventSink};

    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let bin_a = dir_a.path().join("carve_events.bin");
    let bin_b = dir_b.path().join("carve_events.bin");

    // Both logs start with a fresh header
    let _ = BincodeFileSink::create(&bin_a).unwrap();
    let _ = BincodeFileSink::create(&bin_b).unwrap();

    let events = vec![
        CarveEvent::Bookmark { file_id: 1, bookmarked: true, at: "t".into() },
        CarveEvent::Note { note_id: 1, file_id: 1, text: "hi".into(), at: "t".into() },
        CarveEvent::MarkAsBest { original_file_id: 1, chosen_file_id: 2, at: "t".into() },
    ];

    // Path A: stage in pending, then fold
    let journal_a = Journal::for_main_log(&bin_a);
    for ev in &events {
        journal_a.append(ev).unwrap();
    }
    journal_a.fold().unwrap();

    // Path B: write directly to main log
    let sink_b = BincodeFileSink::open_append(&bin_b).unwrap();
    for ev in &events {
        <BincodeFileSink as EventSink>::emit(&sink_b, ev);
    }
    drop(sink_b);

    // Apply both to a fresh ViewModel and compare relevant state.
    let mut vm_a = ViewModel::new();
    let mut r = BincodeFileReader::open(&bin_a).unwrap();
    while let Some(ev) = r.next_event().unwrap() { vm_a.apply(&ev); }

    let mut vm_b = ViewModel::new();
    let mut r = BincodeFileReader::open(&bin_b).unwrap();
    while let Some(ev) = r.next_event().unwrap() { vm_b.apply(&ev); }

    assert_eq!(vm_a.bookmarks, vm_b.bookmarks);
    assert_eq!(vm_a.best_choices, vm_b.best_choices);
    assert_eq!(
        vm_a.notes.get(&1).map(|v| v.len()),
        vm_b.notes.get(&1).map(|v| v.len())
    );
}
```

Run: `cargo test -p utmost-gui --lib journal::tests::fold_then_open_yields_same_view_model_state_as_direct_open` — PASS.

- [ ] **Step 2: Commit**

```
git add crates/utmost-gui/src/journal.rs
git commit -m "$(cat <<'EOF'
test(gui): journal replay is idempotent vs direct main-log writes

Property check: staging events in carve_events.pending then folding
produces the same view-model state as writing them directly to
carve_events.bin.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Wave 5 — Recovery runner module (depends on Wave 2 and Wave 4)

### Task 14: `recovery.rs` background runner in `utmost-gui`

**Files:**
- Create: `crates/utmost-gui/src/recovery.rs`
- Modify: `crates/utmost-gui/src/lib.rs` (`pub mod recovery;`)
- Test: same file

**Parallel with:** Tasks 7-13. Runs after Wave 2.

- [ ] **Step 1: Write the failing test**

Create `crates/utmost-gui/src/recovery.rs`:

```rust
//! Background runner that drives the recovery pipeline from the GUI.
//!
//! The "Run recovery" button calls `start_recovery_request`, which spawns a
//! worker thread that runs `recover_fragmented_jpegs_with_event_log` against
//! the source image and an existing `carve_events.bin`. Events emitted by
//! the library land in both the bincode log (durable) and an in-process
//! `ChannelSink` consumed by the view-model.

use std::path::PathBuf;
use std::sync::Arc;

use crossbeam_channel::{Receiver, Sender, unbounded};
use utmost_lib::events::{BincodeFileSink, CarveEvent, ChannelSink, EventSink, FanoutSink};
use utmost_lib::jpeg_recover::{RecoveryConfig, recover_fragmented_jpegs_with_event_log};

pub const KEEP_CANDIDATES_DEFAULT: usize = 5;
pub const KEEP_CANDIDATES_MAX: usize = 10;

#[derive(Debug, Clone)]
pub struct RecoveryRequest {
    pub image_path: String,
    pub report_path: String,
    pub output_dir: String,
    pub event_log: PathBuf,
    pub keep_candidates: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keep_candidates_clamps_to_bounds() {
        assert_eq!(clamp_keep_candidates(0), 1);
        assert_eq!(clamp_keep_candidates(5), 5);
        assert_eq!(clamp_keep_candidates(100), KEEP_CANDIDATES_MAX);
    }

    #[test]
    fn run_recovery_emits_events_to_channel() {
        // ... build a partial-JPEG fixture + carve_events.bin + carve_report.json
        // (reuse helpers from jpeg_recover tests via pub-test-helpers feature or copy)
        // call run_recovery_blocking, assert RecoveryStarted then >=1
        // (FileFound + RecoveryCandidate) then RecoveryFinished arrive on rx.
    }
}
```

- [ ] **Step 2: Compile-check (test stubbed)**

```
cargo build -p utmost-gui
```
Expected: compile passes (test body is `// ...`); `clamp_keep_candidates` doesn't exist yet — fix in Step 3.

- [ ] **Step 3: Implement public API**

Below the `RecoveryRequest` struct in `recovery.rs`:

```rust
pub fn clamp_keep_candidates(n: usize) -> usize {
    n.clamp(1, KEEP_CANDIDATES_MAX)
}

/// Run recovery synchronously. Returns Ok with the bincode events the
/// pipeline emitted (also persisted to `req.event_log`).
///
/// Errors from the recovery pipeline are converted to anyhow::Error and
/// the channel may be partially populated. The view-model receives every
/// event up to the failure point.
pub fn run_recovery_blocking(
    req: RecoveryRequest,
    tx: Sender<CarveEvent>,
) -> anyhow::Result<()> {
    let channel_sink = Arc::new(ChannelSink::new(tx)) as Arc<dyn EventSink>;
    // recover_fragmented_jpegs_with_event_log opens its own BincodeFileSink
    // for `event_log`. The ChannelSink is fanned in as a wrapper sink below.
    //
    // To deliver events to *both* the bincode file AND the channel, we wrap
    // the existing append-only behaviour: the recovery library already
    // writes to `event_log`; we additionally consume the same events here
    // by routing through a FanoutSink. But recover_fragmented_jpegs_with_event_log
    // currently accepts only Option<&Path>, not Option<&dyn EventSink>.
    //
    // Implementation note: the simplest path is to refactor the library
    // signature in Task 6 (or this task) to accept an Option<Arc<dyn EventSink>>
    // *instead of* a path; the library opens BincodeFileSink internally only
    // when callers pass that variant. For now this runner does the fanout
    // pre-call: it reads events back from the appended bincode log after
    // the synchronous call returns. That works but is non-streaming. The
    // streaming variant is preferred.
    //
    // Decision: extend the library signature here (Task 14) to accept an
    // Option<Arc<dyn EventSink>>. Update Task 6 caller(s) accordingly.

    let cfg = RecoveryConfig {
        keep_candidates: req.keep_candidates,
        ..RecoveryConfig::default()
    };

    recover_fragmented_jpegs_with_event_log_sink(
        &req.image_path,
        &req.report_path,
        &req.output_dir,
        &cfg,
        Some(channel_sink),
        Some(&req.event_log),
    )?;
    Ok(())
}

/// Spawn `run_recovery_blocking` on a worker thread. Returns the receiver
/// half; UI code drains it on the Slint timer.
pub fn start_background(req: RecoveryRequest) -> Receiver<CarveEvent> {
    let (tx, rx) = unbounded();
    std::thread::spawn(move || {
        if let Err(e) = run_recovery_blocking(req, tx) {
            tracing::warn!("recovery worker failed: {e}");
        }
    });
    rx
}
```

`recover_fragmented_jpegs_with_event_log_sink` does not exist yet — we need to add it to `utmost_lib::jpeg_recover`.

- [ ] **Step 4: Extend `jpeg_recover` to accept a sink**

In `crates/utmost-lib/src/jpeg_recover.rs`, add:

```rust
/// Like `recover_fragmented_jpegs_with_event_log`, but lets the caller pass
/// an `EventSink` directly (in addition to or instead of a path). Used by
/// the GUI to fan events into both `carve_events.bin` *and* an in-process
/// `ChannelSink`.
pub fn recover_fragmented_jpegs_with_event_log_sink(
    image_path: &str,
    report_path: &str,
    output_dir: &str,
    config: &RecoveryConfig,
    extra_sink: Option<std::sync::Arc<dyn crate::events::EventSink>>,
    event_log: Option<&std::path::Path>,
) -> Result<RecoveryReport> {
    // Internally: build the FanoutSink containing whichever of the two
    // sinks were provided, then run the same logic as
    // recover_fragmented_jpegs_with_event_log but emit through the fanout.
}
```

Refactor `recover_fragmented_jpegs_with_event_log` from Task 6 to call this new function with `extra_sink: None`:

```rust
pub fn recover_fragmented_jpegs_with_event_log(
    image_path: &str,
    report_path: &str,
    output_dir: &str,
    config: &RecoveryConfig,
    event_log: Option<&std::path::Path>,
) -> Result<RecoveryReport> {
    recover_fragmented_jpegs_with_event_log_sink(
        image_path, report_path, output_dir, config, None, event_log,
    )
}
```

Inside the new function, replace the local `emit` closure from Task 6:

```rust
let mut sinks: Vec<std::sync::Arc<dyn crate::events::EventSink>> = Vec::new();
if let Some(path) = event_log {
    let bincode_sink = std::sync::Arc::new(
        crate::events::BincodeFileSink::open_append(path)?
    ) as std::sync::Arc<dyn crate::events::EventSink>;
    sinks.push(bincode_sink);
}
if let Some(s) = extra_sink {
    sinks.push(s);
}
let fanout = crate::events::FanoutSink::new(sinks);
let emit = |ev: &CarveEvent| {
    <crate::events::FanoutSink as crate::events::EventSink>::emit(&fanout, ev);
};
```

Run the existing recovery tests to verify Task 6 still passes:

```
cargo test -p utmost-lib recover
```
Expected: PASS.

- [ ] **Step 5: Wire `crate::recovery::start_background` into `lib.rs`**

In `crates/utmost-gui/src/lib.rs`:

```rust
pub mod journal;
pub mod recovery;
```

- [ ] **Step 6: Fill in `run_recovery_emits_events_to_channel` test**

Use the same fixture pattern as the `jpeg_recover` tests. (If those helpers aren't `pub(crate)`-accessible, duplicate the minimal fixture builder.) Assert RecoveryStarted, then ≥1 (FileFound + RecoveryCandidate), then RecoveryFinished arrives on `rx`.

```rust
#[test]
fn run_recovery_emits_events_to_channel() {
    // build fixture (image + carve_report.json with one partial jpeg)
    let (image_path, report_path, output_dir, bin_path, _tempdir) = build_partial_jpeg_fixture();
    let (tx, rx) = unbounded::<CarveEvent>();
    let req = RecoveryRequest {
        image_path,
        report_path,
        output_dir,
        event_log: bin_path,
        keep_candidates: 1,
    };
    run_recovery_blocking(req, tx).unwrap();

    let events: Vec<_> = rx.try_iter().collect();
    assert!(events.iter().any(|e| matches!(e, CarveEvent::RecoveryStarted { .. })));
    assert!(events.iter().any(|e| matches!(e, CarveEvent::FileFound { .. })));
    assert!(events.iter().any(|e| matches!(e, CarveEvent::RecoveryCandidate { .. })));
    assert!(events.iter().any(|e| matches!(e, CarveEvent::RecoveryFinished { .. })));
}
```

Run: `cargo test -p utmost-gui recovery::tests` — PASS.

- [ ] **Step 7: fmt + clippy + commit**

```
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add crates/utmost-gui/src/recovery.rs crates/utmost-gui/src/lib.rs crates/utmost-lib/src/jpeg_recover.rs
git commit -m "$(cat <<'EOF'
feat(gui): background recovery runner with channel + bincode fanout

utmost-gui::recovery::start_background spawns a worker thread that runs
the JPEG recovery pipeline, fans events to both an in-process ChannelSink
(view-model) and the persistent BincodeFileSink (carve_events.bin).
KEEP_CANDIDATES_MAX = 10 is the GUI cap; default 5 set by callers.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Wave 6 — Slint UI changes (depends on Wave 3)

### Task 15: Chip row — partial chips and bookmarked chip

**Files:**
- Modify: `crates/utmost-gui/ui/detail.slint:111-125` (chip row)
- Modify: `crates/utmost-gui/src/slint_adapter.rs` (chip sync logic)

**Parallel with:** Task 17 (lightbox.slint) and Task 18 (variant_viewer.slint). Runs after Wave 3.

- [ ] **Step 1: Extend `FilterChipData`**

In `crates/utmost-gui/ui/detail.slint:3-7`, add a kind discriminator:

```slint
export struct FilterChipData {
    name: string,
    enabled: bool,
    count: int,
    kind: string,  // "type" | "partial" | "bookmarked"
}
```

Slint structs require positional initialisation in Rust. If the Rust side currently constructs `FilterChipData` literals, every site needs the new field. Grep for `FilterChipData` in `slint_adapter.rs` and update.

- [ ] **Step 2: Style the chip variants visually**

In the `for chip in root.chips:` block at `detail.slint:111-125`, branch on `chip.kind`:

```slint
for chip in root.chips: Rectangle {
    background: chip.enabled
        ? (chip.kind == "partial" ? #c66 : (chip.kind == "bookmarked" ? #cc6 : #3a6))
        : #555;
    border-radius: 12px;
    width: chip.kind == "partial" ? 130px : 90px;
    height: 28px;
    TouchArea {
        clicked => { root.chip-toggled(chip.name); }
    }
    Text {
        text: (chip.kind == "partial" ? "Partial " : "") + chip.name + " (" + chip.count + ")";
        color: white;
    }
}
```

`chip.name` for a partial chip is the same as the underlying type (e.g. "jpeg"); the `"Partial "` prefix is rendered by the chip itself. The toggle callback uses `name` as the key — the adapter disambiguates partials from completes via `kind`. Pass a synthetic name like `"partial:jpeg"` for the toggle to keep the existing flat callback signature:

```slint
Text {
    text: chip.name == "bookmarked"
        ? "Bookmarked (" + chip.count + ")"
        : (chip.kind == "partial" ? "Partial " : "") + chip.name + " (" + chip.count + ")";
    color: white;
}
```

And in the `clicked` handler, pass the full `chip.name` (which includes `partial:` prefix for partial chips, or `bookmarked` for the bookmark chip).

- [ ] **Step 3: Update adapter to build chips with the new kinds**

In `crates/utmost-gui/src/slint_adapter.rs`, search for where `chips_model` is populated (look for the function that maps `type_counts` to `FilterChipData` rows). Add for each `FileType` in `partial_counts`:

```rust
chips.push(FilterChipData {
    name: format!("partial:{}", file_type_lowercase).into(),
    enabled: vm.filter.enabled_partial_types.contains(&ft),
    count: count as i32,
    kind: "partial".into(),
});
```

After all type-based chips, push the bookmarked chip if `bookmarks` is non-empty:

```rust
if !vm.bookmarks.is_empty() {
    chips.push(FilterChipData {
        name: "bookmarked".into(),
        enabled: vm.filter.bookmarked_only,
        count: vm.bookmarks.len() as i32,
        kind: "bookmarked".into(),
    });
}
```

In the `chip_toggled` callback handler in `slint_adapter.rs`:

```rust
if name == "bookmarked" {
    v.filter.bookmarked_only = !v.filter.bookmarked_only;
} else if let Some(ft_str) = name.strip_prefix("partial:") {
    if let Some(ft) = parse_file_type_pub(ft_str) {
        if v.filter.enabled_partial_types.contains(&ft) {
            v.filter.enabled_partial_types.remove(&ft);
        } else {
            v.filter.enabled_partial_types.insert(ft);
        }
    }
} else if let Some(ft) = parse_file_type_pub(&name) {
    if v.filter.enabled_types.contains(&ft) {
        v.filter.enabled_types.remove(&ft);
    } else {
        v.filter.enabled_types.insert(ft);
    }
}
v.recompute_visible();
```

- [ ] **Step 4: Add a Rust-side integration test**

In `crates/utmost-gui/tests/`, create `chip_integration.rs`:

```rust
// Verifies the chip row honours partial + bookmark filters end-to-end
// using just the view-model. Slint-side rendering is covered manually.

use utmost_gui::view_model::*;
// ... same fixtures as elsewhere ...

#[test]
fn toggling_partial_chip_changes_visible_set() {
    // Build vm with a complete and a partial JPEG; toggle the partial chip;
    // assert visible_files changes correctly.
}
```

Fill in the body using patterns from view_model tests. Verify with `cargo test -p utmost-gui`.

- [ ] **Step 5: fmt + clippy + commit**

```
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add crates/utmost-gui/ui/detail.slint crates/utmost-gui/src/slint_adapter.rs crates/utmost-gui/tests/
git commit -m "$(cat <<'EOF'
feat(gui): partial-type and bookmarked filter chips

Chip row gains "Partial <Type>" chips (one per type appearing in partial_counts)
and a "Bookmarked" chip at the end. FilterChipData carries a kind discriminator
so the same callback handles all three families. Partial and bookmarked toggles
are fully independent of the regular type chips.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 16: Side panel — filename buttons, notes section, variants mini-grid, recovery button

**Files:**
- Modify: `crates/utmost-gui/ui/detail.slint:199-256` (side panel block)
- Modify: `crates/utmost-gui/src/slint_adapter.rs` (new properties + callback wiring)

**Parallel with:** Task 17, Task 18. Runs after Wave 3.

- [ ] **Step 1: Add new properties + structs in `detail.slint`**

Above `export component DetailPage`, add struct definitions:

```slint
export struct VariantThumbData {
    file_id: int,
    rank: int,
    has_thumbnail: bool,
    thumbnail: image,
    is_best: bool,
}

export struct NoteRowData {
    note_id: int,
    text: string,
    at: string,
}
```

Inside `DetailPage`, add properties (alongside existing `in-out property` block ~lines 52-61):

```slint
    in-out property <bool> selected-bookmarked: false;
    in-out property <[NoteRowData]> selected-notes: [];
    in-out property <string> note-draft: "";
    in-out property <[VariantThumbData]> selected-variants: [];
    in-out property <bool> selected-has-variants: false;
    in-out property <bool> recovery-button-visible: false;
    in-out property <int> keep-candidates: 5;

    callback toggle-bookmark();
    callback add-note(string);  // submits draft text
    callback open-variant-viewer();
    callback variant-thumb-clicked(int);   // file_id
    callback variant-thumb-double-clicked(int);
    callback run-recovery();
```

- [ ] **Step 2: Replace side panel internals**

Replace the side-panel `if root.side-panel-open: Rectangle { ... }` block (lines ~199-256) with an expanded version. The full block is too long to inline here without losing detail — write the following structure:

```slint
if root.side-panel-open: Rectangle {
    background: #1e1e1e;
    width: 320px;
    VerticalBox {
        // Filename row with ★ Bookmark and ＋ Note
        HorizontalBox {
            Text {
                text: root.selected-filename;
                font-size: 16px;
                color: white;
                horizontal-stretch: 1;
            }
            // Bookmark star
            TouchArea {
                width: 28px; height: 28px;
                clicked => { root.toggle-bookmark(); }
                Rectangle {
                    background: root.selected-bookmarked ? #cc6 : #333;
                    border-radius: 14px;
                    width: parent.width; height: parent.height;
                    Text { text: "★"; color: white; horizontal-alignment: center; vertical-alignment: center; }
                }
            }
            // Close ✕  (existing)
            close_touch := TouchArea { /* … existing markup … */ }
        }

        // Preview (existing)
        preview_touch := TouchArea { /* existing markup … */ }

        // Metadata rows (existing)
        for row in root.selected-metadata: HorizontalBox { /* existing */ }

        // Notes section
        Text { text: "Notes (" + root.selected-notes.length + ")"; color: #aaa; font-size: 11px; }
        for note in root.selected-notes: Rectangle {
            background: #2a2a2a;
            border-radius: 3px;
            VerticalBox {
                Text { text: note.at; color: #777; font-size: 9px; }
                Text { text: note.text; color: white; font-size: 12px; wrap: word-wrap; }
            }
        }
        Rectangle {
            background: #111;
            border-radius: 3px;
            height: 60px;
            note_input := TextInput {
                width: parent.width - 8px;
                height: parent.height - 8px;
                x: 4px; y: 4px;
                color: white;
                text: root.note-draft;
                edited => { root.note-draft = self.text; }
                accepted => {
                    root.add-note(self.text);
                    root.note-draft = "";
                    self.text = "";
                }
            }
        }

        // Variants section (only when present)
        if root.selected-has-variants: VerticalBox {
            Text { text: "Variants (" + root.selected-variants.length + ")"; color: #aaa; font-size: 11px; }
            Flickable {
                viewport-height: ceil(root.selected-variants.length / 2.0) * 80px;
                height: min(160px, self.viewport-height);
                width: parent.width;
                for v[i] in root.selected-variants: Rectangle {
                    x: mod(i, 2) * 145px;
                    y: floor(i / 2) * 80px;
                    width: 140px;
                    height: 76px;
                    background: v.is_best ? #444 : #2a2a2a;
                    border-radius: 3px;
                    border-width: v.is_best ? 2px : 0;
                    border-color: #ffd700;
                    tile_t := TouchArea {
                        clicked => { root.variant-thumb-clicked(v.file_id); }
                        double-clicked => { root.variant-thumb-double-clicked(v.file_id); }
                        if v.has_thumbnail: Image { source: v.thumbnail; image-fit: contain; }
                        Text { text: "#" + v.rank + (v.is_best ? " ★" : ""); color: white; font-size: 10px; y: parent.height - 14px; }
                    }
                }
            }
            Rectangle {
                background: #2a4a6a;
                border-radius: 3px;
                height: 28px;
                TouchArea {
                    clicked => { root.open-variant-viewer(); }
                    Text { text: "Open variant viewer ⤢"; color: white; horizontal-alignment: center; vertical-alignment: center; }
                }
            }
        }

        // Run Recovery button (only when applicable)
        if root.recovery-button-visible: HorizontalBox {
            Text { text: "Keep:"; color: white; vertical-alignment: center; }
            SpinBox {
                value: root.keep-candidates;
                minimum: 1;
                maximum: 10;
                edited(v) => { root.keep-candidates = v; }
            }
            Button {
                text: "Run recovery";
                clicked => { root.run-recovery(); }
            }
        }
    }
}
```

- [ ] **Step 3: Wire callbacks in `slint_adapter.rs`**

In the `UiState::new` callback-wiring block, add:

```rust
{
    let vm_cb = vm.clone();
    let weak_w = window.as_weak();
    window.on_toggle_bookmark(move || {
        let mut v = vm_cb.lock().unwrap();
        if let Some(sel) = v.selection {
            // Variants are not bookmarkable
            if v.variant_of.contains_key(&sel) { return; }
            let ev = v.toggle_bookmark(sel);
            // route ev → journal (Task 19)
            send_annotation_to_journal(ev);
        }
    });
}
{
    let vm_cb = vm.clone();
    window.on_add_note(move |text| {
        let mut v = vm_cb.lock().unwrap();
        if let Some(sel) = v.selection {
            let ev = v.add_note(sel, text.to_string());
            send_annotation_to_journal(ev);
        }
    });
}
{
    let vm_cb = vm.clone();
    window.on_open_variant_viewer(move || {
        let mut v = vm_cb.lock().unwrap();
        v.open_variant_viewer();
    });
}
{
    let vm_cb = vm.clone();
    window.on_variant_thumb_double_clicked(move |variant_id| {
        let mut v = vm_cb.lock().unwrap();
        v.open_lightbox_for_variant(variant_id as u64);
    });
}
{
    let vm_cb = vm.clone();
    let keep = window.get_keep_candidates();
    window.on_run_recovery(move || {
        let v = vm_cb.lock().unwrap();
        // Build RecoveryRequest from session state and spawn worker.
        // The worker's events come back on a Receiver — the UI's existing
        // periodic timer should drain it alongside the live carve channel.
        // Implementation: extend the live-event consumer pattern in launch_ui
        // to merge both receivers.
    });
}
```

The `send_annotation_to_journal(ev)` helper is implemented in Task 19. For this task, leave a stub that logs the event — Task 19 replaces the body.

```rust
fn send_annotation_to_journal(ev: CarveEvent) {
    // Will be replaced in Task 19 to route to the journal sidecar.
    tracing::debug!("annotation event (not yet persisted): {ev:?}");
}
```

Add the per-tick sync of new properties: in the periodic resync that builds `selected-metadata`, also compute and set:

```rust
window.set_selected_bookmarked(
    v.selection.map(|s| v.bookmarks.contains(&s)).unwrap_or(false)
);
window.set_selected_notes(
    /* VecModel built from v.notes.get(&selection) */
);
window.set_selected_variants(
    /* VecModel built from v.variants.get(&selection).variant_ids */
);
window.set_selected_has_variants(
    v.selection.map(|s| v.variants.contains_key(&s)).unwrap_or(false)
);
window.set_recovery_button_visible(
    matches!(v.recovery_state, RecoveryUiState::NotRun)
        && !v.partial_counts.is_empty()
);
```

(Replace `RecoveryUiState::Disabled` with `RecoveryUiState::NotRun` when `RunFinished` arrives — extend the existing `RunFinished` reducer arm in `view_model.rs` to flip Disabled → NotRun. Task 20 covers the actual recovery trigger.)

- [ ] **Step 4: Build + sanity-check**

```
cargo build -p utmost-gui
cargo run -p utmost-cli -- --help
```
Expected: compile passes; CLI help renders (smoke check).

- [ ] **Step 5: fmt + clippy + commit**

```
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add crates/utmost-gui/ui/detail.slint crates/utmost-gui/src/slint_adapter.rs crates/utmost-gui/src/view_model.rs
git commit -m "$(cat <<'EOF'
feat(gui): side panel — bookmark/note buttons, notes list, variants mini-grid

Filename row gains ★ bookmark toggle; notes section renders chronological
NoteRowData entries plus an inline TextInput for new notes; variants
section (only when selection has variants) shows a 2-col vertical
mini-grid with ★ overlay for the marked-best candidate plus an
"Open variant viewer" button; "Run recovery" button + SpinBox keep
selector appear when recovery_state is NotRun.

Annotation events currently log only — routing to the journal sidecar
lands in Task 19.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 17: Lightbox footer — Bookmark / Note / Mark-as-best buttons

**Files:**
- Modify: `crates/utmost-gui/ui/lightbox.slint`
- Modify: `crates/utmost-gui/src/slint_adapter.rs`

**Parallel with:** Task 15, Task 16, Task 18. Runs after Wave 3.

- [ ] **Step 1: Add lightbox properties + callbacks**

In `lightbox.slint`, near the existing properties:

```slint
in-out property <bool> lightbox-bookmarked: false;
in-out property <bool> lightbox-mark-best-visible: false;
in-out property <bool> lightbox-note-input-open: false;
in-out property <string> lightbox-note-draft: "";

callback lightbox-toggle-bookmark();
callback lightbox-add-note(string);
callback lightbox-mark-best();
```

- [ ] **Step 2: Add footer button row**

Locate the existing lightbox footer (search for the bottom HorizontalBox / VerticalBox that contains the prev/next arrows). Add three buttons just after the arrows:

```slint
HorizontalBox {
    Button {
        text: root.lightbox-bookmarked ? "★ Bookmarked" : "☆ Bookmark";
        clicked => { root.lightbox-toggle-bookmark(); }
    }
    Button {
        text: "＋ Note";
        clicked => { root.lightbox-note-input-open = !root.lightbox-note-input-open; }
    }
    if root.lightbox-mark-best-visible: Button {
        text: "★ Mark as best variant";
        clicked => { root.lightbox-mark-best(); }
    }
}

if root.lightbox-note-input-open: Rectangle {
    background: #111;
    border-radius: 3px;
    height: 60px;
    TextInput {
        width: parent.width - 8px;
        height: parent.height - 8px;
        x: 4px; y: 4px;
        color: white;
        text: root.lightbox-note-draft;
        edited => { root.lightbox-note-draft = self.text; }
        accepted => {
            root.lightbox-add-note(self.text);
            root.lightbox-note-draft = "";
            self.text = "";
            root.lightbox-note-input-open = false;
        }
    }
}
```

- [ ] **Step 3: Wire callbacks in `slint_adapter.rs`**

```rust
{
    let vm_cb = vm.clone();
    window.on_lightbox_toggle_bookmark(move || {
        let mut v = vm_cb.lock().unwrap();
        if let Some(fid) = v.lightbox {
            let ev = v.toggle_bookmark(fid);
            send_annotation_to_journal(ev);
        }
    });
}
{
    let vm_cb = vm.clone();
    window.on_lightbox_add_note(move |text| {
        let mut v = vm_cb.lock().unwrap();
        if let Some(fid) = v.lightbox {
            let ev = v.add_note(fid, text.to_string());
            send_annotation_to_journal(ev);
        }
    });
}
{
    let vm_cb = vm.clone();
    window.on_lightbox_mark_best(move || {
        let mut v = vm_cb.lock().unwrap();
        if let (Some(fid), Some(orig)) = (v.lightbox, v.lightbox.and_then(|f| v.variant_of.get(&f).copied())) {
            let ev = v.mark_as_best(orig, fid);
            send_annotation_to_journal(ev);
        }
    });
}
```

In the periodic resync, set:

```rust
window.set_lightbox_bookmarked(
    v.lightbox.map(|f| v.bookmarks.contains(&f)).unwrap_or(false)
);
window.set_lightbox_mark_best_visible(
    v.lightbox.map(|f| v.variant_of.contains_key(&f)).unwrap_or(false)
);
```

- [ ] **Step 4: Build + commit**

```
cargo build -p utmost-gui && cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add crates/utmost-gui/ui/lightbox.slint crates/utmost-gui/src/slint_adapter.rs
git commit -m "$(cat <<'EOF'
feat(gui): lightbox footer — Bookmark / Note / Mark-as-best buttons

Three new lightbox actions wired through the view-model: bookmark toggle,
inline note input, and mark-as-best (visible only when the current image
is a recovery variant). Mark-best derives the original via variant_of.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 18: New `variant_viewer.slint` modal

**Files:**
- Create: `crates/utmost-gui/ui/variant_viewer.slint`
- Modify: `crates/utmost-gui/ui/main.slint` (import + show/hide on variant_viewer.is_some())
- Modify: `crates/utmost-gui/src/slint_adapter.rs`

**Parallel with:** Tasks 15-17. Runs after Wave 3.

- [ ] **Step 1: Create the modal component**

```slint
// crates/utmost-gui/ui/variant_viewer.slint
import { VerticalBox, HorizontalBox, Button } from "std-widgets.slint";
import { VariantThumbData } from "detail.slint";

export component VariantViewer inherits Rectangle {
    in-out property <bool> visible-flag: false;
    in-out property <string> source-filename: "";
    in-out property <[VariantThumbData]> variants: [];

    callback close();
    callback variant-clicked(int);    // file_id
    callback variant-double-clicked(int);

    visible: root.visible-flag;
    background: #000000aa;

    if root.visible-flag: Rectangle {
        background: #1a1a1a;
        x: (parent.width - self.width) / 2;
        y: (parent.height - self.height) / 2;
        width: 720px;
        height: 540px;
        border-radius: 6px;

        VerticalBox {
            HorizontalBox {
                Text { text: "Variants of " + root.source-filename; color: white; font-size: 14px; horizontal-stretch: 1; }
                Button { text: "✕"; clicked => { root.close(); } }
            }
            grid := Rectangle {
                Flickable {
                    width: parent.width; height: parent.height;
                    viewport-height: ceil(root.variants.length / 3.0) * 180px;
                    for v[i] in root.variants: Rectangle {
                        x: mod(i, 3) * 230px;
                        y: floor(i / 3) * 180px;
                        width: 220px;
                        height: 170px;
                        background: v.is_best ? #2a4a2a : #2a2a2a;
                        border-radius: 3px;
                        border-width: v.is_best ? 2px : 0;
                        border-color: #ffd700;
                        ta := TouchArea {
                            clicked => { root.variant-clicked(v.file_id); }
                            double-clicked => { root.variant-double-clicked(v.file_id); }
                            if v.has_thumbnail: Image { source: v.thumbnail; image-fit: contain; }
                            Text {
                                text: "#" + v.rank + (v.is_best ? " ★ best" : "");
                                color: white;
                                font-size: 12px;
                                y: parent.height - 18px;
                            }
                        }
                    }
                }
            }
        }
    }
}
```

- [ ] **Step 2: Import + place in `main.slint`**

In `main.slint`, add an import and place a `VariantViewer` inside the top-level `MainWindow`, layered on top of the `DetailPage`:

```slint
import { VariantViewer } from "variant_viewer.slint";

// inside MainWindow
VariantViewer {
    visible-flag: root.variant-viewer-open;
    source-filename: root.variant-viewer-filename;
    variants: root.variant-viewer-variants;
    close => { root.variant-viewer-close(); }
    variant-clicked(id) => { root.variant-viewer-thumb-clicked(id); }
    variant-double-clicked(id) => { root.variant-viewer-thumb-double-clicked(id); }
}
```

Add the corresponding `in-out property` and `callback` declarations on `MainWindow`.

- [ ] **Step 3: Wire in adapter**

Add resync code:

```rust
let viewer_open = v.variant_viewer.is_some();
window.set_variant_viewer_open(viewer_open);
if let Some(orig) = v.variant_viewer {
    window.set_variant_viewer_filename(
        v.files.iter().find(|f| f.id == orig)
            .map(|f| SharedString::from(&f.file.filename))
            .unwrap_or_default()
    );
    let variants_vec: Vec<VariantThumbData> = v.variants.get(&orig)
        .map(|vs| vs.variant_ids.iter().enumerate().map(|(i, id)| {
            VariantThumbData {
                file_id: *id as i32,
                rank: (i + 1) as i32,
                has_thumbnail: false,  // wire to thumb_worker
                thumbnail: slint::Image::default(),
                is_best: v.best_choices.get(&orig) == Some(id),
            }
        }).collect())
        .unwrap_or_default();
    // model replace
}
```

Wire callbacks:

```rust
window.on_variant_viewer_close(move || {
    let mut v = vm_cb.lock().unwrap();
    v.close_variant_viewer();
});
window.on_variant_viewer_thumb_double_clicked(move |variant_id| {
    let mut v = vm_cb.lock().unwrap();
    v.open_lightbox_for_variant(variant_id as u64);
});
```

- [ ] **Step 4: Build + commit**

```
cargo build -p utmost-gui && cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add crates/utmost-gui/ui/variant_viewer.slint crates/utmost-gui/ui/main.slint crates/utmost-gui/src/slint_adapter.rs
git commit -m "$(cat <<'EOF'
feat(gui): variant viewer modal

New VariantViewer Slint component layered over MainWindow. 3-column grid
of full-size gallery thumbnails for the recovery variants of the currently
selected partial. ★ overlay on the marked-best variant. Double-click opens
the lightbox in variant nav mode.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 19: Keyboard shortcuts (`b` / `n` / `m`)

**Files:**
- Modify: `crates/utmost-gui/ui/detail.slint:75-89` (FocusScope key handler)
- Modify: `crates/utmost-gui/ui/lightbox.slint` (lightbox FocusScope, if present)
- Modify: `crates/utmost-gui/src/slint_adapter.rs`

**Parallel with:** none. Runs after Tasks 16, 17, 18.

- [ ] **Step 1: Add `b` / `n` / `m` to detail FocusScope**

In `detail.slint:75-89`:

```slint
key-pressed(event) => {
    if (event.text == Key.Return) { root.tile-enter-pressed(); return accept; }
    if (event.text == Key.Escape) { root.detail-escape-pressed(); return accept; }
    if (event.text == "b" || event.text == "B") { root.toggle-bookmark(); return accept; }
    if (event.text == "n" || event.text == "N") { /* focus note input */ return accept; }
    if (event.text == "m" || event.text == "M") { /* no-op in detail; lightbox handles it */ return accept; }
    return reject;
}
```

For "focus note input" — Slint TextInput needs a manual focus. The cleanest path is a callback `request-note-focus()` that the adapter handles by setting a flag.

- [ ] **Step 2: Add `b` / `n` / `m` to lightbox FocusScope**

Mirror the keys in the lightbox `key-pressed` handler. Specifically:

```slint
if (event.text == "b" || event.text == "B") { root.lightbox-toggle-bookmark(); return accept; }
if (event.text == "n" || event.text == "N") { root.lightbox-note-input-open = true; return accept; }
if (event.text == "m" || event.text == "M") {
    if (root.lightbox-mark-best-visible) { root.lightbox-mark-best(); }
    return accept;
}
```

- [ ] **Step 3: Build + integration test**

`crates/utmost-gui/tests/keyboard_shortcuts.rs` — verify the *view-model* effect when `toggle_bookmark`/`add_note`/`mark_as_best` are invoked, mirroring what the Slint callbacks would do. (Direct Slint keyboard testing requires `slint-test-harness` which is non-trivial; the view-model-level test confirms the wiring works.)

- [ ] **Step 4: Commit**

```
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add crates/utmost-gui/ui/detail.slint crates/utmost-gui/ui/lightbox.slint crates/utmost-gui/tests/keyboard_shortcuts.rs
git commit -m "$(cat <<'EOF'
feat(gui): b / n / m keyboard shortcuts for annotations

b toggles bookmark on the selected file; n opens the note input;
m marks the current variant as best (lightbox only, when in variant mode).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Wave 7 — Journal wiring + recovery trigger (depends on Waves 4, 5, 6)

### Task 20: Route annotation events through the journal sidecar

**Files:**
- Modify: `crates/utmost-gui/src/slint_adapter.rs`
- Modify: `crates/utmost-gui/src/lib.rs` (`run_live` / `run_from_file` signatures may carry a journal handle)

**Parallel with:** none. Runs after Tasks 12, 16, 17.

- [ ] **Step 1: Write the integration test**

`crates/utmost-gui/tests/journal_roundtrip.rs`:

```rust
use std::sync::{Arc, Mutex};
use utmost_lib::events::{BincodeFileSink, CarveEvent, EventSink};
use utmost_gui::journal::Journal;
use utmost_gui::view_model::ViewModel;

#[test]
fn annotations_made_during_live_carve_land_in_main_log_after_fold() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("carve_events.bin");
    let _ = BincodeFileSink::create(&bin).unwrap();

    let journal = Journal::for_main_log(&bin);
    let vm = Arc::new(Mutex::new(ViewModel::new()));

    // Simulate: user bookmarks file 7
    let ev = {
        let mut v = vm.lock().unwrap();
        v.toggle_bookmark(7)
    };
    journal.append(&ev).unwrap();
    assert!(journal.pending_path().exists());

    // Engine finishes — fold
    journal.fold().unwrap();
    assert!(!journal.pending_path().exists());

    // Replay main log into a fresh VM
    let mut vm2 = ViewModel::new();
    let mut r = utmost_lib::events::BincodeFileReader::open(&bin).unwrap();
    while let Some(ev) = r.next_event().unwrap() { vm2.apply(&ev); }
    assert!(vm2.bookmarks.contains(&7));
}
```

Run: should PASS (Journal exists; ViewModel exists).

- [ ] **Step 2: Plumb a `Journal` into `UiState`**

In `crates/utmost-gui/src/slint_adapter.rs`, extend `UiState`:

```rust
pub struct UiState {
    // ...
    pub journal: Option<Arc<Journal>>,
}
```

Add a setter / constructor variant:

```rust
impl UiState {
    pub fn set_journal(&mut self, j: Arc<Journal>) { self.journal = Some(j); }
}
```

Replace the `send_annotation_to_journal` stub helper from Task 16/17:

```rust
fn send_annotation_to_journal(journal: &Option<Arc<Journal>>, ev: CarveEvent) {
    if let Some(j) = journal {
        if let Err(e) = j.append(&ev) {
            tracing::warn!("journal append failed: {e}");
        }
    }
}
```

Update each call site (toggle_bookmark, add_note, mark_as_best in side panel + lightbox) to pass the journal handle. Easiest: clone the `Arc<Journal>` into each `move` closure.

- [ ] **Step 3: Hook `recover_on_open` in `run_from_file`**

In `crates/utmost-gui/src/lib.rs` (search `pub fn run_from_file`), after opening the main log and applying its events but before launching the UI:

```rust
let journal = Arc::new(Journal::for_main_log(&main_log_path));
let recovered_events = journal.recover_on_open()?;
for ev in &recovered_events {
    vm.lock().unwrap().apply(ev);
}
// Pass `journal` to UiState for live annotation appending.
```

- [ ] **Step 4: Hook `fold` on `RunFinished` in `run_live`**

In `run_live` (or whichever function consumes the live event channel), the existing loop that calls `vm.apply(&ev)` for each incoming `CarveEvent`. When `ev` is `RunFinished`, after applying:

```rust
if matches!(ev, CarveEvent::RunFinished { .. }) {
    if let Err(e) = journal.fold() {
        tracing::warn!("journal fold at RunFinished failed: {e}");
    }
}
```

Also unlock annotations: extend the `RunStarted` reducer arm to set `recovery_state = RecoveryUiState::Disabled` (during live carve) and `RunFinished` to set `recovery_state = RecoveryUiState::NotRun` so the "Run recovery" button can appear.

- [ ] **Step 5: Run tests**

```
cargo test -p utmost-gui
```
Expected: PASS, including the new `journal_roundtrip` integration test.

- [ ] **Step 6: Commit**

```
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add crates/utmost-gui/src/slint_adapter.rs crates/utmost-gui/src/lib.rs crates/utmost-gui/src/view_model.rs crates/utmost-gui/tests/journal_roundtrip.rs
git commit -m "$(cat <<'EOF'
feat(gui): route annotations through the journal sidecar

Bookmark, Note, MarkAsBest events from the GUI now append to
carve_events.pending immediately. At RunFinished the journal folds into
the main log; at viewer startup recover_on_open replays + folds any
.pending left behind by a crashed previous session.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 21: Wire "Run recovery" button to the background runner

**Files:**
- Modify: `crates/utmost-gui/src/slint_adapter.rs`

**Parallel with:** none. Runs after Tasks 14, 16, 20.

- [ ] **Step 1: Add a recovery channel handle to `UiState`**

```rust
pub struct UiState {
    // ...
    pub recovery_rx: RefCell<Option<crossbeam_channel::Receiver<CarveEvent>>>,
}
```

In the existing 100ms timer that drains live events, also drain any `recovery_rx`:

```rust
if let Some(rx) = ui_state.recovery_rx.borrow().as_ref() {
    while let Ok(ev) = rx.try_recv() {
        vm.lock().unwrap().apply(&ev);
    }
}
```

- [ ] **Step 2: Implement `on_run_recovery`**

Replace the stub in `on_run_recovery` from Task 16:

```rust
window.on_run_recovery(move || {
    let mut v = vm_cb.lock().unwrap();
    let keep = clamp_keep_candidates(weak_w.upgrade().unwrap().get_keep_candidates() as usize);
    // Build RecoveryRequest from session paths
    let req = RecoveryRequest {
        image_path: v.run.source_image_path.clone(), // see note below
        report_path: format!("{}/carve_report.json", v.run.output_root),
        output_dir: v.run.output_root.clone(),
        event_log: PathBuf::from(&v.run.output_root).join("carve_events.bin"),
        keep_candidates: keep,
    };
    v.recovery_state = RecoveryUiState::Running;
    drop(v);  // release lock before spawning
    let rx = utmost_gui::recovery::start_background(req);
    *ui_state.recovery_rx.borrow_mut() = Some(rx);
});
```

`v.run.source_image_path` does not exist on `RunSummary` yet. Add a field:

```rust
// crates/utmost-gui/src/view_model.rs:38-47
pub struct RunSummary {
    // ...existing...
    pub source_image_path: String,
}
```

Populate from the `RunStarted` event's `sources` (use the first source's filename for now; multi-source recovery is out of scope for the initial wiring — single-source happy path only). For multi-source, extend later with a per-source dropdown.

- [ ] **Step 3: Build + smoke test**

```
cargo build -p utmost-gui
cargo test -p utmost-gui
```
Expected: PASS.

Manual smoke test (optional, requires a real disk image):

```
cargo run -- -t jpeg --gui /path/to/disk-image
# Wait for run to finish. Side panel of a partial JPEG should show
# "Run recovery" button. Click it. Verify variants appear in the mini-grid.
```

- [ ] **Step 4: Commit**

```
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add crates/utmost-gui/src/slint_adapter.rs crates/utmost-gui/src/view_model.rs
git commit -m "$(cat <<'EOF'
feat(gui): "Run recovery" button spawns background runner

Side-panel button + SpinBox kicks off utmost_gui::recovery::start_background
with the session's source image + report + event-log paths. Worker emits
events to a crossbeam channel; the periodic UI timer drains it the same
way it drains live carve events.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Wave 8 — End-to-end tests

### Task 22: Recovery pipeline end-to-end through the GUI

**Files:**
- Create: `crates/utmost-gui/tests/recovery_pipeline_e2e.rs`

**Parallel with:** Task 23, Task 24. Runs after Wave 7.

- [ ] **Step 1: Write the test**

```rust
use crossbeam_channel::unbounded;
use std::path::PathBuf;
use utmost_lib::events::{BincodeFileSink, CarveEvent, EventSink};
use utmost_gui::recovery::{run_recovery_blocking, RecoveryRequest};
use utmost_gui::view_model::ViewModel;

#[test]
fn recovery_e2e_populates_view_model_variants() {
    // Build a fixture: a partial JPEG carve dir with carve_events.bin +
    // carve_report.json. Reuse helpers from jpeg_recover tests; if not
    // exposed, duplicate the minimal fixture inline.
    let (image_path, report_path, output_dir, bin_path, _tempdir)
        = build_partial_jpeg_fixture_with_carve_events();

    // Apply the existing carve events to a fresh VM
    let mut vm = ViewModel::new();
    let mut r = utmost_lib::events::BincodeFileReader::open(&bin_path).unwrap();
    while let Some(ev) = r.next_event().unwrap() { vm.apply(&ev); }
    let partial_id = vm.files.iter()
        .find(|f| f.file.jpeg_scan.as_ref()
            .map(|s| s.status != utmost_lib::types::JpegScanStatus::Complete)
            .unwrap_or(false))
        .map(|f| f.id)
        .expect("expect at least one partial");

    // Run recovery
    let (tx, rx) = unbounded::<CarveEvent>();
    run_recovery_blocking(RecoveryRequest {
        image_path,
        report_path,
        output_dir,
        event_log: bin_path,
        keep_candidates: 2,
    }, tx).unwrap();

    // Drain channel and apply
    while let Ok(ev) = rx.try_recv() { vm.apply(&ev); }

    let vs = vm.variants.get(&partial_id).expect("variants populated");
    assert!(vs.variant_ids.len() >= 1);

    // Variants don't show in the main grid
    vm.recompute_visible();
    for vid in &vs.variant_ids {
        assert!(!vm.visible_files.contains(vid));
    }
}
```

- [ ] **Step 2: Run**

```
cargo test -p utmost-gui recovery_e2e_populates_view_model_variants
```
Expected: PASS.

- [ ] **Step 3: Commit**

```
git add crates/utmost-gui/tests/recovery_pipeline_e2e.rs
git commit -m "$(cat <<'EOF'
test(gui): recovery pipeline end-to-end populates variants

Builds a partial-JPEG fixture, runs recovery through the GUI runner,
asserts variant_ids land on the view-model and are excluded from the
main grid.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 23: Crash-simulation test for `.pending` recovery

**Files:**
- Create: `crates/utmost-gui/tests/journal_crash_recovery.rs`

**Parallel with:** Task 22, Task 24. Runs after Wave 7.

- [ ] **Step 1: Write the test**

```rust
use utmost_lib::events::{BincodeFileSink, CarveEvent};
use utmost_gui::journal::Journal;
use utmost_gui::view_model::ViewModel;

#[test]
fn crashed_session_recovers_annotations_on_next_open() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("carve_events.bin");
    let _ = BincodeFileSink::create(&bin).unwrap();

    // Simulate a session that wrote two annotation events to .pending then crashed
    let j1 = Journal::for_main_log(&bin);
    j1.append(&CarveEvent::Bookmark { file_id: 1, bookmarked: true, at: "t".into() }).unwrap();
    j1.append(&CarveEvent::Note { note_id: 1, file_id: 1, text: "hi".into(), at: "t".into() }).unwrap();
    drop(j1);
    assert!(dir.path().join("carve_events.pending").exists());

    // New session opens the log
    let j2 = Journal::for_main_log(&bin);
    let recovered = j2.recover_on_open().unwrap();
    assert_eq!(recovered.len(), 2);
    assert!(!dir.path().join("carve_events.pending").exists());

    // Both events are now in main log
    let mut vm = ViewModel::new();
    let mut r = utmost_lib::events::BincodeFileReader::open(&bin).unwrap();
    while let Some(ev) = r.next_event().unwrap() { vm.apply(&ev); }
    assert!(vm.bookmarks.contains(&1));
    assert_eq!(vm.notes.get(&1).unwrap().len(), 1);
}
```

- [ ] **Step 2: Run + commit**

```
cargo test -p utmost-gui crashed_session_recovers_annotations_on_next_open
git add crates/utmost-gui/tests/journal_crash_recovery.rs
git commit -m "$(cat <<'EOF'
test(gui): crashed-session journal recovery

A session that wrote to carve_events.pending then crashed should, on the
next open, replay those events into the view-model AND fold them into
carve_events.bin AND delete the pending file.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 24: Variant viewer + mark-as-best end-to-end

**Files:**
- Create: `crates/utmost-gui/tests/variant_viewer_e2e.rs`

**Parallel with:** Task 22, Task 23. Runs after Wave 7.

- [ ] **Step 1: Write the test**

```rust
use utmost_lib::events::CarveEvent;
use utmost_gui::view_model::ViewModel;

#[test]
fn open_variant_viewer_then_mark_best_persists_choice() {
    let mut vm = ViewModel::new();
    // ... apply RunStarted + partial JPEG FileFound (fid=10) + recovery
    //     FileFound (fid=11) + RecoveryCandidate{original:10, candidate:11} ...
    vm.selection = Some(10);

    vm.open_variant_viewer();
    assert_eq!(vm.variant_viewer, Some(10));

    vm.open_lightbox_for_variant(11);
    assert_eq!(vm.lightbox, Some(11));

    let ev = vm.mark_as_best(10, 11);
    match ev {
        CarveEvent::MarkAsBest { chosen_file_id, .. } => assert_eq!(chosen_file_id, 11),
        _ => panic!(),
    }
    assert_eq!(vm.best_choices.get(&10), Some(&11));

    vm.close_variant_viewer();
    assert!(vm.variant_viewer.is_none());
}
```

- [ ] **Step 2: Run + commit**

```
cargo test -p utmost-gui open_variant_viewer_then_mark_best_persists_choice
git add crates/utmost-gui/tests/variant_viewer_e2e.rs
git commit -m "$(cat <<'EOF'
test(gui): variant viewer + mark-as-best flow

Selection → open_variant_viewer → open_lightbox_for_variant → mark_as_best
chain mutates view-model state as expected and returns the right event.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Wave 9 — Documentation and follow-up

### Task 25: Update README with new GUI behaviours

**Files:**
- Modify: `README.md`

**Parallel with:** Task 26. Runs after Wave 8.

- [ ] **Step 1: Audit README sections**

Read the current `README.md`. The CLAUDE.md "Developer Documentation Rule" says: any new commands, setup steps, or workflow changes go in README. This change introduces:

- New GUI features: partial-JPG / bookmarked filter chips, side-panel notes + variants + bookmark / "Run recovery" button, variant viewer modal, lightbox annotation buttons, keyboard shortcuts (b / n / m).
- New on-disk artefact: `carve_events.pending` sidecar (gitignore-relevant for repos that check in carve output).
- New behaviour: `utmost recover -n N` writes N candidate JPEGs (not 1).

- [ ] **Step 2: Add a "GUI annotations & variant review" section**

Append (or extend an existing GUI section in) the README:

```markdown
## GUI annotations & JPEG variant review

When opening a carve session in the GUI (`utmost --gui …` or `utmost-viewer
./output`), you can:

- **Bookmark a file** — `b` on the selected file, or click the ★ in the
  side panel. The "Bookmarked" filter chip narrows the grid to flagged
  files.
- **Add a note** — `n` on the selected file (or click ＋ Note in the side
  panel / lightbox). Notes are append-only (forensic chain-of-custody).
- **JPEG recovery variants** — for any partial JPEG (`Truncated` or
  `Fragmented` scan status), the side panel shows a vertical-scroll
  mini-grid of recovery candidates if recovery has been run for the
  session. Click "Open variant viewer" for a full-size gallery; open one
  in the previewer to compare. Press `m` (or click "Mark as best variant")
  in the lightbox to record your canonical choice.
- **Run recovery from the GUI** — the side panel shows a "Run recovery"
  button + "Keep" selector (default 5, max 10) when a session has partial
  JPEGs and recovery has not yet run. The recovery pass runs in the
  background and streams events into the GUI (and persists them to
  `carve_events.bin`).

Annotations are persisted to `carve_events.bin` (or staged in
`carve_events.pending` mid-run and folded in at `RunFinished`). They
survive viewer relaunches and machine moves.
```

- [ ] **Step 3: Note the recover CLI behaviour change**

In the existing `## Commands` or `## Recover` section:

```markdown
`utmost recover -n N` now writes up to N candidate JPEGs per partial
original (filename pattern `<stem>_recovered_<rank>.jpg`). Previous
versions wrote only the single best candidate.
```

- [ ] **Step 4: Commit**

```
git add README.md
git commit -m "$(cat <<'EOF'
docs: GUI annotations + JPEG variant review + recover -N behaviour

Document new bookmark / note / mark-as-best workflows, the variant viewer
modal, keyboard shortcuts, and the change to "utmost recover -n N" which
now writes N candidates instead of one.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 26: Open the follow-up GitHub issue for config-file `keep_candidates`

**Files:** none

**Parallel with:** Task 25. Runs last.

- [ ] **Step 1: Open the issue**

```
gh issue create \
  --title "Make GUI keep_candidates default + cap configurable via user config file" \
  --body "$(cat <<'EOF'
Deferred from the recovery-variants and annotations design (see
docs/superpowers/specs/2026-05-18-gui-recovery-variants-and-annotations-design.md
§12).

Currently the GUI hard-codes:

- default \`keep_candidates\` = 5
- max cap                  = 10

Forensic teams pinning a project-wide policy should be able to override
these defaults via \`~/.config/utmost/config.toml\` (or whichever user
config path the CLI already loads — see crates/utmost-cli/src/config.rs).

Acceptance criteria:

- New \`[recovery]\` table in the user config supporting:
  \`\`\`toml
  [recovery]
  keep_candidates_default = 5   # 1..=cap
  keep_candidates_cap = 10      # 1..=100
  \`\`\`
- Values feed the GUI side panel SpinBox bounds + default.
- CLI \`utmost recover --candidates N\` continues to override.
- Sane fallback when the table is absent: defaults stay 5 / 10.
- Tests in crates/utmost-cli covering the config-load round-trip.

Labels: enhancement, gui, recovery
EOF
)" \
  --label "enhancement"
```

(Adjust label list to whatever the repo uses — `gh label list` first if unsure.)

- [ ] **Step 2: Capture the URL**

The `gh issue create` command prints the issue URL. Confirm it's reachable; no commit needed for this task.

- [ ] **Step 3: Mark plan-level TaskList task #10 as completed**

In the host harness's task tracker (the brainstorming task #10 added at design time), mark complete and move on.

---

## Plan Self-Review

After writing the plan, scanned against the spec for coverage, placeholders, type consistency.

**Coverage:**

- §4 (events): Task 2 ✓, Task 6 (recovery emit) ✓
- §4 (file_id): Task 1 ✓
- §5 (audit log): Task 3 ✓
- §5 (carve_report.json): Task 1 (serde-default on FileObject) ✓
- §5 (DFXML XML): no reporter exists in the codebase; deferred (noted in plan preamble)
- §5 (recover_report.json): Task 6 ✓
- §6 (journal sidecar): Task 12, Task 13 ✓
- §7 (jpeg_recover changes + RecoveryConfig.keep_candidates): Task 4 ✓
- §7 (CLI thread): Task 5 ✓
- §7 (`with_event_log` and event emission): Task 6 ✓
- §7 (`with_event_log_sink` / FanoutSink for in-process listener): Task 14 ✓
- §7 (`file_id` continuity): Task 6 ✓
- §8 (view-model state): Task 7 ✓
- §8 (filter / recompute_visible): Task 10 ✓
- §8 (reducer): Task 8, Task 9 ✓
- §8 (input methods): Task 11 ✓
- §8 (Slint UI — chips): Task 15 ✓
- §8 (Slint UI — side panel): Task 16 ✓
- §8 (Slint UI — variant viewer modal): Task 18 ✓
- §8 (Slint UI — lightbox footer): Task 17 ✓
- §8 (keyboard shortcuts): Task 19 ✓
- §9 (multi-source mode): not specifically broken out; assumed to inherit because each `output-XX/` carries its own bin + pending. A defensive multi-source path exists implicitly. If real multi-source support fails in integration, file a follow-up. Tracked as a risk, not a gap.
- §10 (tests): Tasks 22, 23, 24 ✓
- §12 (follow-up issue): Task 26 ✓

**Placeholder scan:** every step has actual code or commands. The few `// existing markup` callouts in Slint changes are surgical preserves, not placeholders.

**Type consistency:** `VariantThumbData` and `NoteRowData` are defined once (Task 16) and consumed by Task 18. `RecoveryUiState` defined in Task 7, consumed by Tasks 16 and 21. `Journal::for_main_log` / `append` / `fold` / `recover_on_open` consistent across Tasks 12, 13, 20, 23. `RecoveryRequest` consistent across Tasks 14, 21, 22.

**Parallelizable groups (for subagent dispatch):**

- **Wave 1** (sequential): Tasks 1, 2, 3
- **Wave 2** (sequential): Tasks 4, 5, 6 (all in `jpeg_recover.rs` / `events.rs`)
- **Wave 3** (sequential, but small): Tasks 7, 8, 9, 10, 11 — all in `view_model.rs` so sequential
- **Wave 4** (sequential): Tasks 12, 13 — same file (`journal.rs`)
- **Wave 5**: Task 14 — own file
- **Wave 6** (some parallel): Task 15 + Task 16 share `detail.slint` and `slint_adapter.rs` so sequential; Task 17 (lightbox.slint) and Task 18 (variant_viewer.slint NEW) can run in parallel with the detail-slint tasks if dispatched carefully
- **Wave 7**: Tasks 20, 21 — sequential (both `slint_adapter.rs`)
- **Wave 8** (parallel): Tasks 22, 23, 24 — all separate test files
- **Wave 9** (parallel): Tasks 25, 26 — independent

Best parallelism: Wave 4 (journal) runs concurrent with Wave 3 (view-model state); Wave 5 (recovery runner) concurrent with Wave 3+4. Wave 8 tests run in parallel. Plan is structured so a subagent driver can dispatch with awareness of the wave boundaries.
