# Per-Image Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the "Run recovery" button in the GUI's detail view operate on only the currently-selected partial JPEG — not every incomplete JPEG in the carve report — so the user can recover one image at a time and inspect variants in context.

**Architecture:** Additive change. The lib's `RecoveryConfig` gains an optional `only_original_file_id: Option<u64>` filter; when `Some(id)`, `recover_fragmented_jpegs_with_event_log_sink` skips every incomplete JPEG whose `file_id` doesn't match. The GUI button passes the current `vm.selection` through `RecoveryRequest` → lib. Recovered candidates already appear only as variants (the existing `variant_of` map excludes them from the main grid), so no main-list filtering work is needed. The button's visibility and label become per-selection: visible only when the selected file is a partial JPEG.

**Tech Stack:** Rust 2024, `utmost-lib` (jpeg_recover), `utmost-gui` (Slint + view_model), Cargo workspace, `cargo test`, `cargo fmt`, `cargo clippy --all-targets`.

---

## File Structure

**Files to modify:**

- `crates/utmost-lib/src/jpeg_recover.rs` — add `only_original_file_id: Option<u64>` to `RecoveryConfig`; apply it as a filter in the `incomplete` collection.
- `crates/utmost-gui/src/recovery.rs` — add `only_original_file_id: Option<u64>` to `RecoveryRequest`; thread it into the `RecoveryConfig` built in `run_recovery_blocking`.
- `crates/utmost-gui/src/slint_adapter.rs` — in `on_run_recovery`, set `only_original_file_id = v.selection`. In the per-tick resync, gate `recovery-button-visible` on "selected file is a partial JPEG" instead of the global `has_partials`. Update the label to "Recover this image" / "Re-run recovery for this image".
- `crates/utmost-gui/tests/recovery_pipeline_e2e.rs` — extend the existing e2e test (or add a sibling) to cover: two partial JPEGs, recovery scoped to one, only that one gets variants.
- `README.md` — short note under the GUI section explaining per-image recovery.
- `CLAUDE.md` — update the GUI section to mention per-image recovery scope.

**No new files are needed.** The change is small and additive across three production files plus one test file.

---

## Task 1: Lib — add `only_original_file_id` filter to `RecoveryConfig`

**Files:**
- Modify: `crates/utmost-lib/src/jpeg_recover.rs` (`RecoveryConfig` struct, `Default` impl, the `incomplete` collection loop around line 288, and the doc-comment for `recover_fragmented_jpegs_with_event_log_sink`)
- Test: `crates/utmost-lib/src/jpeg_recover.rs` (the `#[cfg(test)] mod tests` block at the bottom of the same file — that's where the existing unit tests live; do **not** add a new file)

### Background for the implementer

`RecoveryConfig` is the public knob struct for the JPEG recovery pass. `recover_fragmented_jpegs_with_event_log_sink` reads `carve_report.json`, builds `incomplete: Vec<&FileObject>` from every JPEG whose `jpeg_scan.status != Complete`, then iterates that list emitting `FileFound` + `RecoveryCandidate` events per kept candidate. Every `FileObject` carries a stable `file_id: u64`.

We want a new optional field `only_original_file_id: Option<u64>`. When `Some(id)`, the filter step keeps only the partial whose `file_id == id` (zero or one element). When `None` (default), behavior is unchanged.

- [ ] **Step 1: Write the failing test**

Append this test to the `#[cfg(test)] mod tests { … }` block at the bottom of `crates/utmost-lib/src/jpeg_recover.rs`. It uses the existing fixture helpers in that module (see the other `recover_fragmented_jpegs(...)` tests in the file as patterns — e.g. the test near line 763 that calls `recover_fragmented_jpegs(...).expect(...)`).

```rust
#[test]
fn only_original_file_id_scopes_recovery_to_one_partial() {
    use crate::types::{ByteRun, CarveReport, Creator, FileObject, JpegScanInfo, JpegScanStatus, Metadata};
    use tempfile::TempDir;
    use std::fs;

    // Build a synthetic source image: two complete-ish JPEG headers, both
    // marked Truncated so recovery would normally process both.
    let tmp = TempDir::new().unwrap();
    let image_path = tmp.path().join("src.img");
    // 1 MB of random-ish bytes; details don't matter for this assertion.
    let mut bytes = vec![0u8; 1024 * 1024];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    // Plant two SOI markers so the byte_run offsets are real.
    bytes[0] = 0xFF;
    bytes[1] = 0xD8;
    bytes[100_000] = 0xFF;
    bytes[100_001] = 0xD8;
    fs::write(&image_path, &bytes).unwrap();

    let make_partial = |fid: u64, offset: u64, name: &str| FileObject {
        file_id: fid,
        filename: name.to_string(),
        filesize: 1024,
        file_type: "jpeg".to_string(),
        byte_runs: vec![ByteRun {
            file_offset: 0,
            img_offset: offset,
            len: 1024,
        }],
        jpeg_scan: Some(JpegScanInfo {
            soi_img_offset: Some(offset),
            sof_kind: None,
            eoi_img_offset: None,
            fragmentation_point_img_offset: Some(offset + 1024),
            status: JpegScanStatus::Truncated,
        }),
    };

    let report = CarveReport {
        metadata: Metadata { dc_type: "Hash List".into() },
        creator: Creator {
            package: "utmost".into(),
            version: "test".into(),
            execution_environment: Default::default(),
        },
        configuration: Default::default(),
        source: Default::default(),
        fileobjects: vec![
            make_partial(10, 0, "00000001.jpg"),
            make_partial(11, 100_000, "00000002.jpg"),
        ],
    };
    let report_path = tmp.path().join("carve_report.json");
    fs::write(&report_path, serde_json::to_string(&report).unwrap()).unwrap();

    let out = tmp.path().join("out");

    // Scope recovery to file_id=10 only.
    let cfg = RecoveryConfig {
        keep_candidates: 1,
        huffman_validation: false,
        min_entropy_score: 0.0,
        min_ff_validity_score: 0.0,
        block_size: 512,
        search_window: 8192,
        max_candidates: 3,
        only_original_file_id: Some(10),
    };
    let rr = recover_fragmented_jpegs(
        image_path.to_str().unwrap(),
        report_path.to_str().unwrap(),
        out.to_str().unwrap(),
        &cfg,
    )
    .expect("recovery should succeed when scoped to one partial");

    // partials_processed counts the filtered set, not the original report.
    assert_eq!(rr.partials_processed, 1, "expected exactly one partial processed");
    // Every recovered file in the report must reference original_file_id == 10.
    for f in &rr.recovered_files {
        assert_eq!(f.original_file_id, 10, "no candidate may target file_id != 10");
    }
}
```

> **Note on `Default::default()` for nested fields above:** If `Metadata` / `Creator` / `CarveReport` fields don't `derive(Default)` in the current codebase, replace the `Default::default()` calls with concrete literals copied from an existing test. Look at the test near `jpeg_recover.rs:763` for a working construction pattern (`recover_fragmented_jpegs(...)` is called there with a real report fixture) and reuse the same field literals. The point of the test is the new filter, not report construction.

- [ ] **Step 2: Run the test to verify it fails**

Run:
```bash
cargo test -p utmost-lib --lib jpeg_recover::tests::only_original_file_id_scopes_recovery_to_one_partial -- --nocapture
```
Expected: FAIL — compile error `no field 'only_original_file_id' on type 'RecoveryConfig'`.

- [ ] **Step 3: Add the field to `RecoveryConfig`**

In `crates/utmost-lib/src/jpeg_recover.rs`, extend the `RecoveryConfig` struct (around line 54). Add the field at the end:

```rust
/// When `Some(id)`, recovery processes only the partial JPEG whose
/// `file_id == id` from the carve report; every other incomplete JPEG is
/// skipped. When `None` (default), all incomplete JPEGs are processed —
/// the historical bulk behaviour.
pub only_original_file_id: Option<u64>,
```

Update the `Default` impl right below (around line 86) to add `only_original_file_id: None,` to the struct literal.

- [ ] **Step 4: Apply the filter when collecting `incomplete`**

In `recover_fragmented_jpegs_with_event_log_sink` (around `crates/utmost-lib/src/jpeg_recover.rs:288`), change the `incomplete` builder. Current code:

```rust
let incomplete: Vec<_> = report
    .fileobjects
    .iter()
    .filter(|fo| {
        fo.file_type == "jpeg"
            && fo
                .jpeg_scan
                .as_ref()
                .map(|js| js.status != JpegScanStatus::Complete)
                .unwrap_or(false)
    })
    .collect();
```

Replace with:

```rust
let incomplete: Vec<_> = report
    .fileobjects
    .iter()
    .filter(|fo| {
        fo.file_type == "jpeg"
            && fo
                .jpeg_scan
                .as_ref()
                .map(|js| js.status != JpegScanStatus::Complete)
                .unwrap_or(false)
            && config
                .only_original_file_id
                .map_or(true, |target| fo.file_id == target)
    })
    .collect();
```

- [ ] **Step 5: Update the function's doc-comment**

Above `pub fn recover_fragmented_jpegs_with_event_log_sink` (around line 232), append a paragraph to the doc-comment table or just below it:

```rust
/// When `config.only_original_file_id` is `Some(id)`, the incomplete-JPEG
/// list is filtered down to the single `FileObject` whose `file_id == id`.
/// If the id isn't found (or its scan status is `Complete`), the function
/// returns successfully with `partials_processed = 0`.
```

- [ ] **Step 6: Run the test to verify it passes**

Run:
```bash
cargo test -p utmost-lib --lib jpeg_recover::tests::only_original_file_id_scopes_recovery_to_one_partial -- --nocapture
```
Expected: PASS.

- [ ] **Step 7: Run the rest of the lib's tests to verify no regression**

Run:
```bash
cargo test -p utmost-lib
```
Expected: every test still passes. (The default-`None` behavior should match the previous unconditional collection.)

- [ ] **Step 8: Format and lint**

Run:
```bash
cargo fmt
cargo clippy --all-targets
```
Expected: no warnings.

- [ ] **Step 9: Commit**

```bash
git add crates/utmost-lib/src/jpeg_recover.rs
git commit -m "feat(lib): scope JPEG recovery to a single file_id via RecoveryConfig.only_original_file_id"
```

---

## Task 2: GUI runner — plumb `only_original_file_id` through `RecoveryRequest`

**Files:**
- Modify: `crates/utmost-gui/src/recovery.rs`
- Test: `crates/utmost-gui/src/recovery.rs` (the existing `#[cfg(test)] mod tests` block)

### Background for the implementer

`RecoveryRequest` is the GUI-side request struct that `start_background` builds and `run_recovery_blocking` consumes. It currently carries `image_path`, `report_path`, `output_dir`, `event_log`, and `keep_candidates`. Add `only_original_file_id: Option<u64>` and pass it into the `RecoveryConfig` built on line 36.

- [ ] **Step 1: Write the failing test**

Append to the existing `#[cfg(test)] mod tests` block at the bottom of `crates/utmost-gui/src/recovery.rs`:

```rust
#[test]
fn request_carries_only_original_file_id() {
    let req = RecoveryRequest {
        image_path: "/tmp/x.img".into(),
        report_path: "/tmp/carve_report.json".into(),
        output_dir: "/tmp/out".into(),
        event_log: std::path::PathBuf::from("/tmp/x-events.bin"),
        keep_candidates: 3,
        only_original_file_id: Some(42),
    };
    assert_eq!(req.only_original_file_id, Some(42));
}
```

- [ ] **Step 2: Run it to verify it fails**

Run:
```bash
cargo test -p utmost-gui --lib recovery::tests::request_carries_only_original_file_id
```
Expected: FAIL — `RecoveryRequest` has no field `only_original_file_id`.

- [ ] **Step 3: Add the field to `RecoveryRequest`**

In `crates/utmost-gui/src/recovery.rs`, extend the struct (line 19-26):

```rust
#[derive(Debug, Clone)]
pub struct RecoveryRequest {
    pub image_path: String,
    pub report_path: String,
    pub output_dir: String,
    pub event_log: PathBuf,
    pub keep_candidates: usize,
    /// When `Some(id)`, only the partial JPEG whose `file_id == id` is
    /// processed. `None` runs the full bulk pass (legacy behaviour).
    pub only_original_file_id: Option<u64>,
}
```

- [ ] **Step 4: Forward it into `RecoveryConfig`**

In `run_recovery_blocking` (line 34), update the config builder:

```rust
let cfg = RecoveryConfig {
    keep_candidates: req.keep_candidates,
    only_original_file_id: req.only_original_file_id,
    ..RecoveryConfig::default()
};
```

- [ ] **Step 5: Run the test to verify it passes**

Run:
```bash
cargo test -p utmost-gui --lib recovery::tests::request_carries_only_original_file_id
```
Expected: PASS.

- [ ] **Step 6: Build the workspace to surface any callers we missed**

Run:
```bash
cargo build -p utmost-gui
```
Expected: build succeeds. (If a caller constructs `RecoveryRequest` by struct literal and was missed, the compile error will list it — fix it before moving on.)

- [ ] **Step 7: Format and lint**

Run:
```bash
cargo fmt
cargo clippy --all-targets
```
Expected: no warnings.

- [ ] **Step 8: Commit**

```bash
git add crates/utmost-gui/src/recovery.rs
git commit -m "feat(gui): RecoveryRequest carries only_original_file_id"
```

---

## Task 3: Slint adapter — fire recovery scoped to the selected file

**Files:**
- Modify: `crates/utmost-gui/src/slint_adapter.rs` (the `on_run_recovery` handler around line 825)

### Background for the implementer

The "Run recovery" button currently fires a bulk recovery over the whole report. We want the click to scope to `v.selection` (the currently-selected file id). If `v.selection` is `None`, the click is a no-op — the button shouldn't be visible in that case anyway (Task 4), but defending against the race where the selection clears between visibility-recompute and click is good hygiene.

This task only changes the click handler. Visibility/label updates are Task 4.

- [ ] **Step 1: Update `on_run_recovery` to pass the selection**

In `crates/utmost-gui/src/slint_adapter.rs`, find the `window.on_run_recovery(move || { … })` block (around line 825). Inside the `let req = { let v = vm_cb.lock().unwrap(); … };` scope, change the `RecoveryRequest` construction so it reads `v.selection` and bails when there is no selection:

```rust
let req = {
    let v = vm_cb.lock().unwrap();
    // Allow starting from NotRun or Finished (re-run). Bail on
    // Running (already in-flight) or Disabled (live carve active).
    if !matches!(
        v.recovery_state,
        crate::view_model::RecoveryUiState::NotRun
            | crate::view_model::RecoveryUiState::Finished
    ) {
        return;
    }
    // Per-image scope: we only run against the selected partial JPEG.
    // No selection → nothing to do.
    let Some(sel) = v.selection else { return };
    crate::recovery::RecoveryRequest {
        image_path: v.run.source_image_path.clone(),
        report_path: format!("{}/carve_report.json", v.run.output_root),
        output_dir: v.run.output_root.clone(),
        event_log,
        keep_candidates: keep,
        only_original_file_id: Some(sel),
    }
};
```

- [ ] **Step 2: Run the adapter tests**

Run:
```bash
cargo test -p utmost-gui --lib slint_adapter
```
Expected: existing tests still pass. (We haven't changed behavior the tests cover; we've only made the request carry a new field.)

- [ ] **Step 3: Format and lint**

Run:
```bash
cargo fmt
cargo clippy --all-targets
```
Expected: no warnings.

- [ ] **Step 4: Commit**

```bash
git add crates/utmost-gui/src/slint_adapter.rs
git commit -m "feat(gui): Run-recovery button scopes recovery to the selected file"
```

---

## Task 4: Slint adapter — per-selection visibility and label

**Files:**
- Modify: `crates/utmost-gui/src/slint_adapter.rs` (the per-tick resync around line 1564 where `set_recovery_button_visible` / `set_recovery_button_enabled` / `set_recovery_button_label` are called)

### Background for the implementer

Today the button is visible whenever **any** incomplete JPEG exists in the case (`has_partials`). After per-image scoping, the button should only show when the **selected** file is a partial JPEG — otherwise the user has no target.

We also want a clearer label:
- No selection or selection isn't a partial JPEG → button hidden.
- Selected partial JPEG has **no** variants yet → label `"Recover this image"`.
- Selected partial JPEG already has variants (re-run case) → label `"Re-run recovery for this image"`.
- A recovery is currently in-flight (`recovery_state == Running`) → button hidden (matches current behavior).
- Live carve still in progress (`recovery_state == Disabled`) → button disabled (matches current behavior — we keep the disabled-on-live-carve guard).

The selection's partial-ness is derived from `vm.window.get(&sel).and_then(|f| f.file.jpeg_scan.as_ref()).map(|s| s.status != Complete).unwrap_or(false)`. Note `vm.window` is keyed by lib `file_id` (since the FileId == lib file_id refactor noted at slint_adapter.rs:1456) and returns `FoundFile`-shaped data.

- [ ] **Step 1: Find the resync block**

Open `crates/utmost-gui/src/slint_adapter.rs` and locate the block starting around line 1559:

```rust
let recovery_running = matches!(
    vm.recovery_state,
    crate::view_model::RecoveryUiState::Running
);
self.window
    .set_recovery_button_visible(has_partials && !recovery_running);
// Enabled except while Running (in-flight) or Disabled (live carve in progress).
let recovery_enabled = has_partials
    && !matches!(
        vm.recovery_state,
        crate::view_model::RecoveryUiState::Running
            | crate::view_model::RecoveryUiState::Disabled
    );
self.window.set_recovery_button_enabled(recovery_enabled);
// Label: "Re-run recovery" after a successful recovery; "Run recovery" otherwise.
let recovery_label = if matches!(
    vm.recovery_state,
    crate::view_model::RecoveryUiState::Finished
) {
    "Re-run recovery"
} else {
    "Run recovery"
};
self.window
    .set_recovery_button_label(SharedString::from(recovery_label));
```

- [ ] **Step 2: Replace it with selection-aware logic**

Substitute:

```rust
let recovery_running = matches!(
    vm.recovery_state,
    crate::view_model::RecoveryUiState::Running
);
let recovery_live_disabled = matches!(
    vm.recovery_state,
    crate::view_model::RecoveryUiState::Disabled
);

// Selection must be a partial JPEG for the per-image button to make sense.
let selected_is_partial_jpeg = vm.selection.and_then(|sel| {
    vm.window.get(&sel).and_then(|f| {
        f.file.jpeg_scan.as_ref().map(|s| {
            s.status != utmost_lib::types::JpegScanStatus::Complete
        })
    })
}).unwrap_or(false);

// Has the selected partial already accumulated variants (i.e. been
// recovered before)? Re-run label hint.
let selected_has_variants = vm
    .selection
    .map(|sel| {
        vm.variants
            .get(&sel)
            .map(|vs| !vs.variant_ids.is_empty())
            .unwrap_or(false)
    })
    .unwrap_or(false);

self.window.set_recovery_button_visible(
    selected_is_partial_jpeg && !recovery_running,
);
self.window.set_recovery_button_enabled(
    selected_is_partial_jpeg && !recovery_running && !recovery_live_disabled,
);
let recovery_label = if selected_has_variants {
    "Re-run recovery for this image"
} else {
    "Recover this image"
};
self.window
    .set_recovery_button_label(SharedString::from(recovery_label));
```

> If `utmost_lib::types::JpegScanStatus` isn't already in scope at that file location, add `use utmost_lib::types::JpegScanStatus;` to the top-of-file `use` block and reference it bare in the new code. (Look at how other `utmost_lib::types::...` references in this file are imported — match the existing style.)

- [ ] **Step 3: Verify the workspace builds**

Run:
```bash
cargo build -p utmost-gui
```
Expected: build succeeds.

- [ ] **Step 4: Run the GUI test suite**

Run:
```bash
cargo test -p utmost-gui
```
Expected: passes. (No existing test asserts the global `has_partials` visibility model, so this should be green. If a test fails because it set up a partial-JPEG case but no selection, fix the test to also set a selection — that matches the new product behavior.)

- [ ] **Step 5: Format and lint**

Run:
```bash
cargo fmt
cargo clippy --all-targets
```
Expected: no warnings.

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-gui/src/slint_adapter.rs
git commit -m "feat(gui): recovery button visibility and label follow the selected file"
```

---

## Task 5: End-to-end test — per-image scope produces variants for one file only

**Files:**
- Modify: `crates/utmost-gui/tests/recovery_pipeline_e2e.rs` (extend with a new test function — do not replace the existing one)

### Background for the implementer

The existing e2e test seeds a case with one partial JPEG (`partial_fid = 10`) and verifies recovery populates variants. We want a sibling test that seeds **two** partial JPEGs and asserts:
- Only the targeted partial gains variants.
- The non-targeted partial's `vm.variants` entry stays empty (or absent).

The fixture builders in `crates/utmost-gui/tests/fixtures/` (look in there for a `build_partial_jpeg` / `build_complete_jpeg` helper — the existing test uses these) take a `file_id` and offset. Mirror that test's structure.

- [ ] **Step 1: Open the existing test**

Read `crates/utmost-gui/tests/recovery_pipeline_e2e.rs` end-to-end to learn the fixture patterns (how it writes the bincode log, the source image, the carve report, then drives `recover_fragmented_jpegs_with_event_log_sink`). The new test reuses everything except: it adds a second partial JPEG with a different `file_id` and sets `only_original_file_id` on `RecoveryConfig`.

- [ ] **Step 2: Append a new test function**

Append a new `#[test]` function to the bottom of `crates/utmost-gui/tests/recovery_pipeline_e2e.rs`. Name it `recovery_only_original_file_id_isolates_variants`. It must:

  1. Build a TempDir with a synthetic source image holding **two** partial JPEGs at different offsets (re-use whatever helper the existing test uses; if the helper takes one fid, call it twice with different fids — say `10` and `11` — and concatenate the bytes).
  2. Write a `carve_report.json` listing **both** as `FileObject`s with `JpegScanStatus::Truncated`.
  3. Pre-seed the bincode event log with `RunStarted` + `FileFound` events for both partials so the fresh `ViewModel` knows they exist.
  4. Call `recover_fragmented_jpegs_with_event_log_sink` with `RecoveryConfig { only_original_file_id: Some(10), …relaxed-thresholds-from-existing-test… }`.
  5. Drain the channel into the VM via `vm.apply(&ev)`.
  6. Assert:
     ```rust
     assert!(
         vm.variants.get(&10).map(|vs| !vs.variant_ids.is_empty()).unwrap_or(false),
         "expected at least one candidate for fid=10",
     );
     assert!(
         vm.variants.get(&11).map(|vs| vs.variant_ids.is_empty()).unwrap_or(true),
         "fid=11 must not have variants when recovery is scoped to fid=10",
     );
     ```

> The exact fixture-call shape depends on what helpers exist in `tests/fixtures/`. Read them first; copy the pattern; don't invent helpers. If no two-partial helper exists, build the second partial inline by repeating the existing single-partial fixture's body with a different `file_id` and a different `img_offset`.

- [ ] **Step 3: Run the new test**

Run:
```bash
cargo test -p utmost-gui --test recovery_pipeline_e2e recovery_only_original_file_id_isolates_variants -- --nocapture
```
Expected: PASS.

- [ ] **Step 4: Run the whole GUI test suite**

Run:
```bash
cargo test -p utmost-gui
```
Expected: every test passes.

- [ ] **Step 5: Format and lint**

Run:
```bash
cargo fmt
cargo clippy --all-targets
```
Expected: no warnings.

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-gui/tests/recovery_pipeline_e2e.rs
git commit -m "test(gui): per-image recovery scope isolates variants to the targeted file_id"
```

---

## Task 6: Docs

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`

### Background

Per the project's "Developer Documentation Rule" (see CLAUDE.md), any behavioral change visible to developers/users gets a README note. The GUI section in CLAUDE.md also needs to mention the per-image scope so future agents understand the model.

- [ ] **Step 1: Update README**

In `README.md`, find the section that describes the GUI's "Run recovery" button (search for `Run recovery` or `recovery`). Append (or insert near the existing recovery description):

```markdown
**Per-image recovery.** The "Recover this image" button in the detail panel
operates on the currently-selected partial JPEG only. Recovered candidates
appear as variants of that image (in the variant strip / variant viewer) and
do **not** show up in the main file grid. To recover another partial, select
it and click again. Use the **Keep** spinbox to cap how many candidate
reassemblies to write per click (default 5, max 10).
```

If no such section exists yet, add one under the GUI heading.

- [ ] **Step 2: Update CLAUDE.md**

In `CLAUDE.md`, find the `## GUI: case model` section. Append a new bullet after the live-picker-updates block (or wherever recovery is most adjacent):

```markdown
**Per-image recovery scope.** The "Recover this image" button in the detail
panel fires `recover_fragmented_jpegs_with_event_log_sink` with
`RecoveryConfig.only_original_file_id = Some(vm.selection)`. The lib filters
the carve-report's incomplete-JPEG list down to that single `file_id` before
running the entropy / Huffman pipeline. Recovered candidates land as
`RecoveryCandidate` events that the view-model files under
`variants[original_file_id]` (and adds to `variant_of` so they're excluded
from the main grid). Bulk recovery — operating on every incomplete JPEG in
one click — is **not** currently exposed in the GUI; if it's wanted later,
pass `only_original_file_id: None`.
```

- [ ] **Step 3: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: per-image recovery scope in GUI"
```

---

## Final verification

- [ ] **Step 1: Full workspace test**

Run:
```bash
cargo test
```
Expected: every test in every crate passes.

- [ ] **Step 2: Full workspace lint**

Run:
```bash
cargo fmt
cargo clippy --all-targets
```
Expected: no warnings.

- [ ] **Step 3: Manual smoke test in the GUI**

Run the GUI against a case that contains at least two partial JPEGs (any prior carve output with `.jpg` partials works). Click into the detail view. Select a partial JPEG → "Recover this image" button is visible. Click it. Wait for the variant strip to populate. Select a different partial JPEG → its variant strip is **empty** (it was not touched). Click "Recover this image" on the second one. Both files now have variants; neither file's candidates show up in the main grid.

Approximate commands:
```bash
cargo run -p utmost-cli -- --gui -t jpeg some-disk-image.bin -o /tmp/utmost-test/
# or against an existing output dir:
cargo run -p utmost-viewer -- /tmp/utmost-test/
```

If the button is visible on a non-partial selection, the visibility gate in Task 4 is wrong — fix the predicate and re-run.

- [ ] **Step 4: Final commit (if any leftover formatting changes)**

If `cargo fmt` produced any uncommitted hunks:

```bash
git add -u
git commit -m "chore: cargo fmt"
```
