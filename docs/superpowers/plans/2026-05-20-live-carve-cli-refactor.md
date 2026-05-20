# Live-carve CLI refactor (Plan 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `utmost --gui f1.img f2.img -o out/` launches the picker with one Running row per source, rows update live as each carve progresses, and closing the GUI window does not abort the carve — the process stays alive until carves finish.

**Architecture:** events.bin is the only communication channel between carve and GUI. Carve thread is joined (not detached) by the CLI after `run_picker` returns. The picker holds a per-row `PickerRowTailer` that incrementally reads each Running case's events.bin on a 1 Hz Slint timer. The indexer-writer thread (spawned by `open_case`) tails past EOF until `shutdown_signal` is set. `CaseSource::Live`, the per-source `ChannelSink`, `run_live`, and `launch_ui_with_journal` are all deleted.

**Tech Stack:** Rust, Slint, Diesel + SQLite, crossbeam_channel (still used for indexer command/event channels and progress, just not for carve→GUI events), tracing.

**Spec:** `docs/superpowers/specs/2026-05-20-live-carve-cli-refactor-design.md`

---

## File structure

**Modify:**
- `crates/utmost-gui/src/indexer_thread.rs` — `rebuild_from_zero` and `resume_from` loops become tail-until-shutdown; new module-private consts `TAIL_POLL_INTERVAL_MS`, `MAX_CONSECUTIVE_ERRORS`.
- `crates/utmost-gui/src/case.rs` — delete `CaseSource::Live` variant, `CaseSource::events_bin()` accessor, `CaseHandle.vm_event_tx` field; rewrite `open_case`'s source-matching to one variant; delete the Live-rejection guard.
- `crates/utmost-gui/src/picker.rs` — add `PickerRowState`, `PickerRowTailer`, `PickerRowTailer::open_fresh`, `reopen`, `poll`, `to_descriptor` + unit tests for each.
- `crates/utmost-gui/src/lib.rs` — `run_picker` adds `perf: Arc<PerfRecorder>` parameter and drops its internal `init_telemetry()` call; new `tailers_rc` map + 1 Hz Slint timer + drop-on-case-clicked / recreate-on-back lifecycle; deletes `run_live` and `launch_ui_with_journal`; deletes the TODO(Plan 2) Live-coercion workaround.
- `crates/utmost-cli/src/main.rs` — `--gui` branch builds `Vec<CaseSource::Historical>` from `plan`, spawns the carve as a joinable handle, passes its existing `perf` clone to `run_picker`, joins `carve_handle` after `run_picker` returns. Deletes the shared `ChannelSink` construction and the "main_log = first source" hack.
- `crates/utmost-viewer/src/main.rs` — init telemetry locally and pass `perf` into `run_picker`.

**Create:**
- `crates/utmost-gui/tests/picker_live_refresh.rs` — integration tests for live-carve picker behavior.

**Documentation:**
- `CLAUDE.md` — adjust the "GUI: case model" section: delete the Plan-1 caveat about `run_live` still being legacy; add the live-tail subsection; note that `utmost --gui` carves survive window close.

---

## Task 1: Indexer-writer tail loop

**Files:**
- Modify: `crates/utmost-gui/src/indexer_thread.rs` — change the `rebuild_from_zero` and `resume_from` loops to tail past EOF until `shutdown_signal` is set; add error-retry cap.

### Step 1: Add the module-private constants

In `crates/utmost-gui/src/indexer_thread.rs`, near the existing module constants (search for `PROGRESS_TICK_BYTES`), add:

```rust
const TAIL_POLL_INTERVAL_MS: u64 = 500;
const MAX_CONSECUTIVE_ERRORS: u32 = 10;
```

### Step 2: Write the failing test `tail_loop_picks_up_events_appended_after_initial_eof`

Add to the `#[cfg(test)] mod tests` block in `indexer_thread.rs`:

```rust
#[test]
fn tail_loop_picks_up_events_appended_after_initial_eof() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use tempfile::TempDir;
    use utmost_lib::events::{BincodeFileSink, CarveEvent, EventSink};
    use utmost_lib::reporting::create_file_object;
    use utmost_lib::types::FileType;

    let tmp = TempDir::new().unwrap();
    let bin = tmp.path().join("tail-events.bin");

    // Initial log: RunStarted only.
    {
        let sink = BincodeFileSink::create(&bin).expect("create");
        sink.emit(&make_run_started_for_tests());
    }

    // Spawn the indexer. It must observe EOF, sleep, then pick up appended events.
    let (tx, rx) = crossbeam_channel::unbounded();
    let vm = std::sync::Arc::new(std::sync::Mutex::new(
        crate::view_model::ViewModel::new()
    ));
    let shutdown = std::sync::Arc::new(AtomicBool::new(false));
    let h = spawn(bin.clone(), vm.clone(), tx, shutdown.clone());

    // Wait for the indexer to reach its first EOF — it emits Started + maybe
    // a few progress ticks during the initial pass, then sleeps. Confirm by
    // observing the file_id 1 row landed in sqlite. Then append more events.
    std::thread::sleep(Duration::from_millis(700));
    {
        let sink = BincodeFileSink::open_append(&bin).expect("append");
        for i in 1..=50u64 {
            sink.emit(&CarveEvent::FileFound {
                source_id: 0,
                file: create_file_object("a.jpg", FileType::Jpeg, 0, 0, None, i),
                img_offset: 0,
                written_path: "a.jpg".into(),
            });
        }
    }

    // Give the tail loop time to pick up the appended events (one
    // TAIL_POLL_INTERVAL_MS + a slack budget).
    std::thread::sleep(Duration::from_millis(1500));

    // Signal shutdown and join.
    shutdown.store(true, Ordering::Relaxed);
    h.join().expect("indexer join");

    // Confirm the appended events landed by reading the sqlite directly.
    let sqlite_path = crate::picker::sqlite_path_for(&bin);
    let mut db = crate::index_db::IndexDb::open(&sqlite_path).expect("reopen");
    use crate::index_db::schema::file::dsl as f;
    use diesel::prelude::*;
    let count: i64 = f::file.count().get_result(db.conn()).unwrap();
    assert_eq!(count, 50, "tail loop must have folded the appended events");

    // Drain progress messages — at least Started should be present.
    let msgs: Vec<_> = rx.try_iter().collect();
    assert!(matches!(msgs.first(), Some(IndexProgress::Started { .. })));
    // No Finished message — we shut down via the signal, not at EOF.
}
```

`make_run_started_for_tests()` is the helper added in Plan 1's persistence Task 4. It already exists in this file.

### Step 3: Run the test; expect FAIL

```bash
cargo test -p utmost-gui --lib indexer_thread::tests::tail_loop_picks_up_events_appended_after_initial_eof -- --nocapture
```

Expected: FAIL (today's loop exits at EOF; the 50 appended events never get folded; assertion `count == 50` fails — likely `count == 0`).

### Step 4: Rewrite `rebuild_from_zero` with the tail loop

In `crates/utmost-gui/src/indexer_thread.rs`, find `fn rebuild_from_zero` (around line 152). Replace the body's while-loop with the tail loop. The full function becomes:

```rust
fn rebuild_from_zero(
    bin: &Path,
    db: &mut IndexDb,
    vm: &Arc<Mutex<ViewModel>>,
    progress: Option<&Sender<IndexProgress>>,
    shutdown: Option<&Arc<AtomicBool>>,
) -> Result<()> {
    let mut reader = BincodeFileReader::open(bin)?;
    let mut writer = IndexDbWriter::new(db.conn(), 5000);
    let mut files_seen: u64 = 0;
    let mut last_tick_offset: u64 = 0;
    let mut consecutive_errors: u32 = 0;

    loop {
        if let Some(s) = shutdown
            && s.load(Ordering::Relaxed)
        {
            writer.flush()?;
            return Ok(());
        }
        match reader.next_event() {
            Ok(Some(ev)) => {
                consecutive_errors = 0;
                let offset_after = reader.byte_offset()?;
                if matches!(ev, utmost_lib::events::CarveEvent::FileFound { .. }) {
                    files_seen += 1;
                }
                {
                    let mut v = vm.lock().unwrap();
                    v.apply(&ev);
                }
                writer.apply(ev, offset_after)?;
                if let Some(tx) = progress
                    && offset_after.saturating_sub(last_tick_offset) >= PROGRESS_TICK_BYTES
                {
                    let _ = tx.send(IndexProgress::Bytes { read: offset_after });
                    let _ = tx.send(IndexProgress::Files { count: files_seen });
                    last_tick_offset = offset_after;
                }
            }
            Ok(None) => {
                consecutive_errors = 0;
                writer.flush()?;
                std::thread::sleep(std::time::Duration::from_millis(TAIL_POLL_INTERVAL_MS));
            }
            Err(e) => {
                consecutive_errors += 1;
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                    tracing::warn!(
                        "indexer giving up after {consecutive_errors} consecutive errors: {e:#}"
                    );
                    writer.flush()?;
                    return Ok(());
                }
                tracing::debug!(
                    "indexer tail retry {consecutive_errors}/{MAX_CONSECUTIVE_ERRORS} after: {e:#}"
                );
                writer.flush()?;
                std::thread::sleep(std::time::Duration::from_millis(TAIL_POLL_INTERVAL_MS));
            }
        }
    }
}
```

### Step 5: Apply the same loop to `resume_from`

In the same file, find `fn resume_from` (around line 332). Make the body identical to `rebuild_from_zero` after the seek. The full function becomes:

```rust
fn resume_from(
    bin: &Path,
    from: u64,
    db: &mut IndexDb,
    vm: &Arc<Mutex<ViewModel>>,
    progress: Option<&Sender<IndexProgress>>,
    shutdown: Option<&Arc<AtomicBool>>,
) -> Result<()> {
    let mut reader = BincodeFileReader::open(bin)?;
    reader.seek_to(from)?;
    let mut writer = IndexDbWriter::new(db.conn(), 5000);
    let mut files_seen: u64 = 0;
    let mut last_tick_offset: u64 = from;
    let mut consecutive_errors: u32 = 0;

    loop {
        if let Some(s) = shutdown
            && s.load(Ordering::Relaxed)
        {
            writer.flush()?;
            return Ok(());
        }
        match reader.next_event() {
            Ok(Some(ev)) => {
                consecutive_errors = 0;
                let offset_after = reader.byte_offset()?;
                if matches!(ev, utmost_lib::events::CarveEvent::FileFound { .. }) {
                    files_seen += 1;
                }
                {
                    let mut v = vm.lock().unwrap();
                    v.apply(&ev);
                }
                writer.apply(ev, offset_after)?;
                if let Some(tx) = progress
                    && offset_after.saturating_sub(last_tick_offset) >= PROGRESS_TICK_BYTES
                {
                    let _ = tx.send(IndexProgress::Bytes { read: offset_after });
                    let _ = tx.send(IndexProgress::Files { count: files_seen });
                    last_tick_offset = offset_after;
                }
            }
            Ok(None) => {
                consecutive_errors = 0;
                writer.flush()?;
                std::thread::sleep(std::time::Duration::from_millis(TAIL_POLL_INTERVAL_MS));
            }
            Err(e) => {
                consecutive_errors += 1;
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                    tracing::warn!(
                        "indexer giving up after {consecutive_errors} consecutive errors: {e:#}"
                    );
                    writer.flush()?;
                    return Ok(());
                }
                tracing::debug!(
                    "indexer tail retry {consecutive_errors}/{MAX_CONSECUTIVE_ERRORS} after: {e:#}"
                );
                writer.flush()?;
                std::thread::sleep(std::time::Duration::from_millis(TAIL_POLL_INTERVAL_MS));
            }
        }
    }
}
```

### Step 6: Run the test; expect PASS

```bash
cargo test -p utmost-gui --lib indexer_thread::tests::tail_loop_picks_up_events_appended_after_initial_eof -- --nocapture
```

Expected: PASS.

### Step 7: Verify existing indexer tests still pass

```bash
cargo test -p utmost-gui --lib indexer_thread::tests 2>&1 | tail -10
cargo test -p utmost-gui --test index_db_progress_signals 2>&1 | tail -10
```

Expected: all pass. The pre-existing `progress_sequence_started_optional_ticks_finished` test SHOULD still pass — it sends `Shutdown` via the cmd channel, which exits run_query_loop, but the writer/spawn path uses its own shutdown_signal (set during close_case). Wait — that test calls `spawn` directly with an `AtomicBool::new(false)` and joins the thread. The thread will now tail forever after consuming the 200 fixture events.

This is a regression of that test's expectation. Adapt the existing test by setting the shutdown signal after a reasonable wait, OR by writing a RunFinished event to the log so... no, we always tail until shutdown. The clean fix is to adapt the test: after appending events, set shutdown, then join.

### Step 8: Adapt the pre-existing `progress_sequence_started_optional_ticks_finished` test

In `crates/utmost-gui/tests/index_db_progress_signals.rs`, find the existing test:

```rust
let h = spawn(bin.clone(), vm, tx, shutdown);
h.join().unwrap();
```

The `h.join()` call now blocks forever because spawn's body never exits at EOF. Adapt by triggering shutdown shortly before joining:

```rust
let shutdown = Arc::new(AtomicBool::new(false));
let h = spawn(bin.clone(), vm, tx, shutdown.clone());

// Give the indexer time to consume the 200 fixture events and reach EOF.
std::thread::sleep(std::time::Duration::from_millis(500));
shutdown.store(true, std::sync::atomic::Ordering::Relaxed);

h.join().unwrap();
```

Also adapt the test's final assertion: it currently asserts `msgs.last() == Some(IndexProgress::Finished)`. With tail mode, Finished is no longer emitted (the indexer exits via shutdown, not at EOF). Change:

```rust
// Was: assert!(matches!(msgs.last(), Some(IndexProgress::Finished)));
// Now: just confirm Started is present at the head.
assert!(matches!(msgs.first(), Some(IndexProgress::Started { .. })));
```

The other test in the same file (`pre_set_shutdown_short_circuits_indexer`) is unaffected — it sets shutdown=true before spawn, so the loop's first iteration takes the shutdown branch.

### Step 9: Re-run the integration test

```bash
cargo test -p utmost-gui --test index_db_progress_signals 2>&1 | tail -10
```

Expected: 2 passed, 0 failed.

### Step 10: Write the second test `tail_loop_recovers_from_partial_frame_at_tail`

Append to the same `#[cfg(test)] mod tests` block in `indexer_thread.rs`:

```rust
#[test]
fn tail_loop_recovers_from_partial_frame_at_tail() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use tempfile::TempDir;
    use utmost_lib::events::{BincodeFileSink, CarveEvent, EventSink};
    use utmost_lib::reporting::create_file_object;
    use utmost_lib::types::FileType;

    let tmp = TempDir::new().unwrap();
    let bin = tmp.path().join("partial-events.bin");

    // Initial log: RunStarted only.
    {
        let sink = BincodeFileSink::create(&bin).expect("create");
        sink.emit(&make_run_started_for_tests());
    }

    let (tx, _rx) = crossbeam_channel::unbounded();
    let vm = std::sync::Arc::new(std::sync::Mutex::new(
        crate::view_model::ViewModel::new()
    ));
    let shutdown = std::sync::Arc::new(AtomicBool::new(false));
    let h = spawn(bin.clone(), vm.clone(), tx, shutdown.clone());

    // Wait for the indexer to reach its first EOF.
    std::thread::sleep(Duration::from_millis(700));

    // Truncate-extend: write a tiny partial frame (just a length prefix, no
    // body) to simulate a writer mid-frame. The reader should see this as
    // an Err on next_event, retry, and eventually succeed once we append a
    // full event.
    use std::io::Write;
    {
        let mut f = std::fs::OpenOptions::new().append(true).open(&bin).unwrap();
        f.write_all(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap(); // 4 bytes of garbage
        f.flush().unwrap();
    }
    std::thread::sleep(Duration::from_millis(700));

    // The indexer's `consecutive_errors` counter is now > 0. Below the cap,
    // it should keep tailing. To prove it can recover, we can't easily
    // overwrite the garbage in-place — so instead just confirm the thread
    // is still alive (didn't exit due to the error) and shutdown cleanly.
    assert!(!h.is_finished(), "indexer must still be tailing despite the corrupt tail bytes");

    shutdown.store(true, Ordering::Relaxed);
    h.join().expect("indexer join");
}
```

### Step 11: Run the test; expect PASS

```bash
cargo test -p utmost-gui --lib indexer_thread::tests::tail_loop_recovers_from_partial_frame_at_tail -- --nocapture
```

Expected: PASS.

### Step 12: Write the third test `tail_loop_gives_up_after_max_consecutive_errors`

```rust
#[test]
fn tail_loop_gives_up_after_max_consecutive_errors() {
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;
    use tempfile::TempDir;

    let tmp = TempDir::new().unwrap();
    let bin = tmp.path().join("corrupt-events.bin");

    // Write a valid header so BincodeFileReader::open succeeds, then
    // garbage bytes that look like a length-prefixed frame.
    {
        use utmost_lib::events::{BincodeFileSink, EventSink};
        let sink = BincodeFileSink::create(&bin).expect("create");
        sink.emit(&make_run_started_for_tests());
    }
    // Append garbage that will fail to deserialize repeatedly.
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&bin).unwrap();
        // A length prefix of 0xFFFFFFFF claims a huge frame; the actual bytes
        // are garbage that bincode will reject every time the reader tries.
        for _ in 0..10 {
            f.write_all(&[0xFF, 0xFF, 0xFF, 0xFF, 0x00]).unwrap();
        }
        f.flush().unwrap();
    }

    let (tx, _rx) = crossbeam_channel::unbounded();
    let vm = std::sync::Arc::new(std::sync::Mutex::new(
        crate::view_model::ViewModel::new()
    ));
    let shutdown = std::sync::Arc::new(AtomicBool::new(false));

    let h = spawn(bin.clone(), vm.clone(), tx, shutdown);

    // MAX_CONSECUTIVE_ERRORS * TAIL_POLL_INTERVAL_MS = ~5 seconds.
    // Wait a generous 7 seconds for the indexer to exhaust the budget
    // and exit on its own — without us setting shutdown.
    let start = std::time::Instant::now();
    while !h.is_finished() && start.elapsed() < Duration::from_secs(8) {
        std::thread::sleep(Duration::from_millis(200));
    }

    assert!(
        h.is_finished(),
        "indexer must exit on its own after MAX_CONSECUTIVE_ERRORS"
    );
    h.join().expect("indexer join");
}
```

### Step 13: Run the test; expect PASS

```bash
cargo test -p utmost-gui --lib indexer_thread::tests::tail_loop_gives_up_after_max_consecutive_errors -- --nocapture
```

Expected: PASS within ~5–6 seconds.

### Step 14: fmt + clippy + commit

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -10
git add crates/utmost-gui/src/indexer_thread.rs crates/utmost-gui/tests/index_db_progress_signals.rs
git commit -m "$(cat <<'EOF'
feat(gui): indexer-writer tails events.bin until shutdown_signal

Replaces the "exit at EOF" loop in rebuild_from_zero/resume_from
with a tail loop: read events; on EOF, flush + sleep + retry; on
Err, retry up to MAX_CONSECUTIVE_ERRORS times then give up. Only
shutdown_signal exits the loop naturally now. writer.flush() runs
before every sleep so last_event_offset stays durable across a
hard process exit.

Adapts the pre-existing progress_sequence test which assumed
Finished would land at EOF.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Delete `CaseSource::Live` / `vm_event_tx` / `events_bin()`

**Files:**
- Modify: `crates/utmost-gui/src/case.rs`
- Modify: `crates/utmost-gui/src/lib.rs` — the Live-coercion workaround in `run_picker`.

### Step 1: Delete the `Live` variant and `events_bin()` accessor

In `crates/utmost-gui/src/case.rs`, find the `CaseSource` enum (around line 21). Replace with:

```rust
/// Where a case's events.bin lives. Single-variant for now; kept as an
/// enum so future variants (e.g. remote URL) have a place to land.
pub enum CaseSource {
    Historical(PathBuf),
}
```

Delete the `impl CaseSource { pub fn events_bin(&self) -> &PathBuf { ... } }` block — single-variant pattern-match is just as readable, and the only callers will need to adjust (see below).

Delete the unused `use crossbeam_channel::{Receiver, Sender};` line if it only existed for the Live variant's `event_rx: Receiver<CarveEvent>` field. Check by re-reading the file's imports after the deletion.

Delete the `use utmost_lib::events::CarveEvent;` line if it was only used for Live.

### Step 2: Delete `CaseHandle.vm_event_tx`

In the same file, find the `pub struct CaseHandle` definition. Delete the `vm_event_tx` field (currently `#[allow(dead_code)] pub vm_event_tx: Option<Sender<CarveEvent>>,`).

In `open_case`'s body, find the `let vm_event_tx = None;` line and the `vm_event_tx,` line in the `Ok(CaseHandle { … })` constructor. Delete both.

### Step 3: Rewrite `open_case`'s source-matching

In `open_case`'s body, find:

```rust
let events_bin = match &source {
    CaseSource::Historical(p) => p.clone(),
    CaseSource::Live { .. } => {
        anyhow::bail!("open_case: Live variant not yet supported (Plan 2)");
    }
};
```

Replace with:

```rust
let CaseSource::Historical(events_bin) = source;
let events_bin = events_bin.clone();
```

(With single-variant enums, the destructuring `let` works directly.)

### Step 4: Delete the Live workaround in `run_picker`

In `crates/utmost-gui/src/lib.rs`, find the `// TODO(Plan 2): CaseSource::Live entries are coerced to Historical here;` comment and the `let sorted_sources` map below it. The block currently looks like:

```rust
let sorted_sources: Vec<case::CaseSource> = rows
    .iter()
    .map(|r| case::CaseSource::Historical(r.events_bin_path.clone()))
    .collect();
```

Since every entry in `rows` came from a `CaseSource::Historical` to begin with (it's the only variant now), the rebuild is redundant. Replace by passing through the original `initial` directly:

```rust
let sorted_sources: Vec<case::CaseSource> = initial;
```

(This consumes `initial`; make sure no later code in `run_picker` reads `initial`. If the body re-uses it, clone before consuming or restructure.)

Also delete the per-source placeholder branch in `run_picker`'s initial-row mapping:

```rust
case::CaseSource::Live { events_bin, .. } => picker::CaseRowDescriptor {
    /* … placeholder Running row … */
},
```

After deletion the `match s` becomes a single-arm match — collapse it to a `let CaseSource::Historical(p) = s; picker::build_case_row(p)` pattern, or use a method call.

### Step 5: Build to check the fallout

```bash
cargo build -p utmost-gui 2>&1 | tail -20
```

Expected: clean build. If clippy or rustc complains about unused imports/dead code in case.rs or lib.rs, remove them.

### Step 6: Run all tests

```bash
cargo test -p utmost-gui 2>&1 | tail -15
```

Expected: all pass.

### Step 7: fmt + clippy + commit

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -10
git add crates/utmost-gui/src/case.rs crates/utmost-gui/src/lib.rs
git commit -m "$(cat <<'EOF'
refactor(gui): collapse CaseSource to single Historical variant

The polling-based live-carve design (Plan 2) makes Live and
Historical indistinguishable from the picker's perspective —
both are just paths to events.bin files that may or may not be
actively being written. Deletes:
- CaseSource::Live variant
- CaseSource::events_bin() accessor
- CaseHandle.vm_event_tx field
- The Live-rejection guard in open_case
- The TODO(Plan 2) coercion workaround in run_picker

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: `PickerRowState` + `PickerRowTailer`

**Files:**
- Modify: `crates/utmost-gui/src/picker.rs` — add the two structs and their methods.

### Step 1: Add `PickerRowState` and skeletal `PickerRowTailer`

In `crates/utmost-gui/src/picker.rs`, append after the existing types section (after the `CaseRowDescriptor` / `PickerStatus` declarations):

```rust
/// Persistent per-row state the picker carries to incrementally update a
/// Running row from its events.bin without re-reading the whole log on
/// each tick. Lives across detail-view transitions (drop the tailer, keep
/// the state). The picker maintains a `HashMap<PathBuf, PickerRowState>`
/// indexed by `events_bin` path.
#[derive(Clone, Debug)]
pub(crate) struct PickerRowState {
    pub events_bin: std::path::PathBuf,
    pub files_seen: u64,
    pub last_offset: u64,
    pub started_at: String,
    pub source_path: String,
    pub finished: bool,
    pub corrupt_retries_remaining: u8,
}

impl PickerRowState {
    /// Initial state when nothing has been read yet. Use only for rows
    /// that initially failed `build_case_row` (Corrupt status); rows
    /// with real metadata should be populated from the build_case_row
    /// descriptor.
    pub(crate) fn for_retry(events_bin: std::path::PathBuf) -> Self {
        Self {
            events_bin,
            files_seen: 0,
            last_offset: 0,
            started_at: String::new(),
            source_path: String::new(),
            finished: false,
            corrupt_retries_remaining: 3,
        }
    }
}

/// Active tailer: holds the file handle while the picker is visible.
/// Dropped when a case is opened in detail view; recreated on back-out.
pub(crate) struct PickerRowTailer {
    pub state: PickerRowState,
    reader: utmost_lib::events::BincodeFileReader,
}
```

### Step 2: Write the failing test `open_fresh_reads_run_started`

In the `#[cfg(test)] mod tests` block in `picker.rs`:

```rust
#[test]
fn picker_row_tailer_open_fresh_reads_run_started() {
    let tmp = TempDir::new().unwrap();
    let log = tmp.path().join("t-events.bin");
    write_log(&log, &[make_run_started("/in/t.img")]);

    let tailer = PickerRowTailer::open_fresh(&log).expect("open_fresh");
    assert_eq!(tailer.state.events_bin, log);
    assert_eq!(tailer.state.source_path, "/in/t.img");
    assert_ne!(tailer.state.started_at, "");
    assert_eq!(tailer.state.files_seen, 0);
    assert!(!tailer.state.finished);
    assert_eq!(tailer.state.corrupt_retries_remaining, 3);
}
```

The existing `make_run_started` and `write_log` helpers in `picker.rs::tests` populate `RunStarted` with a known `sources[0].filename` and `started_at`.

### Step 3: Run the test; expect FAIL ("open_fresh not defined")

```bash
cargo test -p utmost-gui --lib picker::tests::picker_row_tailer_open_fresh_reads_run_started -- --nocapture
```

Expected: FAIL (no such method).

### Step 4: Implement `PickerRowTailer::open_fresh`

In `crates/utmost-gui/src/picker.rs`, add to the `impl PickerRowTailer` block (or create one):

```rust
impl PickerRowTailer {
    /// Open a tailer at the start of `events_bin`. Reads the first event
    /// (must be `RunStarted`) to populate `started_at` and `source_path`.
    /// Returns `None` if the file can't be opened or the first event isn't
    /// `RunStarted`.
    pub(crate) fn open_fresh(events_bin: &Path) -> Option<Self> {
        use utmost_lib::events::{BincodeFileReader, CarveEvent};
        let mut reader = BincodeFileReader::open(events_bin).ok()?;
        let first = reader.next_event().ok().flatten()?;
        let (started_at, source_path) = match first {
            CarveEvent::RunStarted { started_at, sources, .. } => {
                let sp = sources
                    .first()
                    .map(|s| s.filename.clone())
                    .unwrap_or_default();
                (started_at, sp)
            }
            _ => return None,
        };
        let last_offset = reader.byte_offset().ok()?;
        Some(Self {
            state: PickerRowState {
                events_bin: events_bin.to_path_buf(),
                files_seen: 0,
                last_offset,
                started_at,
                source_path,
                finished: false,
                corrupt_retries_remaining: 3,
            },
            reader,
        })
    }
}
```

### Step 5: Run the test; expect PASS

```bash
cargo test -p utmost-gui --lib picker::tests::picker_row_tailer_open_fresh_reads_run_started -- --nocapture
```

Expected: PASS.

### Step 6: Write the failing test `advances_files_seen_on_appended_event`

```rust
#[test]
fn picker_row_tailer_advances_files_seen_on_appended_event() {
    use utmost_lib::reporting::create_file_object;
    use utmost_lib::types::FileType;

    let tmp = TempDir::new().unwrap();
    let log = tmp.path().join("t-events.bin");
    write_log(&log, &[make_run_started("/in/t.img")]);

    let mut tailer = PickerRowTailer::open_fresh(&log).expect("open_fresh");
    assert_eq!(tailer.state.files_seen, 0);

    // Append one FileFound.
    use utmost_lib::events::{BincodeFileSink, CarveEvent, EventSink};
    let sink = BincodeFileSink::open_append(&log).expect("append");
    sink.emit(&CarveEvent::FileFound {
        source_id: 0,
        file: create_file_object("a.jpg", FileType::Jpeg, 0, 0, None, 1),
        img_offset: 0,
        written_path: "a.jpg".into(),
    });
    drop(sink); // flush

    let changed = tailer.poll();
    assert!(changed, "poll() must report change after FileFound appended");
    assert_eq!(tailer.state.files_seen, 1);
    assert!(!tailer.state.finished);
}
```

### Step 7: Run the test; expect FAIL ("poll not defined")

### Step 8: Implement `PickerRowTailer::poll`

```rust
impl PickerRowTailer {
    /// Drain any newly-available events from the reader. Returns true iff
    /// `state.files_seen` advanced or `state.finished` was set.
    pub(crate) fn poll(&mut self) -> bool {
        use utmost_lib::events::CarveEvent;
        let mut changed = false;
        loop {
            match self.reader.next_event() {
                Ok(Some(ev)) => {
                    if matches!(ev, CarveEvent::FileFound { .. }) {
                        self.state.files_seen += 1;
                        changed = true;
                    }
                    if matches!(ev, CarveEvent::RunFinished { .. }) {
                        self.state.finished = true;
                        changed = true;
                    }
                    if let Ok(off) = self.reader.byte_offset() {
                        self.state.last_offset = off;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    tracing::debug!(
                        "PickerRowTailer::poll error on {}: {e}",
                        self.state.events_bin.display()
                    );
                    break;
                }
            }
        }
        changed
    }
}
```

### Step 9: Run the test; expect PASS

### Step 10: Write the failing test `flips_finished_on_run_finished`

```rust
#[test]
fn picker_row_tailer_flips_finished_on_run_finished() {
    use utmost_lib::events::{BincodeFileSink, CarveEvent, EventSink};

    let tmp = TempDir::new().unwrap();
    let log = tmp.path().join("t-events.bin");
    write_log(&log, &[make_run_started("/in/t.img")]);

    let mut tailer = PickerRowTailer::open_fresh(&log).expect("open_fresh");
    assert!(!tailer.state.finished);

    let sink = BincodeFileSink::open_append(&log).expect("append");
    sink.emit(&CarveEvent::RunFinished {
        duration_ms: 1234,
        total_files_written: 0,
    });
    drop(sink);

    assert!(tailer.poll());
    assert!(tailer.state.finished);
}
```

### Step 11: Run the test; expect PASS (poll already handles RunFinished from Step 8)

### Step 12: Write the failing test `reopen_resumes_at_last_offset`

```rust
#[test]
fn picker_row_tailer_reopen_resumes_at_last_offset() {
    use utmost_lib::events::{BincodeFileSink, CarveEvent, EventSink};
    use utmost_lib::reporting::create_file_object;
    use utmost_lib::types::FileType;

    let tmp = TempDir::new().unwrap();
    let log = tmp.path().join("t-events.bin");
    write_log(&log, &[make_run_started("/in/t.img")]);

    // First tailer reads RunStarted + 3 FileFound events.
    let mut tailer = PickerRowTailer::open_fresh(&log).expect("open_fresh");
    {
        let sink = BincodeFileSink::open_append(&log).expect("append");
        for i in 1..=3u64 {
            sink.emit(&CarveEvent::FileFound {
                source_id: 0,
                file: create_file_object("a.jpg", FileType::Jpeg, 0, 0, None, i),
                img_offset: 0,
                written_path: "a.jpg".into(),
            });
        }
    }
    tailer.poll();
    assert_eq!(tailer.state.files_seen, 3);
    let snapshot_state = tailer.state.clone();
    drop(tailer);

    // Append 2 more FileFound while no tailer is alive.
    {
        let sink = BincodeFileSink::open_append(&log).expect("append");
        for i in 4..=5u64 {
            sink.emit(&CarveEvent::FileFound {
                source_id: 0,
                file: create_file_object("a.jpg", FileType::Jpeg, 0, 0, None, i),
                img_offset: 0,
                written_path: "a.jpg".into(),
            });
        }
    }

    // Reopen from the saved state. The reopened tailer should resume at
    // last_offset and pick up the 2 new events on poll().
    let mut tailer2 = PickerRowTailer::reopen(snapshot_state).expect("reopen");
    assert!(tailer2.poll());
    assert_eq!(tailer2.state.files_seen, 5, "reopen must not re-count earlier events");
}
```

### Step 13: Run the test; expect FAIL ("reopen not defined")

### Step 14: Implement `PickerRowTailer::reopen`

```rust
impl PickerRowTailer {
    /// Reopen an existing state. Opens the events.bin and seeks to
    /// `state.last_offset`; returns `None` if the file vanished or the
    /// seek failed (e.g., file was truncated below last_offset).
    pub(crate) fn reopen(state: PickerRowState) -> Option<Self> {
        use utmost_lib::events::BincodeFileReader;
        let mut reader = BincodeFileReader::open(&state.events_bin).ok()?;
        reader.seek_to(state.last_offset).ok()?;
        Some(Self { state, reader })
    }
}
```

### Step 15: Run the test; expect PASS

### Step 16: Write the failing test `open_fresh_returns_none_for_empty_file`

```rust
#[test]
fn picker_row_tailer_open_fresh_returns_none_for_empty_file() {
    let tmp = TempDir::new().unwrap();
    let log = tmp.path().join("empty-events.bin");
    std::fs::write(&log, b"").unwrap();
    assert!(PickerRowTailer::open_fresh(&log).is_none());
}
```

### Step 17: Run the test; expect PASS (already returns None via `BincodeFileReader::open` error path)

### Step 18: Write `PickerRowTailer::to_descriptor`

Add to `impl PickerRowTailer`:

```rust
impl PickerRowTailer {
    /// Build a fresh `CaseRowDescriptor` reflecting the tailer's current
    /// state. Used by the picker to update the Slint model on each tick.
    pub(crate) fn to_descriptor(&self) -> CaseRowDescriptor {
        let basename = std::path::Path::new(&self.state.source_path)
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                self.state
                    .events_bin
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.trim_end_matches("-events").to_string())
                    .unwrap_or_default()
            });
        let status = if self.state.finished {
            PickerStatus::Finished
        } else {
            PickerStatus::Running
        };
        CaseRowDescriptor {
            events_bin_path: self.state.events_bin.clone(),
            source_basename: basename,
            source_path: self.state.source_path.clone(),
            status,
            files_found: self.state.files_seen,
            elapsed_ms: 0,
            started_at: self.state.started_at.clone(),
            progress: if matches!(status, PickerStatus::Running) { 0.0 } else { 1.0 },
            clickable: true,
        }
    }
}
```

(Status is `Copy`; `matches!` works.)

### Step 19: Run all picker tests

```bash
cargo test -p utmost-gui --lib picker::tests -- --nocapture 2>&1 | tail -20
```

Expected: all pass (5 new tests + all pre-existing).

### Step 20: fmt + clippy + commit

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -10
git add crates/utmost-gui/src/picker.rs
git commit -m "$(cat <<'EOF'
feat(gui): PickerRowState + PickerRowTailer for live picker updates

Picker reads events.bin incrementally for each Running row instead
of subscribing to an in-process channel. State (files_seen, offset,
started_at) persists across detail-view transitions; the BincodeFileReader
is dropped while detail view is up and reopened on back-out via
PickerRowTailer::reopen(state), which seeks to last_offset.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: `run_picker` signature change + telemetry plumbing

**Files:**
- Modify: `crates/utmost-gui/src/lib.rs` — `run_picker` takes `perf: Arc<PerfRecorder>` arg, no internal `init_telemetry`.
- Modify: `crates/utmost-viewer/src/main.rs` — init telemetry locally, pass `perf` to `run_picker`.

### Step 1: Change `run_picker`'s signature

In `crates/utmost-gui/src/lib.rs`, find `pub fn run_picker(initial: …, source_search_locations: …) -> Result<()>`. Change to:

```rust
pub fn run_picker(
    initial: Vec<case::CaseSource>,
    source_search_locations: Vec<PathBuf>,
    perf: Arc<telemetry::PerfRecorder>,
) -> Result<()> {
```

Inside the body, find the existing lines:

```rust
let telemetry = init_telemetry();
let perf = telemetry.perf.clone();
```

Delete them.

At the very bottom of `run_picker` (before `Ok(())`), find the `drop(telemetry);` line. Delete it — the caller owns the WorkerGuard now.

### Step 2: Update the viewer binary

Replace `crates/utmost-viewer/src/main.rs` with:

```rust
use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about = "Browse one or more utmost carve event logs")]
struct Args {
    /// Path to either a directory (scanned recursively for <stem>-events.bin
    /// files; each becomes a row on the case-selection screen) or a single
    /// <stem>-events.bin file.
    target: PathBuf,

    /// Search location(s) for the original source image. May be a file (used
    /// directly if its basename matches a recorded source) or a directory
    /// (scanned by basename). May be repeated; entries are tried left to
    /// right. If omitted, the viewer falls back to the path recorded in the
    /// event log and then to the parent of the log's directory.
    #[arg(long, action = clap::ArgAction::Append)]
    source: Vec<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let _telemetry = utmost_gui::init_telemetry();
    let perf = _telemetry.perf.clone();
    let cases = utmost_gui::discover_cases(&args.target)?;
    utmost_gui::run_picker(
        cases
            .into_iter()
            .map(utmost_gui::case::CaseSource::Historical)
            .collect(),
        args.source,
        perf,
    )
}
```

### Step 3: Update the CLI `--gui` branch (placeholder)

In `crates/utmost-cli/src/main.rs`, find the `--gui` branch's call to `utmost_gui::run_live(rx, Some(main_log), perf)?`. We'll do the full rewrite in Task 7. For now, just adapt to the new signature — keep `run_live` calling `run_live` but pass `perf` directly. Hmm — actually `run_live` is being deleted in Task 6. To avoid an intermediate state where nothing compiles, do this Task 4 change at the CLI by:

1. Keep `run_live` calling untouched in this commit (it'll still be removed in Task 6).
2. Defer the CLI change until Task 7, which is where it conceptually belongs.

The build will fail in this Task 4 commit ONLY for the CLI crate, because `run_picker`'s new signature requires `perf` and the viewer is updated but the CLI still calls `run_live`. Actually no — the CLI doesn't call `run_picker` at all today. It calls `run_live`. `run_live` is untouched in Task 4. So the CLI compiles fine.

Just verify by building:

```bash
cargo build --workspace 2>&1 | tail -10
```

Expected: clean. If `run_picker`'s callers in tests pass the old 2-arg form, fix them.

### Step 4: fmt + clippy + commit

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -10
cargo test --workspace 2>&1 | tail -15
git add crates/utmost-gui/src/lib.rs crates/utmost-viewer/src/main.rs
git commit -m "$(cat <<'EOF'
refactor(gui): run_picker takes perf: Arc<PerfRecorder> from caller

Lets the CLI's --gui mode init telemetry once (it already does for
the carve thread's tracing) instead of re-initing inside run_picker.
The viewer binary now inits telemetry itself and passes perf in.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: `run_picker` tailers wiring (state map, 1 Hz timer, lifecycle hooks)

**Files:**
- Modify: `crates/utmost-gui/src/lib.rs` — `run_picker` body.

This is the biggest task in the plan. Read sections 4 and the existing `run_picker` body carefully before starting.

### Step 1: Add the tailer + state maps to `run_picker`'s local state

In `crates/utmost-gui/src/lib.rs`, find `run_picker`'s body, near the existing local-state declarations (`sources`, `current_handle`, `current_ui`). Add:

```rust
use std::collections::HashMap;
let row_states: Rc<RefCell<HashMap<PathBuf, picker::PickerRowState>>> =
    Rc::new(RefCell::new(HashMap::new()));
let active_tailers: Rc<RefCell<HashMap<PathBuf, picker::PickerRowTailer>>> =
    Rc::new(RefCell::new(HashMap::new()));
```

### Step 2: Populate the initial state map

After the existing `let mut rows: Vec<picker::CaseRowDescriptor> = …` block (which builds rows from `CaseSource`), add:

```rust
// Seed the row-state map. For Running/Indexing/Unindexed rows, try to
// open a fresh tailer immediately. For Corrupt rows, create a state
// entry that the refresh timer will retry up to 3 times.
{
    let mut states = row_states.borrow_mut();
    let mut tailers = active_tailers.borrow_mut();
    for row in &rows {
        let path = row.events_bin_path.clone();
        match row.status {
            picker::PickerStatus::Running
            | picker::PickerStatus::Indexing
            | picker::PickerStatus::Unindexed => {
                if let Some(tailer) = picker::PickerRowTailer::open_fresh(&path) {
                    states.insert(path.clone(), tailer.state.clone());
                    tailers.insert(path, tailer);
                } else {
                    states.insert(path.clone(), picker::PickerRowState::for_retry(path));
                }
            }
            picker::PickerStatus::Finished | picker::PickerStatus::Interrupted => {
                // Static row; no tailer / no state needed.
            }
            picker::PickerStatus::Corrupt => {
                states.insert(path.clone(), picker::PickerRowState::for_retry(path));
            }
        }
    }
}
```

### Step 3: Drop tailers on `case-clicked` (defensive teardown block)

In the existing `on_case_clicked` closure body, at the top (where the defensive "tear down any existing open case before opening a new one" block lives), add a tailer drop AFTER the existing UiState/handle teardown:

```rust
// Drop all picker-row tailers — they hold file handles we don't need
// while a case is open in detail view. State map stays intact.
active_tailers.borrow_mut().clear();
```

The `active_tailers` Rc needs to be captured into the `on_case_clicked` closure — add a `let active_tailers = active_tailers.clone();` near the other `let X = X.clone();` lines for the closure.

### Step 4: Recreate tailers on `back-to-picker`

Inside the `on_back_to_picker` closure body, AFTER the existing UiState/timer/handle teardown and BEFORE the `window.set_show_detail(false)` line, add:

```rust
// Recreate picker-row tailers from persisted state for any case that
// isn't already finished.
{
    let mut tailers = active_tailers.borrow_mut();
    let states = row_states.borrow();
    for (path, state) in states.iter() {
        if state.finished { continue; }
        if let Some(t) = picker::PickerRowTailer::reopen(state.clone()) {
            tailers.insert(path.clone(), t);
        }
    }
}
```

Capture `active_tailers` and `row_states` into the closure (the same `.clone()` pattern as other captures).

### Step 5: Add the 1 Hz refresh timer

After the existing `on_back_to_picker` callback wiring and BEFORE `window.run()?`, add a Slint timer:

```rust
// 7) Refresh timer: polls active tailers and rebuilds the cases model.
//    Only effective while the picker is visible (show-detail == false);
//    we still tick at 1 Hz but skip the work when a detail view is up.
let refresh_timer = {
    let window_weak = window.as_weak();
    let active_tailers = active_tailers.clone();
    let row_states = row_states.clone();
    let cases_model = cases_model.clone();
    let timer = slint::Timer::default();
    timer.start(
        slint::TimerMode::Repeated,
        std::time::Duration::from_secs(1),
        move || {
            let Some(window) = window_weak.upgrade() else { return; };
            if window.get_show_detail() { return; }

            let mut any_changed = false;

            // 1) Drain active tailers.
            {
                let mut tailers = active_tailers.borrow_mut();
                let mut states = row_states.borrow_mut();
                let mut finished_paths: Vec<PathBuf> = Vec::new();
                for (path, tailer) in tailers.iter_mut() {
                    if tailer.poll() {
                        any_changed = true;
                        // Mirror state into the persistent map.
                        states.insert(path.clone(), tailer.state.clone());
                        if tailer.state.finished {
                            finished_paths.push(path.clone());
                        }
                    }
                }
                // Drop tailers for finished rows — no more polling needed.
                for p in finished_paths { tailers.remove(&p); }
            }

            // 2) Corrupt-retry: for state entries without an active tailer
            //    AND with retries_remaining > 0, try open_fresh again.
            {
                let mut tailers = active_tailers.borrow_mut();
                let mut states = row_states.borrow_mut();
                let retry_paths: Vec<PathBuf> = states
                    .iter()
                    .filter(|(p, s)| {
                        !tailers.contains_key(*p)
                            && !s.finished
                            && s.corrupt_retries_remaining > 0
                            && s.started_at.is_empty()
                    })
                    .map(|(p, _)| p.clone())
                    .collect();
                for path in retry_paths {
                    match picker::PickerRowTailer::open_fresh(&path) {
                        Some(t) => {
                            states.insert(path.clone(), t.state.clone());
                            tailers.insert(path, t);
                            any_changed = true;
                        }
                        None => {
                            if let Some(s) = states.get_mut(&path) {
                                s.corrupt_retries_remaining =
                                    s.corrupt_retries_remaining.saturating_sub(1);
                            }
                        }
                    }
                }
            }

            // 3) If anything changed, rebuild the Slint model from current
            //    tailer descriptors + static rows.
            if any_changed {
                let tailers = active_tailers.borrow();
                let states = row_states.borrow();
                // Walk the original cases_model and replace each row with its
                // up-to-date descriptor. The model keeps the same case_id =
                // index relationship that on_case_clicked uses.
                let count = cases_model.row_count();
                for i in 0..count {
                    let existing = cases_model.row_data(i).unwrap();
                    let path = std::path::PathBuf::from(existing.events_bin_path.as_str().to_string());
                    // Prefer tailer descriptor; fall back to state-derived;
                    // fall back to existing if no info.
                    if let Some(t) = tailers.get(&path) {
                        let desc = t.to_descriptor();
                        cases_model.set_row_data(i, descriptor_to_row(desc, i));
                    } else if let Some(s) = states.get(&path) {
                        if s.corrupt_retries_remaining == 0 && s.started_at.is_empty() {
                            // Persisted Corrupt: leave existing row as-is
                            // (build_case_row already marked it Corrupt).
                        }
                        // No update needed otherwise — static rows don't change.
                    }
                }
            }
        },
    );
    timer
};
```

> **Implementing-agent notes:**
> - `descriptor_to_row(desc, idx)` is a small helper that maps `CaseRowDescriptor` → `slint_adapter::CaseRowData` with `case_id = idx as i32`. Either reuse the inline conversion from the initial population at the top of `run_picker` (lines ~93-101 of lib.rs), or extract it into a small private fn. Look at the existing inline code that does this and copy it into a helper.
> - The Slint generated struct `CaseRowData` has an `events_bin_path` field which IS NOT what was generated by main.slint as of Plan 1. Look at `crates/utmost-gui/ui/main.slint`'s `export struct CaseRowData` declaration — it has `case_id, source_basename, source_path, status, files_found, elapsed, progress, clickable`. NO `events_bin_path`. The check above (`existing.events_bin_path.as_str()`) needs a different approach. Two options:
>   1. Add an `events_bin_path: string` field to the Slint `CaseRowData` struct (so the Rust side can recover the path from a row). Small main.slint change.
>   2. Maintain a parallel `Vec<PathBuf>` in `run_picker` indexed by case_id; look up the path by index.
>
> Option 2 is cleaner (the picker already has `sorted_sources: Vec<CaseSource>` — use it). Refactor the timer body to walk by index and use `sorted_sources[i].events_bin_path` (after rebinding sorted_sources to keep it accessible — `Rc<Vec<PathBuf>>` works).
> - `refresh_timer` is bound to a local. `slint::Timer` stops when dropped — make sure it's kept alive for the lifetime of `window.run()`. Putting it in a local that lives until after `window.run()?` keeps it alive.

Adjust the model-rebuild path accordingly. Concrete suggestion: store `Rc<Vec<PathBuf>>` (one entry per row, in case_id order) alongside `cases_model`, and use index-based lookup in the timer body.

### Step 6: Build to verify compilation

```bash
cargo build -p utmost-gui 2>&1 | tail -20
```

Expected: clean. If the Slint code-generation doesn't know about an `events_bin_path` field (it doesn't, per the note above), the lookup must use the parallel `Vec<PathBuf>` approach.

### Step 7: Run all GUI tests

```bash
cargo test -p utmost-gui 2>&1 | tail -15
```

Expected: all pass.

### Step 8: fmt + clippy + commit

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -10
git add crates/utmost-gui/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(gui): picker polls per-row tailers at 1Hz; drop/recreate on case nav

run_picker now maintains a HashMap of PickerRowState (persistent) and
PickerRowTailer (ephemeral; dropped while detail view is open) per case.
A Slint repeating timer ticks every second: drains active tailers,
retries Corrupt rows up to 3 times, rebuilds the Slint cases model
when anything changed. on_case_clicked drops tailers; on_back_to_picker
reopens them via PickerRowTailer::reopen(state) which seeks to last_offset.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Delete `run_live` and `launch_ui_with_journal`

**Files:**
- Modify: `crates/utmost-gui/src/lib.rs` — delete the two functions and any helpers exclusively used by them.

### Step 1: Identify and delete `run_live`

In `crates/utmost-gui/src/lib.rs`, find `pub fn run_live(…) -> Result<()>` (it's the legacy live-mode entry around line 153). Delete the entire function definition.

### Step 2: Identify and delete `launch_ui_with_journal`

In the same file, find `fn launch_ui_with_journal(…)` (around line 484). Delete the entire function.

### Step 3: Remove no-longer-used imports

Build to see what's unused:

```bash
cargo build -p utmost-gui 2>&1 | tail -20
```

Clippy will flag any imports that only existed for the deleted functions. Remove them. Likely candidates:
- Anything related to `live_writes` if that pattern was unique to live mode.

### Step 4: Verify the CLI's `--gui` branch breaks (intentional; fixed in Task 7)

```bash
cargo build --workspace 2>&1 | tail -10
```

Expected: `crates/utmost-cli/src/main.rs` fails to compile because `utmost_gui::run_live` no longer exists. This is the **intentional intermediate state** — Task 7 fixes it.

If you want to keep CI green during the intermediate state, add a temporary stub at the bottom of `lib.rs`:

```rust
#[doc(hidden)]
#[deprecated(note = "Use run_picker instead; will be removed in Task 7")]
pub fn run_live(
    _rx: crossbeam_channel::Receiver<utmost_lib::events::CarveEvent>,
    _main_log_path: Option<PathBuf>,
    _perf: Arc<telemetry::PerfRecorder>,
) -> Result<()> {
    anyhow::bail!("run_live is deprecated; this stub exists only between Tasks 6 and 7")
}
```

Either approach is acceptable; the stub keeps the workspace building.

### Step 5: fmt + clippy + commit

```bash
cargo fmt
# Build will fail on workspace if not using the stub; that's OK.
git add crates/utmost-gui/src/lib.rs
git commit -m "$(cat <<'EOF'
refactor(gui): delete run_live and launch_ui_with_journal

Both became dead after Plan 2's picker handles live cases via
polling tailers. CLI --gui branch will be rebuilt on top of
run_picker in the next task.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: CLI `--gui` branch rewrite

**Files:**
- Modify: `crates/utmost-cli/src/main.rs` — `--gui` branch.

### Step 1: Rewrite the `--gui` branch

In `crates/utmost-cli/src/main.rs`, find the existing `#[cfg(feature = "gui")] if settings.gui_enabled { … return Ok(()); }` block (around line 452-499). Replace its body with:

```rust
#[cfg(feature = "gui")]
if settings.gui_enabled {
    let plan_clone = plan.clone();
    let base_cfg = base_config.clone();
    let output_root = args.output_directory.clone();
    let concurrent = args.concurrent_files;
    let export = settings.export_enabled;
    let run_started_clone = run_started.clone();
    let combined_specs_clone = combined_specs.clone();

    // Spawn the carve as a joinable handle. The handle is joined AFTER
    // run_picker returns — so closing the GUI window does not abort the
    // carve.
    let carve_handle = std::thread::spawn(move || {
        process_files_parallel(
            &base_cfg,
            &output_root,
            &plan_clone,
            concurrent,
            export,
            None, // no extra sink — events.bin only
            &run_started_clone,
            &combined_specs_clone,
        )
    });

    // Build CaseSource list from the plan — same shape utmost-viewer uses.
    let cases: Vec<utmost_gui::case::CaseSource> = plan
        .iter()
        .map(|(_, src_path, src_subdir)| {
            let dir = sinks::source_output_dir(
                std::path::Path::new(&args.output_directory),
                src_subdir,
            );
            let stem = sinks::log_stem(src_path);
            let events_bin = dir.join(format!("{stem}-events.bin"));
            utmost_gui::case::CaseSource::Historical(events_bin)
        })
        .collect();

    let perf = _telemetry
        .as_ref()
        .expect("_telemetry installed for GUI-bound runs")
        .perf
        .clone();
    let gui_result = utmost_gui::run_picker(cases, vec![], perf);

    if !carve_handle.is_finished() {
        eprintln!(
            "GUI closed; carve continuing — close this terminal to abort."
        );
    }
    match carve_handle.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::error!("carve thread failed: {e:#}"),
        Err(panic) => tracing::error!("carve thread panicked: {panic:?}"),
    }
    return gui_result;
}
```

The `is_finished()` check skips the "carve continuing" message in the common case where the user closed the GUI only after the carve finished.

### Step 2: Remove the deprecated stub (if used in Task 6)

If Task 6 added a deprecated `run_live` stub in `lib.rs`, delete it now — nothing calls it any more.

### Step 3: Build the workspace

```bash
cargo build --workspace 2>&1 | tail -10
```

Expected: clean.

### Step 4: Run all tests

```bash
cargo test --workspace 2>&1 | tail -15
```

Expected: all pass.

### Step 5: Manual smoke test

```bash
# Carve into a fresh dir with the GUI.
mkdir -p /tmp/utmost-plan2-smoke
cargo run --release -p utmost-cli -- --gui /path/to/test.img -o /tmp/utmost-plan2-smoke
```

Verify:
1. Picker opens with one Running row.
2. File-counter and status update over time.
3. Close the GUI before the carve finishes.
4. Terminal shows "GUI closed; carve continuing…".
5. Re-launch `cargo run --release -p utmost-viewer -- /tmp/utmost-plan2-smoke` from another terminal — same case visible, still Running or now Finished.
6. The original process eventually exits cleanly when the carve completes.

### Step 6: fmt + clippy + commit

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -10
git add crates/utmost-cli/src/main.rs crates/utmost-gui/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(cli): --gui builds CaseSource list and joins the carve handle

Replaces the single-ChannelSink-shared-across-sources hack + the
"main_log = first source" workaround with a clean per-source path
list handed to run_picker. The carve thread is now joined after
run_picker returns, so closing the GUI window does not abort the
carve — the process stays alive until the carve completes.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Integration tests for live-carve picker behavior

**Files:**
- Create: `crates/utmost-gui/tests/picker_live_refresh.rs`

### Step 1: Create the file with the round-trip test

```rust
//! Integration tests for picker tail-reading behavior. Drive the
//! PickerRowTailer + state map without standing up a Slint event loop.

use std::path::Path;
use tempfile::TempDir;
use utmost_gui::picker::{PickerRowState, PickerRowTailer};
use utmost_lib::events::{
    BincodeFileSink, CarveEvent, CliConfigSnapshot, EventSink, SourceDescriptor,
};
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::FileType;

fn write_minimal_events_bin(path: &Path, source_image_path: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let sink = BincodeFileSink::create(path).expect("create sink");
    sink.emit(&CarveEvent::RunStarted {
        utmost_version: "test".into(),
        format_version: 1,
        started_at: "2026-05-20T00:00:00Z".into(),
        command_line: vec![],
        working_directory: "/".into(),
        execution_environment: Default::default(),
        cli_config: CliConfigSnapshot::default(),
        case: None,
        configured_types: vec![FileType::Jpeg],
        sources: vec![SourceDescriptor {
            source_id: 0,
            filename: source_image_path.into(),
            total_bytes: 0,
            output_subdir: "s".into(),
        }],
        output_root: "/out".into(),
    });
}

fn append_file_founds(path: &Path, n: u64) {
    let sink = BincodeFileSink::open_append(path).expect("append sink");
    for i in 1..=n {
        sink.emit(&CarveEvent::FileFound {
            source_id: 0,
            file: create_file_object("a.jpg", FileType::Jpeg, 0, 0, None, i),
            img_offset: 0,
            written_path: "a.jpg".into(),
        });
    }
}

#[test]
fn live_carve_picker_row_updates_as_events_arrive() {
    let tmp = TempDir::new().unwrap();
    let log = tmp.path().join("live-events.bin");
    write_minimal_events_bin(&log, "/in/live.img");

    // Open a fresh tailer; should observe RunStarted only at first.
    let mut tailer = PickerRowTailer::open_fresh(&log).expect("open_fresh");
    assert_eq!(tailer.state.files_seen, 0);
    assert!(!tailer.state.finished);

    // Simulate a live carve writing more events between polls.
    append_file_founds(&log, 5);
    assert!(tailer.poll());
    assert_eq!(tailer.state.files_seen, 5);
    assert!(!tailer.state.finished);

    append_file_founds(&log, 3);
    assert!(tailer.poll());
    assert_eq!(tailer.state.files_seen, 8);

    // Append RunFinished.
    {
        let sink = BincodeFileSink::open_append(&log).expect("append");
        sink.emit(&CarveEvent::RunFinished {
            duration_ms: 100,
            total_files_written: 8,
        });
    }
    assert!(tailer.poll());
    assert!(tailer.state.finished);
}

#[test]
fn picker_corrupt_row_recovers_within_retry_budget() {
    let tmp = TempDir::new().unwrap();
    let log = tmp.path().join("late-events.bin");
    // File doesn't exist yet — open_fresh fails.
    assert!(PickerRowTailer::open_fresh(&log).is_none());

    let mut state = PickerRowState::for_retry(log.clone());
    assert_eq!(state.corrupt_retries_remaining, 3);

    // Two failed retries: file still missing.
    state.corrupt_retries_remaining -= 1;
    assert!(PickerRowTailer::open_fresh(&log).is_none());
    state.corrupt_retries_remaining -= 1;
    assert!(PickerRowTailer::open_fresh(&log).is_none());

    // File appears on the third try.
    write_minimal_events_bin(&log, "/in/late.img");
    let tailer = PickerRowTailer::open_fresh(&log).expect("open_fresh after write");
    assert_eq!(tailer.state.source_path, "/in/late.img");
}

#[test]
fn picker_corrupt_row_stays_corrupt_after_retry_budget_exhausted() {
    let tmp = TempDir::new().unwrap();
    let log = tmp.path().join("never-events.bin");

    let mut state = PickerRowState::for_retry(log.clone());
    while state.corrupt_retries_remaining > 0 {
        assert!(PickerRowTailer::open_fresh(&log).is_none());
        state.corrupt_retries_remaining -= 1;
    }
    assert_eq!(state.corrupt_retries_remaining, 0);
    // Caller (run_picker timer) would now stop retrying. Confirm the
    // file still can't be opened to underscore that we'd keep failing
    // if we did keep retrying.
    assert!(PickerRowTailer::open_fresh(&log).is_none());
}

#[test]
fn picker_tailer_resume_after_detail_view_round_trip() {
    let tmp = TempDir::new().unwrap();
    let log = tmp.path().join("resume-events.bin");
    write_minimal_events_bin(&log, "/in/resume.img");

    // First tailer reads RunStarted + 5 FileFound events.
    let mut tailer = PickerRowTailer::open_fresh(&log).expect("open_fresh");
    append_file_founds(&log, 5);
    tailer.poll();
    assert_eq!(tailer.state.files_seen, 5);
    let saved_state = tailer.state.clone();
    drop(tailer); // simulate detail view opening; tailer dropped.

    // Carve continues writing while no tailer is alive.
    append_file_founds(&log, 4);

    // Detail view closes; tailer reopens from saved state.
    let mut tailer2 = PickerRowTailer::reopen(saved_state).expect("reopen");
    tailer2.poll();
    assert_eq!(tailer2.state.files_seen, 9, "reopen must not double-count");
}
```

### Step 2: Run the tests

```bash
cargo test -p utmost-gui --test picker_live_refresh -- --nocapture 2>&1 | tail -20
```

Expected: 4 passed, 0 failed.

### Step 3: fmt + clippy + commit

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings 2>&1 | tail -10
git add crates/utmost-gui/tests/picker_live_refresh.rs
git commit -m "$(cat <<'EOF'
test(gui): integration tests for live-carve picker tailer behavior

Covers:
- Live-carve picker row updates as events arrive
- Corrupt-row recovery within the 3-retry budget
- Corrupt row staying corrupt after the budget is exhausted
- Detail-view round-trip (tailer drop/reopen) resumes at last_offset
  without double-counting

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: CLAUDE.md updates

**Files:**
- Modify: `CLAUDE.md`

### Step 1: Update the "GUI: case model" section

Find the existing bullet about `run_live` in the "Entry modes" subsection:

> - `utmost --gui ...` — does **not** scan. The CLI knows the input files it's carving; each should become its own row. As of Plan 1 of the picker work, the CLI live-mode path still uses the legacy `run_live` entry — Plan 2 will rebuild it on top of `run_picker`.

Replace with:

```markdown
- `utmost --gui ...` — does **not** scan. The CLI knows the input files it's carving; each becomes its own row. The carve runs on a joined background thread, so closing the GUI window does NOT abort the carve — the process stays alive until all sources finish.
```

### Step 2: Add a "Live updates" subsection

After the "Status values" line and before "Per-case UI-state persistence", insert:

```markdown
**Live picker updates** (`crates/utmost-gui/src/picker.rs`, `crates/utmost-gui/src/lib.rs::run_picker`):

- For each Running case, the picker holds a `PickerRowTailer` that incrementally reads new events from the case's events.bin. A 1 Hz Slint timer polls all active tailers, advances `files_seen` / `last_offset` / status, and rebuilds the Slint model when anything changed.
- Tailers are dropped when the user clicks a case (`on_case_clicked`) and recreated when they back out (`on_back_to_picker`) using the persisted `PickerRowState` (which survives across detail-view transitions).
- A row that fails to open initially (the events.bin's RunStarted hasn't been written yet) gets 3 retry attempts on subsequent 1 Hz ticks before being marked permanently Corrupt for the session.
- The indexer-writer thread (spawned by `open_case` for the case under the user's detail view) tails the same events.bin past EOF until `shutdown_signal` is set, with the same 500ms poll cadence + 10-error retry cap as the picker's tailers.
```

### Step 3: Update the "Specs and plans" list

Find the existing list:

```markdown
**Specs and plans:**

- Design (case picker): `docs/superpowers/specs/2026-05-20-case-selection-screen-design.md`
- Plan 1 (viewer-mode case picker): `docs/superpowers/plans/2026-05-20-case-selection-screen-viewer-mode.md`
- Design (per-case UI-state): `docs/superpowers/specs/2026-05-20-persist-ui-state-design.md`
- Plan (per-case UI-state): `docs/superpowers/plans/2026-05-20-persist-ui-state.md`
- Plan 2 (live-carve CLI refactor): not yet written; will follow.
```

Replace with:

```markdown
**Specs and plans:**

- Design (case picker): `docs/superpowers/specs/2026-05-20-case-selection-screen-design.md`
- Plan 1 (viewer-mode case picker): `docs/superpowers/plans/2026-05-20-case-selection-screen-viewer-mode.md`
- Design (per-case UI-state): `docs/superpowers/specs/2026-05-20-persist-ui-state-design.md`
- Plan (per-case UI-state): `docs/superpowers/plans/2026-05-20-persist-ui-state.md`
- Design (live-carve refactor): `docs/superpowers/specs/2026-05-20-live-carve-cli-refactor-design.md`
- Plan 2 (live-carve refactor): `docs/superpowers/plans/2026-05-20-live-carve-cli-refactor.md`
```

### Step 4: Commit

```bash
git add CLAUDE.md
git commit -m "$(cat <<'EOF'
docs(claude): Plan 2 — live picker tailers + carve survives GUI close

Future sessions need to know:
- utmost --gui keeps the carve alive past window close (carve_handle
  is joined in main after run_picker returns)
- picker reads events.bin per Running row via PickerRowTailer at 1Hz
- tailers drop on case-click, reopen on back via persisted state
- indexer-writer tails events.bin past EOF until shutdown_signal
- run_live + launch_ui_with_journal + CaseSource::Live all deleted

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Self-Review Checklist (for the implementing agent)

After all 9 tasks complete:

1. **Workspace builds cleanly.** `cargo build --workspace --release` succeeds.
2. **All tests pass.** `cargo test --workspace`.
3. **Clippy clean.** `cargo clippy --all-targets --workspace -- -D warnings`.
4. **Multi-source live carve verified.** `utmost --gui f1.img f2.img -o /tmp/test-multi` shows both rows updating; both are clickable; back-and-forth between detail views works.
5. **Carve survives GUI close verified.** Carve a large image, close the GUI mid-carve, observe the terminal message, wait for process exit, confirm events.bin has more events than were visible at close time.
6. **Viewer attaches to running carve verified.** Start `utmost --gui big.img -o /tmp/cross-process`, then from another terminal `utmost-viewer /tmp/cross-process` — confirm the row updates in real time in both viewers.
7. **Corrupt-row retry verified.** Manually create `/tmp/empty-events.bin` with `touch`, launch `utmost-viewer /tmp` — row appears as Corrupt briefly, then transitions to Running once the file gets a real RunStarted appended (or stays Corrupt after 3 ticks).
8. **CLAUDE.md updated.**

If any check fails, fix the failing task before declaring the plan complete.

---

## Out of scope (queued)

- **True daemonization.** Carve survives GUI close but not terminal close. SIGHUP / `setsid` / pid-file management would be a separate Plan 3.
- **Filesystem-watcher backed picker refresh.** Replace 1 Hz polling with FSEvents/inotify-driven updates for tighter latency. YAGNI for now.
- **Carve cancellation from the GUI.** The picker currently has no UI to abort a running carve from inside the GUI — closing the window doesn't kill it. A future feature could add an "Abort" button per row that sets a cooperative cancel flag on the carve thread.
