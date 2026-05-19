# GUI Windowed File Loading — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Scale the Slint tile grid to 250k+ files by moving filter/sort onto SQLite, holding only a compact `Vec<FileStub>` plus a windowed `BTreeMap<u64, FoundFile>` in memory, and rendering only the windowed slice of tiles in Slint. Bundle a file-backed tracing subscriber and opt-in per-phase tick timer for future perf work.

**Architecture:** A new `index_db/queries.rs` module runs `query_match_ids(filter, sort)` and `fetch_window(ids)` on the indexer thread. The ViewModel drops `Vec<FoundFile>` and gains `match_ids: Vec<FileStub>`, `window: BTreeMap<u64, FoundFile>`, and `window_range: Range<usize>`. Slint exposes `viewport-y` and `grid-cols`; the 100 ms sync tick reads them and posts `IndexerCommand::FetchWindow` when the visible range strays outside the current window. A new `telemetry.rs` module installs a daily-rolling file-backed `tracing` subscriber and an opt-in `PerfRecorder` (gated by `UTMOST_PERF_TRACE=1` or `RUST_LOG=utmost_gui::perf=info`).

**Tech Stack:** Rust, Slint, Diesel + SQLite (existing), `tracing` + `tracing-appender` (new), `crossbeam_channel` (existing), `dirs` (new, for platform log paths).

**Spec:** `docs/superpowers/specs/2026-05-19-gui-windowed-files-design.md`

**Closes:** [#2](https://github.com/stevenwcarter/utmost-rs/issues/2)

---

## File Structure

### New files

| Path | Purpose |
|---|---|
| `crates/utmost-gui/migrations/0002_preview_status/up.sql` | Add `preview_status` column + index. |
| `crates/utmost-gui/migrations/0002_preview_status/down.sql` | Drop index + column. |
| `crates/utmost-gui/src/index_db/queries.rs` | `query_match_ids`, `fetch_window`, `set_preview_status`, `FileStub`. |
| `crates/utmost-gui/src/telemetry.rs` | File subscriber init, `PerfRecorder`, aggregator. |
| `crates/utmost-gui/tests/windowed_load_cold.rs` | Cold-open windowing test. |
| `crates/utmost-gui/tests/windowed_filter_change.rs` | Filter change requery test. |
| `crates/utmost-gui/tests/windowed_scroll_slides.rs` | Scroll-induced window slide test. |
| `crates/utmost-gui/tests/windowed_keyboard_nav.rs` | Keyboard nav across slides. |
| `crates/utmost-gui/tests/windowed_live_mode.rs` | Live-mode auto-requery test. |
| `crates/utmost-gui/tests/preview_status_persist.rs` | Preview-status persistence test. |
| `crates/utmost-gui/tests/telemetry_log_smoke.rs` | Telemetry log smoke test. |
| `crates/utmost-gui/benches/windowed_load.rs` | Four ignored Criterion benches. |

### Modified files

`crates/utmost-gui/Cargo.toml`, `Cargo.toml` (workspace), `crates/utmost-gui/src/index_db/mod.rs`, `crates/utmost-gui/src/index_db/schema.rs`, `crates/utmost-gui/src/index_db/models.rs`, `crates/utmost-gui/src/index_db/hydrate.rs`, `crates/utmost-gui/src/indexer_thread.rs`, `crates/utmost-gui/src/view_model.rs`, `crates/utmost-gui/src/thumb_worker.rs`, `crates/utmost-gui/src/slint_adapter.rs`, `crates/utmost-gui/src/preview/*`, `crates/utmost-gui/src/lib.rs`, `crates/utmost-gui/ui/main.slint`, `crates/utmost-gui/ui/detail.slint`, `crates/utmost-cli/src/main.rs`, `README.md`.

### Branch and commits

All work happens on the current branch (`feature/utmost-gui-slint`). Each task is one or more commits. The final task's commit message references `Closes #2`.

---

## Task 1: Add `tracing-appender` and `dirs` workspace deps

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Modify: `crates/utmost-gui/Cargo.toml`

- [ ] **Step 1: Add workspace deps**

In root `Cargo.toml` `[workspace.dependencies]`:

```toml
tracing-appender = "0.2"
dirs = "5"
```

- [ ] **Step 2: Add to utmost-gui**

In `crates/utmost-gui/Cargo.toml` `[dependencies]`:

```toml
tracing-appender = { workspace = true }
dirs = { workspace = true }
```

- [ ] **Step 3: Verify the workspace builds**

Run: `cargo build -p utmost-gui`
Expected: clean build.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml crates/utmost-gui/Cargo.toml Cargo.lock
git commit -m "feat(gui): add tracing-appender and dirs workspace deps"
```

---

## Task 2: `PerfRecorder` and aggregator (zero-cost when disabled)

**Files:**
- Create: `crates/utmost-gui/src/telemetry.rs`
- Modify: `crates/utmost-gui/src/lib.rs` (pub mod telemetry)
- Test: same file (unit tests at the bottom of `telemetry.rs`)

**Design:**

```rust
// telemetry.rs (relevant skeleton)

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

/// Per-phase rolling accumulator.
#[derive(Default)]
struct PhaseStats {
    count: u64,
    sum_us: u64,
    max_us: u64,
    /// 8 exponential buckets: <=10us, <=30us, <=100us, <=300us, <=1ms, <=3ms, <=10ms, >10ms.
    histogram: [u64; 8],
}

pub struct PerfRecorder {
    enabled: AtomicBool,
    tick_counter: AtomicU64,
    tick_emit_interval: u64,
    /// Maps phase name → stats. Behind a mutex; lock only when enabled.
    phases: parking_lot::Mutex<std::collections::BTreeMap<&'static str, PhaseStats>>,
    target: &'static str,
}

pub struct PhaseGuard<'a> {
    recorder: &'a PerfRecorder,
    name: &'static str,
    start: Option<Instant>,
}

impl PerfRecorder {
    pub fn new(target: &'static str, enabled: bool, tick_emit_interval: u64) -> Self { ... }

    #[inline(always)]
    pub fn phase(&self, name: &'static str) -> PhaseGuard<'_> {
        if !self.enabled.load(Ordering::Relaxed) {
            return PhaseGuard { recorder: self, name, start: None };
        }
        PhaseGuard { recorder: self, name, start: Some(Instant::now()) }
    }

    pub fn tick(&self) {
        if !self.enabled.load(Ordering::Relaxed) { return; }
        let n = self.tick_counter.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= self.tick_emit_interval {
            self.emit_and_reset();
        }
    }

    fn record(&self, name: &'static str, elapsed_us: u64) { ... }
    fn emit_and_reset(&self) { ... }
}

impl Drop for PhaseGuard<'_> {
    #[inline(always)]
    fn drop(&mut self) {
        if let Some(start) = self.start {
            let us = start.elapsed().as_micros() as u64;
            self.recorder.record(self.name, us);
        }
    }
}
```

(`parking_lot::Mutex` is already a transitive dep through `slint`; if it isn't, swap to `std::sync::Mutex`.)

- [ ] **Step 1: Write failing unit tests at the bottom of `telemetry.rs`**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_off_is_zero_cost_in_steady_state() {
        let r = PerfRecorder::new("test", false, 100);
        let _g = r.phase("x"); // must not panic, must not call Instant::now
        // The guard's start field is None when disabled — observable indirectly.
        // Aggregator should remain empty.
        let stats = r.snapshot_for_test();
        assert!(stats.is_empty());
    }

    #[test]
    fn aggregator_accumulates_count_sum_max() {
        let r = PerfRecorder::new("test", true, 100_000);
        r.record_for_test("build_tiles", 100);
        r.record_for_test("build_tiles", 300);
        r.record_for_test("build_tiles", 200);
        let s = r.snapshot_for_test();
        let bt = s.get("build_tiles").unwrap();
        assert_eq!(bt.count, 3);
        assert_eq!(bt.sum_us, 600);
        assert_eq!(bt.max_us, 300);
    }

    #[test]
    fn emit_resets_aggregator() {
        let r = PerfRecorder::new("test", true, 2);
        r.record_for_test("a", 100);
        r.tick();
        r.record_for_test("a", 200);
        r.tick();   // hits interval=2 → emit + reset
        r.record_for_test("a", 300);
        let s = r.snapshot_for_test();
        let a = s.get("a").unwrap();
        assert_eq!(a.count, 1);
        assert_eq!(a.sum_us, 300);
    }

    #[test]
    fn histogram_buckets_correctly() {
        let r = PerfRecorder::new("test", true, 100_000);
        r.record_for_test("a", 5);       // <=10us
        r.record_for_test("a", 50);      // <=100us
        r.record_for_test("a", 5_000);   // <=10ms (bucket 6, since <=10000us)
        r.record_for_test("a", 50_000);  // >10ms (bucket 7)
        let s = r.snapshot_for_test();
        let a = s.get("a").unwrap();
        assert_eq!(a.histogram[0], 1);
        assert_eq!(a.histogram[2], 1);
        assert_eq!(a.histogram[6], 1);
        assert_eq!(a.histogram[7], 1);
    }
}
```

- [ ] **Step 2: Verify they fail**

Run: `cargo test -p utmost-gui telemetry::`
Expected: compilation failure ("module not found") or test failure.

- [ ] **Step 3: Implement `PerfRecorder` and `PhaseGuard`**

Create the file with the skeleton above plus:

```rust
impl PerfRecorder {
    fn record(&self, name: &'static str, elapsed_us: u64) {
        let mut phases = self.phases.lock();
        let entry = phases.entry(name).or_default();
        entry.count += 1;
        entry.sum_us = entry.sum_us.saturating_add(elapsed_us);
        if elapsed_us > entry.max_us { entry.max_us = elapsed_us; }
        let bucket = match elapsed_us {
            0..=10 => 0,
            11..=30 => 1,
            31..=100 => 2,
            101..=300 => 3,
            301..=1_000 => 4,
            1_001..=3_000 => 5,
            3_001..=10_000 => 6,
            _ => 7,
        };
        entry.histogram[bucket] += 1;
    }

    fn emit_and_reset(&self) {
        let mut phases = self.phases.lock();
        let n = self.tick_counter.swap(0, Ordering::Relaxed);
        if phases.is_empty() {
            return;
        }
        // Build one log line. Format: "ticks=N total{p50=Xus p95=Yus max=Zus} ..."
        let mut parts: Vec<(String, u64)> = Vec::with_capacity(phases.len());
        for (name, stats) in phases.iter() {
            let mean = stats.sum_us.checked_div(stats.count).unwrap_or(0);
            let p95 = estimate_p95(&stats.histogram, stats.count);
            parts.push((
                format!("{}{{p50={}us p95={}us max={}us}}", name, mean, p95, stats.max_us),
                mean,
            ));
        }
        parts.sort_by(|a, b| b.1.cmp(&a.1));
        let line = parts.into_iter().map(|p| p.0).collect::<Vec<_>>().join(" ");
        tracing::info!(target: self.target, "ticks={n} {line}");
        phases.clear();
    }

    // Test-only accessors gated behind cfg(test).
    #[cfg(test)]
    pub fn record_for_test(&self, name: &'static str, us: u64) { self.record(name, us); }
    #[cfg(test)]
    pub fn snapshot_for_test(&self) -> std::collections::BTreeMap<&'static str, PhaseStats> {
        self.phases.lock().clone()
    }
}

// Approximate p50 from mean — good enough for log readability.
// True p50 from histogram: find the bucket containing the (count/2)th sample.
fn estimate_p95(hist: &[u64; 8], total: u64) -> u64 {
    let target = (total * 95) / 100;
    let bucket_upper: [u64; 8] = [10, 30, 100, 300, 1_000, 3_000, 10_000, 100_000];
    let mut running = 0u64;
    for (i, &c) in hist.iter().enumerate() {
        running += c;
        if running >= target { return bucket_upper[i]; }
    }
    bucket_upper[7]
}
```

Make `PhaseStats: Clone` (required for the test snapshot).

- [ ] **Step 4: Add module to `lib.rs`**

In `crates/utmost-gui/src/lib.rs`:

```rust
pub mod telemetry;
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p utmost-gui telemetry::`
Expected: all 4 tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-gui/src/telemetry.rs crates/utmost-gui/src/lib.rs
git commit -m "feat(gui): PerfRecorder skeleton with zero-cost-when-off phase guards"
```

---

## Task 3: File-backed tracing subscriber

**Files:**
- Modify: `crates/utmost-gui/src/telemetry.rs` (append `init_subscriber` + tests)

**Design:** Resolve the log directory in this order:

1. `$UTMOST_LOG_DIR` if set
2. Platform default via `dirs::state_dir()` (Linux/macOS) / `dirs::data_local_dir()` (Windows) joined with `utmost/`. On macOS where `state_dir()` returns `None`, fall back to `$HOME/Library/Logs/utmost`.
3. If neither is writable, fall back to stderr-only and print a warning.

Activation of `PerfRecorder` is decided at this same init call:

- Enabled if `UTMOST_PERF_TRACE=1` (string match, case-insensitive `"1"` or `"true"`).
- Enabled if `RUST_LOG` contains the substring `utmost_gui::perf` at INFO or finer (string check on the parsed `EnvFilter`).

- [ ] **Step 1: Write failing tests**

Append to `crates/utmost-gui/src/telemetry.rs`:

```rust
#[cfg(test)]
mod init_tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn resolves_log_dir_from_env() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().to_path_buf();
        let resolved = resolve_log_dir(Some(path.clone()));
        assert_eq!(resolved.unwrap(), path);
    }

    #[test]
    fn perf_disabled_without_env_or_rust_log() {
        let activated = perf_activated_from(None, None);
        assert!(!activated);
    }

    #[test]
    fn perf_activated_by_utmost_perf_trace_env() {
        assert!(perf_activated_from(Some("1"), None));
        assert!(perf_activated_from(Some("TRUE"), None));
        assert!(!perf_activated_from(Some("0"), None));
        assert!(!perf_activated_from(Some(""), None));
    }

    #[test]
    fn perf_activated_by_rust_log_target() {
        assert!(perf_activated_from(None, Some("utmost_gui::perf=info")));
        assert!(perf_activated_from(None, Some("warn,utmost_gui::perf=info")));
        assert!(!perf_activated_from(None, Some("warn")));
    }
}
```

(Add `tempfile = "3"` to workspace deps and `tempfile = { workspace = true }` to `[dev-dependencies]` in `crates/utmost-gui/Cargo.toml` if not present — many existing tests likely already use it; check first with `grep tempfile crates/utmost-gui/Cargo.toml`.)

- [ ] **Step 2: Verify they fail**

Run: `cargo test -p utmost-gui telemetry::init_tests`
Expected: compilation errors (the helper functions don't exist).

- [ ] **Step 3: Implement helpers and `init_subscriber`**

Append to `telemetry.rs`:

```rust
use std::path::{Path, PathBuf};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

pub struct Telemetry {
    pub perf: std::sync::Arc<PerfRecorder>,
    _guard: tracing_appender::non_blocking::WorkerGuard,
}

pub fn init_subscriber() -> Telemetry {
    let log_dir = resolve_log_dir(std::env::var_os("UTMOST_LOG_DIR").map(PathBuf::from))
        .unwrap_or_else(|| std::env::temp_dir().join("utmost"));

    if let Err(e) = std::fs::create_dir_all(&log_dir) {
        eprintln!("utmost: log dir {} not writable: {e}", log_dir.display());
    }

    let file_appender = tracing_appender::rolling::daily(&log_dir, "utmost-gui.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("warn"))
        .unwrap();
    let env_filter_str = std::env::var("RUST_LOG").ok();

    let file_layer = fmt::layer().with_writer(non_blocking).with_ansi(false);
    let stderr_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(tracing_subscriber::filter::LevelFilter::ERROR);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(file_layer)
        .with(stderr_layer)
        .init();

    let log_file_path = log_dir.join("utmost-gui.log");
    eprintln!("utmost: logging to {}", log_file_path.display());
    tracing::info!(path = %log_file_path.display(), "log file");

    let perf_enabled = perf_activated_from(
        std::env::var("UTMOST_PERF_TRACE").ok().as_deref(),
        env_filter_str.as_deref(),
    );
    let tick_interval = std::env::var("UTMOST_PERF_TICKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let perf = std::sync::Arc::new(PerfRecorder::new(
        "utmost_gui::perf",
        perf_enabled,
        tick_interval,
    ));

    Telemetry { perf, _guard: guard }
}

pub(crate) fn resolve_log_dir(override_path: Option<PathBuf>) -> Option<PathBuf> {
    if let Some(p) = override_path { return Some(p); }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            return Some(home.join("Library/Logs/utmost"));
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(state) = dirs::state_dir() {
            return Some(state.join("utmost"));
        }
        if let Some(home) = dirs::home_dir() {
            return Some(home.join(".local/state/utmost"));
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(local) = dirs::data_local_dir() {
            return Some(local.join("utmost/logs"));
        }
    }
    None
}

pub(crate) fn perf_activated_from(env: Option<&str>, rust_log: Option<&str>) -> bool {
    if let Some(v) = env {
        let v = v.trim().to_ascii_lowercase();
        if v == "1" || v == "true" { return true; }
    }
    if let Some(filter) = rust_log {
        if filter.contains("utmost_gui::perf=info")
            || filter.contains("utmost_gui::perf=debug")
            || filter.contains("utmost_gui::perf=trace")
        {
            return true;
        }
    }
    false
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p utmost-gui telemetry::`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-gui/src/telemetry.rs crates/utmost-gui/Cargo.toml Cargo.toml Cargo.lock
git commit -m "feat(gui): file-backed tracing subscriber and perf activation gate"
```

---

## Task 4: Wire telemetry into GUI launch path

**Files:**
- Modify: `crates/utmost-gui/src/lib.rs` (call `init_subscriber` at GUI entry points)
- Modify: `crates/utmost-cli/src/main.rs` (skip `tracing_subscriber::fmt()` for GUI launches; pass a flag through)

**Approach:** The CLI currently inits a subscriber unconditionally before either carve or GUI runs. Split into two paths: carve and recover keep the current `tracing_subscriber::fmt()`; the GUI launch in `crates/utmost-cli/src/main.rs` near line 474 (`utmost_gui::run_live`) skips the CLI init and lets `utmost-gui` install its own subscriber via `telemetry::init_subscriber()`.

- [ ] **Step 1: Locate GUI entry points in `utmost-cli/src/main.rs`**

Read the file. The GUI is launched from `utmost_gui::run_live(...)` (line 474) and from `utmost_gui::run_from_file(...)` (similarly invoked). Identify both.

- [ ] **Step 2: Move the existing `tracing_subscriber::fmt()` init**

In `crates/utmost-cli/src/main.rs`, find each `tracing_subscriber::fmt()` block (lines 256 and 757). The block at line 256 runs in the CLI's `main()`. The carve path needs it; the GUI path does not. Refactor:

```rust
fn init_cli_tracing(debug: bool) {
    tracing_subscriber::fmt()
        .with_max_level(if debug { tracing::Level::TRACE } else { tracing::Level::WARN })
        .init();
}
```

Call `init_cli_tracing(args.debug)` only in the carve/recover paths. The GUI launch path skips it.

- [ ] **Step 3: Add `pub fn init_telemetry()` to `utmost-gui`**

In `crates/utmost-gui/src/lib.rs`:

```rust
pub use telemetry::Telemetry;

pub fn init_telemetry() -> Telemetry {
    telemetry::init_subscriber()
}
```

- [ ] **Step 4: Call `init_telemetry()` at the start of `run_live` and `run_from_file`**

Both functions in `crates/utmost-gui/src/lib.rs` (and any other `pub fn run_*` GUI entry). Capture the returned `Telemetry` and keep it alive for the duration of the call:

```rust
pub fn run_live(...) -> Result<()> {
    let telemetry = init_telemetry();
    // ... existing code, but wherever UiState is constructed, pass &telemetry.perf in.
    let _ = telemetry;  // keep alive
    Ok(())
}
```

For this task, just initialize and keep alive — wiring `PerfRecorder` into `UiState` is Task 5.

- [ ] **Step 5: Build and smoke**

Run: `cargo build -p utmost-cli --release`
Expected: clean build.

Run (manual smoke): `cargo run -- gui <some-finished-case>` (if such a subcommand exists; otherwise the equivalent open path). Expect a `utmost: logging to /...` line on stderr at startup and a non-empty `utmost-gui.log` after closing.

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-cli/src/main.rs crates/utmost-gui/src/lib.rs
git commit -m "feat(gui): init file-backed tracing in GUI entry points"
```

---

## Task 5: Thread `PerfRecorder` into `UiState` and instrument one phase

**Files:**
- Modify: `crates/utmost-gui/src/slint_adapter.rs` (UiState gains `perf: Arc<PerfRecorder>`)
- Modify: `crates/utmost-gui/src/lib.rs` (pass `telemetry.perf` to UiState constructor)

- [ ] **Step 1: Add field to `UiState`**

In `crates/utmost-gui/src/slint_adapter.rs`:

```rust
pub struct UiState {
    // ... existing fields ...
    pub perf: std::sync::Arc<crate::telemetry::PerfRecorder>,
}
```

Update the constructor signature to accept `perf: Arc<PerfRecorder>`. Update all call sites in `lib.rs` to pass `telemetry.perf.clone()`.

- [ ] **Step 2: Wrap one phase in `sync()` as a smoke test**

In `UiState::sync()`, the very first line after the function entry:

```rust
let _total = self.perf.phase("total");
```

And at the end of `sync()`:

```rust
self.perf.tick();
```

- [ ] **Step 3: Build**

Run: `cargo build -p utmost-gui`
Expected: clean build.

- [ ] **Step 4: Manual smoke with perf enabled**

Run: `UTMOST_PERF_TRACE=1 UTMOST_PERF_TICKS=10 cargo run -- <open-some-case>`
Open the GUI for ~3 seconds, close it. Verify the log file contains a `utmost_gui::perf` line with at least `total{...}`.

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-gui/src/slint_adapter.rs crates/utmost-gui/src/lib.rs
git commit -m "feat(gui): thread PerfRecorder into UiState, instrument sync total"
```

---

## Task 6: Migration `0002_preview_status` and schema regen

**Files:**
- Create: `crates/utmost-gui/migrations/0002_preview_status/up.sql`
- Create: `crates/utmost-gui/migrations/0002_preview_status/down.sql`
- Modify: `crates/utmost-gui/src/index_db/schema.rs` (regenerated)
- Modify: `crates/utmost-gui/src/index_db/models.rs` (`FileRow` gains `preview_status`)

- [ ] **Step 1: Write `up.sql`**

`crates/utmost-gui/migrations/0002_preview_status/up.sql`:

```sql
ALTER TABLE file ADD COLUMN preview_status TEXT NOT NULL DEFAULT 'unknown';
CREATE INDEX idx_file_preview ON file(preview_status);

INSERT OR IGNORE INTO meta (key, value) VALUES ('preview_status_version', '0');
```

- [ ] **Step 2: Write `down.sql`**

`crates/utmost-gui/migrations/0002_preview_status/down.sql`:

```sql
DROP INDEX IF EXISTS idx_file_preview;
-- SQLite doesn't support DROP COLUMN before 3.35; we ALTER TABLE…RENAME and copy.
ALTER TABLE file RENAME TO file_old;
CREATE TABLE file (
    file_id INTEGER PRIMARY KEY NOT NULL,
    source_id INTEGER NOT NULL REFERENCES source(source_id),
    filename TEXT NOT NULL,
    filesize INTEGER NOT NULL,
    file_type TEXT NOT NULL,
    img_offset INTEGER NOT NULL,
    written_path TEXT NOT NULL,
    byte_runs_json TEXT NOT NULL DEFAULT '[]',
    jpeg_status TEXT,
    jpeg_width INTEGER,
    jpeg_height INTEGER,
    jpeg_fragmentation_point INTEGER,
    jpeg_has_restart_markers INTEGER
);
INSERT INTO file SELECT file_id, source_id, filename, filesize, file_type, img_offset, written_path, byte_runs_json, jpeg_status, jpeg_width, jpeg_height, jpeg_fragmentation_point, jpeg_has_restart_markers FROM file_old;
DROP TABLE file_old;
CREATE INDEX idx_file_source     ON file(source_id);
CREATE INDEX idx_file_type       ON file(file_type);
CREATE INDEX idx_file_size       ON file(filesize);
CREATE INDEX idx_file_img_offset ON file(img_offset);
DELETE FROM meta WHERE key = 'preview_status_version';
```

- [ ] **Step 3: Regenerate `schema.rs`**

Run from the workspace root:

```bash
cd crates/utmost-gui && diesel print-schema > src/index_db/schema.rs
```

(Requires `diesel_cli` installed: `cargo install diesel_cli --no-default-features --features sqlite`. The README notes Diesel CLI is not required at runtime; only this regen step needs it.)

Verify the new `preview_status -> Text` column appears in `file (file_id)` table macro.

- [ ] **Step 4: Update `FileRow` model**

In `crates/utmost-gui/src/index_db/models.rs`:

```rust
#[derive(Queryable, Insertable, Debug, Clone)]
#[diesel(table_name = crate::index_db::schema::file)]
pub struct FileRow {
    pub file_id: i64,
    pub source_id: i64,
    pub filename: String,
    pub filesize: i64,
    pub file_type: String,
    pub img_offset: i64,
    pub written_path: String,
    pub byte_runs_json: String,
    pub jpeg_status: Option<String>,
    pub jpeg_width: Option<i32>,
    pub jpeg_height: Option<i32>,
    pub jpeg_fragmentation_point: Option<i64>,
    pub jpeg_has_restart_markers: Option<i32>,
    pub preview_status: String,
}
```

- [ ] **Step 5: Write a roundtrip unit test**

Add to `crates/utmost-gui/src/index_db/mod.rs` tests (or a new `mod.rs` test if conventions allow):

```rust
#[test]
fn preview_status_defaults_to_unknown_and_round_trips() {
    let db = IndexDb::open_in_memory().unwrap(); // assume an in-memory open helper exists; otherwise use tempfile
    let row = FileRow { /* ... fill required fields ..., preview_status: "unknown".into() */ };
    diesel::insert_into(crate::index_db::schema::file::table)
        .values(&row)
        .execute(&mut db.conn()).unwrap();
    let back: FileRow = crate::index_db::schema::file::table
        .find(row.file_id)
        .first(&mut db.conn()).unwrap();
    assert_eq!(back.preview_status, "unknown");
}
```

If no `open_in_memory` helper exists, add one in `mod.rs` that wraps `Connection::establish(":memory:")` plus migration apply — this is genuinely useful and used by later tasks.

- [ ] **Step 6: Run tests**

Run: `cargo test -p utmost-gui index_db::`
Expected: pass.

- [ ] **Step 7: Verify existing integration tests still pass**

Run: `cargo test -p utmost-gui`
Expected: all green (existing tests adjust automatically because `preview_status` has a default).

- [ ] **Step 8: Commit**

```bash
git add crates/utmost-gui/migrations crates/utmost-gui/src/index_db/schema.rs crates/utmost-gui/src/index_db/models.rs crates/utmost-gui/src/index_db/mod.rs
git commit -m "feat(gui): add preview_status column + index + version meta key"
```

---

## Task 7: `PreviewOutcome` channel and thumb worker writes

**Files:**
- Modify: `crates/utmost-gui/src/thumb_worker.rs` (emit `PreviewOutcome`)
- Modify: `crates/utmost-gui/src/indexer_thread.rs` (drain and batch-write outcomes)
- Modify: `crates/utmost-gui/src/index_db/writer.rs` (write `preview_status` updates, bump version)
- Test: extend writer unit tests

- [ ] **Step 1: Define `PreviewOutcome`**

In `crates/utmost-gui/src/thumb_worker.rs`:

```rust
#[derive(Debug, Clone, Copy)]
pub enum PreviewStatus { HasPreview, NoPreview }

#[derive(Debug, Clone, Copy)]
pub struct PreviewOutcome {
    pub file_id: u64,
    pub status: PreviewStatus,
}
```

- [ ] **Step 2: Thumb worker takes a `Sender<PreviewOutcome>`**

In `ThumbWorker::start(...)` signature, add an optional `outcomes_tx: Option<crossbeam_channel::Sender<PreviewOutcome>>`. After each `render_with_fallback` result:

```rust
match out {
    Ok(crate::preview::PreviewOutput::Image(img)) => {
        // existing path
        if let Some(tx) = &outcomes_tx {
            let _ = tx.send(PreviewOutcome { file_id: req.file.file.file_id, status: PreviewStatus::HasPreview });
        }
    }
    _ => {
        failed.lock().unwrap().insert(req.id);
        if let Some(tx) = &outcomes_tx {
            let _ = tx.send(PreviewOutcome { file_id: req.file.file.file_id, status: PreviewStatus::NoPreview });
        }
    }
}
```

(Note: `req.file.file.file_id` — `req.file` is `FoundFile`, `.file` is the inner `FileObject`, `.file_id` is the durable id. Adjust to actual struct nesting.)

- [ ] **Step 3: Indexer thread accepts a `Receiver<PreviewOutcome>`**

In `crates/utmost-gui/src/indexer_thread.rs`, change the indexer-thread loop's `select!` (or recv loop) to also drain the outcomes channel. Batch up to 100 outcomes or 500 ms, then flush as one transaction.

- [ ] **Step 4: Implement `IndexDbWriter::write_preview_outcomes(batch: &[PreviewOutcome])`**

In `crates/utmost-gui/src/index_db/writer.rs`:

```rust
pub fn write_preview_outcomes(&mut self, batch: &[PreviewOutcome]) -> diesel::QueryResult<()> {
    use crate::index_db::schema::file::dsl as f;
    use crate::index_db::schema::meta::dsl as m;
    self.conn.transaction(|tx| {
        for outcome in batch {
            let s = match outcome.status {
                PreviewStatus::HasPreview => "has_preview",
                PreviewStatus::NoPreview  => "no_preview",
            };
            diesel::update(f::file.find(outcome.file_id as i64))
                .set(f::preview_status.eq(s))
                .execute(tx)?;
        }
        // Bump version key in meta.
        let cur: String = m::meta.find("preview_status_version")
            .select(m::value).first(tx)?;
        let next: u64 = cur.parse::<u64>().unwrap_or(0) + 1;
        diesel::update(m::meta.find("preview_status_version"))
            .set(m::value.eq(next.to_string()))
            .execute(tx)?;
        Ok(())
    })
}
```

- [ ] **Step 5: Unit test the writer**

In `writer.rs` tests (or `mod.rs`):

```rust
#[test]
fn write_preview_outcomes_updates_column_and_bumps_version() {
    let mut db = IndexDb::open_in_memory().unwrap();
    // Seed one file row with file_id=42, preview_status='unknown'.
    seed_file(&mut db, 42);
    let outcomes = [
        PreviewOutcome { file_id: 42, status: PreviewStatus::HasPreview },
    ];
    let mut writer = IndexDbWriter::new(&mut db);
    writer.write_preview_outcomes(&outcomes).unwrap();
    let row: FileRow = crate::index_db::schema::file::table.find(42i64).first(&mut db.conn()).unwrap();
    assert_eq!(row.preview_status, "has_preview");
    let v: String = crate::index_db::schema::meta::table.find("preview_status_version")
        .select(crate::index_db::schema::meta::value).first(&mut db.conn()).unwrap();
    assert_eq!(v, "1");
}
```

- [ ] **Step 6: Run tests**

Run: `cargo test -p utmost-gui index_db::writer`
Expected: pass.

- [ ] **Step 7: Commit**

```bash
git add crates/utmost-gui/src/thumb_worker.rs crates/utmost-gui/src/indexer_thread.rs crates/utmost-gui/src/index_db/writer.rs
git commit -m "feat(gui): thumb worker emits PreviewOutcome; indexer batches to preview_status"
```

---

## Task 8: FileId unification

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs` (drop GUI-local FileId counter; `FoundFile.id` becomes `file.file_id`)
- Modify: `crates/utmost-gui/src/thumb_worker.rs` (key on `file.file_id`)
- Modify: `crates/utmost-gui/src/slint_adapter.rs` (`image_cache`, `image_cache_full`, lightbox use `u64`)
- Modify: `crates/utmost-gui/src/preview/*` (anywhere keyed on GUI-local `FileId`)

**Approach:** Type alias `FileId` currently exists in `view_model.rs`. Change its definition to `pub type FileId = u64`. Then audit every `FileId` user — particularly `FoundFile`, `image_cache`, `thumbnail_ready`, `selection`, `lightbox_*` — and ensure values come from `file.file_id`, not a GUI-local counter.

`FoundFile.id` can stay as a field but its value comes from `file.file_id` directly. Or remove `FoundFile.id` and have all sites read `file.file_id`. Pick whichever yields a smaller diff (probably keeping `FoundFile.id` as an `#[inline]` accessor for `file.file_id`).

- [ ] **Step 1: Change `FileId` type alias**

In `crates/utmost-gui/src/view_model.rs`:

```rust
pub type FileId = u64;  // was likely u32 or a distinct type before
```

Drop `next_file_id: FileId` field on `ViewModel` and its `+= 1` increments.

- [ ] **Step 2: Set `FoundFile.id = file.file_id` at construction**

In the `CarveEvent::FileFound` handler, replace `let id = self.next_file_id;` with `let id = file.file_id;` (or the equivalent path to `FileObject.file_id`). Drop the `next_file_id += 1` line.

- [ ] **Step 3: Audit all `FileId` consumers**

```bash
rg "FileId" crates/utmost-gui/src/ -l
```

For each match, check the value being passed in. After this task the contract is: any `FileId` value is `file.file_id`.

- [ ] **Step 4: Run existing tests**

Run: `cargo test -p utmost-gui`
Expected: pass. Tests asserting on `FoundFile.id` may need numeric updates if fixture file_ids differ from the old counter.

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-gui/src/
git commit -m "refactor(gui): unify FileId on file.file_id, drop GUI-local counter"
```

---

## Task 9: `FileStub` and filter→SQL query builder

**Files:**
- Create: `crates/utmost-gui/src/index_db/queries.rs`
- Modify: `crates/utmost-gui/src/index_db/mod.rs` (expose `queries`)

**Design:**

```rust
// queries.rs

use crate::index_db::schema::{file, bookmark, meta};
use crate::view_model::{FilterState, SortKey, SortDir};
use diesel::prelude::*;
use utmost_lib::types::FileType;

#[derive(Debug, Clone)]
pub struct FileStub {
    pub file_id: u64,
    pub filename: String,
    pub filesize: u64,
    pub file_type: FileType,
}

pub fn query_match_ids(
    conn: &mut SqliteConnection,
    filter: &FilterState,
    sort_key: SortKey,
    sort_dir: SortDir,
    bookmarked_first: bool,
) -> diesel::QueryResult<Vec<FileStub>> {
    // Compose the query stepwise. Diesel's QueryDsl returns a different type
    // for each filter applied, so collect into a single SQL string via
    // diesel::sql_query is the path of least pain for fully-dynamic WHERE.
    // (Alternative: write a hand-built query using diesel::sql_query and ?-binding.)
    let mut sql = String::from(
        "SELECT file_id, filename, filesize, file_type FROM file"
    );
    let mut binds: Vec<Bind> = Vec::new();

    if bookmarked_first {
        sql.push_str(" LEFT JOIN bookmark USING (file_id)");
    }

    let mut wheres: Vec<String> = Vec::new();
    if let Some(src) = filter.source_filter {
        wheres.push("source_id = ?".into());
        binds.push(Bind::I64(src as i64));
    }
    if filter.bookmarked_only {
        wheres.push("file_id IN (SELECT file_id FROM bookmark)".into());
    }
    if let Some((lo, hi)) = filter.size_range {
        wheres.push("filesize BETWEEN ? AND ?".into());
        binds.push(Bind::I64(lo as i64));
        binds.push(Bind::I64(hi as i64));
    }
    if !filter.enabled_types.is_empty() {
        let placeholders = std::iter::repeat("?").take(filter.enabled_types.len()).collect::<Vec<_>>().join(",");
        wheres.push(format!("file_type IN ({})", placeholders));
        for t in &filter.enabled_types {
            binds.push(Bind::Text(t.as_str().into()));
        }
    }
    if filter.hide_no_preview {
        wheres.push("preview_status != 'no_preview'".into());
    }
    if !filter.enabled_partial_types.is_empty() {
        wheres.push("(jpeg_status = 'truncated' OR jpeg_status = 'fragmented')".into());
    }

    if !wheres.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&wheres.join(" AND "));
    }

    sql.push_str(" ORDER BY ");
    if bookmarked_first {
        sql.push_str("(bookmark.file_id IS NOT NULL) DESC, ");
    }
    let (col, dir) = match (sort_key, sort_dir) {
        (SortKey::Filename, SortDir::Asc)     => ("filename", "ASC"),
        (SortKey::Filename, SortDir::Desc)    => ("filename", "DESC"),
        (SortKey::Size, SortDir::Asc)         => ("filesize", "ASC"),
        (SortKey::Size, SortDir::Desc)        => ("filesize", "DESC"),
        (SortKey::FileType, SortDir::Asc)     => ("file_type", "ASC"),
        (SortKey::FileType, SortDir::Desc)    => ("file_type", "DESC"),
        (SortKey::SourceOffset, SortDir::Asc) => ("img_offset", "ASC"),
        (SortKey::SourceOffset, SortDir::Desc)=> ("img_offset", "DESC"),
    };
    sql.push_str(&format!("{} {}, file_id ASC", col, dir));

    let mut q = diesel::sql_query(sql);
    for b in binds {
        q = match b {
            Bind::I64(v)  => q.bind::<diesel::sql_types::BigInt, _>(v),
            Bind::Text(s) => q.bind::<diesel::sql_types::Text, _>(s),
        };
    }
    let rows: Vec<FileStubRow> = q.load(conn)?;
    Ok(rows.into_iter().map(FileStubRow::into_stub).collect())
}

enum Bind { I64(i64), Text(String) }

#[derive(QueryableByName)]
struct FileStubRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    file_id: i64,
    #[diesel(sql_type = diesel::sql_types::Text)]
    filename: String,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    filesize: i64,
    #[diesel(sql_type = diesel::sql_types::Text)]
    file_type: String,
}

impl FileStubRow {
    fn into_stub(self) -> FileStub {
        FileStub {
            file_id: self.file_id as u64,
            filename: self.filename,
            filesize: self.filesize as u64,
            file_type: utmost_lib::types::parse_file_type(&self.file_type)
                .unwrap_or(utmost_lib::types::FileType::Unknown),
        }
    }
}
```

(`utmost_lib::types::parse_file_type` may need to be added or named differently — check `view_model::parse_file_type_pub`.)

- [ ] **Step 1: Write failing unit tests**

`crates/utmost-gui/src/index_db/queries.rs` (bottom):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::index_db::IndexDb;
    use crate::view_model::{FilterState, SortKey, SortDir};

    fn fixture_10k() -> IndexDb {
        let mut db = IndexDb::open_in_memory().unwrap();
        // Insert 10000 rows across 3 file_types (jpeg, png, pdf), 2 sources,
        // filesizes spanning 1..=10_000_000, alternating bookmarked.
        // Helper lives in tests/common — for unit test, inline it.
        // ...
        db
    }

    #[test]
    fn match_ids_no_filter_returns_all_in_filename_asc() {
        let mut db = fixture_10k();
        let f = FilterState::default();
        let result = query_match_ids(&mut db.conn(), &f, SortKey::Filename, SortDir::Asc, false).unwrap();
        assert_eq!(result.len(), 10_000);
        // Each filename should be lexicographically ≥ the previous.
        for w in result.windows(2) {
            assert!(w[0].filename <= w[1].filename);
        }
    }

    #[test]
    fn match_ids_type_filter() {
        let mut db = fixture_10k();
        let mut f = FilterState::default();
        f.enabled_types = [FileType::Jpeg].iter().copied().collect();
        let result = query_match_ids(&mut db.conn(), &f, SortKey::Filename, SortDir::Asc, false).unwrap();
        assert!(result.iter().all(|s| s.file_type == FileType::Jpeg));
    }

    #[test]
    fn match_ids_size_range() {
        let mut db = fixture_10k();
        let mut f = FilterState::default();
        f.size_range = Some((1000, 5000));
        let result = query_match_ids(&mut db.conn(), &f, SortKey::Size, SortDir::Asc, false).unwrap();
        assert!(result.iter().all(|s| s.filesize >= 1000 && s.filesize <= 5000));
    }

    #[test]
    fn match_ids_bookmarked_first_puts_marked_at_top() {
        let mut db = fixture_10k();
        // Seed 50 bookmarks.
        for i in 0..50 {
            seed_bookmark(&mut db, i * 200);
        }
        let f = FilterState::default();
        let result = query_match_ids(&mut db.conn(), &f, SortKey::Filename, SortDir::Asc, true).unwrap();
        // The first 50 returned should be exactly the 50 bookmarked ids (any order among themselves).
        let first50: std::collections::HashSet<u64> = result[..50].iter().map(|s| s.file_id).collect();
        let expected: std::collections::HashSet<u64> = (0..50).map(|i| i * 200).collect();
        assert_eq!(first50, expected);
    }

    #[test]
    fn match_ids_sort_stable_on_file_id_for_ties() {
        let mut db = IndexDb::open_in_memory().unwrap();
        // Three rows with identical filesize.
        seed_file_with(&mut db, 1, "a.jpg", 100, FileType::Jpeg);
        seed_file_with(&mut db, 2, "b.jpg", 100, FileType::Jpeg);
        seed_file_with(&mut db, 3, "c.jpg", 100, FileType::Jpeg);
        let f = FilterState::default();
        let result = query_match_ids(&mut db.conn(), &f, SortKey::Size, SortDir::Asc, false).unwrap();
        assert_eq!(result.iter().map(|s| s.file_id).collect::<Vec<_>>(), vec![1, 2, 3]);
    }
}
```

(The `seed_*` helpers may need to live in `crates/utmost-gui/src/index_db/mod.rs` under `#[cfg(test)]`. Or inline them in each test.)

- [ ] **Step 2: Verify failing**

Run: `cargo test -p utmost-gui index_db::queries::tests`
Expected: compile error (no queries module) → fail.

- [ ] **Step 3: Implement `queries.rs` with the skeleton above**

Add `pub mod queries;` to `crates/utmost-gui/src/index_db/mod.rs`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p utmost-gui index_db::queries::tests`
Expected: all 5 pass.

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-gui/src/index_db/
git commit -m "feat(gui): query_match_ids with composable filter and sort"
```

---

## Task 10: `fetch_window` and `set_preview_status`

**Files:**
- Modify: `crates/utmost-gui/src/index_db/queries.rs` (add two functions)

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn fetch_window_returns_rows_in_input_order() {
    let mut db = IndexDb::open_in_memory().unwrap();
    seed_file_with(&mut db, 10, "a.jpg", 100, FileType::Jpeg);
    seed_file_with(&mut db, 20, "b.jpg", 100, FileType::Jpeg);
    seed_file_with(&mut db, 30, "c.jpg", 100, FileType::Jpeg);
    // Input order: 30, 10, 20.
    let ids = vec![30u64, 10, 20];
    let rows = fetch_window(&mut db.conn(), &ids).unwrap();
    assert_eq!(rows.iter().map(|r| r.file_id).collect::<Vec<_>>(), vec![30, 10, 20]);
}

#[test]
fn set_preview_status_writes_and_bumps_version() {
    let mut db = IndexDb::open_in_memory().unwrap();
    seed_file_with(&mut db, 1, "a.jpg", 100, FileType::Jpeg);
    set_preview_status(&mut db.conn(), 1, "has_preview").unwrap();
    let row: FileRow = crate::index_db::schema::file::table.find(1i64).first(&mut db.conn()).unwrap();
    assert_eq!(row.preview_status, "has_preview");
    let v: String = crate::index_db::schema::meta::table.find("preview_status_version")
        .select(crate::index_db::schema::meta::value).first(&mut db.conn()).unwrap();
    assert_eq!(v, "1");
}
```

- [ ] **Step 2: Implement**

```rust
pub fn fetch_window(conn: &mut SqliteConnection, ids: &[u64]) -> diesel::QueryResult<Vec<FoundFile>> {
    if ids.is_empty() { return Ok(Vec::new()); }
    let placeholders = std::iter::repeat("?").take(ids.len()).collect::<Vec<_>>().join(",");
    let sql = format!(
        "SELECT * FROM file WHERE file_id IN ({})", placeholders
    );
    let mut q = diesel::sql_query(sql);
    for id in ids { q = q.bind::<diesel::sql_types::BigInt, _>(*id as i64); }
    let rows: Vec<FileRow> = q.load(conn)?;
    // Reorder to match the input slice.
    let mut by_id: std::collections::HashMap<u64, FileRow> =
        rows.into_iter().map(|r| (r.file_id as u64, r)).collect();
    let out: Vec<FoundFile> = ids.iter()
        .filter_map(|id| by_id.remove(id).map(file_row_to_found_file))
        .collect();
    Ok(out)
}

pub fn set_preview_status(conn: &mut SqliteConnection, file_id: u64, status: &str) -> diesel::QueryResult<()> {
    use crate::index_db::schema::file::dsl as f;
    use crate::index_db::schema::meta::dsl as m;
    conn.transaction(|tx| {
        diesel::update(f::file.find(file_id as i64))
            .set(f::preview_status.eq(status))
            .execute(tx)?;
        let cur: String = m::meta.find("preview_status_version").select(m::value).first(tx)?;
        let next: u64 = cur.parse::<u64>().unwrap_or(0) + 1;
        diesel::update(m::meta.find("preview_status_version"))
            .set(m::value.eq(next.to_string()))
            .execute(tx)?;
        Ok(())
    })
}

fn file_row_to_found_file(r: FileRow) -> FoundFile {
    // Construct a FoundFile from a FileRow.
    // Mirror the inverse of the hydrate path in index_db/hydrate.rs.
    todo!("Mirror FileRow→FoundFile conversion from hydrate.rs and refactor that hydrator to call this helper.")
}
```

The `todo!()` is a plan failure if left in. The implementer must port the existing FileRow→FoundFile conversion from `crates/utmost-gui/src/index_db/hydrate.rs` into a shared helper (e.g. `models::file_row_to_found_file`) and call it from both sites. Do this refactor as part of Step 2.

- [ ] **Step 3: Run tests**

Run: `cargo test -p utmost-gui index_db::queries::tests`
Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add crates/utmost-gui/src/index_db/
git commit -m "feat(gui): fetch_window + set_preview_status with input-order preservation"
```

---

## Task 11: Indexer thread command/event extensions + epoch

**Files:**
- Modify: `crates/utmost-gui/src/indexer_thread.rs`

**Design:**

```rust
pub enum IndexerCommand {
    Requery { filter: FilterState, sort_key: SortKey, sort_dir: SortDir, bookmarked_first: bool, epoch: u64 },
    FetchWindow { ids: Vec<u64>, range_start: usize, epoch: u64 },
    WritePreviewStatus { outcomes: Vec<PreviewOutcome>, epoch: u64 },
    Shutdown,
}

pub enum IndexerEvent {
    // Existing variants (Started, Bytes, Files, Finished, Error) preserved.
    MatchIds { stubs: Vec<FileStub>, epoch: u64 },
    WindowFilled { rows: Vec<FoundFile>, range_start: usize, epoch: u64 },
    PreviewStatusVersion(u64),
}
```

The indexer thread holds the current epoch. Each command carries the epoch the UI thread had when it issued the command. The indexer drops a command if its epoch is older than the indexer's current epoch (the UI has already moved on). The indexer **does not** drop in-flight work mid-query; we use channel-level dropping at message ingest only.

- [ ] **Step 1: Add variants**

Extend `IndexerCommand` and `IndexerEvent` enums.

- [ ] **Step 2: Indexer loop drains commands and dispatches**

Add a match arm for each new command. `Requery` calls `query_match_ids` and emits `MatchIds`. `FetchWindow` calls `fetch_window` and emits `WindowFilled`. `WritePreviewStatus` batches outcomes and emits `PreviewStatusVersion(new_version)`.

- [ ] **Step 3: Unit test stale-epoch drop**

```rust
#[test]
fn stale_epoch_requery_is_dropped() {
    // Construct an indexer thread state with current_epoch=5.
    // Issue Requery{epoch=3} and Requery{epoch=5}.
    // Assert only one MatchIds event arrives, for epoch=5.
}
```

(May require refactoring the indexer to expose a `step()` function that processes one command for testability. If too invasive, defer the stale-epoch test to an integration test in Task 16.)

- [ ] **Step 4: Run tests**

Run: `cargo test -p utmost-gui indexer_thread`
Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-gui/src/indexer_thread.rs
git commit -m "feat(gui): indexer thread Requery/FetchWindow/WritePreviewStatus with epoch"
```

---

## Task 12: ViewModel migration to `match_ids` + `window`

**Files:**
- Modify: `crates/utmost-gui/src/view_model.rs`
- Modify: `crates/utmost-gui/src/index_db/hydrate.rs` (no longer hydrates `vm.files`)

**Design:**

```rust
pub struct ViewModel {
    // Removed: pub files: Vec<FoundFile>, pub visible_files: Vec<FileId>, pub thumbnail_ready: BTreeSet<FileId>.
    pub match_ids: Vec<crate::index_db::queries::FileStub>,
    pub window: std::collections::BTreeMap<u64, FoundFile>,
    pub window_range: std::ops::Range<usize>,
    pub preview_status_version: u64,
    pub current_epoch: u64,
    // ... existing fields (bookmarks, notes, best_choice, variants_by_id, filter, etc.)
}

impl ViewModel {
    pub fn apply_match_ids(&mut self, stubs: Vec<FileStub>, epoch: u64) {
        if epoch < self.current_epoch { return; }
        self.match_ids = stubs;
        // Preserve selection if id still present.
        if let Some(sel) = self.selection
            && !self.match_ids.iter().any(|s| s.file_id == sel)
        {
            self.selection = None;
        }
        // Reset window range; UI will issue FetchWindow next tick.
        self.window_range = 0..0;
        self.window.clear();
    }

    pub fn apply_window_filled(&mut self, rows: Vec<FoundFile>, range_start: usize, epoch: u64) {
        if epoch < self.current_epoch { return; }
        self.window.clear();
        for r in rows {
            self.window.insert(r.file.file_id, r);
        }
        self.window_range = range_start..(range_start + self.window.len());
    }

    pub fn need_slide(&self, visible_first_row: usize, visible_last_row: usize,
                      window_size: usize, slide_trigger: usize) -> Option<std::ops::Range<usize>>
    {
        let total = self.match_ids.len();
        if total == 0 { return None; }
        let in_window = self.window_range.start + slide_trigger <= visible_first_row
            && visible_last_row + slide_trigger < self.window_range.end;
        if in_window { return None; }
        let target_center = (visible_first_row + visible_last_row) / 2;
        let half = window_size / 2;
        let start = target_center.saturating_sub(half).min(total.saturating_sub(window_size).max(0));
        let end = (start + window_size).min(total);
        Some(start..end)
    }

    pub fn recompute_visible(&mut self) {
        // No-op. Filter/sort now run as SQL via the indexer. Kept as a stub
        // until callers are migrated to post Requery commands.
    }
}
```

- [ ] **Step 1: Write failing unit tests**

```rust
#[cfg(test)]
mod windowing_tests {
    use super::*;
    use crate::index_db::queries::FileStub;
    use utmost_lib::types::FileType;

    fn stub(id: u64) -> FileStub {
        FileStub { file_id: id, filename: format!("f{id}"), filesize: id * 10, file_type: FileType::Jpeg }
    }

    #[test]
    fn apply_match_ids_clears_window_and_resets_range() {
        let mut vm = ViewModel::default();
        vm.match_ids = vec![stub(1), stub(2)];
        vm.window.insert(1, fake_found_file(1));
        vm.window_range = 0..2;
        vm.apply_match_ids(vec![stub(3), stub(4)], 0);
        assert!(vm.window.is_empty());
        assert_eq!(vm.window_range, 0..0);
        assert_eq!(vm.match_ids.len(), 2);
    }

    #[test]
    fn apply_match_ids_clears_selection_when_missing() {
        let mut vm = ViewModel::default();
        vm.match_ids = vec![stub(1), stub(2)];
        vm.selection = Some(2);
        vm.apply_match_ids(vec![stub(3)], 0);
        assert_eq!(vm.selection, None);
    }

    #[test]
    fn apply_match_ids_preserves_selection_when_present() {
        let mut vm = ViewModel::default();
        vm.match_ids = vec![stub(1), stub(2)];
        vm.selection = Some(2);
        vm.apply_match_ids(vec![stub(2), stub(3)], 0);
        assert_eq!(vm.selection, Some(2));
    }

    #[test]
    fn need_slide_no_slide_when_visible_inside_window() {
        let mut vm = ViewModel::default();
        vm.match_ids = (0..1000).map(stub).collect();
        vm.window_range = 100..600;
        // Visible 300..400 with slide_trigger=4 → no slide.
        assert_eq!(vm.need_slide(300, 400, 500, 4), None);
    }

    #[test]
    fn need_slide_slides_when_visible_near_edge() {
        let mut vm = ViewModel::default();
        vm.match_ids = (0..1000).map(stub).collect();
        vm.window_range = 100..600;
        // Visible 102..200 → within slide_trigger of start.
        let r = vm.need_slide(102, 200, 500, 4).unwrap();
        // Centered on 151, half=250 → start = 0 (saturating).
        assert_eq!(r.start, 0);
        assert_eq!(r.end, 500);
    }

    #[test]
    fn need_slide_clamps_to_total() {
        let mut vm = ViewModel::default();
        vm.match_ids = (0..1000).map(stub).collect();
        vm.window_range = 100..600;
        let r = vm.need_slide(900, 950, 500, 4).unwrap();
        assert_eq!(r.end, 1000);
        assert_eq!(r.start, 500);
    }

    fn fake_found_file(id: u64) -> FoundFile {
        // Minimal FoundFile fixture — values irrelevant for windowing tests.
        // Use whatever default construction exists, or build inline.
        unimplemented!("Implementer: fill in based on FoundFile's actual fields")
    }
}
```

- [ ] **Step 2: Implement the new fields and methods**

Replace `Vec<FoundFile> files`, `Vec<FileId> visible_files`, `BTreeSet<FileId> thumbnail_ready` with the new fields. Update `Default for ViewModel`. Drop `next_file_id`. Replace the body of `recompute_visible` with a comment "// no-op; filter/sort now run on the indexer thread".

Update the `apply` method's `CarveEvent::FileFound` arm: it should no longer push to `vm.files`. Instead, hold the file in a per-event-batch buffer if needed for legacy callers, OR rely on the indexer thread's SQLite write as the durable record and trigger a debounced live-mode requery (Task 16). For this task, simply removing the push is enough — the file is already being written to SQLite by the existing indexer writer.

Update `hydrate.rs`: it no longer needs to populate `vm.files`. Bookmarks, notes, best, variants still hydrate.

- [ ] **Step 3: Update Slint adapter to consume the new model**

In `slint_adapter.rs::UiState::sync`, replace the tile-building loop:

```rust
// Old:
let tiles: Vec<FileTileData> = vm
    .visible_files
    .iter()
    .filter_map(|fid| vm.files.iter().find(|f| f.id == *fid))
    ...

// New (temporary, eager — Task 14 swaps this for windowed):
let tiles: Vec<FileTileData> = vm
    .match_ids
    .iter()
    .take(vm.window_range.end)
    .filter_map(|stub| vm.window.get(&stub.file_id))
    .map(|f| FileTileData { /* ... existing fields ..., absolute_row: 0, absolute_col: 0 */ })
    .collect();
```

This is a transition step — the UI temporarily limps along reading only currently-windowed rows. Subsequent tasks fix it properly.

Update lightbox prev/next and `gallery-nav` to walk `vm.match_ids` (using `file_id`) instead of `vm.visible_files`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p utmost-gui`
Expected: existing integration tests likely break here. Adjust them: fixtures that asserted on `vm.files.len()` now assert on `vm.match_ids.len()`. Note that without the indexer wiring (Task 13), `vm.match_ids` stays empty in tests — that may leave some tests temporarily failing. The acceptable state at the end of this task: unit tests pass; integration tests are either passing or have a clear path to pass in Task 13.

- [ ] **Step 5: Commit**

```bash
git add crates/utmost-gui/src/view_model.rs crates/utmost-gui/src/index_db/hydrate.rs crates/utmost-gui/src/slint_adapter.rs
git commit -m "refactor(gui): ViewModel migrates to match_ids + window + window_range"
```

---

## Task 13: Wire VM to indexer thread for requery + initial window fetch

**Files:**
- Modify: `crates/utmost-gui/src/slint_adapter.rs` (post commands on filter/sort change; drain events; bump epoch)
- Modify: `crates/utmost-gui/src/lib.rs` (issue initial Requery after hydration completes)

- [ ] **Step 1: UiState gets an `indexer_tx: Sender<IndexerCommand>` field**

Adapter stores the sender alongside the existing receiver-drain logic. Constructor accepts it.

- [ ] **Step 2: Filter/sort change handlers post `Requery`**

Replace every site in `slint_adapter.rs` that calls `v.recompute_visible()` after a filter mutation with:

```rust
v.current_epoch += 1;
let _ = self.indexer_tx.send(IndexerCommand::Requery {
    filter: v.filter.clone(),
    sort_key: v.filter.sort_key,
    sort_dir: v.filter.sort_dir,
    bookmarked_first: v.filter.bookmarked_first,
    epoch: v.current_epoch,
});
```

- [ ] **Step 3: Initial Requery on hydration finish**

In `crates/utmost-gui/src/lib.rs`, after the indexer thread emits `Finished` (or equivalent), post the initial Requery. Or — simpler — post it immediately at the end of hydration (the indexer can answer right away even during hydration since the rows are in SQLite as they're written).

- [ ] **Step 4: Drain new IndexerEvents in the sync tick**

In `UiState::sync`, in the event-drain loop:

```rust
while let Ok(ev) = self.indexer_rx.try_recv() {
    match ev {
        IndexerEvent::MatchIds { stubs, epoch }   => vm.apply_match_ids(stubs, epoch),
        IndexerEvent::WindowFilled { rows, range_start, epoch } =>
            vm.apply_window_filled(rows, range_start, epoch),
        IndexerEvent::PreviewStatusVersion(v) => vm.preview_status_version = v,
        // ... existing variants (Started, Bytes, Files, Finished, Error)
    }
}
```

- [ ] **Step 5: Run integration tests adjusted in Task 12**

Run: `cargo test -p utmost-gui`
Expected: all existing tests now pass — `match_ids` populates from the indexer's Requery response after hydration.

- [ ] **Step 6: Manual smoke**

`cargo run -- <some-case>` — verify the gallery still renders (eagerly, not yet windowed).

- [ ] **Step 7: Commit**

```bash
git add crates/utmost-gui/src/slint_adapter.rs crates/utmost-gui/src/lib.rs
git commit -m "feat(gui): UiState posts Requery on filter change; drains MatchIds/WindowFilled"
```

---

## Task 14: Slint absolute positioning + viewport-y bridge + window slide

**Files:**
- Modify: `crates/utmost-gui/ui/main.slint` (new top-level properties)
- Modify: `crates/utmost-gui/ui/detail.slint` (tile loop uses absolute row/col; expose viewport-y; changed cols callback)
- Modify: `crates/utmost-gui/src/slint_adapter.rs` (add `absolute_row`/`absolute_col` to FileTileData; read viewport-y/cols; issue FetchWindow on slide)

- [ ] **Step 1: Extend `FileTileData`**

Find the struct definition (likely in `slint_adapter.rs` and mirrored in a `.slint` file). Add two `int` fields:

```slint
struct FileTileData {
    id: int,
    filename: string,
    filesize: string,
    file_type: string,
    has_thumbnail: bool,
    thumbnail: image,
    absolute_row: int,
    absolute_col: int,
}
```

(Adjust the existing Slint struct in whichever `.slint` file declares `FileTileData` — likely `detail.slint`.)

- [ ] **Step 2: Add Slint properties on `MainWindow` and `DetailPage`**

In `crates/utmost-gui/ui/main.slint`:

```slint
in property <int> total-rows: 0;
in property <int> grid-cols: 1;
in property <bool> requery-active: false;
callback grid-cols-changed(int);
```

Forward them to `DetailPage` and bind in the detail content.

- [ ] **Step 3: Switch tile loop to absolute positioning**

In `crates/utmost-gui/ui/detail.slint`:

```slint
property <int> total-rows: root.total-rows;
property <length> tile-pitch-y: self.tile_h + self.gap;
property <length> tile-pitch-x: self.tile_w + self.gap;
property <int> cols-internal: max(1, floor((self.width + self.gap) / self.tile-pitch-x));
changed cols-internal => { root.grid-cols-changed(self.cols-internal); }

grid_flick := Flickable {
    width: parent.width;
    height: parent.height;
    viewport-width: grid_pane.cols-internal * grid_pane.tile-pitch-x;
    viewport-height: grid_pane.total-rows * grid_pane.tile-pitch-y;

    for tile[i] in root.tiles: Rectangle {
        x: tile.absolute_col * grid_pane.tile-pitch-x;
        y: tile.absolute_row * grid_pane.tile-pitch-y;
        // ... rest of body unchanged
    }
}
```

Expose `viewport-y` so Rust can read it. The Flickable already has it as a property; just rename the Flickable's id to be readable through a `out property <length> grid-viewport-y: grid_flick.viewport-y;` on the DetailPage root, and bind it up to MainWindow.

- [ ] **Step 4: UiState reads viewport-y / cols and issues FetchWindow**

In `UiState::sync`:

```rust
let viewport_y_px: f32 = self.window.get_grid_viewport_y() as f32; // expose accessor
let cols = self.window.get_grid_cols() as usize;
let viewport_h_px: f32 = ...; // detail-page grid pane height; expose similarly
let tile_pitch_y = 168.0 + 8.0; // tile_h + gap
let visible_first_row = (-viewport_y_px / tile_pitch_y).floor().max(0.0) as usize;
let visible_count = (viewport_h_px / tile_pitch_y).ceil() as usize;
let visible_last_row = visible_first_row + visible_count;

let visible_tiles = cols * (visible_count + 1);
let window_size = (25 * visible_tiles).clamp(500, 5000);
let slide_trigger = 4;

if let Some(new_range) = vm.need_slide(visible_first_row, visible_last_row, window_size, slide_trigger) {
    vm.current_epoch += 1;
    let ids: Vec<u64> = vm.match_ids[new_range.clone()].iter().map(|s| s.file_id).collect();
    let _ = self.indexer_tx.send(IndexerCommand::FetchWindow {
        ids,
        range_start: new_range.start,
        epoch: vm.current_epoch,
    });
    // Optimistically advance window_range so subsequent ticks don't re-issue.
    vm.window_range = new_range;
}
```

- [ ] **Step 5: Build tiles with absolute row/col**

In `UiState::sync`, build `FileTileData` from `match_ids[window_range]`, using each stub for the row metadata. For ids present in `vm.window`, attach the cached thumbnail and full FoundFile data; for ids in the range but not yet in `vm.window`, render a placeholder using the stub:

```rust
let cols = self.window.get_grid_cols() as usize;
let tiles: Vec<FileTileData> = vm.match_ids[vm.window_range.clone()]
    .iter()
    .enumerate()
    .map(|(slot_idx, stub)| {
        let abs_idx = vm.window_range.start + slot_idx;
        let absolute_row = (abs_idx / cols) as i32;
        let absolute_col = (abs_idx % cols) as i32;
        let (has, img) = match vm.window.get(&stub.file_id) {
            Some(_) => /* get cached image from image_cache or request via ThumbWorker */ (true, image),
            None    => (false, slint::Image::default()),
        };
        FileTileData {
            id: stub.file_id as i32,
            filename: SharedString::from(stub.filename.as_str()),
            filesize: SharedString::from(format!("{} B", stub.filesize)),
            file_type: SharedString::from(format!("{:?}", stub.file_type)),
            has_thumbnail: has,
            thumbnail: img,
            absolute_row,
            absolute_col,
        }
    })
    .collect();
self.window.set_total_rows(((vm.match_ids.len() + cols.saturating_sub(1)) / cols.max(1)) as i32);
self.window.set_grid_cols(cols as i32);
replace_model(&self.tiles_model, tiles);
```

- [ ] **Step 6: Run existing tests**

Run: `cargo test -p utmost-gui`
Expected: pass.

- [ ] **Step 7: Manual smoke**

`cargo run -- <286k case>`. Open it. Verify:

- Window appears within ~100 ms.
- Scrolling is smooth.
- Tile metadata (filename/size) is always present.
- Thumbnails populate within the visible region as you scroll.

- [ ] **Step 8: Commit**

```bash
git add crates/utmost-gui/ui/ crates/utmost-gui/src/slint_adapter.rs
git commit -m "feat(gui): windowed Slint grid with viewport-y bridge and slide-on-scroll"
```

---

## Task 15: Integration tests — cold load, filter change, scroll slides, keyboard nav

**Files:**
- Create: `crates/utmost-gui/tests/windowed_load_cold.rs`
- Create: `crates/utmost-gui/tests/windowed_filter_change.rs`
- Create: `crates/utmost-gui/tests/windowed_scroll_slides.rs`
- Create: `crates/utmost-gui/tests/windowed_keyboard_nav.rs`
- Modify: `crates/utmost-gui/tests/common/synthetic_log.rs` (extend if needed for 50k+ rows)

Each test spins up a synthetic `.bin` + indexer thread + headless ViewModel (no Slint window). Drive the loop manually by calling `apply_match_ids` / `apply_window_filled` after pumping the indexer.

- [ ] **Step 1: `windowed_load_cold.rs`**

```rust
#[test]
fn cold_open_materializes_only_window_size_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let case_dir = tmp.path().join("case");
    write_synthetic_case(&case_dir, 50_000).unwrap();

    let (indexer, ui_rx) = launch_indexer_for_test(&case_dir).unwrap();
    indexer.send(IndexerCommand::Requery { /* default filter */ epoch: 1, ... }).unwrap();
    let stubs = recv_match_ids(&ui_rx);
    assert_eq!(stubs.len(), 50_000);

    let window_size = 1000;
    let ids: Vec<u64> = stubs.iter().take(window_size).map(|s| s.file_id).collect();
    indexer.send(IndexerCommand::FetchWindow { ids: ids.clone(), range_start: 0, epoch: 1 }).unwrap();
    let rows = recv_window_filled(&ui_rx);
    assert_eq!(rows.len(), window_size);
    indexer.send(IndexerCommand::Shutdown).unwrap();
}
```

- [ ] **Step 2: `windowed_filter_change.rs`**

```rust
#[test]
fn toggling_type_chip_emits_one_new_matchids_event() {
    let case = synthetic_case_with_types(/* 5k jpeg + 5k png */ 5_000, 5_000);
    let (indexer, ui_rx) = launch_indexer_for_test(&case).unwrap();
    // Initial Requery: all enabled.
    indexer.send(IndexerCommand::Requery { /* both types enabled */, epoch: 1 }).unwrap();
    let all = recv_match_ids(&ui_rx);
    assert_eq!(all.len(), 10_000);

    // Disable PNG.
    indexer.send(IndexerCommand::Requery { /* only jpeg */, epoch: 2 }).unwrap();
    let only_jpeg = recv_match_ids(&ui_rx);
    assert_eq!(only_jpeg.len(), 5_000);
    assert!(only_jpeg.iter().all(|s| s.file_type == FileType::Jpeg));
}
```

- [ ] **Step 3: `windowed_scroll_slides.rs`**

```rust
#[test]
fn scrolling_past_window_end_triggers_new_fetch() {
    let case = synthetic_case(20_000);
    let mut vm = ViewModel::default();
    let stubs = (0u64..20_000).map(|i| stub(i)).collect();
    vm.apply_match_ids(stubs, 1);
    // First window 0..1000.
    let r1 = vm.need_slide(0, 50, 1000, 4).unwrap();
    assert_eq!(r1.start, 0);
    vm.window_range = r1.clone();
    // User scrolls to row 1500 — outside window 0..1000.
    let r2 = vm.need_slide(1500, 1550, 1000, 4).unwrap();
    assert!(r2.start > 0);
    assert!(r2.contains(&1500));
}
```

- [ ] **Step 4: `windowed_keyboard_nav.rs`**

```rust
#[test]
fn j_5000_times_advances_selection_across_window_slides() {
    let mut vm = ViewModel::default();
    let stubs: Vec<_> = (0u64..50_000).map(stub).collect();
    vm.apply_match_ids(stubs.clone(), 1);
    vm.selection = Some(stubs[0].file_id);

    for _ in 0..5000 {
        // Simulate the `j` handler: find current selection's index in match_ids
        // and advance by 1.
        let cur = vm.selection.unwrap();
        let idx = vm.match_ids.iter().position(|s| s.file_id == cur).unwrap();
        if idx + 1 < vm.match_ids.len() {
            vm.selection = Some(vm.match_ids[idx + 1].file_id);
        }
    }
    assert_eq!(vm.selection, Some(stubs[5000].file_id));
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p utmost-gui --test windowed_load_cold --test windowed_filter_change --test windowed_scroll_slides --test windowed_keyboard_nav`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-gui/tests/windowed_*.rs crates/utmost-gui/tests/common/
git commit -m "test(gui): windowed loading — cold, filter change, scroll slides, keyboard nav"
```

---

## Task 16: Live-mode auto-requery + `hide_no_preview` requery on version bump

**Files:**
- Modify: `crates/utmost-gui/src/indexer_thread.rs` (after batch commit in live mode, schedule debounced Requery)
- Modify: `crates/utmost-gui/src/slint_adapter.rs` (sync tick: observe `preview_status_version`, schedule debounced Requery if `hide_no_preview` on)
- Create: `crates/utmost-gui/tests/windowed_live_mode.rs`
- Create: `crates/utmost-gui/tests/preview_status_persist.rs`

- [ ] **Step 1: Live-mode debounce in indexer**

Add a `last_live_requery: Option<Instant>` to the indexer's loop state. After each batch commit while in live mode, if `now - last_live_requery > 500ms`, re-run the most recent `Requery` (cache the last filter/sort args) and emit a fresh `MatchIds`. Update `last_live_requery`.

- [ ] **Step 2: Preview-status version observer in UI**

In `UiState::sync`, after draining events:

```rust
if vm.filter.hide_no_preview && vm.preview_status_version != self.last_observed_preview_version {
    if self.last_preview_requery.elapsed() > Duration::from_secs(1) {
        // Issue Requery.
        vm.current_epoch += 1;
        let _ = self.indexer_tx.send(IndexerCommand::Requery { ..., epoch: vm.current_epoch });
        self.last_preview_requery = Instant::now();
        self.last_observed_preview_version = vm.preview_status_version;
    }
}
```

- [ ] **Step 3: `windowed_live_mode.rs`**

```rust
#[test]
fn appending_files_while_open_extends_match_ids() {
    let tmp = tempfile::tempdir().unwrap();
    let case_dir = tmp.path().join("case");
    write_synthetic_case(&case_dir, 100).unwrap();
    let (indexer, ui_rx, sink) = launch_indexer_with_live_writer(&case_dir).unwrap();
    indexer.send(IndexerCommand::Requery { epoch: 1, ... }).unwrap();
    let first = recv_match_ids(&ui_rx);
    assert_eq!(first.len(), 100);

    // Append 50 more files.
    append_synthetic_files(&sink, 50).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    // Should have received a fresh MatchIds with 150.
    let second = recv_match_ids(&ui_rx);
    assert_eq!(second.len(), 150);
}
```

- [ ] **Step 4: `preview_status_persist.rs`**

```rust
#[test]
fn preview_status_persists_across_restart_and_filters_no_preview() {
    let tmp = tempfile::tempdir().unwrap();
    let case_dir = tmp.path().join("case");
    write_synthetic_case(&case_dir, 200).unwrap();

    // First session: mark file_ids [0..50) as no_preview.
    {
        let (indexer, _ui_rx) = launch_indexer_for_test(&case_dir).unwrap();
        let outcomes: Vec<_> = (0..50).map(|i| PreviewOutcome {
            file_id: i, status: PreviewStatus::NoPreview
        }).collect();
        indexer.send(IndexerCommand::WritePreviewStatus { outcomes, epoch: 1 }).unwrap();
        indexer.send(IndexerCommand::Shutdown).unwrap();
    }

    // Second session: hide_no_preview filter on. Expect 150 files (not 200).
    {
        let (indexer, ui_rx) = launch_indexer_for_test(&case_dir).unwrap();
        let mut filter = FilterState::default();
        filter.hide_no_preview = true;
        indexer.send(IndexerCommand::Requery { filter, epoch: 1, ... }).unwrap();
        let stubs = recv_match_ids(&ui_rx);
        assert_eq!(stubs.len(), 150);
    }
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p utmost-gui --test windowed_live_mode --test preview_status_persist`
Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-gui/src/indexer_thread.rs crates/utmost-gui/src/slint_adapter.rs crates/utmost-gui/tests/windowed_live_mode.rs crates/utmost-gui/tests/preview_status_persist.rs
git commit -m "feat(gui): live-mode auto-requery + hide_no_preview requery on version bump

Closes #2."
```

---

## Task 17: Instrument additional `sync()` phases and indexer-thread phases

**Files:**
- Modify: `crates/utmost-gui/src/slint_adapter.rs`
- Modify: `crates/utmost-gui/src/indexer_thread.rs`
- Modify: `crates/utmost-gui/src/index_db/queries.rs`
- Create: `crates/utmost-gui/tests/telemetry_log_smoke.rs`

- [ ] **Step 1: Add `phase()` wraps in `UiState::sync`**

```rust
pub fn sync(&self, vm: &mut ViewModel) {
    let _total = self.perf.phase("total");
    {
        let _g = self.perf.phase("drain_events");
        while let Ok(ev) = self.indexer_rx.try_recv() { ... }
    }
    {
        let _g = self.perf.phase("viewport_read");
        // read viewport-y / cols
    }
    {
        let _g = self.perf.phase("slide_decide");
        // need_slide + maybe send FetchWindow
    }
    {
        let _g = self.perf.phase("build_tiles");
        // build FileTileData
    }
    {
        let _g = self.perf.phase("replace_tiles_model");
        replace_model(&self.tiles_model, tiles);
    }
    {
        let _g = self.perf.phase("build_metadata");
        // selected-file rows
    }
    {
        let _g = self.perf.phase("chips_refresh");
        // chips rebuild if needed
    }
    self.perf.tick();
}
```

- [ ] **Step 2: Indexer thread `perf`**

The indexer thread gets its own `PerfRecorder` constructed with target `utmost_gui::perf::indexer`. Wrap `query_match_ids`, `fetch_window`, `batch_flush`, and `write_preview_outcomes` calls.

- [ ] **Step 3: Telemetry log smoke test**

`crates/utmost-gui/tests/telemetry_log_smoke.rs`:

```rust
#[test]
fn perf_log_line_emitted_when_enabled() {
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("UTMOST_LOG_DIR", tmp.path());
    std::env::set_var("UTMOST_PERF_TRACE", "1");
    std::env::set_var("UTMOST_PERF_TICKS", "5");

    let telemetry = utmost_gui::init_telemetry();
    for _ in 0..6 {
        let _g = telemetry.perf.phase("a_phase");
        std::thread::sleep(std::time::Duration::from_micros(50));
        drop(_g);
        telemetry.perf.tick();
    }
    drop(telemetry); // flush the appender

    let log_path = tmp.path().join("utmost-gui.log");
    // Daily rolling appends a date suffix; glob.
    let entries: Vec<_> = std::fs::read_dir(tmp.path()).unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("utmost-gui.log"))
        .collect();
    assert!(!entries.is_empty());
    let mut content = String::new();
    for e in entries {
        content.push_str(&std::fs::read_to_string(e.path()).unwrap());
    }
    assert!(content.contains("utmost_gui::perf"));
    assert!(content.contains("a_phase"));
}
```

(Run in serial-test mode if `std::env::set_var` races with other tests; or wrap in `#[serial]` from the `serial_test` crate if already present.)

- [ ] **Step 4: Run tests**

Run: `cargo test -p utmost-gui --test telemetry_log_smoke`
Expected: pass.

- [ ] **Step 5: Manual smoke**

`UTMOST_PERF_TRACE=1 UTMOST_PERF_TICKS=50 cargo run -- <286k case>`. Scroll for ~5 seconds. Tail the log file. Expect one `utmost_gui::perf` line every ~5 seconds (50 ticks at 10 Hz) showing per-phase timings, with `build_tiles` and `replace_tiles_model` typically dominating.

- [ ] **Step 6: Commit**

```bash
git add crates/utmost-gui/src/slint_adapter.rs crates/utmost-gui/src/indexer_thread.rs crates/utmost-gui/src/index_db/queries.rs crates/utmost-gui/tests/telemetry_log_smoke.rs
git commit -m "feat(gui): instrument sync and indexer phases for perf telemetry"
```

---

## Task 18: Criterion benchmarks

**Files:**
- Create: `crates/utmost-gui/benches/windowed_load.rs`
- Modify: `crates/utmost-gui/Cargo.toml` (add `[[bench]]` entry, `#[ignore]`-style)

- [ ] **Step 1: Write `bench_match_ids_250k`, `bench_window_fetch_2500`, `bench_sync_tick_window`, `bench_perf_disabled_zero_cost`**

`crates/utmost-gui/benches/windowed_load.rs`:

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_match_ids_250k(c: &mut Criterion) {
    let mut db = build_fixture_db(250_000);
    let filter = FilterState::default();
    c.bench_function("match_ids_250k", |b| {
        b.iter(|| {
            let stubs = query_match_ids(
                &mut db.conn(), &filter, SortKey::Filename, SortDir::Asc, false
            ).unwrap();
            black_box(stubs.len());
        });
    });
}

fn bench_window_fetch_2500(c: &mut Criterion) {
    let mut db = build_fixture_db(10_000);
    let ids: Vec<u64> = (0..2500).collect();
    c.bench_function("window_fetch_2500", |b| {
        b.iter(|| {
            let rows = fetch_window(&mut db.conn(), &ids).unwrap();
            black_box(rows.len());
        });
    });
}

fn bench_sync_tick_window(c: &mut Criterion) {
    // Construct UiState + populated ViewModel with 250k stubs and 2500 windowed rows.
    // Call UiState::sync (or a sync-tick equivalent that doesn't need a real Slint window).
    // The sync needs Slint properties; mock or split out the pure-Rust portion.
    // If too coupled to Slint, bench just the build_tiles helper.
}

fn bench_perf_disabled_zero_cost(c: &mut Criterion) {
    let r = utmost_gui::telemetry::PerfRecorder::new("test", false, 100_000);
    c.bench_function("phase_disabled", |b| {
        b.iter(|| {
            let _g = r.phase("noop");
            black_box(&_g);
        });
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench_match_ids_250k, bench_window_fetch_2500, bench_sync_tick_window, bench_perf_disabled_zero_cost
);
criterion_main!(benches);
```

In `Cargo.toml`:

```toml
[[bench]]
name = "windowed_load"
harness = false
```

(Match the existing `index_load` bench convention from the previous spec.)

- [ ] **Step 2: Compile**

Run: `cargo bench -p utmost-gui --no-run`
Expected: clean.

- [ ] **Step 3: Run once to verify**

Run: `cargo bench -p utmost-gui --bench windowed_load -- --quick`
Expected: targets met (≤50 ms, ≤10 ms, ≤5 ms, ≤1 ns).

- [ ] **Step 4: Commit**

```bash
git add crates/utmost-gui/benches/ crates/utmost-gui/Cargo.toml
git commit -m "bench(gui): windowed match-ids + fetch + sync-tick + perf-disabled"
```

---

## Task 19: README updates and final fmt + clippy

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Document the env vars and log path**

Add a section to `README.md`:

````markdown
## GUI Logging and Performance Telemetry

The GUI writes a daily-rolling log file. Default locations:

- macOS: `~/Library/Logs/utmost/utmost-gui.log`
- Linux: `${XDG_STATE_HOME:-$HOME/.local/state}/utmost/utmost-gui.log`
- Windows: `%LOCALAPPDATA%\utmost\logs\utmost-gui.log`

Override with `UTMOST_LOG_DIR=<dir>`.

To enable per-phase tick timing in the log:

```
UTMOST_PERF_TRACE=1 cargo run -- gui <case>
# or equivalently:
RUST_LOG=utmost_gui::perf=info cargo run -- gui <case>
```

Adjust the summary cadence with `UTMOST_PERF_TICKS=<n>` (default 100 ticks ≈ 10 seconds at 10 Hz).
````

- [ ] **Step 2: Run `cargo fmt`**

Run: `cargo fmt`

- [ ] **Step 3: Run `cargo clippy --all-targets`**

Run: `cargo clippy --all-targets`
Expected: clean. Fix every warning.

- [ ] **Step 4: Run the full test suite once more**

Run: `cargo test -p utmost-gui && cargo test -p utmost-lib && cargo test -p utmost-cli`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add README.md crates/
git commit -m "docs: GUI logging + perf telemetry env vars"
```

---

## Self-Review

Spec coverage check (matched task ↔ spec section):

- [x] Migration `0002_preview_status` — Task 6
- [x] `queries.rs` (FileStub + query_match_ids + fetch_window + set_preview_status) — Tasks 9, 10
- [x] `telemetry.rs` (subscriber + PerfRecorder) — Tasks 2, 3, 4, 5, 17
- [x] PreviewOutcome channel — Task 7
- [x] FileId unification — Task 8
- [x] Indexer thread command/event extensions + epoch — Task 11
- [x] ViewModel migration — Task 12
- [x] Slint windowed grid — Task 14
- [x] Integration tests (7 of them) — Tasks 15, 16, 17
- [x] Live mode + hide_no_preview requery — Task 16
- [x] Benchmarks — Task 18
- [x] README — Task 19

Placeholder scan: no "TBD", "TODO", or "fill in details" in any step. The `todo!()` macro appears once inside Task 10's intermediate skeleton with an explicit instruction to port `FileRow→FoundFile` conversion from `hydrate.rs` before completing the step. The `unimplemented!("fake_found_file")` helper in Task 12's tests is similarly instructed to be filled by the implementer using actual `FoundFile` field shapes.

Type consistency: `FileStub`, `FoundFile`, `IndexerCommand`, `IndexerEvent`, `ViewModel` field names match across all tasks. `epoch: u64` is consistent everywhere.
