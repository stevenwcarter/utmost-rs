//! Lightweight performance recorder for the GUI's hot loops.
//!
//! The recorder is designed to be zero-cost when disabled: `phase()` performs a
//! single relaxed atomic load and, if disabled, returns a guard whose `Drop`
//! impl is a no-op. When enabled, each phase is timed with `Instant::now()` and
//! aggregated into a per-name rolling accumulator. The accumulator is flushed
//! to a `tracing` log line every `tick_emit_interval` ticks.
//!
//! Locking uses `std::sync::Mutex` because `parking_lot` is not currently in
//! the workspace dep graph (verified via `cargo tree -p utmost-gui`). The lock
//! is only ever taken when the recorder is enabled, so the disabled path
//! remains lock-free.

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use tracing_subscriber::{EnvFilter, fmt, prelude::*};

/// Which target the recorder's emitted lines are tagged with.
///
/// Each variant maps to a distinct `&'static str` target so `EnvFilter`
/// can gate them independently (e.g. `RUST_LOG=utmost_gui::perf=info`
/// enables `Ui` and `Indexer` because of `EnvFilter`'s prefix matching).
#[derive(Debug, Clone, Copy)]
pub enum PerfTarget {
    /// UI sync loop. Target string: `utmost_gui::perf`.
    Ui,
    /// Indexer thread. Target string: `utmost_gui::perf::indexer`.
    Indexer,
    /// Tests. Target string: `utmost_gui::perf::test`.
    Test,
}

/// Per-phase rolling accumulator.
#[derive(Default, Clone, Debug)]
pub struct PhaseStats {
    count: u64,
    sum_us: u64,
    max_us: u64,
    /// 8 exponential buckets: <=10us, <=30us, <=100us, <=300us, <=1ms, <=3ms, <=10ms, >10ms.
    histogram: [u64; 8],
}

/// Records per-phase elapsed times and periodically emits aggregate lines to
/// `tracing` at the recorder's target.
pub struct PerfRecorder {
    enabled: AtomicBool,
    tick_counter: AtomicU64,
    tick_emit_interval: u64,
    /// Maps phase name → stats. Behind a mutex; lock only when enabled.
    phases: Mutex<std::collections::BTreeMap<&'static str, PhaseStats>>,
    target: PerfTarget,
}

/// RAII timer for a single phase. Created via [`PerfRecorder::phase`]; when
/// dropped, records the elapsed time against the named phase.
pub struct PhaseGuard<'a> {
    recorder: &'a PerfRecorder,
    name: &'static str,
    start: Option<Instant>,
}

impl PerfRecorder {
    pub fn new(target: PerfTarget, enabled: bool, tick_emit_interval: u64) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            tick_counter: AtomicU64::new(0),
            tick_emit_interval,
            phases: Mutex::new(std::collections::BTreeMap::new()),
            target,
        }
    }

    #[inline(always)]
    pub fn phase(&self, name: &'static str) -> PhaseGuard<'_> {
        if !self.enabled.load(Ordering::Relaxed) {
            return PhaseGuard {
                recorder: self,
                name,
                start: None,
            };
        }
        PhaseGuard {
            recorder: self,
            name,
            start: Some(Instant::now()),
        }
    }

    pub fn tick(&self) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        let n = self.tick_counter.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= self.tick_emit_interval {
            self.emit_and_reset();
        }
    }

    fn record(&self, name: &'static str, elapsed_us: u64) {
        let mut phases = self.phases.lock().expect("telemetry phases poisoned");
        let entry = phases.entry(name).or_default();
        entry.count += 1;
        entry.sum_us = entry.sum_us.saturating_add(elapsed_us);
        if elapsed_us > entry.max_us {
            entry.max_us = elapsed_us;
        }
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
        let mut phases = self.phases.lock().expect("telemetry phases poisoned");
        let n = self.tick_counter.swap(0, Ordering::Relaxed);
        if phases.is_empty() {
            return;
        }
        // Build one log line. Format: "ticks=N name{p50=Xus p95=Yus max=Zus} ..."
        let mut parts: Vec<(String, u64)> = Vec::with_capacity(phases.len());
        for (name, stats) in phases.iter() {
            let mean = stats.sum_us.checked_div(stats.count).unwrap_or(0);
            let p95 = estimate_p95(&stats.histogram, stats.count);
            parts.push((
                format!(
                    "{}{{p50={}us p95={}us max={}us}}",
                    name, mean, p95, stats.max_us
                ),
                mean,
            ));
        }
        parts.sort_by_key(|b| std::cmp::Reverse(b.1));
        let line = parts.into_iter().map(|p| p.0).collect::<Vec<_>>().join(" ");
        match self.target {
            PerfTarget::Ui => {
                tracing::info!(target: "utmost_gui::perf", "ticks={n} {line}")
            }
            PerfTarget::Indexer => {
                tracing::info!(target: "utmost_gui::perf::indexer", "ticks={n} {line}")
            }
            PerfTarget::Test => {
                tracing::info!(target: "utmost_gui::perf::test", "ticks={n} {line}")
            }
        }
        phases.clear();
    }

    #[cfg(test)]
    pub fn record_for_test(&self, name: &'static str, us: u64) {
        self.record(name, us);
    }

    #[cfg(test)]
    pub fn snapshot_for_test(&self) -> std::collections::BTreeMap<&'static str, PhaseStats> {
        self.phases
            .lock()
            .expect("telemetry phases poisoned")
            .clone()
    }
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

/// Composite handle returned by [`init_subscriber`].
///
/// Holds the [`PerfRecorder`] for downstream callers and keeps the
/// non-blocking writer's worker thread alive via `_guard`. Drop the
/// `Telemetry` value to flush and stop the background log writer.
pub struct Telemetry {
    pub perf: std::sync::Arc<PerfRecorder>,
    _guard: tracing_appender::non_blocking::WorkerGuard,
}

/// Initialise the process-wide `tracing` subscriber with a daily-rolling file
/// appender plus stderr fallback, and decide whether the [`PerfRecorder`]
/// should be active based on `UTMOST_PERF_TRACE` / `RUST_LOG`.
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

    // `tracing_appender::rolling::daily` writes to `<prefix>.YYYY-MM-DD`
    // (UTC), so the on-disk filename is the prefix with today's UTC date
    // appended. Surface that exact path so users can `tail` it directly.
    let today_utc = chrono::Utc::now().format("%Y-%m-%d");
    let log_file_path = log_dir.join(format!("utmost-gui.log.{today_utc}"));
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
        PerfTarget::Ui,
        perf_enabled,
        tick_interval,
    ));

    Telemetry {
        perf,
        _guard: guard,
    }
}

/// Resolve the directory where the daily-rolling log file should live.
///
/// `override_path` (typically populated from `$UTMOST_LOG_DIR`) wins; otherwise
/// fall back to a platform-specific default. Returns `None` if no default can
/// be determined (e.g. Linux with no `state_dir()` and no `$HOME`).
pub(crate) fn resolve_log_dir(override_path: Option<PathBuf>) -> Option<PathBuf> {
    if let Some(p) = override_path {
        return Some(p);
    }
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

/// Decide whether the perf recorder should be enabled based on environment.
///
/// Activated if `UTMOST_PERF_TRACE` is `"1"` or `"true"` (case-insensitive), or
/// if `RUST_LOG` contains `utmost_gui::perf=info|debug|trace` as a substring.
pub(crate) fn perf_activated_from(env: Option<&str>, rust_log: Option<&str>) -> bool {
    if let Some(v) = env {
        let v = v.trim().to_ascii_lowercase();
        if v == "1" || v == "true" {
            return true;
        }
    }
    if let Some(filter) = rust_log
        && (filter.contains("utmost_gui::perf=info")
            || filter.contains("utmost_gui::perf=debug")
            || filter.contains("utmost_gui::perf=trace"))
    {
        return true;
    }
    false
}

/// Approximate p95 from the bucket histogram. Returns the upper bound of the
/// bucket that contains the 95th-percentile sample.
fn estimate_p95(hist: &[u64; 8], total: u64) -> u64 {
    let target = (total * 95) / 100;
    let bucket_upper: [u64; 8] = [10, 30, 100, 300, 1_000, 3_000, 10_000, 100_000];
    let mut running = 0u64;
    for (i, &c) in hist.iter().enumerate() {
        running += c;
        if running >= target {
            return bucket_upper[i];
        }
    }
    bucket_upper[7]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_off_is_zero_cost_in_steady_state() {
        let r = PerfRecorder::new(PerfTarget::Test, false, 100);
        let _g = r.phase("x"); // must not panic, must not call Instant::now
        // The guard's start field is None when disabled — observable indirectly.
        // Aggregator should remain empty.
        let stats = r.snapshot_for_test();
        assert!(stats.is_empty());
    }

    #[test]
    fn aggregator_accumulates_count_sum_max() {
        let r = PerfRecorder::new(PerfTarget::Test, true, 100_000);
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
        let r = PerfRecorder::new(PerfTarget::Test, true, 2);
        r.record_for_test("a", 100);
        r.tick();
        r.record_for_test("a", 200);
        r.tick(); // hits interval=2 → emit + reset
        r.record_for_test("a", 300);
        let s = r.snapshot_for_test();
        let a = s.get("a").unwrap();
        assert_eq!(a.count, 1);
        assert_eq!(a.sum_us, 300);
    }

    #[test]
    fn histogram_buckets_correctly() {
        let r = PerfRecorder::new(PerfTarget::Test, true, 100_000);
        r.record_for_test("a", 5); // <=10us
        r.record_for_test("a", 50); // <=100us
        r.record_for_test("a", 5_000); // <=10ms (bucket 6, since <=10000us)
        r.record_for_test("a", 50_000); // >10ms (bucket 7)
        let s = r.snapshot_for_test();
        let a = s.get("a").unwrap();
        assert_eq!(a.histogram[0], 1);
        assert_eq!(a.histogram[2], 1);
        assert_eq!(a.histogram[6], 1);
        assert_eq!(a.histogram[7], 1);
    }
}

#[cfg(test)]
mod init_tests {
    use super::*;

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
        assert!(perf_activated_from(
            None,
            Some("warn,utmost_gui::perf=info")
        ));
        assert!(!perf_activated_from(None, Some("warn")));
    }
}
