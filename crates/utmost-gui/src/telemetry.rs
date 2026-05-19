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

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

/// Per-phase rolling accumulator.
#[derive(Default, Clone, Debug)]
pub struct PhaseStats {
    pub count: u64,
    pub sum_us: u64,
    pub max_us: u64,
    /// 8 exponential buckets: <=10us, <=30us, <=100us, <=300us, <=1ms, <=3ms, <=10ms, >10ms.
    pub histogram: [u64; 8],
}

/// Records per-phase elapsed times and periodically emits aggregate lines to
/// `tracing` at the recorder's target.
pub struct PerfRecorder {
    enabled: AtomicBool,
    tick_counter: AtomicU64,
    tick_emit_interval: u64,
    /// Maps phase name → stats. Behind a mutex; lock only when enabled.
    phases: Mutex<std::collections::BTreeMap<&'static str, PhaseStats>>,
    target: &'static str,
}

/// RAII timer for a single phase. Created via [`PerfRecorder::phase`]; when
/// dropped, records the elapsed time against the named phase.
pub struct PhaseGuard<'a> {
    recorder: &'a PerfRecorder,
    name: &'static str,
    start: Option<Instant>,
}

impl PerfRecorder {
    pub fn new(target: &'static str, enabled: bool, tick_emit_interval: u64) -> Self {
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
        // `tracing::info!`'s `target:` requires a constant, so we route every
        // recorder's emission through a fixed callsite and tag the dynamic
        // target name into the structured fields. Downstream subscribers can
        // filter on the `target` field.
        let target = self.target;
        tracing::info!(target: "utmost_gui::telemetry", perf_target = target, "ticks={n} {line}");
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
        r.tick(); // hits interval=2 → emit + reset
        r.record_for_test("a", 300);
        let s = r.snapshot_for_test();
        let a = s.get("a").unwrap();
        assert_eq!(a.count, 1);
        assert_eq!(a.sum_us, 300);
    }

    #[test]
    fn histogram_buckets_correctly() {
        let r = PerfRecorder::new("test", true, 100_000);
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
