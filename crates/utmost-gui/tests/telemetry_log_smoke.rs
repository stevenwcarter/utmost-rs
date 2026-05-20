//! Smoke test for the GUI's tracing pipeline: when `UTMOST_PERF_TRACE=1`
//! is set, the `PerfRecorder` emits at least one aggregated line to the
//! daily-rolling log file under `UTMOST_LOG_DIR` after enough ticks.
//!
//! Lives in its own integration-test binary so the global subscriber
//! install in `init_telemetry()` doesn't collide with sibling tests
//! (a second `init()` call panics on the same process).

#[test]
fn perf_log_line_emitted_when_enabled() {
    let tmp = tempfile::tempdir().unwrap();
    // Edition 2024 marks `std::env::set_var` as `unsafe` because the
    // process-wide env table isn't thread-safe; this test sets the vars
    // before any other thread reads them and is the only test in the
    // binary, so the call is sound.
    unsafe {
        std::env::set_var("UTMOST_LOG_DIR", tmp.path());
        std::env::set_var("UTMOST_PERF_TRACE", "1");
        std::env::set_var("UTMOST_PERF_TICKS", "5");
        // Make sure no RUST_LOG inherited from the runner suppresses the
        // perf target. The recorder logs at INFO; default filter is `warn`.
        std::env::set_var("RUST_LOG", "utmost_gui::perf=info");
    }

    let telemetry = utmost_gui::init_telemetry();
    for _ in 0..6 {
        {
            let _g = telemetry.perf.phase("a_phase");
            std::thread::sleep(std::time::Duration::from_micros(50));
        }
        telemetry.perf.tick();
    }
    // Dropping `Telemetry` drops the `WorkerGuard`, which flushes any
    // remaining buffered log lines from the non-blocking appender.
    drop(telemetry);
    // Give the appender's worker thread a brief moment to finalise the
    // last write to disk before we read the file.
    std::thread::sleep(std::time::Duration::from_millis(100));

    let mut content = String::new();
    for e in std::fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(|e| e.ok())
    {
        let name = e.file_name().to_string_lossy().to_string();
        if name.starts_with("utmost-gui.log") {
            content.push_str(&std::fs::read_to_string(e.path()).unwrap());
        }
    }
    assert!(
        content.contains("utmost_gui::perf"),
        "log content was: {content}"
    );
    assert!(content.contains("a_phase"), "log content was: {content}");
}
