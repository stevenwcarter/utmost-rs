mod common;

use common::run_started_event;
use utmost_lib::events::{BincodeFileSink, CarveEvent, EventSink};
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::FileType;

/// Drive `run_live_writes_with_initial_offset` directly (no Slint event
/// loop) and verify that each `FileFound` shows up as a row in the SQLite
/// index after the writer thread joins. This exercises the live-mode
/// fan-out path used by `lib.rs::run_live`.
///
/// We use the `_with_initial_offset` variant so the writer's seed offset
/// is deterministic: we capture the `.bin`'s header-only size before any
/// frame is emitted, pass it in, then write to sink and channel in
/// lockstep. The wrapper `run_live_writes` reads the seed via
/// `fs::metadata` — that path is the same code modulo where the u64
/// comes from.
#[test]
fn live_writes_persist_each_event_to_sqlite() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("output-disk1_dd");
    std::fs::create_dir_all(&sub).unwrap();
    let bin = sub.join("disk1_dd-events.bin");
    let sink = BincodeFileSink::create(&bin).unwrap();

    // Seed = the `.bin` size after the FileHeader and before any events.
    let initial_offset = std::fs::metadata(&bin).unwrap().len();

    let mut events: Vec<CarveEvent> = Vec::new();
    events.push(run_started_event());
    for i in 1..=5u64 {
        events.push(CarveEvent::FileFound {
            source_id: 0,
            file: create_file_object("x.jpg", FileType::Jpeg, 0, 0, None, i),
            img_offset: 0,
            written_path: "x.jpg".into(),
        });
    }

    let (tx, rx) = crossbeam_channel::unbounded();
    // Pre-queue every event so the writer thread sees a consistent stream
    // regardless of scheduling. The synthetic offset adds 4 + bytes.len()
    // per persistable event, and the sink writes exactly the same frames.
    for ev in &events {
        sink.emit(ev);
        tx.send(ev.clone()).unwrap();
    }
    drop(sink);
    drop(tx);

    let main_log = bin.clone();
    let join = std::thread::spawn(move || {
        utmost_gui::indexer_thread::run_live_writes_with_initial_offset(
            &main_log,
            rx,
            initial_offset,
        )
        .unwrap();
    });
    join.join().unwrap();

    let pool = common::open_pool(&sub.join("disk1_dd-index.sqlite"));
    let n: i64 = common::count(&pool, "file");
    assert_eq!(n, 5);

    // The synthetic offset tracked inside `run_live_writes` must match the
    // actual `.bin` size on disk after the writer has joined; otherwise a
    // crash-resume from `last_event_offset` would skip or re-apply events.
    let size = std::fs::metadata(&bin).unwrap().len();
    let off: String = common::meta_value(&pool, "last_event_offset").unwrap();
    let off_n: u64 = off.parse().unwrap();
    assert_eq!(off_n, size, "synthetic offset must match .bin size");
}
