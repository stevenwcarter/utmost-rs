use std::sync::{Arc, Mutex};
use utmost_lib::{
    engine,
    events::{CarveEvent, EventSink},
    types::{FileInfo, State, StateConfig},
};

#[derive(Default)]
struct RecordingSink {
    events: Mutex<Vec<CarveEvent>>,
}
impl EventSink for RecordingSink {
    fn emit(&self, ev: &CarveEvent) {
        self.events.lock().unwrap().push(ev.clone());
    }
}

fn make_state(dir: &std::path::Path) -> State {
    let cfg = StateConfig {
        output_directory: dir.to_string_lossy().to_string(),
        debug: false,
        prefix_filenames: false,
        chunk_size: None,
        block_size: None,
        skip: None,
        disable_validation: false,
        report_only: false,
        disable_report: true,
        disable_audit: true,
        quick: false,
        write_all: false,
        keep_incomplete_jpeg: false,
    };
    State::new(cfg).unwrap()
}

#[test]
fn buffer_search_emits_source_lifecycle_events() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(tmp.path());
    let sink: Arc<RecordingSink> = Arc::new(RecordingSink::default());
    state.set_event_sink(sink.clone());

    let mut fi = FileInfo {
        filename: "buf".into(),
        total_bytes: 0,
        total_megs: 0,
        bytes_read: 0,
        per_file_counter: 0,
        source_id: 0,
    };
    let data = vec![0u8; 16];
    engine::search_buffer(&data, &state, &mut fi, 0, 1).unwrap();

    let events = sink.events.lock().unwrap().clone();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, CarveEvent::SourceStarted { .. })),
        "expected a SourceStarted event, got: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, CarveEvent::SourceFinished { .. })),
        "expected a SourceFinished event, got: {events:?}"
    );
}

#[test]
fn search_emits_file_found_for_each_extracted_file() {
    // A minimal JPEG: SOI (FFD8 FFE0) + some payload + EOI (FFD9).
    let mut data = vec![0xFFu8, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
    data.extend_from_slice(b"JFIF\0");
    data.extend(std::iter::repeat_n(0xAAu8, 64));
    data.extend_from_slice(&[0xFF, 0xD9]);

    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(tmp.path());
    state.set_search_specs(utmost_lib::search_specs::init_all_search_specs());
    let sink: Arc<RecordingSink> = Arc::new(RecordingSink::default());
    state.set_event_sink(sink.clone());

    let mut fi = FileInfo {
        filename: "buf".into(),
        total_bytes: data.len(),
        total_megs: 0,
        bytes_read: 0,
        per_file_counter: 0,
        source_id: 0,
    };
    engine::search_buffer(&data, &state, &mut fi, 0, 1).unwrap();

    let events = sink.events.lock().unwrap().clone();
    let found_count = events
        .iter()
        .filter(|e| matches!(e, CarveEvent::FileFound { .. }))
        .count();
    assert!(
        found_count >= 1,
        "expected at least 1 FileFound event, got events: {events:?}"
    );
}
