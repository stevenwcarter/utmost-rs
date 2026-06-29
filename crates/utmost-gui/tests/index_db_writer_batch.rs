mod common;

use common::run_started_event;
use utmost_gui::index_db::writer::IndexDbWriter;
use utmost_lib::events::CarveEvent;
use utmost_lib::reporting::create_file_object;
use utmost_lib::types::FileType;

fn ff(id: u64) -> CarveEvent {
    CarveEvent::FileFound {
        source_id: 0,
        file: create_file_object("x.jpg", FileType::Jpeg, 1, 0, None, id),
        img_offset: 0,
        written_path: "x.jpg".into(),
    }
}

#[test]
fn batch_threshold_commits_and_resets_pending() {
    let dir = tempfile::tempdir().unwrap();
    let pool = common::open_pool(&dir.path().join("idx.sqlite"));

    // Seed run + source via RunStarted with a batch_size large enough to keep it in pending.
    {
        let mut w = IndexDbWriter::new(pool.clone(), 100);
        w.apply(run_started_event(), 0).unwrap();
        w.flush().unwrap();
    }

    // Now drive 125 FileFound events through a batch_size=50 writer.
    {
        let mut w = IndexDbWriter::new(pool.clone(), 50);
        for i in 1..=125u64 {
            w.apply(ff(i), i * 10).unwrap();
        }
        w.flush().unwrap();
    }

    let n = common::count(&pool, "file");
    assert_eq!(n, 125);
    let off = common::meta_value(&pool, "last_event_offset").unwrap();
    assert_eq!(off, "1250");
    let cnt = common::meta_value(&pool, "last_event_count").unwrap();
    // 1 RunStarted + 125 FileFound = 126
    assert_eq!(cnt, "126");
}
