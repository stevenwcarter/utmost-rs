//! Integration tests for `utmost process`.

use assert_cmd::Command;
use tempfile::TempDir;
use turso::Value;
use utmost_index::db::{IndexDb, TursoPool, block_on};
use utmost_index::processing::ProcessCounts;

/// Seed a minimal case: one source row + one `preview_status = 'unknown'` JPEG
/// file row pointing at a non-existent path (so it will be marked `NoPreview`,
/// removing it from the `unknown` queue after processing).
fn seed_minimal_case(pool: &TursoPool) {
    block_on(async {
        let conn = pool.get().await.unwrap();
        conn.execute(
            "INSERT INTO source \
             (source_id, filename, output_subdir, total_bytes, bytes_read, files_found, status) \
             VALUES (1, 'src.img', '', 0, 0, 0, 'Finished')",
            (),
        )
        .await
        .unwrap();
        conn.execute(
            "INSERT INTO file \
             (file_id, source_id, filename, filesize, file_type, img_offset, \
              written_path, byte_runs_json, preview_status) \
             VALUES (1, 1, '00000001.jpeg', 1024, 'jpeg', 0, ?1, '[]', 'unknown')",
            (Value::Text("/nonexistent/missing/00000001.jpeg".to_owned()),),
        )
        .await
        .unwrap();
    });
}

/// `utmost process` drains `previews_remaining` to zero for a case whose
/// carved file is missing on disk (render fails → `NoPreview` → removed from
/// the `unknown` queue).
#[test]
fn process_command_drains_previews_to_zero() {
    let tmp = TempDir::new().unwrap();

    // A file named `<stem>-events.bin` is what `discover_cases` looks for.
    let events_bin = tmp.path().join("testcase-events.bin");
    std::fs::write(&events_bin, b"").unwrap();

    // The index DB lives at `<stem>-index.sqlite` next to the events file.
    let sqlite_path = tmp.path().join("testcase-index.sqlite");

    {
        let db = IndexDb::open(&sqlite_path).unwrap();
        seed_minimal_case(db.pool());

        // Pre-condition: one file awaiting preview.
        let before = ProcessCounts::load(db.pool(), "").unwrap();
        assert_eq!(
            before.previews_remaining, 1,
            "pre-condition: one pending preview"
        );
    }

    // Run `utmost process -o <tmpdir> --no-embeddings` (no model download in CI).
    Command::cargo_bin("utmost")
        .unwrap()
        .args([
            "process",
            "-o",
            tmp.path().to_str().unwrap(),
            "--no-embeddings",
        ])
        .assert()
        .success();

    // Post-condition: queue fully drained.
    let db2 = IndexDb::open(&sqlite_path).unwrap();
    let after = ProcessCounts::load(db2.pool(), "").unwrap();
    assert_eq!(
        after.previews_remaining, 0,
        "process must drain all pending previews to zero"
    );
}

/// `utmost process --help` exits successfully and mentions key flags.
#[test]
fn process_help_mentions_flags() {
    let out = Command::cargo_bin("utmost")
        .unwrap()
        .args(["process", "--help"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("--no-embeddings"),
        "help must mention --no-embeddings"
    );
    assert!(stdout.contains("--count"), "help must mention --count");
}
