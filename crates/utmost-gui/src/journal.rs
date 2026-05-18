//! Append-and-replay sidecar for forensic annotations.
//!
//! While the engine is actively writing `carve_events.bin`, the GUI cannot
//! also write to it. Annotation events (Bookmark, Note, MarkAsBest) are
//! durably staged in `carve_events.pending` (same framing) and folded into
//! the main log when the engine signals `RunFinished` (or at next session
//! open if the run crashed before that).

use std::io::Result as IoResult;
use std::path::{Path, PathBuf};
use utmost_lib::events::CarveEvent;

pub struct Journal {
    main_log: PathBuf,
}

impl Journal {
    pub fn for_main_log(main_log: &Path) -> Self {
        Self {
            main_log: main_log.to_path_buf(),
        }
    }

    pub fn pending_path(&self) -> PathBuf {
        // carve_events.bin → carve_events.pending
        // (Sibling with the .pending extension regardless of the main log's stem)
        let mut p = self.main_log.clone();
        let stem = self
            .main_log
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "carve_events".into());
        p.set_file_name(format!("{stem}.pending"));
        p
    }

    /// Append a single event to the pending sidecar. Creates the file with
    /// the same framing as the main log (length-prefixed bincode frames) on
    /// first call. Failures are returned to the caller — they are surfaced
    /// by the GUI as a non-fatal warning.
    pub fn append(&self, event: &CarveEvent) -> IoResult<()> {
        use std::io::Write;
        let bytes = bincode::serialize(event)
            .map_err(|e| std::io::Error::other(format!("bincode serialize: {e}")))?;
        let len = u32::try_from(bytes.len())
            .map_err(|_| std::io::Error::other("frame larger than u32::MAX"))?;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.pending_path())?;
        f.write_all(&len.to_le_bytes())?;
        f.write_all(&bytes)?;
        f.flush()?;
        Ok(())
    }

    /// Read all events currently in the pending file. Tolerates a malformed
    /// trailing frame (truncated mid-write): returns events up to the last
    /// well-formed frame; logs a warning at `tracing::warn` if truncation
    /// was detected.
    pub fn read_pending(&self) -> IoResult<Vec<CarveEvent>> {
        use std::io::Read;
        let path = self.pending_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let mut f = std::fs::File::open(&path)?;
        let mut events = Vec::new();
        loop {
            let mut len_buf = [0u8; 4];
            match f.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            if let Err(e) = f.read_exact(&mut buf) {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    tracing::warn!(
                        "journal: truncated trailing frame in {} — ignoring tail",
                        path.display()
                    );
                    break;
                }
                return Err(e);
            }
            match bincode::deserialize::<CarveEvent>(&buf) {
                Ok(ev) => events.push(ev),
                Err(e) => {
                    tracing::warn!(
                        "journal: undecodable frame at end of {}: {e}",
                        path.display()
                    );
                    break;
                }
            }
        }
        Ok(events)
    }

    /// Append every event currently in the pending file to the main log,
    /// then delete the pending file. Idempotent: if the pending file does
    /// not exist, returns Ok.
    pub fn fold(&self) -> IoResult<()> {
        let pending = self.pending_path();
        if !pending.exists() {
            return Ok(());
        }
        let events = self.read_pending()?;
        {
            let sink = utmost_lib::events::BincodeFileSink::open_append(&self.main_log)?;
            for ev in &events {
                <utmost_lib::events::BincodeFileSink as utmost_lib::events::EventSink>::emit(
                    &sink, ev,
                );
            }
            // sink drops here, flushing
        }
        std::fs::remove_file(&pending)?;
        Ok(())
    }

    /// Combined startup routine: read pending (if any), append to main log,
    /// delete pending. Returns the events that were folded (for the caller
    /// to also apply to the view-model, since they aren't replayed via the
    /// main log this session).
    pub fn recover_on_open(&self) -> IoResult<Vec<CarveEvent>> {
        let events = self.read_pending()?;
        if events.is_empty() {
            // Still remove the (empty or malformed) file if present.
            if self.pending_path().exists() {
                std::fs::remove_file(self.pending_path())?;
            }
            return Ok(events);
        }
        {
            let sink = utmost_lib::events::BincodeFileSink::open_append(&self.main_log)?;
            for ev in &events {
                <utmost_lib::events::BincodeFileSink as utmost_lib::events::EventSink>::emit(
                    &sink, ev,
                );
            }
        }
        std::fs::remove_file(self.pending_path())?;
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use utmost_lib::events::{BincodeFileReader, BincodeFileSink};

    #[test]
    fn append_one_event_creates_pending_with_framing() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("carve_events.bin");
        // Create a valid main log so .pending lives next to it.
        let _sink = BincodeFileSink::create(&bin).unwrap();

        let journal = Journal::for_main_log(&bin);
        journal
            .append(&CarveEvent::Bookmark {
                file_id: 7,
                bookmarked: true,
                at: "t".into(),
            })
            .unwrap();

        let pending_path = journal.pending_path();
        assert!(pending_path.exists(), "pending file should exist");

        let events = journal.read_pending().unwrap();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], CarveEvent::Bookmark { file_id: 7, .. }));
    }

    #[test]
    fn fold_appends_pending_into_main_log_and_deletes_pending() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("carve_events.bin");
        let _sink = BincodeFileSink::create(&bin).unwrap();

        let journal = Journal::for_main_log(&bin);
        journal
            .append(&CarveEvent::Bookmark {
                file_id: 1,
                bookmarked: true,
                at: "t".into(),
            })
            .unwrap();
        journal
            .append(&CarveEvent::Note {
                note_id: 1,
                file_id: 1,
                text: "hi".into(),
                at: "t".into(),
            })
            .unwrap();

        journal.fold().unwrap();

        assert!(
            !journal.pending_path().exists(),
            "pending should be deleted after fold"
        );

        // Replay the main log and check the events landed.
        let mut r = BincodeFileReader::open(&bin).unwrap();
        let mut count = 0;
        while r.next_event().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn replay_pending_at_startup_applies_then_folds_and_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("carve_events.bin");
        let _sink = BincodeFileSink::create(&bin).unwrap();

        // Pre-create a pending file with one event (simulates a crashed run)
        let journal = Journal::for_main_log(&bin);
        journal
            .append(&CarveEvent::Bookmark {
                file_id: 9,
                bookmarked: true,
                at: "t".into(),
            })
            .unwrap();
        drop(journal);

        // Now a fresh GUI starts: open the log, expect to recover the pending.
        let journal2 = Journal::for_main_log(&bin);
        let recovered = journal2.recover_on_open().unwrap();
        assert_eq!(recovered.len(), 1);
        assert!(matches!(
            recovered[0],
            CarveEvent::Bookmark { file_id: 9, .. }
        ));
        assert!(!journal2.pending_path().exists());

        // The events are now folded into the main log.
        let mut r = BincodeFileReader::open(&bin).unwrap();
        let mut count = 0;
        while r.next_event().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 1);
    }

    #[test]
    fn malformed_trailing_frame_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("carve_events.bin");
        let _sink = BincodeFileSink::create(&bin).unwrap();

        let journal = Journal::for_main_log(&bin);
        journal
            .append(&CarveEvent::Bookmark {
                file_id: 1,
                bookmarked: true,
                at: "t".into(),
            })
            .unwrap();

        // Append junk to the pending file
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(journal.pending_path())
            .unwrap();
        f.write_all(&[0xff, 0xff, 0xff, 0xff]).unwrap(); // length 4.29e9 — won't fit; truncated read

        let events = journal.read_pending().unwrap();
        assert_eq!(events.len(), 1, "should recover only the well-formed event");
    }
}
