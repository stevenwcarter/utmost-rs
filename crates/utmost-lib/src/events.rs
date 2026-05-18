//! Event stream for live and replayable carve runs.
//!
//! See `docs/superpowers/specs/2026-05-17-utmost-gui-design.md` for the
//! versioned binary format.

use serde::{Deserialize, Serialize};

pub const CURRENT_FORMAT_VERSION: u32 = 1;
pub const MAGIC: [u8; 4] = *b"UTMS";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileHeader {
    pub magic: [u8; 4],
    pub format_version: u32,
}

impl Default for FileHeader {
    fn default() -> Self {
        Self {
            magic: MAGIC,
            format_version: CURRENT_FORMAT_VERSION,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_header_round_trips_through_bincode() {
        let header = FileHeader {
            magic: *b"UTMS",
            format_version: CURRENT_FORMAT_VERSION,
        };
        let bytes = bincode::serialize(&header).unwrap();
        let decoded: FileHeader = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.magic, *b"UTMS");
        assert_eq!(decoded.format_version, CURRENT_FORMAT_VERSION);
    }
}
