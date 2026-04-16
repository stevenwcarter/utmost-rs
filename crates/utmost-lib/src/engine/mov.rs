use std::cmp;

use crate::{
    SearchSpec,
    types::{Endianness, bytes_to_u32},
};

/// Validate MOV/QuickTime file structure to reduce false positives
/// Performs comprehensive validation of QuickTime atom structure
pub fn validate_mov_file(data: &[u8]) -> bool {
    // MOV files are structured as atoms (also called boxes)
    // Each atom has: [4 bytes size][4 bytes type][data]

    // We need at least 8 bytes for a minimal atom
    if data.len() < 8 {
        return false;
    }

    // Find the first atom that looks like it should contain a "moov" atom
    // The search might start with different atoms, so we need to validate the structure
    if let Some(moov_pos) = find_moov_atom(data) {
        // Validate the moov atom structure
        validate_moov_atom(&data[moov_pos..])
    } else {
        // If we can't find a moov atom, this might not be a valid MOV file
        false
    }
}

/// Find the position of the "moov" atom in the data
fn find_moov_atom(data: &[u8]) -> Option<usize> {
    let mut pos = 0;

    // The "moov" might be the first atom or preceded by other atoms
    while pos + 8 <= data.len() {
        // Check if we found "moov" at current position
        if &data[pos..pos + 4] == b"moov" {
            // This might be the type field, so the atom starts 4 bytes earlier
            if pos >= 4 {
                return Some(pos - 4);
            }
        }

        // Check if current position is start of an atom with "moov" type
        if pos + 8 <= data.len() {
            let atom_size = bytes_to_u32(&data[pos..pos + 4], Endianness::Big) as usize;
            let atom_type = &data[pos + 4..pos + 8];

            if atom_type == b"moov" {
                return Some(pos);
            }

            // If this is a valid atom, skip to the next one
            if is_valid_atom_type(atom_type) && atom_size >= 8 && atom_size <= data.len() - pos {
                pos += atom_size;
            } else {
                pos += 1; // Not a valid atom, try next byte
            }
        } else {
            pos += 1;
        }
    }

    None
}

/// Validate the structure of a moov atom
fn validate_moov_atom(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }

    let atom_size = bytes_to_u32(&data[0..4], Endianness::Big) as usize;
    let atom_type = &data[4..8];

    // Verify this is actually a moov atom
    if atom_type != b"moov" {
        return false;
    }

    // Atom size should be reasonable
    if atom_size < 8 || atom_size > data.len() {
        return false;
    }

    // Parse child atoms within the moov atom
    let mut pos = 8; // Skip atom header
    let end_pos = cmp::min(atom_size, data.len());
    let mut found_mvhd = false;
    let mut found_trak = false;

    while pos + 8 <= end_pos {
        if pos + 4 > data.len() {
            break;
        }

        let child_size = bytes_to_u32(&data[pos..pos + 4], Endianness::Big) as usize;
        if pos + 8 > data.len() {
            break;
        }
        let child_type = &data[pos + 4..pos + 8];

        // Validate child atom size
        if child_size < 8 || pos + child_size > end_pos {
            return false;
        }

        match child_type {
            b"mvhd" => {
                // Movie header atom - validate its structure
                if !validate_mvhd_atom(&data[pos..pos + child_size]) {
                    return false;
                }
                found_mvhd = true;
            }
            b"trak" => {
                // Track atom - validate its structure
                if !validate_trak_atom(&data[pos..pos + child_size]) {
                    return false;
                }
                found_trak = true;
            }
            b"udta" | b"meta" | b"iods" => {
                // Valid optional atoms, just check they're properly formed
                if !is_valid_atom_structure(&data[pos..pos + child_size]) {
                    return false;
                }
            }
            _ => {
                // Unknown atom type - check if it looks like a valid atom
                if !is_valid_atom_type(child_type) {
                    return false;
                }
            }
        }

        pos += child_size;
    }

    // A valid moov atom should have at least mvhd and one trak
    found_mvhd && found_trak
}

/// Validate movie header (mvhd) atom structure
fn validate_mvhd_atom(data: &[u8]) -> bool {
    if data.len() < 16 {
        return false;
    }

    let atom_size = bytes_to_u32(&data[0..4], Endianness::Big) as usize;
    let atom_type = &data[4..8];

    if atom_type != b"mvhd" || atom_size < 108 {
        return false;
    }

    // Check version field (should be 0 or 1)
    let version = data[8];
    if version > 1 {
        return false;
    }

    // Flags should be reasonable (3 bytes, usually 0)
    // Skip detailed flag validation for now

    // Check creation and modification times (should be reasonable)
    let creation_time = bytes_to_u32(&data[12..16], Endianness::Big);
    let modification_time = bytes_to_u32(&data[16..20], Endianness::Big);

    // Times should be reasonable (not way in the future or way in the past)
    // QuickTime epoch is 1904, so times should be > 0 and < some reasonable future date
    if creation_time == 0 && modification_time == 0 {
        return false; // Both times being 0 is suspicious
    }

    // Time scale should be reasonable (samples per second)
    let time_scale = bytes_to_u32(&data[20..24], Endianness::Big);
    if time_scale == 0 || time_scale > 1_000_000 {
        return false;
    }

    // Duration can be 0 for live streams, so don't validate too strictly
    let _duration = bytes_to_u32(&data[24..28], Endianness::Big);

    true
}

/// Validate track (trak) atom structure  
fn validate_trak_atom(data: &[u8]) -> bool {
    if data.len() < 16 {
        return false;
    }

    let atom_size = bytes_to_u32(&data[0..4], Endianness::Big) as usize;
    let atom_type = &data[4..8];

    if atom_type != b"trak" || atom_size < 16 {
        return false;
    }

    // Parse child atoms within the trak atom
    let mut pos = 8; // Skip atom header
    let end_pos = cmp::min(atom_size, data.len());
    let mut found_tkhd = false;
    let mut found_mdia = false;

    while pos + 8 <= end_pos {
        if pos + 4 > data.len() {
            break;
        }

        let child_size = bytes_to_u32(&data[pos..pos + 4], Endianness::Big) as usize;
        if child_size < 8 || pos + child_size > end_pos || pos + 8 > data.len() {
            return false;
        }

        let child_type = &data[pos + 4..pos + 8];

        match child_type {
            b"tkhd" => {
                // Track header - basic validation
                if child_size < 32 {
                    return false;
                }
                found_tkhd = true;
            }
            b"mdia" => {
                // Media atom - should contain mdhd, hdlr, minf
                found_mdia = true;
            }
            b"edts" | b"tref" | b"load" | b"imap" | b"udta" => {
                // Valid optional track atoms
            }
            _ => {
                // Unknown atom type
                if !is_valid_atom_type(child_type) {
                    return false;
                }
            }
        }

        pos += child_size;
    }

    // A valid trak should have both tkhd and mdia
    found_tkhd && found_mdia
}

/// Check if an atom type consists of valid characters
fn is_valid_atom_type(atom_type: &[u8]) -> bool {
    if atom_type.len() != 4 {
        return false;
    }

    // Atom types should be printable ASCII or specific control characters
    for &byte in atom_type {
        match byte {
            // Common valid atom type characters
            b'a'..=b'z'
            | b'A'..=b'Z'
            | b'0'..=b'9'
            | b' '
            | b'.'
            | b'-'
            | b'_'
            | b'('
            | b')'
            | 0xA9 => {} // Copyright symbol used in some atoms
            _ => return false,
        }
    }

    true
}

/// Basic validation that an atom has a valid structure
fn is_valid_atom_structure(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }

    let atom_size = bytes_to_u32(&data[0..4], Endianness::Big) as usize;
    let atom_type = &data[4..8];

    // Size should match actual data length and be reasonable
    atom_size >= 8 && atom_size <= data.len() && is_valid_atom_type(atom_type)
}

/// Determine MOV file size using heuristics
pub fn mov_file_size_heuristic(spec: &SearchSpec, buf: &[u8]) -> usize {
    // For MOV files, we can try to parse the atom structure to determine the actual size
    if let Some(file_size) = determine_mov_file_size_from_atoms(buf) {
        cmp::min(file_size, spec.max_len)
    } else {
        // Fallback to conservative estimate
        cmp::min(spec.max_len, buf.len())
    }
}

/// Determine MOV file size by parsing atom structure
fn determine_mov_file_size_from_atoms(data: &[u8]) -> Option<usize> {
    let mut pos = 0;
    let mut total_size = 0;

    // Parse atoms to find the total file size
    while pos + 8 <= data.len() {
        let atom_size = bytes_to_u32(&data[pos..pos + 4], Endianness::Big) as usize;
        let atom_type = &data[pos + 4..pos + 8];

        if atom_size < 8 {
            break; // Invalid atom
        }

        if !is_valid_atom_type(atom_type) {
            break; // Invalid atom type
        }

        total_size = pos + atom_size;

        // If this atom extends beyond our buffer, use the buffer size
        if pos + atom_size > data.len() {
            return Some(data.len());
        }

        pos += atom_size;

        // If we've parsed all the way to the end, we have the file size
        if pos >= data.len() {
            return Some(total_size);
        }
    }

    if total_size > 0 {
        Some(total_size)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FileType, SearchSpec, SearchType};

    fn create_valid_mov_header() -> Vec<u8> {
        let mut data = Vec::new();

        // Create a simple moov atom with mvhd and trak
        let mvhd_data = create_mvhd_atom();
        let trak_data = create_trak_atom();

        // Calculate moov atom size
        let moov_size = 8 + mvhd_data.len() + trak_data.len();

        // moov atom header
        data.extend_from_slice(&(moov_size as u32).to_be_bytes());
        data.extend_from_slice(b"moov");

        // Add child atoms
        data.extend_from_slice(&mvhd_data);
        data.extend_from_slice(&trak_data);

        data
    }

    fn create_mvhd_atom() -> Vec<u8> {
        let mut data = Vec::new();

        // mvhd atom (108 bytes minimum)
        data.extend_from_slice(&108u32.to_be_bytes()); // size
        data.extend_from_slice(b"mvhd"); // type
        data.push(0); // version
        data.extend_from_slice(&[0, 0, 0]); // flags
        data.extend_from_slice(&123456u32.to_be_bytes()); // creation_time
        data.extend_from_slice(&123457u32.to_be_bytes()); // modification_time
        data.extend_from_slice(&1000u32.to_be_bytes()); // time_scale
        data.extend_from_slice(&30000u32.to_be_bytes()); // duration

        // Fill the rest with reasonable values
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // preferred_rate
        data.extend_from_slice(&[0x01, 0x00]); // preferred_volume
        data.extend_from_slice(&[0; 10]); // reserved

        // Matrix (36 bytes)
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // matrix[0]
        data.extend_from_slice(&[0; 32]); // rest of matrix

        // Preview and poster times
        data.extend_from_slice(&[0; 16]);

        // Selection and current times
        data.extend_from_slice(&[0; 8]);

        // Next track ID
        data.extend_from_slice(&2u32.to_be_bytes());

        data
    }

    fn create_trak_atom() -> Vec<u8> {
        let mut data = Vec::new();

        // Create tkhd and mdia atoms
        let tkhd_data = create_tkhd_atom();
        let mdia_data = create_mdia_atom();

        // Calculate trak atom size
        let trak_size = 8 + tkhd_data.len() + mdia_data.len();

        // trak atom header
        data.extend_from_slice(&(trak_size as u32).to_be_bytes());
        data.extend_from_slice(b"trak");

        // Add child atoms
        data.extend_from_slice(&tkhd_data);
        data.extend_from_slice(&mdia_data);

        data
    }

    fn create_tkhd_atom() -> Vec<u8> {
        let mut data = Vec::new();

        // tkhd atom (92 bytes)
        data.extend_from_slice(&92u32.to_be_bytes()); // size
        data.extend_from_slice(b"tkhd"); // type
        data.push(0); // version
        data.extend_from_slice(&[0, 0, 1]); // flags (track enabled)

        // Fill with minimal valid data
        data.extend_from_slice(&[0; 80]); // Track header data

        data
    }

    fn create_mdia_atom() -> Vec<u8> {
        let mut data = Vec::new();

        // Simple mdia atom (just header for testing)
        data.extend_from_slice(&16u32.to_be_bytes()); // size
        data.extend_from_slice(b"mdia"); // type
        data.extend_from_slice(&[0; 8]); // minimal content

        data
    }

    #[test]
    fn test_validate_mov_file_valid() {
        let valid_mov = create_valid_mov_header();
        assert!(validate_mov_file(&valid_mov));
    }

    #[test]
    fn test_validate_mov_file_too_small() {
        let small_data = vec![b'm', b'o', b'o', b'v']; // Only 4 bytes
        assert!(!validate_mov_file(&small_data));
    }

    #[test]
    fn test_validate_mov_file_no_moov() {
        let invalid_data = vec![
            0x00, 0x00, 0x00, 0x10, // size
            b'f', b'r', b'e', b'e', // type (not moov)
            0x00, 0x00, 0x00, 0x00, // data
            0x00, 0x00, 0x00, 0x00,
        ];
        assert!(!validate_mov_file(&invalid_data));
    }

    #[test]
    fn test_find_moov_atom() {
        let data_with_moov = create_valid_mov_header();
        assert_eq!(find_moov_atom(&data_with_moov), Some(0));

        // Test with moov not at the beginning
        let mut data_with_prefix = vec![
            0x00, 0x00, 0x00, 0x08, // free atom
            b'f', b'r', b'e', b'e',
        ];
        data_with_prefix.extend_from_slice(&data_with_moov);

        assert_eq!(find_moov_atom(&data_with_prefix), Some(8));
    }

    #[test]
    fn test_validate_mvhd_atom() {
        let mvhd_data = create_mvhd_atom();
        assert!(validate_mvhd_atom(&mvhd_data));

        // Test with invalid version
        let mut invalid_mvhd = mvhd_data.clone();
        invalid_mvhd[8] = 5; // Invalid version
        assert!(!validate_mvhd_atom(&invalid_mvhd));

        // Test with zero time scale
        let mut invalid_mvhd2 = mvhd_data.clone();
        invalid_mvhd2[20..24].copy_from_slice(&0u32.to_be_bytes());
        assert!(!validate_mvhd_atom(&invalid_mvhd2));
    }

    #[test]
    fn test_validate_trak_atom() {
        let trak_data = create_trak_atom();
        assert!(validate_trak_atom(&trak_data));
    }

    #[test]
    fn test_is_valid_atom_type() {
        assert!(is_valid_atom_type(b"moov"));
        assert!(is_valid_atom_type(b"mvhd"));
        assert!(is_valid_atom_type(b"trak"));
        assert!(is_valid_atom_type(b"free"));
        assert!(is_valid_atom_type(b"(c) "));

        assert!(!is_valid_atom_type(b"\x00\x00\x00\x00"));
        assert!(!is_valid_atom_type(b"\xFF\xFF\xFF\xFF"));
        assert!(!is_valid_atom_type(b"abc")); // Wrong length
    }

    #[test]
    fn test_mov_file_size_heuristic() {
        let spec = SearchSpec::new(
            FileType::Mov,
            "mov",
            b"moov",
            None,
            40 * 1024 * 1024,
            true,
            SearchType::Forward,
        );

        let mov_data = create_valid_mov_header();
        let size = mov_file_size_heuristic(&spec, &mov_data);
        assert_eq!(size, mov_data.len());
    }

    #[test]
    fn test_determine_mov_file_size_from_atoms() {
        let mov_data = create_valid_mov_header();
        let size = determine_mov_file_size_from_atoms(&mov_data);
        assert_eq!(size, Some(mov_data.len()));

        // Test with invalid data
        let invalid_data = vec![0x00, 0x00, 0x00, 0x04]; // Size too small
        assert_eq!(determine_mov_file_size_from_atoms(&invalid_data), None);
    }

    #[test]
    fn test_validate_moov_with_optional_udta_atom() {
        let mvhd_data = create_mvhd_atom();
        let trak_data = create_trak_atom();

        // Build a minimal udta atom (just header + padding)
        let udta_size: u32 = 16;
        let mut udta_data = Vec::new();
        udta_data.extend_from_slice(&udta_size.to_be_bytes());
        udta_data.extend_from_slice(b"udta");
        udta_data.extend_from_slice(&[0u8; 8]); // padding

        let moov_size = (8 + mvhd_data.len() + trak_data.len() + udta_data.len()) as u32;
        let mut moov = Vec::new();
        moov.extend_from_slice(&moov_size.to_be_bytes());
        moov.extend_from_slice(b"moov");
        moov.extend_from_slice(&mvhd_data);
        moov.extend_from_slice(&trak_data);
        moov.extend_from_slice(&udta_data);

        assert!(validate_moov_atom(&moov));
    }

    #[test]
    fn test_validate_moov_with_unknown_non_ascii_atom() {
        let mvhd_data = create_mvhd_atom();
        let trak_data = create_trak_atom();

        // Build an atom whose type contains non-ASCII bytes — should fail
        let bad_size: u32 = 16;
        let mut bad_atom = Vec::new();
        bad_atom.extend_from_slice(&bad_size.to_be_bytes());
        bad_atom.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // invalid type
        bad_atom.extend_from_slice(&[0u8; 8]); // padding

        let moov_size = (8 + mvhd_data.len() + trak_data.len() + bad_atom.len()) as u32;
        let mut moov = Vec::new();
        moov.extend_from_slice(&moov_size.to_be_bytes());
        moov.extend_from_slice(b"moov");
        moov.extend_from_slice(&mvhd_data);
        moov.extend_from_slice(&trak_data);
        moov.extend_from_slice(&bad_atom);

        assert!(!validate_moov_atom(&moov));
    }

    #[test]
    fn test_validate_trak_with_edts() {
        let tkhd_data = create_tkhd_atom();
        let mdia_data = create_mdia_atom();

        // Build a minimal edts atom
        let edts_size: u32 = 16;
        let mut edts_data = Vec::new();
        edts_data.extend_from_slice(&edts_size.to_be_bytes());
        edts_data.extend_from_slice(b"edts");
        edts_data.extend_from_slice(&[0u8; 8]); // padding

        let trak_size = (8 + tkhd_data.len() + mdia_data.len() + edts_data.len()) as u32;
        let mut trak = Vec::new();
        trak.extend_from_slice(&trak_size.to_be_bytes());
        trak.extend_from_slice(b"trak");
        trak.extend_from_slice(&tkhd_data);
        trak.extend_from_slice(&mdia_data);
        trak.extend_from_slice(&edts_data);

        assert!(validate_trak_atom(&trak));
    }

    #[test]
    fn test_validate_mvhd_both_times_zero() {
        let mut mvhd = create_mvhd_atom();
        // creation_time at bytes 12-15, modification_time at bytes 16-19
        mvhd[12..16].copy_from_slice(&0u32.to_be_bytes());
        mvhd[16..20].copy_from_slice(&0u32.to_be_bytes());
        assert!(!validate_mvhd_atom(&mvhd));
    }

    #[test]
    fn test_validate_mvhd_time_scale_too_high() {
        let mut mvhd = create_mvhd_atom();
        // time_scale at bytes 20-23; value > 1_000_000 should be rejected
        mvhd[20..24].copy_from_slice(&1_000_001u32.to_be_bytes());
        assert!(!validate_mvhd_atom(&mvhd));
    }

    #[test]
    fn test_determine_mov_file_size_atom_exceeds_buffer() {
        // Build an atom whose declared size is larger than the buffer
        let declared_size: u32 = 1000; // much larger than actual buffer
        let mut data = Vec::new();
        data.extend_from_slice(&declared_size.to_be_bytes());
        data.extend_from_slice(b"moov");
        data.extend_from_slice(&[0u8; 8]); // only 16 bytes total

        let result = determine_mov_file_size_from_atoms(&data);
        // Should return Some(buf.len()) since atom extends beyond buffer
        assert_eq!(result, Some(data.len()));
    }
}
