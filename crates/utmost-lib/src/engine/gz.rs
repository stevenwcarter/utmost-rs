use std::cmp;

use crate::{
    SearchSpec,
    types::{CONSERVATIVE_FALLBACK_SIZE, Endianness, bytes_to_u16, bytes_to_u32},
};

/// Validate GZIP file structure to reduce false positives.
/// Performs comprehensive validation of GZIP header fields.
pub fn validate_gz_file(data: &[u8]) -> bool {
    let Some(flags) = check_gz_fixed_header(data) else {
        return false;
    };
    let Some(header_end) = skip_gz_optional_fields(data, flags) else {
        return false;
    };
    validate_gz_payload(data, header_end)
}

/// Validate the 10-byte fixed GZIP header.
/// Returns `Some(flags)` on success, `None` on any violation.
fn check_gz_fixed_header(data: &[u8]) -> Option<u8> {
    if data.len() < 10 {
        return None;
    }

    // Magic number (already verified by search, but double-check)
    if data[0] != 0x1F || data[1] != 0x8B {
        return None;
    }

    // Compression method must be 8 (deflate)
    if data[2] != 0x08 {
        return None;
    }

    let flags = data[3];

    // Reserved bits 5-7 must be zero
    if (flags & 0xE0) != 0 {
        return None;
    }

    // Modification time: 0 = unknown; otherwise in range 86400–3_153_600_000 (~1970–2070)
    let mtime = bytes_to_u32(&data[4..8], Endianness::Little);
    if mtime != 0 && !(86400..=3153600000).contains(&mtime) {
        return None;
    }

    // Extra flags: 0=unknown, 2=max compression, 4=fastest compression
    match data[8] {
        0 | 2 | 4 => {}
        _ => return None,
    }

    // OS: 0–13 are defined values, 255 = unknown
    if data[9] > 13 && data[9] != 255 {
        return None;
    }

    Some(flags)
}

/// Walk the optional GZIP header fields (FEXTRA, FNAME, FCOMMENT, FHCRC).
/// Returns `Some(header_end_pos)` on success, `None` on truncation or invalid content.
fn skip_gz_optional_fields(data: &[u8], flags: u8) -> Option<usize> {
    let mut pos = 10;

    // FEXTRA (bit 2): 2-byte length field followed by that many bytes
    if (flags & 0x04) != 0 {
        if pos + 2 > data.len() {
            return None;
        }
        let xlen = bytes_to_u16(&data[pos..pos + 2], Endianness::Little) as usize;
        pos += 2;
        if pos + xlen > data.len() {
            return None;
        }
        pos += xlen;
    }

    // FNAME (bit 3): null-terminated original filename
    if (flags & 0x08) != 0 {
        let start = pos;
        loop {
            if pos >= data.len() {
                return None; // no null terminator
            }
            let byte = data[pos];
            pos += 1;
            if byte == 0 {
                break;
            }
        }
        let filename_len = pos - start - 1;
        if filename_len > 1024 {
            return None;
        }
        for &byte in &data[start..pos - 1] {
            if !(32..=126).contains(&byte) && byte < 128 && byte != 9 && byte != 10 && byte != 13 {
                return None;
            }
        }
    }

    // FCOMMENT (bit 4): null-terminated comment
    if (flags & 0x10) != 0 {
        let start = pos;
        loop {
            if pos >= data.len() {
                return None;
            }
            let byte = data[pos];
            pos += 1;
            if byte == 0 {
                break;
            }
        }
        let comment_len = pos - start - 1;
        if comment_len > 2048 {
            return None;
        }
        for &byte in &data[start..pos - 1] {
            if !(32..=126).contains(&byte) && byte < 128 && byte != 9 && byte != 10 && byte != 13 {
                return None;
            }
        }
    }

    // FHCRC (bit 1): 2-byte header CRC
    if (flags & 0x02) != 0 {
        if pos + 2 > data.len() {
            return None;
        }
        pos += 2;
    }

    Some(pos)
}

/// Validate the deflate payload and GZIP trailer starting at `header_end`.
fn validate_gz_payload(data: &[u8], header_end: usize) -> bool {
    // Must have at least 8 bytes for the CRC32 + ISIZE trailer
    if data.len() < header_end + 8 {
        return false;
    }

    // Basic deflate stream validation (first block header)
    let deflate = &data[header_end..];
    if deflate.len() >= 3 {
        let btype = (deflate[0] >> 1) & 0x03;
        // BTYPE 3 is reserved/invalid
        if btype == 3 {
            return false;
        }
        // Uncompressed block (BTYPE=0): validate LEN/NLEN one's complement
        if btype == 0 && deflate.len() >= 5 {
            let len = bytes_to_u16(&deflate[1..3], Endianness::Little);
            let nlen = bytes_to_u16(&deflate[3..5], Endianness::Little);
            if len != !nlen {
                return false;
            }
        }
    }

    // Trailer: check that there is a non-empty compressed data section
    let trailer_start = data.len() - 8;
    let compressed_size = trailer_start - header_end;
    if compressed_size == 0 {
        return false;
    }

    true
}

/// Determine GZIP file size heuristic
/// GZIP files have a defined trailer at the end with CRC32 and ISIZE
pub fn gz_file_size_heuristic(spec: &SearchSpec, buf: &[u8]) -> usize {
    // For GZIP files, we need to find the end of the deflate stream
    // This is complex as it requires parsing the deflate format
    // For now, use a simple heuristic that looks for the trailer pattern

    if buf.len() < 18 {
        // Minimum: 10 byte header + some data + 8 byte trailer
        return 0;
    }

    // For validation purposes, if the entire buffer validates as a complete
    // GZIP file, return the full buffer size
    if validate_gz_file(buf) {
        return buf.len();
    }

    // Otherwise, look for potential GZIP trailer (last 8 bytes contain CRC32 + ISIZE)
    // We'll search forwards from a reasonable minimum to find a valid end

    let max_search = cmp::min(spec.max_len, buf.len());

    // Start from a reasonable minimum (18 bytes) and search forward
    for end_pos in 18..=max_search {
        if end_pos > buf.len() {
            break;
        }

        // Check if this position could be a valid GZIP file end
        let candidate = &buf[..end_pos];
        if validate_gz_file(candidate) {
            return end_pos;
        }
    }

    // Fallback to a reasonable size if no clear end found
    cmp::min(
        CONSERVATIVE_FALLBACK_SIZE,
        cmp::min(spec.max_len, buf.len()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FileType, SearchSpec, SearchType};

    fn create_valid_gzip_header() -> Vec<u8> {
        let mut data = vec![
            0x1F, 0x8B, // Magic number
            0x08, // Compression method (deflate)
            0x00, // Flags (no optional fields)
            0x00, 0x00, 0x00, 0x00, // Modification time (0 = unknown)
            0x00, // Extra flags (0 = unknown)
            0xFF, // OS (255 = unknown)
        ];

        // Add some deflate data (simplified)
        // Final block, uncompressed, 5 bytes: "hello"
        data.push(0x01); // BFINAL=1, BTYPE=00 (uncompressed)
        data.extend_from_slice(&[0x05, 0x00]); // LEN = 5
        data.extend_from_slice(&[0xFA, 0xFF]); // NLEN = ~5
        data.extend_from_slice(b"hello"); // Uncompressed data

        // Trailer: CRC32 + ISIZE
        data.extend_from_slice(&[0x36, 0x38, 0xFE, 0x90]); // CRC32 for "hello"
        data.extend_from_slice(&[0x05, 0x00, 0x00, 0x00]); // ISIZE = 5

        data
    }

    #[test]
    fn test_validate_gz_file_valid() {
        let valid_gz = create_valid_gzip_header();
        assert!(validate_gz_file(&valid_gz));
    }

    #[test]
    fn test_validate_gz_file_too_small() {
        let small_data = vec![0x1F, 0x8B]; // Only 2 bytes
        assert!(!validate_gz_file(&small_data));
    }

    #[test]
    fn test_validate_gz_file_wrong_magic() {
        let mut invalid_gz = create_valid_gzip_header();
        invalid_gz[0] = 0x1E; // Wrong magic number
        assert!(!validate_gz_file(&invalid_gz));
    }

    #[test]
    fn test_validate_gz_file_wrong_compression_method() {
        let mut invalid_gz = create_valid_gzip_header();
        invalid_gz[2] = 0x09; // Wrong compression method
        assert!(!validate_gz_file(&invalid_gz));
    }

    #[test]
    fn test_validate_gz_file_reserved_flags() {
        let mut invalid_gz = create_valid_gzip_header();
        invalid_gz[3] = 0x80; // Reserved bit set
        assert!(!validate_gz_file(&invalid_gz));
    }

    #[test]
    fn test_validate_gz_file_invalid_mtime() {
        let mut invalid_gz = create_valid_gzip_header();
        // Set invalid timestamp (too old)
        invalid_gz[4] = 0x01;
        invalid_gz[5] = 0x00;
        invalid_gz[6] = 0x00;
        invalid_gz[7] = 0x00;
        assert!(!validate_gz_file(&invalid_gz));
    }

    #[test]
    fn test_validate_gz_file_invalid_xfl() {
        let mut invalid_gz = create_valid_gzip_header();
        invalid_gz[8] = 0x01; // Invalid extra flags
        assert!(!validate_gz_file(&invalid_gz));
    }

    #[test]
    fn test_validate_gz_file_invalid_os() {
        let mut invalid_gz = create_valid_gzip_header();
        invalid_gz[9] = 50; // Invalid OS identifier
        assert!(!validate_gz_file(&invalid_gz));
    }

    #[test]
    fn test_validate_gz_file_with_filename() {
        let mut data = Vec::new();

        // Magic number and compression method
        data.extend_from_slice(&[0x1F, 0x8B, 0x08]);

        // Flags with FNAME set
        data.push(0x08);

        // Modification time, xfl, os
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0xFF]);

        // Filename
        data.extend_from_slice(b"test.txt\0");

        // Minimal deflate data and trailer
        data.push(0x01); // Final uncompressed block
        data.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF]); // Empty block
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // CRC32
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ISIZE

        assert!(validate_gz_file(&data));
    }

    #[test]
    fn test_validate_gz_file_with_comment() {
        let mut data = Vec::new();

        // Magic number and compression method
        data.extend_from_slice(&[0x1F, 0x8B, 0x08]);

        // Flags with FCOMMENT set
        data.push(0x10);

        // Modification time, xfl, os
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0xFF]);

        // Comment
        data.extend_from_slice(b"This is a test file\0");

        // Minimal deflate data and trailer
        data.push(0x01); // Final uncompressed block
        data.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF]); // Empty block
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // CRC32
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ISIZE

        assert!(validate_gz_file(&data));
    }

    #[test]
    fn test_validate_gz_file_invalid_deflate_block() {
        let mut invalid_gz = create_valid_gzip_header();
        // Corrupt the deflate block type
        invalid_gz[10] = 0x07; // BTYPE = 11 (reserved/invalid)
        assert!(!validate_gz_file(&invalid_gz));
    }

    #[test]
    fn test_validate_gz_file_uncompressed_block_mismatch() {
        let mut data = Vec::new();

        // Valid header
        data.extend_from_slice(&[0x1F, 0x8B, 0x08, 0x00]);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0xFF]);

        // Uncompressed block with mismatched LEN/NLEN
        data.push(0x01); // BFINAL=1, BTYPE=00 (uncompressed)
        data.extend_from_slice(&[0x05, 0x00]); // LEN = 5
        data.extend_from_slice(&[0xFB, 0xFF]); // NLEN = ~5 + 1 (wrong)
        data.extend_from_slice(b"hello");

        // Trailer
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&[0x05, 0x00, 0x00, 0x00]);

        assert!(!validate_gz_file(&data));
    }

    #[test]
    fn test_gz_file_size_heuristic() {
        let spec = SearchSpec::new(
            FileType::Gzip,
            "gz",
            &[0x1F, 0x8B, 0x08],
            Some(&[0x00, 0x00, 0x00, 0x00]),
            100 * 1024 * 1024,
            true,
            SearchType::Forward,
        );

        let valid_gz = create_valid_gzip_header();
        let size = gz_file_size_heuristic(&spec, &valid_gz);

        // Should detect the full file size
        assert_eq!(size, valid_gz.len());
    }

    #[test]
    fn test_gz_file_size_heuristic_too_small() {
        let spec = SearchSpec::new(
            FileType::Gzip,
            "gz",
            &[0x1F, 0x8B, 0x08],
            Some(&[0x00, 0x00, 0x00, 0x00]),
            100 * 1024 * 1024,
            true,
            SearchType::Forward,
        );

        let data = vec![0x1F, 0x8B, 0x08]; // Too small
        let size = gz_file_size_heuristic(&spec, &data);
        assert_eq!(size, 0);
    }

    #[test]
    fn test_validate_gz_file_with_extra_field() {
        let mut data = Vec::new();

        // Magic number and compression method
        data.extend_from_slice(&[0x1F, 0x8B, 0x08]);

        // Flags with FEXTRA set
        data.push(0x04);

        // Modification time, xfl, os
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0xFF]);

        // Extra field length (4 bytes)
        data.extend_from_slice(&[0x04, 0x00]);

        // Extra field data
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);

        // Minimal deflate data and trailer
        data.push(0x01); // Final uncompressed block
        data.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF]); // Empty block
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // CRC32
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ISIZE

        assert!(validate_gz_file(&data));
    }

    #[test]
    fn test_validate_gz_mtime_zero() {
        // mtime=0 means "unknown timestamp" and is explicitly allowed
        let mut gz = create_valid_gzip_header();
        gz[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert!(validate_gz_file(&gz));
    }

    #[test]
    fn test_validate_gz_mtime_boundary() {
        // mtime=86400 is the exact lower bound of the valid non-zero range
        let mut gz = create_valid_gzip_header();
        gz[4..8].copy_from_slice(&86400u32.to_le_bytes());
        assert!(validate_gz_file(&gz));
    }

    #[test]
    fn test_validate_gz_xfl_values() {
        // xfl=2 (max compression) and xfl=4 (fast compression) are both valid
        let mut gz = create_valid_gzip_header();
        gz[8] = 2;
        assert!(
            validate_gz_file(&gz),
            "xfl=2 (max compression) should be valid"
        );

        let mut gz = create_valid_gzip_header();
        gz[8] = 4;
        assert!(
            validate_gz_file(&gz),
            "xfl=4 (fast compression) should be valid"
        );
    }

    #[test]
    fn test_validate_gz_btype_fixed_huffman() {
        // BTYPE=1 (fixed Huffman coding) is a valid deflate block type
        let mut gz = create_valid_gzip_header();
        // Byte 10 is the first deflate byte; BFINAL=1, BTYPE=01 → 0x03
        gz[10] = 0x03;
        assert!(validate_gz_file(&gz));
    }

    #[test]
    fn test_validate_gz_btype_dynamic_huffman() {
        // BTYPE=2 (dynamic Huffman coding) is a valid deflate block type
        let mut gz = create_valid_gzip_header();
        // BFINAL=1, BTYPE=10 → 0x05
        gz[10] = 0x05;
        assert!(validate_gz_file(&gz));
    }

    #[test]
    fn test_validate_gz_all_optional_fields() {
        // All four optional header fields present simultaneously
        let mut data = Vec::new();
        data.extend_from_slice(&[0x1F, 0x8B, 0x08]);
        data.push(0x1E); // flags: FHCRC(0x02)|FEXTRA(0x04)|FNAME(0x08)|FCOMMENT(0x10)
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // mtime=0
        data.push(0x00); // xfl=0
        data.push(0xFF); // os=255 (unknown)

        // FEXTRA: 2-byte length + 2 bytes of data
        data.extend_from_slice(&[0x02, 0x00]);
        data.extend_from_slice(&[0xAB, 0xCD]);

        // FNAME: null-terminated filename
        data.extend_from_slice(b"test.txt\0");

        // FCOMMENT: null-terminated comment
        data.extend_from_slice(b"ok\0");

        // FHCRC: 2-byte header CRC (value not validated)
        data.extend_from_slice(&[0x12, 0x34]);

        // Deflate: final uncompressed block with "hello"
        data.push(0x01); // BFINAL=1, BTYPE=00
        data.extend_from_slice(&[0x05, 0x00]); // LEN=5
        data.extend_from_slice(&[0xFA, 0xFF]); // NLEN=~5
        data.extend_from_slice(b"hello");

        // Trailer: CRC32 + ISIZE (CRC not validated)
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&[0x05, 0x00, 0x00, 0x00]);

        assert!(validate_gz_file(&data));
    }

    #[test]
    fn test_validate_gz_file_with_header_crc() {
        let mut data = Vec::new();

        // Magic number and compression method
        data.extend_from_slice(&[0x1F, 0x8B, 0x08]);

        // Flags with FHCRC set
        data.push(0x02);

        // Modification time, xfl, os
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0xFF]);

        // Header CRC
        data.extend_from_slice(&[0x12, 0x34]);

        // Minimal deflate data and trailer
        data.push(0x01); // Final uncompressed block
        data.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF]); // Empty block
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // CRC32
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ISIZE

        assert!(validate_gz_file(&data));
    }
}
