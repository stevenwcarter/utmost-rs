use std::cmp;

use crate::{
    SearchSpec,
    types::{Endianness, bytes_to_u16, bytes_to_u32},
};

/// Validate GZIP file structure to reduce false positives
/// Performs comprehensive validation of GZIP header fields
pub fn validate_gz_file(data: &[u8]) -> bool {
    // Minimum GZIP header size is 10 bytes
    if data.len() < 10 {
        return false;
    }

    // Check magic number (already verified by search, but double-check)
    if data[0] != 0x1F || data[1] != 0x8B {
        return false;
    }

    // Check compression method (byte 2) - should be 8 (deflate)
    if data[2] != 0x08 {
        return false;
    }

    // Get flags (byte 3)
    let flags = data[3];

    // Reserved bits (bits 5-7) should be zero
    if (flags & 0xE0) != 0 {
        return false;
    }

    // Check modification time (bytes 4-7) - reasonable timestamp
    let mtime = bytes_to_u32(&data[4..8], Endianness::Little);

    // Modification time should be reasonable (after 1970 and not too far in future)
    // Allow 0 (unknown) and reasonable range from 1970 to ~2070
    if mtime != 0 && !(86400..=3153600000).contains(&mtime) {
        return false;
    }

    // Get extra flags (byte 8)
    let xfl = data[8];

    // Extra flags validation based on compression method
    // For deflate (method 8):
    // 0 = unknown, 2 = slow/max compression, 4 = fast compression
    match xfl {
        0 | 2 | 4 => {}
        _ => return false,
    }

    // Get OS (byte 9) - should be valid OS identifier
    let os = data[9];

    // Valid OS values (0-13 are defined, 255 = unknown)
    if os > 13 && os != 255 {
        return false;
    }

    let mut header_pos = 10;

    // Check optional fields based on flags

    // FEXTRA flag (bit 2) - extra field
    if (flags & 0x04) != 0 {
        if header_pos + 2 > data.len() {
            return false;
        }

        let xlen = bytes_to_u16(&data[header_pos..header_pos + 2], Endianness::Little) as usize;
        header_pos += 2;

        // Extra field length should be reasonable
        if xlen > 65535 {
            return false;
        }

        if header_pos + xlen > data.len() {
            return false;
        }

        header_pos += xlen;
    }

    // FNAME flag (bit 3) - original filename
    if (flags & 0x08) != 0 {
        // Find null terminator for filename
        let mut found_null = false;
        let start_pos = header_pos;

        while header_pos < data.len() {
            if data[header_pos] == 0 {
                found_null = true;
                header_pos += 1;
                break;
            }
            header_pos += 1;
        }

        if !found_null {
            return false;
        }

        // Filename should be reasonable length
        let filename_len = header_pos - start_pos - 1;
        if filename_len > 1024 {
            return false;
        }

        // Validate filename contains printable characters
        for &byte in &data[start_pos..header_pos - 1] {
            if !(32..=126).contains(&byte) {
                // Allow some extended ASCII but reject control characters
                if byte < 128 && byte != 9 && byte != 10 && byte != 13 {
                    return false;
                }
            }
        }
    }

    // FCOMMENT flag (bit 4) - comment
    if (flags & 0x10) != 0 {
        // Find null terminator for comment
        let mut found_null = false;
        let start_pos = header_pos;

        while header_pos < data.len() {
            if data[header_pos] == 0 {
                found_null = true;
                header_pos += 1;
                break;
            }
            header_pos += 1;
        }

        if !found_null {
            return false;
        }

        // Comment should be reasonable length
        let comment_len = header_pos - start_pos - 1;
        if comment_len > 2048 {
            return false;
        }

        // Validate comment contains printable characters
        for &byte in &data[start_pos..header_pos - 1] {
            if !(32..=126).contains(&byte) {
                // Allow some extended ASCII but reject control characters
                if byte < 128 && byte != 9 && byte != 10 && byte != 13 {
                    return false;
                }
            }
        }
    }

    // FHCRC flag (bit 1) - header CRC
    if (flags & 0x02) != 0 {
        if header_pos + 2 > data.len() {
            return false;
        }
        header_pos += 2;
    }

    // Check that we have enough data for compressed payload and trailer
    // GZIP files must end with CRC32 (4 bytes) + ISIZE (4 bytes)
    if data.len() < header_pos + 8 {
        return false;
    }

    // Verify deflate stream starts properly after header
    if header_pos < data.len() {
        let deflate_start = &data[header_pos..];

        // Basic deflate stream validation
        // First block header should be reasonable
        if deflate_start.len() >= 3 {
            let first_byte = deflate_start[0];

            // Check BFINAL and BTYPE bits
            let _bfinal = first_byte & 0x01;
            let btype = (first_byte >> 1) & 0x03;

            // BTYPE should be 0 (uncompressed), 1 (fixed Huffman), or 2 (dynamic Huffman)
            // 3 is reserved/invalid
            if btype == 3 {
                return false;
            }

            // If uncompressed block (BTYPE = 0), validate LEN/NLEN fields
            if btype == 0 && deflate_start.len() >= 5 {
                let len = bytes_to_u16(&deflate_start[1..3], Endianness::Little);
                let nlen = bytes_to_u16(&deflate_start[3..5], Endianness::Little);

                // LEN and NLEN should be one's complement of each other
                if len != (!nlen) {
                    return false;
                }
            }
        }
    }

    // Check trailer (last 8 bytes) if we can see the end
    if data.len() >= header_pos + 8 {
        let trailer_start = data.len() - 8;

        // Get CRC32 and ISIZE from trailer
        let _crc32 = bytes_to_u32(&data[trailer_start..trailer_start + 4], Endianness::Little);
        let _isize = bytes_to_u32(
            &data[trailer_start + 4..trailer_start + 8],
            Endianness::Little,
        );

        // ISIZE should be reasonable (original uncompressed size modulo 2^32)
        // Very large values might indicate corruption, but this is hard to validate
        // without decompression, so we'll be lenient here

        // Check that compressed data section is not empty
        let compressed_size = trailer_start - header_pos;
        if compressed_size == 0 {
            return false;
        }
    }

    // All checks passed
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
    cmp::min(64 * 1024, cmp::min(spec.max_len, buf.len()))
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

