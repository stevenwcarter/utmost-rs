use std::cmp;

use crate::types::{CONSERVATIVE_FALLBACK_SIZE, Endianness, bytes_to_u16, bytes_to_u32};

/// Determine the actual size of a ZIP file by parsing its structure
pub fn determine_zip_file_size(buf: &[u8], max_len: usize) -> usize {
    // ZIP file structure:
    // - Local file headers (PK\x03\x04) with file data
    // - Central directory entries (PK\x01\x02)
    // - End of central directory record (PK\x05\x06)

    // Look for the End of Central Directory (EOCD) record
    // The EOCD signature is 0x50, 0x4B, 0x05, 0x06 (PK\x05\x06)
    let eocd_signature = [0x50, 0x4B, 0x05, 0x06];

    // Search FORWARD from the beginning for the first EOCD record
    // This ensures we find the EOCD that belongs to THIS ZIP file,
    // not a later ZIP file that might also be in the buffer
    for i in 0..buf.len().saturating_sub(21) {
        if buf[i..i + 4] == eocd_signature {
            // Found EOCD record, parse it to get the actual ZIP file size
            return parse_zip_eocd_record(&buf[i..], i, max_len);
        }
    }

    // If no EOCD found, fall back to scanning for local file headers
    // and estimating based on the last one found
    find_zip_end_by_local_headers(buf, max_len)
}

/// Parse the End of Central Directory record to determine ZIP file size
pub fn parse_zip_eocd_record(eocd_data: &[u8], eocd_offset: usize, max_len: usize) -> usize {
    if eocd_data.len() < 22 {
        return cmp::min(max_len, eocd_offset + 22);
    }

    // EOCD structure (all little-endian):
    // 0-3:   End of central dir signature (0x06054b50)
    // 4-5:   Number of this disk
    // 6-7:   Disk where central directory starts
    // 8-9:   Number of central directory records on this disk
    // 10-11: Total number of central directory records
    // 12-15: Size of central directory
    // 16-19: Offset of start of central directory
    // 20-21: ZIP file comment length
    // 22+:   ZIP file comment

    let comment_length = bytes_to_u16(&eocd_data[20..22], Endianness::Little) as usize;

    // The actual ZIP file ends after the EOCD record + comment
    let zip_end = eocd_offset + 22 + comment_length;

    cmp::min(zip_end, max_len)
}

/// Parse a ZIP local file header to determine where this file entry ends
fn parse_zip_local_header(header_data: &[u8], header_offset: usize) -> Option<usize> {
    if header_data.len() < 30 {
        return None;
    }

    // Local file header structure (all little-endian):
    // 0-3:   Local file header signature (0x04034b50)
    // 4-5:   Version needed to extract
    // 6-7:   General purpose bit flag
    // 8-9:   Compression method
    // 10-11: Last mod file time
    // 12-13: Last mod file date
    // 14-17: CRC-32
    // 18-21: Compressed size
    // 22-25: Uncompressed size
    // 26-27: File name length
    // 28-29: Extra field length
    // 30+:   File name + extra field + compressed data

    let compressed_size = bytes_to_u32(&header_data[18..22], Endianness::Little) as usize;
    let filename_length = bytes_to_u16(&header_data[26..28], Endianness::Little) as usize;
    let extra_field_length = bytes_to_u16(&header_data[28..30], Endianness::Little) as usize;

    // Calculate the end of this file entry; use checked arithmetic to guard
    // against overflow from untrusted field values.
    let file_end = header_offset
        .checked_add(30)?
        .checked_add(filename_length)?
        .checked_add(extra_field_length)?
        .checked_add(compressed_size)?;

    Some(file_end)
}

/// Fallback method: find ZIP end by scanning local file headers.
///
/// This is O(n) byte-by-byte when no EOCD is present (e.g. truncated or
/// corrupted ZIPs). Acceptable for rare cases; normal ZIPs exit via EOCD.
fn find_zip_end_by_local_headers(buf: &[u8], max_len: usize) -> usize {
    let local_header_sig = [0x50, 0x4B, 0x03, 0x04]; // PK\x03\x04
    let mut last_file_end = 0;
    let mut pos = 0;

    while pos < buf.len().saturating_sub(29) {
        if buf[pos..pos + 4] == local_header_sig {
            // Found local file header, parse it to find the end of this file
            if let Some(file_end) = parse_zip_local_header(&buf[pos..], pos) {
                last_file_end = cmp::max(last_file_end, file_end);
                pos = file_end;
            } else {
                pos += 4;
            }
        } else {
            pos += 1;
        }
    }

    if last_file_end > 0 {
        cmp::min(last_file_end, max_len)
    } else {
        // No valid local headers found, use conservative estimate
        cmp::min(CONSERVATIVE_FALLBACK_SIZE, cmp::min(max_len, buf.len()))
    }
}

#[cfg(test)]
mod tests {
    use crate::engine::determine_file_size_heuristic;
    use crate::types::{FileType, SearchSpec, SearchType};

    use super::*;

    #[test]
    fn test_determine_zip_file_size_with_eocd() {
        // Create a minimal ZIP file structure with EOCD
        let mut zip_data = Vec::new();

        // Local file header (PK\x03\x04)
        zip_data.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]); // Signature
        zip_data.extend_from_slice(&[0x14, 0x00]); // Version needed
        zip_data.extend_from_slice(&[0x00, 0x00]); // General purpose flag
        zip_data.extend_from_slice(&[0x00, 0x00]); // Compression method
        zip_data.extend_from_slice(&[0x00, 0x00]); // Last mod time
        zip_data.extend_from_slice(&[0x00, 0x00]); // Last mod date
        zip_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // CRC-32
        zip_data.extend_from_slice(&[0x05, 0x00, 0x00, 0x00]); // Compressed size (5 bytes)
        zip_data.extend_from_slice(&[0x05, 0x00, 0x00, 0x00]); // Uncompressed size (5 bytes)
        zip_data.extend_from_slice(&[0x08, 0x00]); // Filename length (8 bytes)
        zip_data.extend_from_slice(&[0x00, 0x00]); // Extra field length (0)
        zip_data.extend_from_slice(b"test.txt"); // Filename
        zip_data.extend_from_slice(b"hello"); // File data (5 bytes)

        // Central directory entry (PK\x01\x02)
        let central_dir_start = zip_data.len();
        zip_data.extend_from_slice(&[0x50, 0x4B, 0x01, 0x02]); // Signature
        zip_data.extend_from_slice(&[0x14, 0x00]); // Version made by
        zip_data.extend_from_slice(&[0x14, 0x00]); // Version needed
        zip_data.extend_from_slice(&[0x00, 0x00]); // General purpose flag
        zip_data.extend_from_slice(&[0x00, 0x00]); // Compression method
        zip_data.extend_from_slice(&[0x00, 0x00]); // Last mod time
        zip_data.extend_from_slice(&[0x00, 0x00]); // Last mod date
        zip_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // CRC-32
        zip_data.extend_from_slice(&[0x05, 0x00, 0x00, 0x00]); // Compressed size
        zip_data.extend_from_slice(&[0x05, 0x00, 0x00, 0x00]); // Uncompressed size
        zip_data.extend_from_slice(&[0x08, 0x00]); // Filename length
        zip_data.extend_from_slice(&[0x00, 0x00]); // Extra field length
        zip_data.extend_from_slice(&[0x00, 0x00]); // File comment length
        zip_data.extend_from_slice(&[0x00, 0x00]); // Disk number start
        zip_data.extend_from_slice(&[0x00, 0x00]); // Internal file attributes
        zip_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // External file attributes
        zip_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Relative offset of local header
        zip_data.extend_from_slice(b"test.txt"); // Filename

        // End of Central Directory (PK\x05\x06)
        let eocd_start = zip_data.len();
        zip_data.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]); // Signature
        zip_data.extend_from_slice(&[0x00, 0x00]); // Number of this disk
        zip_data.extend_from_slice(&[0x00, 0x00]); // Disk where central directory starts
        zip_data.extend_from_slice(&[0x01, 0x00]); // Number of central directory records on this disk
        zip_data.extend_from_slice(&[0x01, 0x00]); // Total number of central directory records

        let central_dir_size = eocd_start - central_dir_start;
        zip_data.extend_from_slice(&(central_dir_size as u32).to_le_bytes()); // Size of central directory
        zip_data.extend_from_slice(&(central_dir_start as u32).to_le_bytes()); // Offset of central directory
        zip_data.extend_from_slice(&[0x0A, 0x00]); // ZIP file comment length (10 bytes)
        zip_data.extend_from_slice(b"Test ZIP!!"); // ZIP file comment

        let expected_size = zip_data.len();

        let spec = SearchSpec::new(
            FileType::Zip,
            "zip",
            &[0x50, 0x4B, 0x03, 0x04],
            Some(&[0x50, 0x4B, 0x05, 0x06]),
            100 * 1024 * 1024,
            true,
            SearchType::Forward,
        );

        let calculated_size = determine_file_size_heuristic(&spec, &zip_data);
        assert_eq!(
            calculated_size, expected_size,
            "ZIP file size should be calculated correctly"
        );
    }

    #[test]
    fn test_determine_zip_file_size_fallback() {
        // Create ZIP data with local file header but no EOCD (corrupted/truncated)
        let mut zip_data = Vec::new();

        // Local file header (PK\x03\x04)
        zip_data.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]); // Signature
        zip_data.extend_from_slice(&[0x14, 0x00]); // Version needed
        zip_data.extend_from_slice(&[0x00, 0x00]); // General purpose flag
        zip_data.extend_from_slice(&[0x00, 0x00]); // Compression method
        zip_data.extend_from_slice(&[0x00, 0x00]); // Last mod time
        zip_data.extend_from_slice(&[0x00, 0x00]); // Last mod date
        zip_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // CRC-32
        zip_data.extend_from_slice(&[0x05, 0x00, 0x00, 0x00]); // Compressed size (5 bytes)
        zip_data.extend_from_slice(&[0x05, 0x00, 0x00, 0x00]); // Uncompressed size (5 bytes)
        zip_data.extend_from_slice(&[0x08, 0x00]); // Filename length (8 bytes)
        zip_data.extend_from_slice(&[0x00, 0x00]); // Extra field length (0)
        zip_data.extend_from_slice(b"test.txt"); // Filename
        zip_data.extend_from_slice(b"hello"); // File data (5 bytes)

        // Add some padding/garbage after the file
        zip_data.extend_from_slice(&[0x00; 100]);

        let expected_size = 30 + 8 + 5; // Header + filename + data

        let spec = SearchSpec::new(
            FileType::Zip,
            "zip",
            &[0x50, 0x4B, 0x03, 0x04],
            Some(&[0x50, 0x4B, 0x05, 0x06]),
            100 * 1024 * 1024,
            true,
            SearchType::Forward,
        );

        let calculated_size = determine_zip_file_size(&zip_data, spec.max_len);
        assert_eq!(
            calculated_size, expected_size,
            "ZIP fallback parsing should find end of last file"
        );
    }

    #[test]
    fn test_parse_zip_local_header() {
        // Create a valid local file header
        let mut header_data = Vec::new();
        header_data.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]); // Signature
        header_data.extend_from_slice(&[0x14, 0x00]); // Version needed
        header_data.extend_from_slice(&[0x00, 0x00]); // General purpose flag
        header_data.extend_from_slice(&[0x00, 0x00]); // Compression method
        header_data.extend_from_slice(&[0x00, 0x00]); // Last mod time
        header_data.extend_from_slice(&[0x00, 0x00]); // Last mod date
        header_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // CRC-32
        header_data.extend_from_slice(&[0x0A, 0x00, 0x00, 0x00]); // Compressed size (10 bytes)
        header_data.extend_from_slice(&[0x0A, 0x00, 0x00, 0x00]); // Uncompressed size (10 bytes)
        header_data.extend_from_slice(&[0x04, 0x00]); // Filename length (4 bytes)
        header_data.extend_from_slice(&[0x02, 0x00]); // Extra field length (2 bytes)
        header_data.extend_from_slice(b"test"); // Filename (4 bytes)
        header_data.extend_from_slice(&[0x00, 0x00]); // Extra field (2 bytes)
        header_data.extend_from_slice(b"1234567890"); // File data (10 bytes)

        let result = parse_zip_local_header(&header_data, 0);
        assert!(result.is_some());

        let file_end = result.unwrap();
        let expected_end = 30 + 4 + 2 + 10; // Header + filename + extra + data
        assert_eq!(file_end, expected_end);
    }

    #[test]
    fn test_parse_zip_eocd_record() {
        // Create a valid EOCD record with comment
        let mut eocd_data = Vec::new();
        eocd_data.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]); // Signature
        eocd_data.extend_from_slice(&[0x00, 0x00]); // Number of this disk
        eocd_data.extend_from_slice(&[0x00, 0x00]); // Disk where central directory starts
        eocd_data.extend_from_slice(&[0x01, 0x00]); // Number of central directory records on this disk
        eocd_data.extend_from_slice(&[0x01, 0x00]); // Total number of central directory records
        eocd_data.extend_from_slice(&[0x2E, 0x00, 0x00, 0x00]); // Size of central directory
        eocd_data.extend_from_slice(&[0x43, 0x00, 0x00, 0x00]); // Offset of central directory
        eocd_data.extend_from_slice(&[0x05, 0x00]); // ZIP file comment length (5 bytes)
        eocd_data.extend_from_slice(b"hello"); // ZIP file comment

        let eocd_offset = 100;
        let result = parse_zip_eocd_record(&eocd_data, eocd_offset, 1000);

        let expected_size = eocd_offset + 22 + 5; // EOCD offset + EOCD header + comment
        assert_eq!(result, expected_size);
    }
}
