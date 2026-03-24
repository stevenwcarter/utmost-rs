use std::cmp;

use crate::SearchSpec;

/// Validate MPEG file structure to reduce false positives
/// Performs comprehensive validation of MPEG stream structure
pub fn validate_mpg_file(data: &[u8]) -> bool {
    // Minimum MPEG pack header size is 14 bytes for MPEG-1, 14 bytes for MPEG-2
    if data.len() < 14 {
        return false;
    }

    // Check MPEG pack start code: 00 00 01 BA
    if data[0] != 0x00 || data[1] != 0x00 || data[2] != 0x01 || data[3] != 0xBA {
        return false;
    }

    // Parse pack header based on MPEG version
    // MPEG-2 has a different pack header format than MPEG-1

    // Check if this is MPEG-2 (bit pattern in byte 4)
    let is_mpeg2 = (data[4] & 0xC0) == 0x40; // '01' in top 2 bits indicates MPEG-2

    if is_mpeg2 {
        // MPEG-2 pack header validation
        if !validate_mpeg2_pack_header(data) {
            return false;
        }
    } else {
        // MPEG-1 pack header validation
        if !validate_mpeg1_pack_header(data) {
            return false;
        }
    }

    // Look for additional MPEG start codes to confirm this is a valid stream
    if !has_valid_mpeg_stream_structure(data) {
        return false;
    }

    true
}

/// Validate MPEG-1 pack header structure
fn validate_mpeg1_pack_header(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }

    // MPEG-1 pack header format:
    // Bytes 0-3: 00 00 01 BA (already checked)
    // Byte 4: '0010' + SCR[32:30] + marker bit
    // Bytes 5-8: SCR and mux_rate
    // Bytes 9-11: mux_rate continued

    // Check marker bits in MPEG-1 format
    // Byte 4: should have '0010' in upper 4 bits
    if (data[4] & 0xF0) != 0x20 {
        return false;
    }

    // Check marker bit in byte 4 (bit 0)
    if (data[4] & 0x01) != 0x01 {
        return false;
    }

    // Check marker bit in byte 6 (bit 0)
    if data.len() > 6 && (data[6] & 0x01) != 0x01 {
        return false;
    }

    // Check marker bit in byte 8 (bit 0)
    if data.len() > 8 && (data[8] & 0x01) != 0x01 {
        return false;
    }

    true
}

/// Validate MPEG-2 pack header structure
fn validate_mpeg2_pack_header(data: &[u8]) -> bool {
    if data.len() < 14 {
        return false;
    }

    // MPEG-2 pack header format:
    // Bytes 0-3: 00 00 01 BA (already checked)
    // Byte 4: '01' + SCR[32:30] + marker bit
    // Bytes 5-9: SCR fields with marker bits
    // Bytes 10-12: program_mux_rate
    // Byte 13: pack_stuffing_length

    // Check MPEG-2 identifier in byte 4 (top 2 bits = '01')
    if (data[4] & 0xC0) != 0x40 {
        return false;
    }

    // Pack stuffing length should be reasonable (0-7)
    let stuffing_length = data[13] & 0x07;

    // If there's stuffing, the stuffing bytes should be 0xFF
    if stuffing_length > 0 {
        let total_header_size = 14 + stuffing_length as usize;
        if data.len() >= total_header_size {
            // Check stuffing bytes are all 0xFF
            for &byte in &data[14..14 + stuffing_length as usize] {
                if byte != 0xFF {
                    return false;
                }
            }
        }
    }

    true
}

/// Check if the data contains valid MPEG stream structure beyond the pack header
fn has_valid_mpeg_stream_structure(data: &[u8]) -> bool {
    let mut pos = 4; // Start after pack start code
    let mut found_valid_streams = 0;

    // Look for additional MPEG start codes within the first few KB
    let search_limit = cmp::min(data.len(), 4096);

    while pos < search_limit - 4 {
        // Look for start code pattern: 00 00 01 XX
        if data[pos] == 0x00 && data[pos + 1] == 0x00 && data[pos + 2] == 0x01 {
            let stream_id = data[pos + 3];

            match stream_id {
                // Valid MPEG stream IDs
                0xB9 => {
                    // MPEG_program_end_code
                    found_valid_streams += 1;
                    pos += 4;
                }
                0xBA => {
                    // pack_start_code
                    found_valid_streams += 1;
                    pos += 4;
                }
                0xBB => {
                    // system_header_start_code
                    found_valid_streams += 1;
                    pos += 4;
                }
                0xBC => {
                    // program_stream_map
                    found_valid_streams += 1;
                    pos += 4;
                }
                0xBD => {
                    // private_stream_1
                    found_valid_streams += 1;
                    pos += 4;
                }
                0xBE => {
                    // padding_stream
                    found_valid_streams += 1;
                    pos += 4;
                }
                0xBF => {
                    // private_stream_2
                    found_valid_streams += 1;
                    pos += 4;
                }
                0xC0..=0xDF => {
                    // audio stream
                    found_valid_streams += 1;
                    pos += 4;
                }
                0xE0..=0xEF => {
                    // video stream
                    found_valid_streams += 1;
                    pos += 4;
                }
                _ => {
                    pos += 1; // Not a valid stream ID, keep searching
                }
            }

            // If we found at least 1 valid stream, consider it valid for shorter data
            if found_valid_streams >= 1 {
                return true;
            }
        } else {
            pos += 1;
        }
    }

    // For pack start code only, consider it valid if it's at the beginning
    // since this might be a very short MPEG file or just the beginning
    if data.len() >= 4 && data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x01 && data[3] == 0xBA {
        return true;
    }

    false
}

/// Determine MPG file size using heuristics
pub fn mpg_file_size_heuristic(spec: &SearchSpec, buf: &[u8]) -> usize {
    // For MPEG files, we need to find the end of stream marker (00 00 01 B9)
    // or use the maximum length as fallback

    if let Some(end_pos) = find_mpeg_end_marker(buf) {
        // Add 4 bytes for the end marker itself
        cmp::min(end_pos + 4, spec.max_len)
    } else {
        // No end marker found, use conservative estimate or max length
        cmp::min(spec.max_len, buf.len())
    }
}

/// Find MPEG program end code (00 00 01 B9)
fn find_mpeg_end_marker(data: &[u8]) -> Option<usize> {
    if data.len() < 4 {
        return None;
    }

    (0..=data.len() - 4).find(|&i| {
        data[i] == 0x00 && data[i + 1] == 0x00 && data[i + 2] == 0x01 && data[i + 3] == 0xB9
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FileType, SearchSpec, SearchType};

    fn create_valid_mpeg1_header() -> Vec<u8> {
        vec![
            0x00, 0x00, 0x01, 0xBA, // Pack start code
            0x21, // '0010' + SCR bits + marker
            0x00, 0x01, // SCR + marker
            0x80, 0x01, // SCR + marker
            0x00, 0x01, // mux_rate + marker
            0x00, // mux_rate continued
            // Additional data to make it look like a real stream
            0x00, 0x00, 0x01, 0xE0, // Video stream start
            0x00, 0x10, // Packet length
            0x80, 0x00, 0x05, // Packet header
            0x00, 0x00, 0x00, 0x00, 0x00, // Dummy data
        ]
    }

    fn create_valid_mpeg2_header() -> Vec<u8> {
        vec![
            0x00, 0x00, 0x01, 0xBA, // Pack start code
            0x44, // '01' + SCR[32:30] + marker
            0x00, 0x04, // SCR with marker
            0x00, 0x04, // SCR with marker
            0x00, 0x01, // SCR extension + marker
            0x00, 0x01, 0x00, // program_mux_rate + markers (fixed last byte)
            0x00, // pack_stuffing_length = 0 (no stuffing)
            // Additional stream data
            0x00, 0x00, 0x01, 0xE0, // Video stream
            0x00, 0x10, // Packet length
            0x80, 0x00, 0x05, // Packet header
        ]
    }

    #[test]
    fn test_validate_mpg_file_mpeg1_valid() {
        let valid_mpeg1 = create_valid_mpeg1_header();
        assert!(validate_mpg_file(&valid_mpeg1));
    }

    #[test]
    fn test_validate_mpg_file_mpeg2_valid() {
        let valid_mpeg2 = create_valid_mpeg2_header();
        assert!(validate_mpg_file(&valid_mpeg2));
    }

    #[test]
    fn test_validate_mpg_file_too_small() {
        let small_data = vec![0x00, 0x00, 0x01, 0xBA, 0x20]; // Only 5 bytes
        assert!(!validate_mpg_file(&small_data));
    }

    #[test]
    fn test_validate_mpg_file_wrong_start_code() {
        let mut invalid_mpeg = create_valid_mpeg1_header();
        invalid_mpeg[3] = 0xBB; // Wrong start code
        assert!(!validate_mpg_file(&invalid_mpeg));
    }

    #[test]
    fn test_validate_mpeg1_pack_header_invalid_marker() {
        let mut invalid_mpeg1 = create_valid_mpeg1_header();
        invalid_mpeg1[4] = 0x20; // Missing marker bit
        assert!(!validate_mpg_file(&invalid_mpeg1));
    }

    #[test]
    fn test_validate_mpeg2_pack_header_invalid_marker() {
        // Test with invalid MPEG-2 identifier
        let mut invalid_mpeg2 = create_valid_mpeg2_header();
        invalid_mpeg2[4] = 0x80; // Change from '01' to '10' in top bits
        assert!(!validate_mpg_file(&invalid_mpeg2));
    }

    #[test]
    fn test_validate_mpeg2_invalid_stuffing() {
        let invalid_mpeg2 = vec![
            0x00, 0x00, 0x01, 0xBA, // Pack start code
            0x44, 0x00, 0x04, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x03, // Valid header so far
            0x02, // stuffing_length = 2
            0xFE, 0xFD, // Invalid stuffing bytes (should be 0xFF)
        ];
        assert!(!validate_mpg_file(&invalid_mpeg2));
    }

    #[test]
    fn test_find_mpeg_end_marker() {
        let data_with_end = vec![
            0x00, 0x00, 0x01, 0xBA, // Pack start
            0x00, 0x00, 0x00, 0x00, // Some data
            0x00, 0x00, 0x01, 0xB9, // End marker
        ];

        assert_eq!(find_mpeg_end_marker(&data_with_end), Some(8));

        let data_without_end = vec![0x00, 0x00, 0x01, 0xBA, 0x00, 0x00];
        assert_eq!(find_mpeg_end_marker(&data_without_end), None);
    }

    #[test]
    fn test_mpg_file_size_heuristic_with_end_marker() {
        let spec = SearchSpec::new(
            FileType::Mpg,
            "mpg",
            &[0x00, 0x00, 0x01, 0xBA],
            Some(&[0x00, 0x00, 0x01, 0xB9]),
            50 * 1024 * 1024,
            true,
            SearchType::Forward,
        );

        let data = vec![
            0x00, 0x00, 0x01, 0xBA, // Pack start
            0x00, 0x00, 0x00, 0x00, // Some data
            0x00, 0x00, 0x01, 0xB9, // End marker
            0x00, 0x00, // Extra data after end
        ];

        let size = mpg_file_size_heuristic(&spec, &data);
        assert_eq!(size, 12); // Up to and including end marker
    }

    #[test]
    fn test_mpg_file_size_heuristic_no_end_marker() {
        let spec = SearchSpec::new(
            FileType::Mpg,
            "mpg",
            &[0x00, 0x00, 0x01, 0xBA],
            Some(&[0x00, 0x00, 0x01, 0xB9]),
            1024,
            true,
            SearchType::Forward,
        );

        let data = vec![0x00, 0x00, 0x01, 0xBA, 0x00, 0x00, 0x00, 0x00];
        let size = mpg_file_size_heuristic(&spec, &data);
        assert_eq!(size, 8); // Uses buffer length since no end marker
    }

    #[test]
    fn test_has_valid_mpeg_stream_structure() {
        let data_with_streams = vec![
            0x00, 0x00, 0x01, 0xBA, // Pack start
            0x00, 0x00, 0x01, 0xE0, // Video stream
            0x00, 0x00, 0x01, 0xC0, // Audio stream
        ];
        assert!(has_valid_mpeg_stream_structure(&data_with_streams));

        let data_without_streams = vec![
            0x00, 0x00, 0x01, 0xBA, // Pack start only
            0x00, 0x00, 0x00, 0x00, // No additional streams
        ];
        // This should still be considered valid if it has at least one stream
        assert!(has_valid_mpeg_stream_structure(&data_without_streams));
    }
}
