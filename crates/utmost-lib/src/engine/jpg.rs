use std::cmp;

/// Find the appropriate JPEG end marker (FF D9) for this JPEG file
/// This implementation parses the JPEG header structure properly to skip embedded content
pub fn find_jpeg_end_marker(buf: &[u8], max_len: usize) -> Option<usize> {
    let footer = &[0xFF, 0xD9];
    let search_limit = cmp::min(max_len, buf.len());
    
    if buf.len() < 10 {
        // For very small buffers, just do a simple footer search
        return find_first_pattern(buf, footer);
    }
    
    // Validate JPEG header format
    if buf.len() < 4 || buf[0] != 0xFF || buf[1] != 0xD8 || buf[2] != 0xFF {
        return None;
    }
    
    // Check for valid JPEG header types (JFIF=0xE0, EXIF=0xE1)
    if buf[3] != 0xE0 && buf[3] != 0xE1 {
        // Invalid JPEG header type, fall back to simple search
        return find_first_pattern(buf, footer);
    }
    
    let mut pos = 2; // Start after FF D8
    let mut has_quantization_table = false;
    let mut has_huffman_table = false;
    
    // Parse through JPEG segments until we reach the image data
    while pos + 4 < search_limit {
        // Check for FF marker
        if buf[pos] != 0xFF {
            break; // No longer in header, reached image data
        }
        
        // Skip consecutive FF bytes
        if buf[pos + 1] == 0xFF {
            pos += 1;
            continue;
        }
        
        let marker = buf[pos + 1];
        
        // Check for important markers
        if marker == 0xDB {
            has_quantization_table = true;
        } else if marker == 0xC4 {
            has_huffman_table = true;
        }
        
        // Skip past the FF marker byte
        pos += 2;
        
        // Check if we have enough bytes for segment length
        if pos + 2 > buf.len() {
            break;
        }
        
        // Read segment length (big-endian)
        let segment_length = ((buf[pos] as u16) << 8) | (buf[pos + 1] as u16);
        
        // Validate segment length
        if segment_length < 2 || pos + segment_length as usize > buf.len() {
            break;
        }
        
        // Skip this segment
        pos += segment_length as usize;
        
        // If the next bytes don't start with FF, we've reached image data
        if pos < buf.len() && buf[pos] != 0xFF {
            break;
        }
    }
    
    // Validate that this is a proper JPEG (must have both tables)
    if !has_quantization_table || !has_huffman_table {
        // Not a valid JPEG, fall back to simple search
        return find_first_pattern(buf, footer);
    }
    
    // Now search for FF D9 from the current position (start of image data)
    let remaining_buf = &buf[pos..];
    find_first_pattern(remaining_buf, footer).map(|footer_pos| pos + footer_pos)
}

/// Find the first occurrence of a pattern in buffer
fn find_first_pattern(buf: &[u8], pattern: &[u8]) -> Option<usize> {
    (0..=buf.len().saturating_sub(pattern.len())).find(|&i| buf[i..i + pattern.len()] == *pattern)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_jpeg_end_marker_valid_jfif() {
        // Create a minimal valid JPEG with JFIF header
        let mut jpeg_data = vec![
            0xFF, 0xD8, 0xFF, 0xE0, // JPEG header with JFIF marker
            0x00, 0x10, // Segment length (16 bytes)
            b'J', b'F', b'I', b'F', 0x00, // JFIF identifier
            0x01, 0x01, // Version
            0x01, // Units
            0x00, 0x48, 0x00, 0x48, // X and Y density
            0x00, 0x00, // Thumbnail width and height
            // Quantization table
            0xFF, 0xDB, // DQT marker
            0x00, 0x43, // Length (67 bytes)
        ];
        
        // Add 65 bytes of quantization table data
        jpeg_data.extend(vec![0x00; 65]);
        
        // Huffman table
        jpeg_data.extend(&[0xFF, 0xC4]); // DHT marker
        jpeg_data.extend(&[0x00, 0x1F]); // Length (31 bytes)
        jpeg_data.extend(vec![0x00; 29]); // Huffman table data
        
        // Image data starts (no more FF markers)
        jpeg_data.extend(&[0x12, 0x34, 0x56, 0x78]);
        
        // JPEG footer
        jpeg_data.extend(&[0xFF, 0xD9]);
        
        let result = find_jpeg_end_marker(&jpeg_data, jpeg_data.len());
        assert!(result.is_some());
        let footer_pos = result.unwrap();
        assert_eq!(&jpeg_data[footer_pos..footer_pos + 2], &[0xFF, 0xD9]);
    }

    #[test]
    fn test_find_jpeg_end_marker_valid_exif() {
        // Create a minimal valid JPEG with EXIF header
        let mut jpeg_data = vec![
            0xFF, 0xD8, 0xFF, 0xE1, // JPEG header with EXIF marker
            0x00, 0x16, // Segment length (22 bytes)
            b'E', b'x', b'i', b'f', 0x00, 0x00, // EXIF identifier
            // TIFF header
            0x49, 0x49, 0x2A, 0x00, // Little-endian TIFF
            0x08, 0x00, 0x00, 0x00, // Offset to first IFD
            0x00, 0x00, 0x00, 0x00, // Padding
            // Quantization table
            0xFF, 0xDB, // DQT marker
            0x00, 0x43, // Length
        ];
        
        // Add quantization table data
        jpeg_data.extend(vec![0x00; 65]);
        
        // Huffman table
        jpeg_data.extend(&[0xFF, 0xC4]); // DHT marker
        jpeg_data.extend(&[0x00, 0x1F]); // Length
        jpeg_data.extend(vec![0x00; 29]); // Huffman table data
        
        // Image data
        jpeg_data.extend(&[0x12, 0x34]);
        
        // Footer
        jpeg_data.extend(&[0xFF, 0xD9]);
        
        let result = find_jpeg_end_marker(&jpeg_data, jpeg_data.len());
        assert!(result.is_some());
    }

    #[test]
    fn test_find_jpeg_end_marker_invalid_header() {
        // Invalid JPEG header (wrong marker)
        let jpeg_data = vec![0xFF, 0xD8, 0xFF, 0xE2, 0x12, 0x34, 0xFF, 0xD9];
        
        let result = find_jpeg_end_marker(&jpeg_data, jpeg_data.len());
        assert!(result.is_some());
        // Should fall back to simple search and find the footer
        assert_eq!(result.unwrap(), 6);
    }

    #[test]
    fn test_find_jpeg_end_marker_too_small() {
        let jpeg_data = vec![0xFF, 0xD8, 0xFF]; // Too small
        
        let result = find_jpeg_end_marker(&jpeg_data, jpeg_data.len());
        assert!(result.is_none());
    }

    #[test]
    fn test_find_jpeg_end_marker_no_tables() {
        // JPEG without required tables
        let jpeg_data = vec![
            0xFF, 0xD8, 0xFF, 0xE0, // JPEG header
            0x00, 0x10, // Segment length
            b'J', b'F', b'I', b'F', 0x00, // JFIF
            0x01, 0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00,
            // No quantization or Huffman tables - should fall back to simple search
            0x12, 0x34, 0xFF, 0xD9,
        ];
        
        let result = find_jpeg_end_marker(&jpeg_data, jpeg_data.len());
        assert!(result.is_some());
        // Should find the footer via fallback
        let footer_pos = result.unwrap();
        assert_eq!(&jpeg_data[footer_pos..footer_pos + 2], &[0xFF, 0xD9]);
    }

    #[test]
    fn test_find_jpeg_end_marker_no_footer() {
        // Valid JPEG structure but no footer
        let mut jpeg_data = vec![
            0xFF, 0xD8, 0xFF, 0xE0, // JPEG header
            0x00, 0x10, // Segment length
            b'J', b'F', b'I', b'F', 0x00, // JFIF
            0x01, 0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00,
            // Quantization table
            0xFF, 0xDB, 0x00, 0x43,
        ];
        jpeg_data.extend(vec![0x00; 65]);
        
        // Huffman table
        jpeg_data.extend(&[0xFF, 0xC4, 0x00, 0x1F]);
        jpeg_data.extend(vec![0x00; 29]);
        
        // Image data but no footer
        jpeg_data.extend(&[0x12, 0x34, 0x56, 0x78]);
        
        let result = find_jpeg_end_marker(&jpeg_data, jpeg_data.len());
        assert!(result.is_none());
    }

    #[test]
    fn test_find_first_pattern() {
        let data = b"Hello World\xFF\xD9End";
        let pattern = &[0xFF, 0xD9];
        
        let result = find_first_pattern(data, pattern);
        assert_eq!(result, Some(11));
    }

    #[test]
    fn test_find_first_pattern_not_found() {
        let data = b"Hello World End";
        let pattern = &[0xFF, 0xD9];
        
        let result = find_first_pattern(data, pattern);
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_first_pattern_multiple_occurrences() {
        let data = b"AA\xFF\xD9BB\xFF\xD9CC";
        let pattern = &[0xFF, 0xD9];
        
        let result = find_first_pattern(data, pattern);
        assert_eq!(result, Some(2)); // Should find the first occurrence
    }
}