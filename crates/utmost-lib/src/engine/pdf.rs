use std::cmp;

use tracing::debug;

use crate::engine::{find_first_pattern, find_last_pattern};
use crate::types::CONSERVATIVE_FALLBACK_SIZE;

/// Determine the actual size of a PDF file by finding the last %%EOF marker
/// and validating the xref table structure
pub fn determine_pdf_file_size(buf: &[u8], max_len: usize) -> usize {
    // PDF file structure:
    // - Header: %PDF-1.x
    // - Body: objects, streams, etc.
    // - Cross-reference table (xref)
    // - Trailer (contains startxref)
    // - %%EOF marker

    // PDFs can have incremental updates, so we need to find the LAST %%EOF
    let eof_marker = b"%%EOF";

    if let Some(eof_pos) = find_last_pattern(buf, eof_marker) {
        debug!("PDF: Found last %%EOF at position {}", eof_pos);

        // Found the last %%EOF, now validate the PDF structure
        if validate_pdf_structure(&buf[..eof_pos + eof_marker.len()]) {
            let pdf_end = eof_pos + eof_marker.len();

            // Skip any trailing whitespace after %%EOF
            let mut actual_end = pdf_end;
            while actual_end < buf.len()
                && (buf[actual_end] == b'\r'
                    || buf[actual_end] == b'\n'
                    || buf[actual_end] == b' '
                    || buf[actual_end] == b'\t')
            {
                actual_end += 1;
            }

            debug!("PDF: Using last %%EOF, file size: {}", actual_end);
            return cmp::min(actual_end, max_len);
        } else {
            debug!("PDF: Last %%EOF failed validation, falling back");
        }
    }

    // Fallback: search for the first %%EOF if validation fails
    if let Some(first_eof_pos) = find_first_pattern(buf, eof_marker) {
        let pdf_end = first_eof_pos + eof_marker.len();
        debug!("PDF: Using first %%EOF fallback, file size: {}", pdf_end);
        cmp::min(pdf_end, max_len)
    } else {
        // No %%EOF found, use conservative estimate
        debug!("PDF: No %%EOF found, using conservative estimate");
        cmp::min(CONSERVATIVE_FALLBACK_SIZE, cmp::min(max_len, buf.len()))
    }
}

/// Validate PDF structure by checking for startxref and xref table
fn validate_pdf_structure(buf: &[u8]) -> bool {
    // Look for "startxref" followed by a number and %%EOF
    let startxref_pattern = b"startxref";

    if let Some(startxref_pos) = find_last_pattern(buf, startxref_pattern) {
        debug!("PDF: Found startxref at position {}", startxref_pos);

        // Parse the offset after startxref
        let after_startxref = startxref_pos + startxref_pattern.len();
        if let Some(xref_offset) = parse_pdf_number(&buf[after_startxref..]) {
            debug!("PDF: startxref points to offset {}", xref_offset);

            // Be more lenient with xref validation - check a wider range around the offset
            for offset_adjustment in [0isize, -10, -20, -50, 10, 20, 50] {
                let adjusted_offset = xref_offset as isize + offset_adjustment;
                if adjusted_offset >= 0 && (adjusted_offset as usize) < buf.len() {
                    let xref_valid = validate_pdf_xref_table(&buf[adjusted_offset as usize..]);
                    if xref_valid {
                        debug!(
                            "PDF: xref table found with offset adjustment {}",
                            offset_adjustment
                        );
                        return true;
                    }
                }
            }
            debug!("PDF: No valid xref table found at any adjusted offset");
        } else {
            debug!("PDF: Could not parse startxref offset");
        }
    } else {
        debug!("PDF: No startxref found");
    }

    // If we can't find or validate startxref, require more-specific PDF markers
    // to reduce false positives. "obj" alone is too common in binary data.
    let has_basic_markers = find_first_pattern(buf, b"/Length").is_some()
        || find_first_pattern(buf, b"endobj").is_some();

    let has_trailer = find_first_pattern(buf, b"trailer").is_some();
    let has_startxref = find_first_pattern(buf, startxref_pattern).is_some();

    // Accept if we have basic PDF structure components
    let is_valid = has_basic_markers && (has_trailer || has_startxref);
    debug!(
        "PDF: Basic validation - markers: {}, trailer: {}, startxref: {}, result: {}",
        has_basic_markers, has_trailer, has_startxref, is_valid
    );
    is_valid
}

/// Parse a PDF number (integer) from buffer, skipping whitespace
fn parse_pdf_number(buf: &[u8]) -> Option<usize> {
    let mut i = 0;

    // Skip whitespace
    while i < buf.len() && (buf[i] == b' ' || buf[i] == b'\t' || buf[i] == b'\r' || buf[i] == b'\n')
    {
        i += 1;
    }

    // Parse decimal number
    let mut num = 0usize;
    let mut found_digit = false;

    while i < buf.len() && buf[i].is_ascii_digit() {
        if let Some(new_num) = num
            .checked_mul(10)
            .and_then(|n| n.checked_add((buf[i] - b'0') as usize))
        {
            num = new_num;
            found_digit = true;
            i += 1;
        } else {
            // Overflow, return None
            return None;
        }
    }

    if found_digit { Some(num) } else { None }
}

/// Validate that there's a valid xref table at the given offset
fn validate_pdf_xref_table(buf: &[u8]) -> bool {
    debug!(
        "PDF: Validating xref table, buffer starts with: {:?}",
        String::from_utf8_lossy(&buf[..cmp::min(20, buf.len())])
    );

    // Look for "xref" at the beginning
    let xref_pattern = b"xref";

    // Skip whitespace before xref
    let mut i = 0;
    while i < buf.len() && (buf[i] == b' ' || buf[i] == b'\t' || buf[i] == b'\r' || buf[i] == b'\n')
    {
        i += 1;
    }

    if i + xref_pattern.len() <= buf.len() && buf[i..i + xref_pattern.len()] == *xref_pattern {
        debug!("PDF: Found 'xref' keyword");
        return true;
    }

    // Alternative: look for trailer without xref (for compressed xref streams)
    let trailer_pattern = b"trailer";
    if buf.len() >= trailer_pattern.len() && buf.starts_with(trailer_pattern) {
        debug!("PDF: Found 'trailer' keyword");
        return true;
    }

    // Also check for xref stream objects (newer PDF format)
    if find_first_pattern(buf, b"/Type/XRef").is_some()
        || find_first_pattern(buf, b"/Type /XRef").is_some()
    {
        debug!("PDF: Found xref stream object");
        return true;
    }

    debug!("PDF: No valid xref table found");
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── determine_pdf_file_size ──────────────────────────────────────────────

    #[test]
    fn test_determine_pdf_file_size_with_valid_structure() {
        // %PDF-1.4\n  (9 bytes, offsets 0..8)
        // xref\n0 1\n (at offset 9)
        // 0000000000 65535 f\n
        // startxref\n9\n%%EOF\n
        let mut buf = Vec::new();
        buf.extend_from_slice(b"%PDF-1.4\n"); // 9 bytes
        buf.extend_from_slice(b"xref\n0 1\n");
        buf.extend_from_slice(b"0000000000 65535 f\n");
        buf.extend_from_slice(b"startxref\n9\n%%EOF\n");

        let size = determine_pdf_file_size(&buf, buf.len());
        assert_eq!(size, buf.len());
    }

    #[test]
    fn test_determine_pdf_file_size_no_eof() {
        let buf = b"%PDF-1.4\nsome content without eof marker";
        let size = determine_pdf_file_size(buf, buf.len());
        assert_eq!(size, cmp::min(CONSERVATIVE_FALLBACK_SIZE, buf.len()));
    }

    #[test]
    fn test_determine_pdf_file_size_first_eof_fallback() {
        // Has %%EOF but no valid PDF structure (no startxref, /Length, endobj, or trailer)
        let buf = b"%PDF-1.4\nsome random content%%EOFmore";
        let eof_pos = buf.windows(5).position(|w| w == b"%%EOF").unwrap();
        let expected = eof_pos + 5; // "%%EOF".len()
        let size = determine_pdf_file_size(buf, buf.len());
        assert_eq!(size, expected);
    }

    // ── validate_pdf_structure ───────────────────────────────────────────────

    #[test]
    fn test_validate_pdf_structure_with_startxref_and_xref() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"%PDF-1.4\n"); // 9 bytes
        buf.extend_from_slice(b"xref\n0 1\n");
        buf.extend_from_slice(b"0000000000 65535 f\n");
        buf.extend_from_slice(b"startxref\n9\n%%EOF\n");

        assert!(validate_pdf_structure(&buf));
    }

    #[test]
    fn test_validate_pdf_structure_basic_markers_only() {
        // No startxref, but has /Length and trailer → basic markers path
        let buf = b"/Length 100\ntrailer\n<<>>\n";
        assert!(validate_pdf_structure(buf));
    }

    #[test]
    fn test_validate_pdf_structure_no_markers() {
        let buf = b"hello world foobar";
        assert!(!validate_pdf_structure(buf));
    }

    // ── parse_pdf_number ─────────────────────────────────────────────────────

    #[test]
    fn test_parse_pdf_number_valid() {
        assert_eq!(parse_pdf_number(b"  12345\n"), Some(12345));
    }

    #[test]
    fn test_parse_pdf_number_leading_whitespace() {
        assert_eq!(parse_pdf_number(b"\t\r\n42"), Some(42));
    }

    #[test]
    fn test_parse_pdf_number_no_digits() {
        assert_eq!(parse_pdf_number(b"abc"), None);
    }

    #[test]
    fn test_parse_pdf_number_empty() {
        assert_eq!(parse_pdf_number(b""), None);
    }

    #[test]
    fn test_parse_pdf_number_overflow() {
        // Number too large to fit in usize → None
        let huge = b"999999999999999999999999999999999999999999";
        assert_eq!(parse_pdf_number(huge), None);
    }

    // ── validate_pdf_xref_table ──────────────────────────────────────────────

    #[test]
    fn test_validate_pdf_xref_table_xref_keyword() {
        assert!(validate_pdf_xref_table(b"xref\n0 1\n"));
    }

    #[test]
    fn test_validate_pdf_xref_table_trailer_keyword() {
        assert!(validate_pdf_xref_table(b"trailer\n"));
    }

    #[test]
    fn test_validate_pdf_xref_table_xref_stream() {
        let buf = b"1 0 obj\n<<\n/Type/XRef\n/Size 10\n>>\nstream\n";
        assert!(validate_pdf_xref_table(buf));
    }

    #[test]
    fn test_validate_pdf_xref_table_no_match() {
        assert!(!validate_pdf_xref_table(b"random data here"));
    }
}
