use super::find_first_pattern;
use std::cmp;

/// Rich result from a JPEG structure analysis pass.
#[allow(dead_code)]
pub struct JpegScanResult {
    /// Offset of the FFD9 (EOI) byte pair relative to `buf` start, if found.
    pub end_offset: Option<usize>,
    /// Offset within `buf` where compressed scan data begins (after the SOS
    /// segment header).  Zero when the SOS marker was not reached.
    pub scan_data_start: usize,
    /// Offset within `buf` where an unexpected marker was encountered inside
    /// scan data, suggesting a fragmentation boundary.  `None` when the scan
    /// data either ended cleanly (EOI found) or was simply truncated at the
    /// buffer edge with no anomalous marker.
    pub fragmentation_point: Option<usize>,
    /// Image width in pixels from the SOF marker, if parsed.
    pub sof_width: Option<u16>,
    /// Image height in pixels from the SOF marker, if parsed.
    pub sof_height: Option<u16>,
    /// Whether any RST0–RST7 restart markers were observed in the scan data.
    pub has_restart_markers: bool,
}

/// Analyse a JPEG buffer and return rich structural metadata alongside the
/// location of the EOI marker.
///
/// Parses the JPEG segment chain (APP, DQT, DHT, SOF, SOS …), extracts image
/// dimensions and table presence flags, then walks the compressed scan data
/// byte-by-byte to detect the EOI, restart markers, and potential
/// fragmentation boundaries.
pub fn analyze_jpeg(buf: &[u8], max_len: usize) -> JpegScanResult {
    let search_limit = cmp::min(max_len, buf.len());
    let footer = &[0xFF_u8, 0xD9];

    // Helper that builds a minimal result using simple footer search.
    let simple = |sof_width, sof_height| JpegScanResult {
        end_offset: find_first_pattern(&buf[..search_limit], footer),
        scan_data_start: 0,
        fragmentation_point: None,
        sof_width,
        sof_height,
        has_restart_markers: false,
    };

    if buf.len() < 10 {
        return simple(None, None);
    }

    // SOI must be FF D8 FF
    if buf[0] != 0xFF || buf[1] != 0xD8 || buf[2] != 0xFF {
        return JpegScanResult {
            end_offset: None,
            scan_data_start: 0,
            fragmentation_point: None,
            sof_width: None,
            sof_height: None,
            has_restart_markers: false,
        };
    }

    // Only attempt full structural parsing for JFIF (E0) and EXIF (E1) headers.
    if buf[3] != 0xE0 && buf[3] != 0xE1 {
        return simple(None, None);
    }

    let mut pos = 2; // start after FF D8
    let mut has_quantization_table = false;
    let mut has_huffman_table = false;
    let mut sof_width: Option<u16> = None;
    let mut sof_height: Option<u16> = None;
    let mut found_sos = false;

    // ── Walk JPEG segment chain ──────────────────────────────────────────────
    'segments: loop {
        // Need at least FF + marker byte
        if pos + 2 > search_limit {
            break;
        }
        if buf[pos] != 0xFF {
            break; // reached raw image data without SOS — unusual, stop
        }

        // Skip padding FF bytes
        while pos + 1 < search_limit && buf[pos + 1] == 0xFF {
            pos += 1;
        }
        if pos + 2 > search_limit {
            break;
        }

        let marker = buf[pos + 1];
        pos += 2; // advance past FF + marker

        match marker {
            0xD8 => continue, // SOI inside stream — skip
            0xD9 => break,    // EOI before scan data — treat as empty file

            0xDA => {
                // SOS: read the SOS segment header length, then leave `pos`
                // pointing at the start of the compressed scan data.
                found_sos = true;
                if pos + 2 > buf.len() {
                    break;
                }
                let seg_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
                if seg_len < 2 {
                    break;
                }
                pos += seg_len; // skip over the SOS header (component selectors etc.)
                break 'segments; // pos now = start of scan data
            }

            _ => {
                // All other markers carry a big-endian length field immediately
                // after the marker byte.
                if pos + 2 > buf.len() {
                    break;
                }
                let seg_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
                if seg_len < 2 || pos + seg_len > buf.len() {
                    break;
                }

                match marker {
                    0xDB => has_quantization_table = true,
                    0xC4 => has_huffman_table = true,
                    // SOF0 (baseline), SOF1 (extended sequential), SOF2 (progressive)
                    0xC0..=0xC2 => {
                        // Layout after FF Cx [len_hi len_lo]:
                        //   [precision 1B] [height 2B] [width 2B] …
                        // `pos` currently points at len_hi.
                        if pos + 7 <= buf.len() {
                            let h = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]);
                            let w = u16::from_be_bytes([buf[pos + 5], buf[pos + 6]]);
                            if w > 0 && h > 0 {
                                sof_height = Some(h);
                                sof_width = Some(w);
                            }
                        }
                    }
                    _ => {}
                }

                pos += seg_len; // skip past this segment
            }
        }
    }

    let scan_data_start = pos;

    // Fall back to simple footer search when required tables are absent.
    if !has_quantization_table || !has_huffman_table {
        return JpegScanResult {
            end_offset: find_first_pattern(&buf[..search_limit], footer),
            scan_data_start,
            fragmentation_point: None,
            sof_width,
            sof_height,
            has_restart_markers: false,
        };
    }

    if !found_sos || scan_data_start >= search_limit {
        // No SOS found (or nothing left to scan): fall back to a simple footer
        // search from wherever we stopped in the segment chain.  This handles
        // minimal / truncated test fixtures that lack a formal SOS segment but
        // still contain an EOI.
        let end_offset = if scan_data_start < search_limit {
            let tail = &buf[scan_data_start..search_limit];
            find_first_pattern(tail, footer).map(|p| scan_data_start + p)
        } else {
            None
        };
        return JpegScanResult {
            end_offset,
            scan_data_start,
            fragmentation_point: None,
            sof_width,
            sof_height,
            has_restart_markers: false,
        };
    }

    // ── Walk compressed scan data ────────────────────────────────────────────
    let mut scan_pos = scan_data_start;
    let mut has_restart_markers = false;
    let mut fragmentation_point: Option<usize> = None;

    while scan_pos < search_limit {
        if buf[scan_pos] == 0xFF && scan_pos + 1 < search_limit {
            match buf[scan_pos + 1] {
                0x00 => {
                    // Byte-stuffed FF — normal inside compressed data
                    scan_pos += 2;
                }
                0xD0..=0xD7 => {
                    // RST0–RST7 restart markers — normal inside compressed data
                    has_restart_markers = true;
                    scan_pos += 2;
                }
                0xD9 => {
                    // EOI — clean end of image
                    return JpegScanResult {
                        end_offset: Some(scan_pos),
                        scan_data_start,
                        fragmentation_point: None,
                        sof_width,
                        sof_height,
                        has_restart_markers,
                    };
                }
                _ => {
                    // Any other FF XX inside scan data is unexpected and suggests
                    // a fragmentation boundary or corruption.
                    fragmentation_point = Some(scan_pos);
                    break;
                }
            }
        } else {
            scan_pos += 1;
        }
    }

    JpegScanResult {
        end_offset: None,
        scan_data_start,
        fragmentation_point,
        sof_width,
        sof_height,
        has_restart_markers,
    }
}

/// Find the appropriate JPEG end marker (FF D9) for this JPEG file.
///
/// Thin wrapper around [`analyze_jpeg`] kept for call sites that only need the
/// EOI offset.
#[allow(dead_code)]
pub fn find_jpeg_end_marker(buf: &[u8], max_len: usize) -> Option<usize> {
    analyze_jpeg(buf, max_len).end_offset
}

/// Estimate a plausible upper-bound file size for a JPEG with the given
/// pixel dimensions.
///
/// Uses 30 % of the uncompressed RGB byte count (`w × h × 3 × 0.30`).
/// Even at the highest JPEG quality settings real compression ratios are
/// well above 3.3×, so this ceiling is generous enough for any genuine
/// image while still preventing multi-megabyte garbage when the actual
/// content is only a few hundred kilobytes.
///
/// Returns `None` when either dimension is zero (no parseable SOF marker).
pub fn max_plausible_jpeg_size(w: u16, h: u16) -> Option<usize> {
    if w == 0 || h == 0 {
        return None;
    }
    let uncompressed = (w as usize) * (h as usize) * 3;
    // 30 % expressed as integer arithmetic: multiply by 3, divide by 10.
    Some(uncompressed * 3 / 10)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────────────

    /// Build a minimal valid JFIF JPEG with the supplied scan data.
    fn build_jfif_jpeg(scan_data: &[u8]) -> Vec<u8> {
        let mut buf = vec![
            0xFF, 0xD8, 0xFF, 0xE0, // SOI + JFIF APP0 marker
            0x00, 0x10, // APP0 segment length = 16
            b'J', b'F', b'I', b'F', 0x00, // identifier
            0x01, 0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00,
        ];
        // DQT
        buf.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43]);
        buf.extend(std::iter::repeat_n(0x10u8, 65));
        // DHT
        buf.extend_from_slice(&[0xFF, 0xC4, 0x00, 0x1F]);
        buf.extend(std::iter::repeat_n(0x00u8, 29));
        // SOF0: precision=8, height=100, width=100, 3 components
        buf.extend_from_slice(&[
            0xFF, 0xC0, 0x00, 0x11, // length = 17
            0x08, // precision
            0x00, 0x64, // height = 100
            0x00, 0x64, // width = 100
            0x03, // components
            0x01, 0x11, 0x00, // component 1
            0x02, 0x11, 0x01, // component 2
            0x03, 0x11, 0x01, // component 3
        ]);
        // SOS header (minimal)
        buf.extend_from_slice(&[
            0xFF, 0xDA, 0x00, 0x08, // length = 8
            0x01, // 1 component
            0x01, 0x00, // component selector
            0x00, 0x3F, 0x00, // Ss, Se, Ah/Al
        ]);
        // compressed scan data
        buf.extend_from_slice(scan_data);
        buf
    }

    // ── analyze_jpeg tests ───────────────────────────────────────────────────

    #[test]
    fn test_analyze_jpeg_complete_jfif() {
        let mut jpeg = build_jfif_jpeg(&[0x12, 0x34, 0x56, 0x78]);
        jpeg.extend_from_slice(&[0xFF, 0xD9]); // EOI

        let result = analyze_jpeg(&jpeg, jpeg.len());
        assert!(result.end_offset.is_some(), "should find EOI");
        let eoi = result.end_offset.unwrap();
        assert_eq!(&jpeg[eoi..eoi + 2], &[0xFF, 0xD9]);
        assert_eq!(result.sof_width, Some(100));
        assert_eq!(result.sof_height, Some(100));
        assert!(!result.has_restart_markers);
        assert!(result.fragmentation_point.is_none());
    }

    #[test]
    fn test_analyze_jpeg_complete_with_restart_markers() {
        let scan = [0x12, 0xFF, 0xD0, 0x34, 0xFF, 0xD1, 0x56]; // RST0 + RST1 in scan data
        let mut jpeg = build_jfif_jpeg(&scan);
        jpeg.extend_from_slice(&[0xFF, 0xD9]);

        let result = analyze_jpeg(&jpeg, jpeg.len());
        assert!(result.end_offset.is_some());
        assert!(result.has_restart_markers);
    }

    #[test]
    fn test_analyze_jpeg_complete_with_stuffed_bytes() {
        let scan = [0x12, 0xFF, 0x00, 0x34]; // FF 00 is a stuffed byte
        let mut jpeg = build_jfif_jpeg(&scan);
        jpeg.extend_from_slice(&[0xFF, 0xD9]);

        let result = analyze_jpeg(&jpeg, jpeg.len());
        assert!(result.end_offset.is_some());
        assert!(!result.has_restart_markers);
    }

    #[test]
    fn test_analyze_jpeg_truncated_no_eoi() {
        let jpeg = build_jfif_jpeg(&[0x12, 0x34, 0x56, 0x78]);
        // No EOI appended

        let result = analyze_jpeg(&jpeg, jpeg.len());
        assert!(result.end_offset.is_none());
        assert!(result.fragmentation_point.is_none()); // truncated, not fragmented
        assert!(result.scan_data_start > 0);
    }

    #[test]
    fn test_analyze_jpeg_fragmented_unexpected_marker() {
        // Scan data that contains a spurious non-RST marker (FF E0 = APP0)
        let scan = [0x12, 0x34, 0xFF, 0xE0, 0x56, 0x78];
        let jpeg = build_jfif_jpeg(&scan);
        // No EOI

        let result = analyze_jpeg(&jpeg, jpeg.len());
        assert!(result.end_offset.is_none());
        assert!(
            result.fragmentation_point.is_some(),
            "should detect fragmentation point"
        );
    }

    #[test]
    fn test_analyze_jpeg_sof_dimensions() {
        let mut jpeg = build_jfif_jpeg(&[0xAB]);
        jpeg.extend_from_slice(&[0xFF, 0xD9]);

        let result = analyze_jpeg(&jpeg, jpeg.len());
        assert_eq!(result.sof_width, Some(100));
        assert_eq!(result.sof_height, Some(100));
    }

    #[test]
    fn test_analyze_jpeg_too_small() {
        let result = analyze_jpeg(&[0xFF, 0xD8, 0xFF], 100);
        assert!(result.end_offset.is_none());
    }

    #[test]
    fn test_analyze_jpeg_invalid_header() {
        let data = vec![0xFF, 0xD8, 0xFF, 0xE2, 0x12, 0x34, 0xFF, 0xD9];
        let result = analyze_jpeg(&data, data.len());
        // Falls back to simple search — should still find the footer
        assert!(result.end_offset.is_some());
        assert_eq!(result.end_offset.unwrap(), 6);
    }

    // ── find_jpeg_end_marker compatibility tests (original test-suite) ────────

    #[test]
    fn test_find_jpeg_end_marker_valid_jfif() {
        let mut jpeg_data = vec![
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00, 0x01, 0x01, 0x01,
            0x00, 0x48, 0x00, 0x48, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43,
        ];
        jpeg_data.extend(vec![0x00; 65]);
        jpeg_data.extend_from_slice(&[0xFF, 0xC4, 0x00, 0x1F]);
        jpeg_data.extend(vec![0x00; 29]);
        jpeg_data.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        jpeg_data.extend_from_slice(&[0xFF, 0xD9]);

        let result = find_jpeg_end_marker(&jpeg_data, jpeg_data.len());
        assert!(result.is_some());
        let footer_pos = result.unwrap();
        assert_eq!(&jpeg_data[footer_pos..footer_pos + 2], &[0xFF, 0xD9]);
    }

    #[test]
    fn test_find_jpeg_end_marker_valid_exif() {
        let mut jpeg_data = vec![
            0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x16, b'E', b'x', b'i', b'f', 0x00, 0x00, 0x49, 0x49,
            0x2A, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43,
        ];
        jpeg_data.extend(vec![0x00; 65]);
        jpeg_data.extend_from_slice(&[0xFF, 0xC4, 0x00, 0x1F]);
        jpeg_data.extend(vec![0x00; 29]);
        jpeg_data.extend_from_slice(&[0x12, 0x34]);
        jpeg_data.extend_from_slice(&[0xFF, 0xD9]);

        let result = find_jpeg_end_marker(&jpeg_data, jpeg_data.len());
        assert!(result.is_some());
    }

    #[test]
    fn test_find_jpeg_end_marker_invalid_header() {
        let jpeg_data = vec![0xFF, 0xD8, 0xFF, 0xE2, 0x12, 0x34, 0xFF, 0xD9];
        let result = find_jpeg_end_marker(&jpeg_data, jpeg_data.len());
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 6);
    }

    #[test]
    fn test_find_jpeg_end_marker_too_small() {
        let result = find_jpeg_end_marker(&[0xFF, 0xD8, 0xFF], 100);
        assert!(result.is_none());
    }

    #[test]
    fn test_find_jpeg_end_marker_no_tables() {
        let jpeg_data = vec![
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00, 0x01, 0x01, 0x01,
            0x00, 0x48, 0x00, 0x48, 0x00, 0x00, 0x12, 0x34, 0xFF, 0xD9,
        ];
        let result = find_jpeg_end_marker(&jpeg_data, jpeg_data.len());
        assert!(result.is_some());
        let footer_pos = result.unwrap();
        assert_eq!(&jpeg_data[footer_pos..footer_pos + 2], &[0xFF, 0xD9]);
    }

    #[test]
    fn test_find_jpeg_end_marker_no_footer() {
        let mut jpeg_data = vec![
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00, 0x01, 0x01, 0x01,
            0x00, 0x48, 0x00, 0x48, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43,
        ];
        jpeg_data.extend(vec![0x00; 65]);
        jpeg_data.extend_from_slice(&[0xFF, 0xC4, 0x00, 0x1F]);
        jpeg_data.extend(vec![0x00; 29]);
        jpeg_data.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);

        let result = find_jpeg_end_marker(&jpeg_data, jpeg_data.len());
        assert!(result.is_none());
    }

    #[test]
    fn test_find_first_pattern() {
        let data = b"Hello World\xFF\xD9End";
        let pattern = &[0xFF, 0xD9];
        assert_eq!(find_first_pattern(data, pattern), Some(11));
    }

    #[test]
    fn test_find_first_pattern_not_found() {
        let data = b"Hello World End";
        let pattern = &[0xFF, 0xD9];
        assert_eq!(find_first_pattern(data, pattern), None);
    }

    #[test]
    fn test_find_first_pattern_multiple_occurrences() {
        let data = b"AA\xFF\xD9BB\xFF\xD9CC";
        let pattern = &[0xFF, 0xD9];
        assert_eq!(find_first_pattern(data, pattern), Some(2));
    }

    // ── max_plausible_jpeg_size tests ─────────────────────────────────────────

    #[test]
    fn test_max_plausible_jpeg_size_typical() {
        // 3264x2448 → uncompressed = 23,970,816 bytes → 30% ≈ 7,191,244
        let result = max_plausible_jpeg_size(3264, 2448);
        assert!(result.is_some());
        let cap = result.unwrap();
        // Should be well under the raw uncompressed size
        assert!(cap < 3264 * 2448 * 3);
        // Should be above zero and reasonable
        assert!(cap > 1_000_000, "cap={cap} should be > 1MB for a 8MP image");
        assert!(
            cap < 10_000_000,
            "cap={cap} should be < 10MB for a 8MP image"
        );
    }

    #[test]
    fn test_max_plausible_jpeg_size_zero_width() {
        assert_eq!(max_plausible_jpeg_size(0, 100), None);
    }

    #[test]
    fn test_max_plausible_jpeg_size_zero_height() {
        assert_eq!(max_plausible_jpeg_size(100, 0), None);
    }

    #[test]
    fn test_max_plausible_jpeg_size_small_image() {
        // 100x100 → uncompressed = 30,000 bytes → 30% = 9,000
        let result = max_plausible_jpeg_size(100, 100);
        assert_eq!(result, Some(9_000));
    }
}
