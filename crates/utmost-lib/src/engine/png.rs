/// Validate a PNG file candidate.
///
/// Checks the 8-byte magic, that the first chunk is a well-formed IHDR
/// (13-byte length), and that the image dimensions are plausible.
pub fn validate_png_file(data: &[u8]) -> bool {
    // Need at least: 8 magic + 4 length + 4 IHDR + 13 data = 29 bytes
    if data.len() < 29 {
        return false;
    }

    let magic: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    if data[..8] != magic {
        return false;
    }

    // Bytes 8-11: IHDR chunk data length (must be exactly 13)
    let ihdr_len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    if ihdr_len != 13 {
        return false;
    }

    // Bytes 12-15: chunk type must be "IHDR"
    if &data[12..16] != b"IHDR" {
        return false;
    }

    // Bytes 16-19: image width (big-endian u32), must be 1..=99_999
    let width = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
    // Bytes 20-23: image height (big-endian u32), must be 1..=99_999
    let height = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);

    width > 0 && width < 100_000 && height > 0 && height < 100_000
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to build a valid PNG header with configurable width and height
    fn build_png_header(width: u32, height: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 29];
        // PNG magic
        buf[0..8].copy_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        // IHDR chunk length (13 bytes)
        buf[8..12].copy_from_slice(&[0u8, 0u8, 0u8, 13u8]);
        // IHDR chunk type
        buf[12..16].copy_from_slice(b"IHDR");
        // Width (big-endian u32)
        buf[16..20].copy_from_slice(&width.to_be_bytes());
        // Height (big-endian u32)
        buf[20..24].copy_from_slice(&height.to_be_bytes());
        buf
    }

    #[test]
    fn test_validate_png_valid() {
        let buf = build_png_header(100, 200);
        assert!(validate_png_file(&buf));
    }

    #[test]
    fn test_validate_png_too_short() {
        let buf = vec![0u8; 28];
        assert!(!validate_png_file(&buf));
    }

    #[test]
    fn test_validate_png_bad_magic() {
        let mut buf = build_png_header(100, 200);
        buf[0] = 0x00; // Corrupt first byte of magic
        assert!(!validate_png_file(&buf));
    }

    #[test]
    fn test_validate_png_bad_ihdr_length() {
        let mut buf = build_png_header(100, 200);
        buf[8..12].copy_from_slice(&[0u8, 0u8, 0u8, 12u8]); // Wrong length (12 instead of 13)
        assert!(!validate_png_file(&buf));
    }

    #[test]
    fn test_validate_png_bad_ihdr_type() {
        let mut buf = build_png_header(100, 200);
        buf[12..16].copy_from_slice(b"IDAT"); // Wrong chunk type
        assert!(!validate_png_file(&buf));
    }

    #[test]
    fn test_validate_png_zero_width() {
        let buf = build_png_header(0, 200); // Width = 0
        assert!(!validate_png_file(&buf));
    }

    #[test]
    fn test_validate_png_zero_height() {
        let buf = build_png_header(100, 0); // Height = 0
        assert!(!validate_png_file(&buf));
    }

    #[test]
    fn test_validate_png_huge_dimensions() {
        let mut buf = build_png_header(100_000, 200);
        assert!(!validate_png_file(&buf));
        // also test huge height
        buf = build_png_header(100, 100_000);
        assert!(!validate_png_file(&buf));
    }
}
