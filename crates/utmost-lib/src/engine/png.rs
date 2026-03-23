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
