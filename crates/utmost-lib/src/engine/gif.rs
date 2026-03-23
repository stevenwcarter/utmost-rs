/// Validate a GIF file candidate.
///
/// Checks that the file starts with a GIF87a or GIF89a header and that
/// the canvas dimensions are non-zero.
pub fn validate_gif_file(data: &[u8]) -> bool {
    // Need at least 10 bytes: 6 header + 2 width + 2 height
    if data.len() < 10 {
        return false;
    }

    // First 6 bytes must be "GIF87a" or "GIF89a"
    if &data[..6] != b"GIF87a" && &data[..6] != b"GIF89a" {
        return false;
    }

    // Bytes 6-7: canvas width (little-endian u16), must be > 0
    let width = u16::from_le_bytes([data[6], data[7]]);
    // Bytes 8-9: canvas height (little-endian u16), must be > 0
    let height = u16::from_le_bytes([data[8], data[9]]);

    width > 0 && height > 0
}
