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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_gif_zero_width() {
        // GIF89a header + width=0 (little-endian) + height=100 (little-endian)
        let mut buf = vec![0u8; 10];
        buf[0..6].copy_from_slice(b"GIF89a");
        buf[6..8].copy_from_slice(&0u16.to_le_bytes()); // width = 0
        buf[8..10].copy_from_slice(&100u16.to_le_bytes()); // height = 100
        assert!(!validate_gif_file(&buf));
    }

    #[test]
    fn test_validate_gif_zero_height() {
        // GIF89a header + width=100 (little-endian) + height=0 (little-endian)
        let mut buf = vec![0u8; 10];
        buf[0..6].copy_from_slice(b"GIF89a");
        buf[6..8].copy_from_slice(&100u16.to_le_bytes()); // width = 100
        buf[8..10].copy_from_slice(&0u16.to_le_bytes()); // height = 0
        assert!(!validate_gif_file(&buf));
    }
}
