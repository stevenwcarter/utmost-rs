use std::cmp;

use crate::{
    SearchSpec,
    types::{Endianness, bytes_to_u16, bytes_to_u32},
};

#[inline(always)]
pub fn bmp_file_size_heuristic(spec: &SearchSpec, buf: &[u8]) -> usize {
    if buf.len() >= 6 {
        let size = bytes_to_u32(&buf[2..6], Endianness::Little);
        cmp::min(size as usize, spec.max_len)
    } else {
        0
    }
}

/// Validate BMP file structure to reduce false positives.
/// Performs comprehensive validation of BMP header fields.
pub fn validate_bmp_file(data: &[u8]) -> bool {
    if data.len() < 54 {
        return false;
    }
    let Some((file_size, pixel_offset)) = check_bmp_file_header(data) else {
        return false;
    };
    if !check_bmp_dib_header(data, file_size, pixel_offset) {
        return false;
    }
    check_bmp_image_params(data, file_size, pixel_offset)
}

/// Validate the 14-byte BMP file header (signature, file size, reserved, pixel offset).
/// Returns `Some((file_size, pixel_data_offset))` on success.
fn check_bmp_file_header(data: &[u8]) -> Option<(usize, usize)> {
    // BM signature (already verified by search, but double-check)
    if data[0] != b'B' || data[1] != b'M' {
        return None;
    }

    // File size (bytes 2-5): must be ≥54 and not exceed the buffer
    let file_size = bytes_to_u32(&data[2..6], Endianness::Little) as usize;
    if file_size < 54 || file_size > data.len() {
        return None;
    }

    // Reserved fields (bytes 6-9) must be zero
    if data[6] != 0 || data[7] != 0 || data[8] != 0 || data[9] != 0 {
        return None;
    }

    // Pixel data offset (bytes 10-13): at least 54, must not exceed file_size
    let pixel_data_offset = bytes_to_u32(&data[10..14], Endianness::Little) as usize;
    if pixel_data_offset < 54 || pixel_data_offset > file_size {
        return None;
    }

    Some((file_size, pixel_data_offset))
}

/// Validate the DIB header (size, dimensions, pixel format, compression).
/// Returns `false` immediately on any constraint violation.
fn check_bmp_dib_header(data: &[u8], _file_size: usize, _pixel_offset: usize) -> bool {
    // DIB header size (bytes 14-17): accepted values per spec
    let dib_header_size = bytes_to_u32(&data[14..18], Endianness::Little);
    match dib_header_size {
        40 | 52 | 56 | 108 | 124 => {}
        _ => return false,
    }

    // All accepted DIB sizes are ≥40, so the BITMAPINFOHEADER fields are always present
    let width = bytes_to_u32(&data[18..22], Endianness::Little);
    let height_raw = bytes_to_u32(&data[22..26], Endianness::Little);

    if width == 0 || width > 65536 {
        return false;
    }

    // Height can be negative (top-down bitmap); check absolute value
    let height = if height_raw > 0x80000000 {
        !(height_raw - 1) // two's complement negate
    } else {
        height_raw
    };
    if height == 0 || height > 65536 {
        return false;
    }

    // Color planes (bytes 26-27) must be 1
    let planes = bytes_to_u16(&data[26..28], Endianness::Little);
    if planes != 1 {
        return false;
    }

    // Bits per pixel (bytes 28-29): only standard values accepted
    let bits_per_pixel = bytes_to_u16(&data[28..30], Endianness::Little);
    match bits_per_pixel {
        1 | 4 | 8 | 16 | 24 | 32 => {}
        _ => return false,
    }

    // Compression method (bytes 30-33):
    // 0=BI_RGB, 1=BI_RLE8, 2=BI_RLE4, 3=BI_BITFIELDS, 4=BI_JPEG, 5=BI_PNG
    let compression = bytes_to_u32(&data[30..34], Endianness::Little);
    if compression > 5 {
        return false;
    }

    // Compression↔bpp compatibility
    match compression {
        1 if bits_per_pixel != 8 => return false, // BI_RLE8 requires 8-bit
        2 if bits_per_pixel != 4 => return false, // BI_RLE4 requires 4-bit
        _ => {}
    }

    true
}

/// Validate image data parameters: size consistency, resolution, palette, and bounds.
fn check_bmp_image_params(data: &[u8], file_size: usize, pixel_data_offset: usize) -> bool {
    let width = bytes_to_u32(&data[18..22], Endianness::Little);
    let height_raw = bytes_to_u32(&data[22..26], Endianness::Little);
    let height = if height_raw > 0x80000000 {
        !(height_raw - 1)
    } else {
        height_raw
    };
    let bits_per_pixel = bytes_to_u16(&data[28..30], Endianness::Little);
    let compression = bytes_to_u32(&data[30..34], Endianness::Little);

    // Image size (bytes 34-37) — may be 0 for uncompressed images
    let image_size = bytes_to_u32(&data[34..38], Endianness::Little);
    if image_size > 0 {
        // Row size aligned to 4-byte boundaries: ((width * bpp + 31) / 32) * 4
        let bits_per_row = width * bits_per_pixel as u32;
        #[allow(clippy::manual_div_ceil)]
        let calculated_row_size = ((bits_per_row + 31) / 32) * 4;
        let expected_size = calculated_row_size * height;

        if compression == 0 && image_size != expected_size {
            return false;
        }
        if pixel_data_offset + image_size as usize > file_size {
            return false;
        }
    }

    // X/Y pixels-per-meter (bytes 38-45): if non-zero must be in 1–1_000_000
    let x_ppm = bytes_to_u32(&data[38..42], Endianness::Little);
    let y_ppm = bytes_to_u32(&data[42..46], Endianness::Little);
    let valid_range = 1..=1_000_000;
    if (x_ppm > 0 && !valid_range.contains(&x_ppm)) || (y_ppm > 0 && !valid_range.contains(&y_ppm))
    {
        return false;
    }

    // Colors used (bytes 46-49): must not exceed palette capacity for the bit depth
    let colors_used = bytes_to_u32(&data[46..50], Endianness::Little);
    if colors_used > 0 {
        let max_colors: u32 = match bits_per_pixel {
            1 => 2,
            4 => 16,
            8 => 256,
            _ => 0, // 16/24/32-bit don't use indexed palettes
        };
        if max_colors > 0 && colors_used > max_colors {
            return false;
        }
    }

    // Important colors (bytes 50-53): must not exceed colors_used
    let important_colors = bytes_to_u32(&data[50..54], Endianness::Little);
    if important_colors > colors_used && colors_used > 0 {
        return false;
    }

    // Final bounds: pixel data offset must be within the buffer
    if pixel_data_offset > data.len() {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FileType, SearchSpec, SearchType};

    fn create_valid_bmp_header() -> Vec<u8> {
        let mut data = vec![0u8; 54];

        // BMP signature
        data[0] = b'B';
        data[1] = b'M';

        // File size (54 bytes header)
        data[2] = 54;
        data[3] = 0;
        data[4] = 0;
        data[5] = 0;

        // Reserved fields (bytes 6-9) = 0
        // Already zeroed

        // Offset to pixel data (54 bytes)
        data[10] = 54;
        data[11] = 0;
        data[12] = 0;
        data[13] = 0;

        // DIB header size (40 bytes - BITMAPINFOHEADER)
        data[14] = 40;
        data[15] = 0;
        data[16] = 0;
        data[17] = 0;

        // Width (100 pixels)
        data[18] = 100;
        data[19] = 0;
        data[20] = 0;
        data[21] = 0;

        // Height (100 pixels)
        data[22] = 100;
        data[23] = 0;
        data[24] = 0;
        data[25] = 0;

        // Color planes (1)
        data[26] = 1;
        data[27] = 0;

        // Bits per pixel (24)
        data[28] = 24;
        data[29] = 0;

        // Compression (0 = no compression)
        data[30] = 0;
        data[31] = 0;
        data[32] = 0;
        data[33] = 0;

        // Image size (0 for uncompressed)
        data[34] = 0;
        data[35] = 0;
        data[36] = 0;
        data[37] = 0;

        // X pixels per meter (2835 = ~72 DPI)
        data[38] = 0x13;
        data[39] = 0x0B;
        data[40] = 0;
        data[41] = 0;

        // Y pixels per meter (2835 = ~72 DPI)
        data[42] = 0x13;
        data[43] = 0x0B;
        data[44] = 0;
        data[45] = 0;

        // Colors used (0)
        data[46] = 0;
        data[47] = 0;
        data[48] = 0;
        data[49] = 0;

        // Important colors (0)
        data[50] = 0;
        data[51] = 0;
        data[52] = 0;
        data[53] = 0;

        data
    }

    #[test]
    fn test_validate_bmp_file_valid() {
        let valid_bmp = create_valid_bmp_header();
        assert!(validate_bmp_file(&valid_bmp));
    }

    #[test]
    fn test_validate_bmp_file_too_small() {
        let small_data = vec![b'B', b'M']; // Only 2 bytes
        assert!(!validate_bmp_file(&small_data));
    }

    #[test]
    fn test_validate_bmp_file_wrong_signature() {
        let mut invalid_bmp = create_valid_bmp_header();
        invalid_bmp[0] = b'X'; // Wrong signature
        assert!(!validate_bmp_file(&invalid_bmp));
    }

    #[test]
    fn test_validate_bmp_file_invalid_file_size() {
        let mut invalid_bmp = create_valid_bmp_header();
        // Set file size to be larger than buffer
        invalid_bmp[2] = 255;
        invalid_bmp[3] = 255;
        invalid_bmp[4] = 255;
        invalid_bmp[5] = 255;
        assert!(!validate_bmp_file(&invalid_bmp));
    }

    #[test]
    fn test_validate_bmp_file_nonzero_reserved() {
        let mut invalid_bmp = create_valid_bmp_header();
        invalid_bmp[6] = 1; // Reserved field should be 0
        assert!(!validate_bmp_file(&invalid_bmp));
    }

    #[test]
    fn test_validate_bmp_file_invalid_pixel_offset() {
        let mut invalid_bmp = create_valid_bmp_header();
        // Set pixel offset beyond file size
        invalid_bmp[10] = 100;
        invalid_bmp[11] = 0;
        invalid_bmp[12] = 0;
        invalid_bmp[13] = 0;
        assert!(!validate_bmp_file(&invalid_bmp));
    }

    #[test]
    fn test_validate_bmp_file_invalid_dib_header_size() {
        let mut invalid_bmp = create_valid_bmp_header();
        invalid_bmp[14] = 39; // Invalid DIB header size
        assert!(!validate_bmp_file(&invalid_bmp));
    }

    #[test]
    fn test_validate_bmp_file_zero_width() {
        let mut invalid_bmp = create_valid_bmp_header();
        invalid_bmp[18] = 0; // Zero width
        invalid_bmp[19] = 0;
        invalid_bmp[20] = 0;
        invalid_bmp[21] = 0;
        assert!(!validate_bmp_file(&invalid_bmp));
    }

    #[test]
    fn test_validate_bmp_file_zero_height() {
        let mut invalid_bmp = create_valid_bmp_header();
        invalid_bmp[22] = 0; // Zero height
        invalid_bmp[23] = 0;
        invalid_bmp[24] = 0;
        invalid_bmp[25] = 0;
        assert!(!validate_bmp_file(&invalid_bmp));
    }

    #[test]
    fn test_validate_bmp_file_invalid_planes() {
        let mut invalid_bmp = create_valid_bmp_header();
        invalid_bmp[26] = 2; // Should be 1
        assert!(!validate_bmp_file(&invalid_bmp));
    }

    #[test]
    fn test_validate_bmp_file_invalid_bits_per_pixel() {
        let mut invalid_bmp = create_valid_bmp_header();
        invalid_bmp[28] = 7; // Invalid bits per pixel
        assert!(!validate_bmp_file(&invalid_bmp));
    }

    #[test]
    fn test_validate_bmp_file_invalid_compression() {
        let mut invalid_bmp = create_valid_bmp_header();
        invalid_bmp[30] = 10; // Invalid compression method
        assert!(!validate_bmp_file(&invalid_bmp));
    }

    #[test]
    fn test_validate_bmp_file_compression_mismatch() {
        let mut invalid_bmp = create_valid_bmp_header();
        invalid_bmp[28] = 24; // 24 bits per pixel
        invalid_bmp[30] = 1; // BI_RLE8 compression (only valid for 8-bit)
        assert!(!validate_bmp_file(&invalid_bmp));
    }

    #[test]
    fn test_validate_bmp_file_negative_height() {
        let mut valid_bmp = create_valid_bmp_header();
        // Set negative height (top-down bitmap) - should still be valid
        valid_bmp[22] = 0x9C; // -100 in two's complement (little endian)
        valid_bmp[23] = 0xFF;
        valid_bmp[24] = 0xFF;
        valid_bmp[25] = 0xFF;
        assert!(validate_bmp_file(&valid_bmp));
    }

    #[test]
    fn test_bmp_file_size_heuristic() {
        let spec = SearchSpec::new(
            FileType::Bmp,
            "bmp",
            b"BM",
            None,
            10 * 1024 * 1024,
            true,
            SearchType::Forward,
        );

        let mut data = vec![0u8; 100];
        data[0] = b'B';
        data[1] = b'M';
        // File size = 64 bytes
        data[2] = 64;
        data[3] = 0;
        data[4] = 0;
        data[5] = 0;

        let size = bmp_file_size_heuristic(&spec, &data);
        assert_eq!(size, 64);
    }

    #[test]
    fn test_bmp_file_size_heuristic_too_small() {
        let spec = SearchSpec::new(
            FileType::Bmp,
            "bmp",
            b"BM",
            None,
            10 * 1024 * 1024,
            true,
            SearchType::Forward,
        );

        let data = vec![0u8; 4]; // Too small for size field
        let size = bmp_file_size_heuristic(&spec, &data);
        assert_eq!(size, 0);
    }

    #[test]
    fn test_valid_dib_sizes() {
        // DIB header sizes 52, 56, 108, 124 are all valid
        for &dib_size in &[52u32, 56, 108, 124] {
            let total_size = 14 + dib_size as usize;
            let mut data = vec![0u8; total_size];
            data[0] = b'B';
            data[1] = b'M';
            let sz = total_size as u32;
            data[2..6].copy_from_slice(&sz.to_le_bytes());
            data[10..14].copy_from_slice(&sz.to_le_bytes());
            data[14..18].copy_from_slice(&dib_size.to_le_bytes());
            data[18] = 1; // width = 1
            data[22] = 1; // height = 1
            data[26] = 1; // planes = 1
            data[28] = 24; // bpp = 24
            assert!(
                validate_bmp_file(&data),
                "DIB size {dib_size} should be valid"
            );
        }
    }

    #[test]
    fn test_valid_compression_methods() {
        // BI_RLE8 (1) requires bpp=8
        let mut bmp = create_valid_bmp_header();
        bmp[28] = 8;
        bmp[30] = 1;
        assert!(
            validate_bmp_file(&bmp),
            "BI_RLE8 with bpp=8 should be valid"
        );

        // BI_RLE4 (2) requires bpp=4
        let mut bmp = create_valid_bmp_header();
        bmp[28] = 4;
        bmp[30] = 2;
        assert!(
            validate_bmp_file(&bmp),
            "BI_RLE4 with bpp=4 should be valid"
        );

        // BI_BITFIELDS (3), BI_JPEG (4), BI_PNG (5) have no bpp constraint
        for compression in [3u8, 4, 5] {
            let mut bmp = create_valid_bmp_header();
            bmp[30] = compression;
            assert!(
                validate_bmp_file(&bmp),
                "compression method {compression} should be valid"
            );
        }
    }

    #[test]
    fn test_rle4_compression_mismatch() {
        let mut bmp = create_valid_bmp_header();
        bmp[28] = 8; // bpp=8, but BI_RLE4 requires bpp=4
        bmp[30] = 2; // BI_RLE4
        assert!(!validate_bmp_file(&bmp));
    }

    #[test]
    fn test_uncompressed_image_size_mismatch() {
        let mut bmp = create_valid_bmp_header();
        // width=100, height=100, bpp=24, compression=0 → expected size is 30000
        // Set image_size=1 (wrong) to trigger mismatch rejection
        bmp[34] = 1;
        assert!(!validate_bmp_file(&bmp));
    }

    #[test]
    fn test_dpi_out_of_range() {
        let mut bmp = create_valid_bmp_header();
        // x_ppm = 1_000_001 exceeds the valid range of 1–1_000_000
        let out_of_range: u32 = 1_000_001;
        bmp[38..42].copy_from_slice(&out_of_range.to_le_bytes());
        assert!(!validate_bmp_file(&bmp));
    }

    #[test]
    fn test_colors_used_exceeds_palette_1bit() {
        let mut bmp = create_valid_bmp_header();
        bmp[28] = 1; // bpp=1 → max palette is 2
        bmp[46] = 3; // colors_used=3 > 2
        assert!(!validate_bmp_file(&bmp));
    }

    #[test]
    fn test_colors_used_exceeds_palette_4bit() {
        let mut bmp = create_valid_bmp_header();
        bmp[28] = 4; // bpp=4 → max palette is 16
        bmp[46] = 17; // colors_used=17 > 16
        assert!(!validate_bmp_file(&bmp));
    }

    #[test]
    fn test_colors_used_exceeds_palette_8bit() {
        let mut bmp = create_valid_bmp_header();
        bmp[28] = 8; // bpp=8 → max palette is 256
        bmp[46..50].copy_from_slice(&257u32.to_le_bytes()); // colors_used=257 > 256
        assert!(!validate_bmp_file(&bmp));
    }

    #[test]
    fn test_important_colors_exceeds_colors_used() {
        let mut bmp = create_valid_bmp_header();
        bmp[46] = 4; // colors_used=4
        bmp[50] = 5; // important_colors=5 > colors_used
        assert!(!validate_bmp_file(&bmp));
    }

    #[test]
    fn test_bmp_file_size_heuristic_exceeds_max() {
        let spec = SearchSpec::new(
            FileType::Bmp,
            "bmp",
            b"BM",
            None,
            1024, // Max 1KB
            true,
            SearchType::Forward,
        );

        let mut data = vec![0u8; 100];
        data[0] = b'B';
        data[1] = b'M';
        // File size = 2048 bytes (exceeds max)
        data[2] = 0x00;
        data[3] = 0x08;
        data[4] = 0x00;
        data[5] = 0x00;

        let size = bmp_file_size_heuristic(&spec, &data);
        assert_eq!(size, 1024); // Should be clamped to max_len
    }
}
