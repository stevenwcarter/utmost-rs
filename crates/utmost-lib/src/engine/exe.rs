use crate::types::{Endianness, SearchSpec, bytes_to_u32};
use std::cmp;

/// Offset of `e_lfanew` (PE header RVA) within the DOS header.
const PE_LFANEW_OFFSET: usize = 0x3C;
/// Minimum DOS header bytes needed to read `e_lfanew`.
const PE_DOS_HEADER_MIN_SIZE: usize = 0x40;
/// Offset from `e_lfanew` to `SizeOfImage` in the PE Optional Header:
/// 4 (PE signature) + 20 (COFF File Header) + 56 (field offset in Optional Header).
const PE_SIZE_OF_IMAGE_FROM_LFANEW: usize = 80;

/// Determine the on-disk size of a PE executable by reading `SizeOfImage`
/// from the Optional Header.
///
/// `SizeOfImage` is the in-memory size of the image rounded up to section
/// alignment — a reliable upper bound for the on-disk PE size.  Falls back
/// to `min(spec.max_len, buf.len())` when the PE header cannot be parsed.
pub fn exe_file_size_heuristic(spec: &SearchSpec, buf: &[u8]) -> usize {
    // Need at least the DOS header to read e_lfanew
    if buf.len() < PE_DOS_HEADER_MIN_SIZE {
        return cmp::min(spec.max_len, buf.len());
    }

    let e_lfanew = bytes_to_u32(
        &buf[PE_LFANEW_OFFSET..PE_DOS_HEADER_MIN_SIZE],
        Endianness::Little,
    ) as usize;

    // SizeOfImage: e_lfanew + 4 (PE sig) + 20 (COFF header) + 56 (field offset)
    let size_of_image_offset = e_lfanew.saturating_add(PE_SIZE_OF_IMAGE_FROM_LFANEW);
    if size_of_image_offset + 4 > buf.len() {
        return cmp::min(spec.max_len, buf.len());
    }

    // Verify PE signature
    if e_lfanew + 4 > buf.len() || &buf[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return cmp::min(spec.max_len, buf.len());
    }

    let size_of_image = bytes_to_u32(
        &buf[size_of_image_offset..size_of_image_offset + 4],
        Endianness::Little,
    ) as usize;

    if size_of_image > 0 && size_of_image <= spec.max_len {
        cmp::min(size_of_image, buf.len())
    } else {
        cmp::min(spec.max_len, buf.len())
    }
}

/// Validate EXE file by checking PE header
pub fn validate_exe_file(data: &[u8]) -> bool {
    // Check if we have enough data to read e_lfanew
    if data.len() < PE_DOS_HEADER_MIN_SIZE {
        return false;
    }

    // Read e_lfanew value (4 bytes little-endian)
    let e_lfanew_bytes = &data[PE_LFANEW_OFFSET..PE_DOS_HEADER_MIN_SIZE];
    let e_lfanew = bytes_to_u32(e_lfanew_bytes, Endianness::Little) as usize;

    // Check if the PE header offset is within bounds
    if e_lfanew >= data.len() || e_lfanew + 4 > data.len() {
        return false;
    }

    // Check if PE signature exists at the calculated offset
    let pe_signature = &data[e_lfanew..e_lfanew + 4];
    pe_signature == b"PE\0\0"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FileType, SearchSpec, SearchType};

    /// Helper function to create a minimal SearchSpec for testing
    fn create_test_spec(max_len: usize) -> SearchSpec {
        SearchSpec::new(
            FileType::Exe,
            "exe",
            b"MZ",
            None,
            max_len,
            true,
            SearchType::Forward,
        )
    }

    #[test]
    fn test_exe_file_size_heuristic_buffer_too_small() {
        // Test path: buffer < PE_DOS_HEADER_MIN_SIZE (0x40 = 64)
        let spec = create_test_spec(5000);
        let buf = vec![0u8; 30]; // Less than 64 bytes
        let result = exe_file_size_heuristic(&spec, &buf);
        assert_eq!(result, cmp::min(spec.max_len, 30));
        assert_eq!(result, 30);
    }

    #[test]
    fn test_exe_file_size_heuristic_valid_pe() {
        // Test path: valid PE header with SizeOfImage within max_len
        let spec = create_test_spec(5000);
        let mut buf = vec![0u8; 1500];

        // Set e_lfanew = 64 at offset 0x3C
        let e_lfanew: u32 = 64;
        buf[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());

        // Set PE signature at offset 64
        buf[64..68].copy_from_slice(b"PE\0\0");

        // Set SizeOfImage = 1000 at offset 64 + 80 = 144
        let size_of_image: u32 = 1000;
        buf[144..148].copy_from_slice(&size_of_image.to_le_bytes());

        let result = exe_file_size_heuristic(&spec, &buf);
        assert_eq!(result, 1000);
    }

    #[test]
    fn test_exe_file_size_heuristic_bad_pe_signature() {
        // Test path: invalid PE signature (not "PE\0\0")
        let spec = create_test_spec(5000);
        let mut buf = vec![0u8; 1500];

        // Set e_lfanew = 64 at offset 0x3C
        let e_lfanew: u32 = 64;
        buf[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());

        // Set wrong signature at offset 64 (e.g., "MZ\0\0" instead of "PE\0\0")
        buf[64..68].copy_from_slice(b"MZ\0\0");

        let result = exe_file_size_heuristic(&spec, &buf);
        assert_eq!(result, cmp::min(spec.max_len, buf.len()));
        assert_eq!(result, 1500);
    }

    #[test]
    fn test_exe_file_size_heuristic_size_of_image_exceeds_max_len() {
        // Test path: valid PE header but SizeOfImage > spec.max_len
        let spec = create_test_spec(5000);
        let mut buf = vec![0u8; 1500];

        // Set e_lfanew = 64 at offset 0x3C
        let e_lfanew: u32 = 64;
        buf[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());

        // Set PE signature at offset 64
        buf[64..68].copy_from_slice(b"PE\0\0");

        // Set SizeOfImage = 999999 (exceeds spec.max_len)
        let size_of_image: u32 = 999999;
        buf[144..148].copy_from_slice(&size_of_image.to_le_bytes());

        let result = exe_file_size_heuristic(&spec, &buf);
        assert_eq!(result, cmp::min(spec.max_len, buf.len()));
        assert_eq!(result, 1500);
    }
}
