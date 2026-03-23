use crate::types::{Endianness, SearchSpec, bytes_to_u32};
use std::cmp;

/// Determine the on-disk size of a PE executable by reading `SizeOfImage`
/// from the Optional Header.
///
/// `SizeOfImage` is the in-memory size of the image rounded up to section
/// alignment — a reliable upper bound for the on-disk PE size.  Falls back
/// to `min(spec.max_len, buf.len())` when the PE header cannot be parsed.
pub fn exe_file_size_heuristic(spec: &SearchSpec, buf: &[u8]) -> usize {
    // Need at least the DOS header (0x40 bytes) to read e_lfanew
    if buf.len() < 0x40 {
        return cmp::min(spec.max_len, buf.len());
    }

    let e_lfanew = bytes_to_u32(&buf[0x3C..0x40], Endianness::Little) as usize;

    // Optional header starts at e_lfanew + 4 (PE sig) + 20 (COFF file header)
    // SizeOfImage is at offset 56 within the Optional Header.
    // Total offset from file start: e_lfanew + 24 + 56 = e_lfanew + 80
    let size_of_image_offset = e_lfanew.saturating_add(80);
    if size_of_image_offset + 4 > buf.len() {
        return cmp::min(spec.max_len, buf.len());
    }

    // Verify PE signature
    if e_lfanew + 4 > buf.len() || &buf[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return cmp::min(spec.max_len, buf.len());
    }

    let size_of_image =
        bytes_to_u32(&buf[size_of_image_offset..size_of_image_offset + 4], Endianness::Little)
            as usize;

    if size_of_image > 0 && size_of_image <= spec.max_len {
        cmp::min(size_of_image, buf.len())
    } else {
        cmp::min(spec.max_len, buf.len())
    }
}

/// Validate EXE file by checking PE header
pub fn validate_exe_file(data: &[u8]) -> bool {
    // Check if we have enough data to read e_lfanew at offset 0x3C
    if data.len() < 0x40 {
        return false;
    }

    // Read e_lfanew value (4 bytes little-endian at offset 0x3C)
    let e_lfanew_bytes = &data[0x3C..0x40];
    let e_lfanew = bytes_to_u32(e_lfanew_bytes, Endianness::Little) as usize;

    // Check if the PE header offset is within bounds
    if e_lfanew >= data.len() || e_lfanew + 4 > data.len() {
        return false;
    }

    // Check if PE signature exists at the calculated offset
    let pe_signature = &data[e_lfanew..e_lfanew + 4];
    pe_signature == b"PE\0\0"
}
