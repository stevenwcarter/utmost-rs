use std::cmp;

use crate::{
    SearchSpec,
    types::{Endianness, bytes_to_u32},
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
