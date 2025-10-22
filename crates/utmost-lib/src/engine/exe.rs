/// Validate EXE file by checking PE header
pub fn validate_exe_file(data: &[u8]) -> bool {
    // Check if we have enough data to read e_lfanew at offset 0x3C
    if data.len() < 0x40 {
        return false;
    }

    // Read e_lfanew value (4 bytes little-endian at offset 0x3C)
    let e_lfanew_bytes = &data[0x3C..0x40];
    let e_lfanew = u32::from_le_bytes([
        e_lfanew_bytes[0],
        e_lfanew_bytes[1],
        e_lfanew_bytes[2],
        e_lfanew_bytes[3],
    ]) as usize;

    // Check if the PE header offset is within bounds
    if e_lfanew >= data.len() || e_lfanew + 4 > data.len() {
        return false;
    }

    // Check if PE signature exists at the calculated offset
    let pe_signature = &data[e_lfanew..e_lfanew + 4];
    pe_signature == b"PE\0\0"
}
