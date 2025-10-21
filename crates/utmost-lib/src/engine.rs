use crate::{
    search::BoyerMoore,
    types::{FileInfo, Mode, SearchSpec, SearchType, State, clean_filename},
};
use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tracing::{debug, info};

/// Process a buffer directly (useful for stdin)
pub async fn search_buffer(
    buffer: &[u8],
    state: &State,
    file_info: &mut FileInfo,
    f_offset: u64,
    total_input_files: usize,
) -> Result<()> {
    setup_stream_info(state, file_info).await?;
    audit_layout(state).await?;

    info!("Searching buffer for file signatures...");
    debug!("Buffer size: {} bytes", buffer.len());

    // Get search specs once for buffer processing
    let search_specs = state.get_search_specs().await;

    // Search the buffer directly
    search_chunk(
        state,
        &search_specs,
        buffer,
        file_info,
        buffer.len(),
        f_offset,
        total_input_files,
    )
    .await?;

    file_info.bytes_read = buffer.len();
    debug!("Completed processing {} bytes", file_info.bytes_read);
    Ok(())
}

/// Set up stream information without file operations
async fn setup_stream_info(state: &State, file_info: &FileInfo) -> Result<()> {
    info!("Setting up stream for processing...");

    if file_info.total_bytes != 0 {
        state
            .audit_entry(&format!(
                "Length: {} ({} MB)",
                file_info.total_bytes, file_info.total_megs
            ))
            .await?;
    } else {
        state.audit_entry("Length: Unknown").await?;
    }

    state.audit_entry(" ").await?;
    Ok(())
}
/// Process a file by searching for file signatures in chunks
pub async fn search_stream(
    input_file: &mut tokio::fs::File,
    state: &State,
    file_info: &mut FileInfo,
    total_input_files: usize,
) -> Result<()> {
    setup_stream(state, file_info, input_file).await?;
    audit_layout(state).await?;

    let chunk_size = state.chunk_size;
    let mut f_offset = 0u64;
    let mut buffer = vec![0u8; chunk_size];

    // Get search specs once at the beginning to avoid locking on every chunk
    let search_specs = state.get_search_specs().await;

    info!("Starting file signature search...");
    debug!("Chunk size: {} bytes", chunk_size);

    loop {
        // Read chunk from file
        let bytes_read = input_file
            .read(&mut buffer)
            .await
            .context("Failed to read from input file")?;

        if bytes_read == 0 {
            break; // EOF reached
        }

        debug!("Read {} bytes at offset {}", bytes_read, f_offset);

        // Search this chunk for file signatures
        search_chunk(
            state,
            &search_specs,
            &buffer[..bytes_read],
            file_info,
            bytes_read,
            f_offset,
            total_input_files,
        )
        .await?;

        f_offset += bytes_read as u64;
        file_info.bytes_read += bytes_read;

        // Progress indicator
        if !state.get_mode(Mode::Quiet) {
            eprint!("*");
        }

        // TODO: Handle bridging between chunks for signatures that span chunk boundaries
    }

    if !state.get_mode(Mode::Quiet) {
        eprintln!("|\n");
    }

    debug!("Completed reading {} bytes", file_info.bytes_read);
    Ok(())
}

/// Process a stream with progress callback support
pub async fn search_stream_with_progress<F>(
    input_file: &mut tokio::fs::File,
    state: &State,
    file_info: &mut FileInfo,
    progress_callback: F,
    total_input_files: usize,
) -> Result<()>
where
    F: Fn(u64) + Send + Sync,
{
    setup_stream(state, file_info, input_file).await?;
    audit_layout(state).await?;

    let chunk_size = state.chunk_size;
    let mut f_offset = 0u64;
    let mut buffer = vec![0u8; chunk_size];

    // Get search specs once at the beginning to avoid locking on every chunk
    let search_specs = state.get_search_specs().await;

    info!("Starting file signature search...");
    debug!("Chunk size: {} bytes", chunk_size);

    loop {
        // Read chunk from file
        let bytes_read = input_file
            .read(&mut buffer)
            .await
            .context("Failed to read from input file")?;

        if bytes_read == 0 {
            break; // EOF reached
        }

        debug!("Read {} bytes at offset {}", bytes_read, f_offset);

        // Search this chunk for file signatures
        search_chunk(
            state,
            &search_specs,
            &buffer[..bytes_read],
            file_info,
            bytes_read,
            f_offset,
            total_input_files,
        )
        .await?;

        f_offset += bytes_read as u64;
        file_info.bytes_read += bytes_read;

        // Update progress via callback
        progress_callback(f_offset);

        // TODO: Handle bridging between chunks for signatures that span chunk boundaries
    }

    debug!("Completed reading {} bytes", file_info.bytes_read);
    Ok(())
}

/// Set up the stream for processing
async fn setup_stream(
    state: &State,
    file_info: &mut FileInfo,
    input_file: &mut tokio::fs::File,
) -> Result<()> {
    info!("Setting up stream for processing...");

    if file_info.total_bytes != 0 {
        state
            .audit_entry(&format!(
                "Length: {} ({} MB)",
                file_info.total_bytes, file_info.total_megs
            ))
            .await?;
    } else {
        state.audit_entry("Length: Unknown").await?;
    }

    if state.skip > 0 {
        let skip_bytes = (state.skip as u64) * (state.block_size as u64);
        state
            .audit_entry(&format!("Skipping first {} bytes", skip_bytes))
            .await?;

        input_file
            .seek(tokio::io::SeekFrom::Start(skip_bytes))
            .await
            .context("Failed to seek to skip position")?;

        if file_info.total_bytes > skip_bytes as usize {
            file_info.total_bytes -= skip_bytes as usize;
        }
    }

    state.audit_entry(" ").await?;
    Ok(())
}

/// Write audit layout header
async fn audit_layout(state: &State) -> Result<()> {
    state
        .audit_entry(&format!(
            "Num\t {} (bs={})\t {}\t {}\t {} \n",
            "Name", state.block_size, "Size", "File Offset", "Comment"
        ))
        .await?;
    Ok(())
}

/// Search a chunk of data for file signatures
async fn search_chunk(
    state: &State,
    search_specs: &[SearchSpec],
    buf: &[u8],
    file_info: &mut FileInfo,
    chunk_size: usize,
    f_offset: u64,
    total_input_files: usize,
) -> Result<()> {
    debug!(
        "Searching chunk of {} bytes at offset {}",
        chunk_size, f_offset
    );

    debug!("Number of search specs: {}", search_specs.len());

    // Check mode once to avoid borrowing issues
    let quick_mode = state.get_mode(Mode::Quick);
    let block_size = state.block_size;

    // Process each search spec
    for (i, spec) in search_specs.iter().enumerate() {
        debug!("Processing search spec {}: {}", i, spec.suffix);
        let mut search_pos = 0;

        while search_pos < buf.len() {
            let found_pos = if quick_mode {
                // Quick mode: search only on block boundaries
                search_quick_mode(spec, buf, search_pos, block_size)
            } else {
                // Standard Boyer-Moore search
                search_standard_mode(spec, buf, search_pos)
            };

            if let Some(pos) = found_pos {
                // Clone the spec to avoid borrowing issues
                let spec_clone = spec.clone();
                let extracted_size = process_found_signature(
                    state,
                    &spec_clone,
                    buf,
                    pos,
                    f_offset,
                    file_info,
                    total_input_files,
                )
                .await?;
                
                // For ZIP files, skip ahead by the extracted size to avoid 
                // finding internal PK signatures within the same ZIP file
                let advance_by = if extracted_size > 0 && spec.file_type == crate::types::FileType::Zip {
                    extracted_size
                } else {
                    spec.header_len
                };
                
                search_pos = pos + advance_by;
            } else {
                break;
            }
        }
    }

    Ok(())
}

/// Quick mode search (block-aligned)
fn search_quick_mode(
    spec: &SearchSpec,
    buf: &[u8],
    start_pos: usize,
    block_size: usize,
) -> Option<usize> {
    let mut pos = start_pos;

    // Align to block boundary
    let remainder = pos % block_size;
    if remainder != 0 {
        pos += block_size - remainder;
    }

    while pos + spec.header_len <= buf.len() {
        if crate::search::memwildcardcmp(
            &spec.header,
            &buf[pos..pos + spec.header_len],
            spec.case_sensitive,
        ) {
            return Some(pos);
        }
        pos += block_size;
    }

    None
}

/// Standard Boyer-Moore search
fn search_standard_mode(spec: &SearchSpec, buf: &[u8], start_pos: usize) -> Option<usize> {
    if start_pos >= buf.len() {
        return None;
    }

    debug!(
        "Searching for {} header in {} bytes starting at pos {}",
        spec.suffix,
        buf.len() - start_pos,
        start_pos
    );
    debug!("Header bytes: {:?}", spec.header);

    let searcher = BoyerMoore::new(&spec.header, spec.case_sensitive, spec.search_type);
    let result = searcher
        .search_from(&buf[start_pos..], 0)
        .map(|pos| pos + start_pos);

    if let Some(pos) = result {
        debug!("Found {} header at position {}", spec.suffix, pos);
    } else {
        debug!("No {} header found", spec.suffix);
    }

    result
}

/// Process a found file signature
/// Returns the size of the extracted file (or 0 if no file was extracted)
async fn process_found_signature(
    state: &State,
    spec: &SearchSpec,
    buf: &[u8],
    found_pos: usize,
    f_offset: u64,
    file_info: &mut FileInfo,
    total_input_files: usize,
) -> Result<usize> {
    let absolute_offset = f_offset + found_pos as u64;

    debug!(
        "Found {} signature at offset {}",
        spec.suffix, absolute_offset
    );

    // For now, just extract a basic header-based file
    let extracted_size =
        extract_basic_file(state, spec, buf, found_pos, file_info, total_input_files).await?;

    if extracted_size > 0 {
        let new_file_number = state.increment_fileswritten().await;
        let filename = format!("{}.{}", new_file_number, spec.suffix);
        state
            .audit_entry(&format!(
                "{}\t {}\t {}\t {}\t {}",
                new_file_number, filename, extracted_size, absolute_offset, spec.comment
            ))
            .await?;

        // Update found count for this file type
        state.increment_found_count(spec.file_type).await;
    }

    Ok(extracted_size)
}

/// Perform additional validation checks for specific file types
/// Returns true if the file passes validation, false otherwise
fn validate_file_candidate(spec: &SearchSpec, data: &[u8]) -> bool {
    use crate::types::FileType;
    
    match spec.file_type {
        FileType::Exe => validate_exe_file(data),
        // Add more validation functions here as needed
        _ => true, // No validation for other types (yet)
    }
}

/// Validate EXE file by checking PE header
fn validate_exe_file(data: &[u8]) -> bool {
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

/// Basic file extraction (simplified version)
async fn extract_basic_file(
    state: &State,
    spec: &SearchSpec,
    buf: &[u8],
    found_pos: usize,
    file_info: &mut FileInfo,
    total_input_files: usize,
) -> Result<usize> {
    let remaining_buf = &buf[found_pos..];

    // Determine file size based on file type and footer or max length
    let file_size = match spec.file_type {
        crate::types::FileType::Zip => {
            // ZIP files need special parsing to find the actual end
            determine_zip_file_size(remaining_buf, spec.max_len)
        }
        crate::types::FileType::Pdf => {
            // PDF files need special parsing to find the last %%EOF and validate xref
            determine_pdf_file_size(remaining_buf, spec.max_len)
        }
        _ => {
            // For other file types, use standard footer search or heuristics
            if let Some(ref footer) = spec.footer {
                if let Some(footer_pos) = find_footer(remaining_buf, footer, spec.case_sensitive) {
                    footer_pos + footer.len()
                } else {
                    // Fallback to maximum length or remaining buffer
                    std::cmp::min(spec.max_len, remaining_buf.len())
                }
            } else {
                // No footer, use heuristics or max length
                determine_file_size_heuristic(spec, remaining_buf)
            }
        }
    };

    if file_size > 0 && file_size <= remaining_buf.len() {
        let candidate_data = &remaining_buf[..file_size];
        
        // Perform additional validation for specific file types (unless disabled)
        if !state.config.disable_validation && !validate_file_candidate(spec, candidate_data) {
            debug!(
                "File candidate at offset {} failed validation for type {:?}",
                found_pos, spec.file_type
            );
            return Ok(0); // Skip this candidate
        }
        
        // Write file to disk
        write_to_disk(
            state,
            spec,
            candidate_data,
            found_pos as u64,
            file_info,
            total_input_files,
        )
        .await?;
        Ok(file_size)
    } else {
        Ok(0)
    }
}

/// Find footer in buffer
fn find_footer(buf: &[u8], footer: &[u8], case_sensitive: bool) -> Option<usize> {
    let searcher = BoyerMoore::new(footer, case_sensitive, SearchType::Forward);
    searcher.search(buf)
}

/// Determine file size using heuristics for files without footers
fn determine_file_size_heuristic(spec: &SearchSpec, buf: &[u8]) -> usize {
    // For now, use a simple heuristic based on file type
    match spec.file_type {
        crate::types::FileType::Bmp => {
            // BMP files have size in header at offset 2
            if buf.len() >= 6 {
                let size = crate::types::bytes_to_u32(&buf[2..6], crate::types::Endianness::Little);
                std::cmp::min(size as usize, spec.max_len)
            } else {
                0
            }
        }
        crate::types::FileType::Exe => {
            // For EXE files, use a conservative estimate
            std::cmp::min(64 * 1024, buf.len()) // 64KB default
        }
        _ => {
            // Default: search up to max_len or use remaining buffer
            std::cmp::min(spec.max_len, buf.len())
        }
    }
}

/// Determine the actual size of a ZIP file by parsing its structure
fn determine_zip_file_size(buf: &[u8], max_len: usize) -> usize {
    // ZIP file structure:
    // - Local file headers (PK\x03\x04) with file data
    // - Central directory entries (PK\x01\x02) 
    // - End of central directory record (PK\x05\x06)
    
    // Look for the End of Central Directory (EOCD) record
    // The EOCD signature is 0x50, 0x4B, 0x05, 0x06 (PK\x05\x06)
    let eocd_signature = [0x50, 0x4B, 0x05, 0x06];
    
    // Search FORWARD from the beginning for the first EOCD record
    // This ensures we find the EOCD that belongs to THIS ZIP file,
    // not a later ZIP file that might also be in the buffer
    for i in 0..buf.len().saturating_sub(21) {
        if buf[i..i+4] == eocd_signature {
            // Found EOCD record, parse it to get the actual ZIP file size
            return parse_zip_eocd_record(&buf[i..], i, max_len);
        }
    }
    
    // If no EOCD found, fall back to scanning for local file headers
    // and estimating based on the last one found
    find_zip_end_by_local_headers(buf, max_len)
}

/// Parse the End of Central Directory record to determine ZIP file size
fn parse_zip_eocd_record(eocd_data: &[u8], eocd_offset: usize, max_len: usize) -> usize {
    if eocd_data.len() < 22 {
        return std::cmp::min(max_len, eocd_offset + 22);
    }
    
    // EOCD structure (all little-endian):
    // 0-3:   End of central dir signature (0x06054b50)
    // 4-5:   Number of this disk
    // 6-7:   Disk where central directory starts  
    // 8-9:   Number of central directory records on this disk
    // 10-11: Total number of central directory records
    // 12-15: Size of central directory
    // 16-19: Offset of start of central directory
    // 20-21: ZIP file comment length
    // 22+:   ZIP file comment
    
    let comment_length = crate::types::bytes_to_u16(&eocd_data[20..22], crate::types::Endianness::Little) as usize;
    
    // The actual ZIP file ends after the EOCD record + comment
    let zip_end = eocd_offset + 22 + comment_length;
    
    std::cmp::min(zip_end, max_len)
}

/// Fallback method: find ZIP end by scanning local file headers
fn find_zip_end_by_local_headers(buf: &[u8], max_len: usize) -> usize {
    let local_header_sig = [0x50, 0x4B, 0x03, 0x04]; // PK\x03\x04
    let mut last_file_end = 0;
    let mut pos = 0;
    
    while pos < buf.len().saturating_sub(29) {
        if buf[pos..pos+4] == local_header_sig {
            // Found local file header, parse it to find the end of this file
            if let Some(file_end) = parse_zip_local_header(&buf[pos..], pos) {
                last_file_end = std::cmp::max(last_file_end, file_end);
                pos = file_end;
            } else {
                pos += 4;
            }
        } else {
            pos += 1;
        }
    }
    
    if last_file_end > 0 {
        std::cmp::min(last_file_end, max_len)
    } else {
        // No valid local headers found, use conservative estimate
        std::cmp::min(64 * 1024, std::cmp::min(max_len, buf.len()))
    }
}

/// Parse a ZIP local file header to determine where this file entry ends
fn parse_zip_local_header(header_data: &[u8], header_offset: usize) -> Option<usize> {
    if header_data.len() < 30 {
        return None;
    }
    
    // Local file header structure (all little-endian):
    // 0-3:   Local file header signature (0x04034b50)
    // 4-5:   Version needed to extract
    // 6-7:   General purpose bit flag
    // 8-9:   Compression method
    // 10-11: Last mod file time
    // 12-13: Last mod file date
    // 14-17: CRC-32
    // 18-21: Compressed size
    // 22-25: Uncompressed size
    // 26-27: File name length
    // 28-29: Extra field length
    // 30+:   File name + extra field + compressed data
    
    let compressed_size = crate::types::bytes_to_u32(&header_data[18..22], crate::types::Endianness::Little) as usize;
    let filename_length = crate::types::bytes_to_u16(&header_data[26..28], crate::types::Endianness::Little) as usize;
    let extra_field_length = crate::types::bytes_to_u16(&header_data[28..30], crate::types::Endianness::Little) as usize;
    
    // Calculate the end of this file entry
    let file_end = header_offset + 30 + filename_length + extra_field_length + compressed_size;
    
    Some(file_end)
}

/// Determine the actual size of a PDF file by finding the last %%EOF marker
/// and validating the xref table structure
fn determine_pdf_file_size(buf: &[u8], max_len: usize) -> usize {
    // PDF file structure:
    // - Header: %PDF-1.x
    // - Body: objects, streams, etc.
    // - Cross-reference table (xref)
    // - Trailer (contains startxref)
    // - %%EOF marker
    
    // PDFs can have incremental updates, so we need to find the LAST %%EOF
    let eof_marker = b"%%EOF";
    let mut last_eof_pos = None;
    
    // Search for all %%EOF markers
    let mut pos = 0;
    while pos <= buf.len().saturating_sub(eof_marker.len()) {
        if buf[pos..pos + eof_marker.len()] == *eof_marker {
            last_eof_pos = Some(pos);
            pos += eof_marker.len();
        } else {
            pos += 1;
        }
    }
    
    if let Some(eof_pos) = last_eof_pos {
        debug!("PDF: Found last %%EOF at position {}", eof_pos);
        
        // Found the last %%EOF, now validate the PDF structure
        if validate_pdf_structure(&buf[..eof_pos + eof_marker.len()]) {
            let pdf_end = eof_pos + eof_marker.len();
            
            // Skip any trailing whitespace after %%EOF
            let mut actual_end = pdf_end;
            while actual_end < buf.len() && (buf[actual_end] == b'\r' || buf[actual_end] == b'\n' || buf[actual_end] == b' ' || buf[actual_end] == b'\t') {
                actual_end += 1;
            }
            
            debug!("PDF: Using last %%EOF, file size: {}", actual_end);
            return std::cmp::min(actual_end, max_len);
        } else {
            debug!("PDF: Last %%EOF failed validation, falling back");
        }
    }
    
    // Fallback: search for the first %%EOF if validation fails
    if let Some(first_eof_pos) = find_first_pattern(buf, eof_marker) {
        let pdf_end = first_eof_pos + eof_marker.len();
        debug!("PDF: Using first %%EOF fallback, file size: {}", pdf_end);
        std::cmp::min(pdf_end, max_len)
    } else {
        // No %%EOF found, use conservative estimate
        debug!("PDF: No %%EOF found, using conservative estimate");
        std::cmp::min(64 * 1024, std::cmp::min(max_len, buf.len()))
    }
}

/// Validate PDF structure by checking for startxref and xref table
fn validate_pdf_structure(buf: &[u8]) -> bool {
    // Look for "startxref" followed by a number and %%EOF
    let startxref_pattern = b"startxref";
    
    if let Some(startxref_pos) = find_last_pattern(buf, startxref_pattern) {
        debug!("PDF: Found startxref at position {}", startxref_pos);
        
        // Parse the offset after startxref
        let after_startxref = startxref_pos + startxref_pattern.len();
        if let Some(xref_offset) = parse_pdf_number(&buf[after_startxref..]) {
            debug!("PDF: startxref points to offset {}", xref_offset);
            
            // Be more lenient with xref validation - check a wider range around the offset
            for offset_adjustment in [0isize, -10, -20, -50, 10, 20, 50] {
                let adjusted_offset = xref_offset as isize + offset_adjustment;
                if adjusted_offset >= 0 && (adjusted_offset as usize) < buf.len() {
                    let xref_valid = validate_pdf_xref_table(&buf[adjusted_offset as usize..]);
                    if xref_valid {
                        debug!("PDF: xref table found with offset adjustment {}", offset_adjustment);
                        return true;
                    }
                }
            }
            debug!("PDF: No valid xref table found at any adjusted offset");
        } else {
            debug!("PDF: Could not parse startxref offset");
        }
    } else {
        debug!("PDF: No startxref found");
    }
    
    // If we can't find or validate startxref, be more lenient
    // Just check that we have some basic PDF markers and structure
    let has_basic_markers = find_first_pattern(buf, b"/Length").is_some() || 
                           find_first_pattern(buf, b"obj").is_some() || 
                           find_first_pattern(buf, b"endobj").is_some();
    
    let has_trailer = find_first_pattern(buf, b"trailer").is_some();
    let has_startxref = find_first_pattern(buf, startxref_pattern).is_some();
    
    // Accept if we have basic PDF structure components
    let is_valid = has_basic_markers && (has_trailer || has_startxref);
    debug!("PDF: Basic validation - markers: {}, trailer: {}, startxref: {}, result: {}", 
           has_basic_markers, has_trailer, has_startxref, is_valid);
    is_valid
}

/// Find the last occurrence of a pattern in buffer
fn find_last_pattern(buf: &[u8], pattern: &[u8]) -> Option<usize> {
    let mut last_pos = None;
    let mut pos = 0;
    
    while pos <= buf.len().saturating_sub(pattern.len()) {
        if buf[pos..pos + pattern.len()] == *pattern {
            last_pos = Some(pos);
            pos += pattern.len();
        } else {
            pos += 1;
        }
    }
    
    last_pos
}

/// Find the first occurrence of a pattern in buffer
fn find_first_pattern(buf: &[u8], pattern: &[u8]) -> Option<usize> {
    (0..=buf.len().saturating_sub(pattern.len()))
        .find(|&i| buf[i..i + pattern.len()] == *pattern)
}

/// Parse a PDF number (integer) from buffer, skipping whitespace
fn parse_pdf_number(buf: &[u8]) -> Option<usize> {
    let mut i = 0;
    
    // Skip whitespace
    while i < buf.len() && (buf[i] == b' ' || buf[i] == b'\t' || buf[i] == b'\r' || buf[i] == b'\n') {
        i += 1;
    }
    
    // Parse decimal number
    let mut num = 0usize;
    let mut found_digit = false;
    
    while i < buf.len() && buf[i].is_ascii_digit() {
        if let Some(new_num) = num.checked_mul(10).and_then(|n| n.checked_add((buf[i] - b'0') as usize)) {
            num = new_num;
            found_digit = true;
            i += 1;
        } else {
            // Overflow, return None
            return None;
        }
    }
    
    if found_digit {
        Some(num)
    } else {
        None
    }
}

/// Validate that there's a valid xref table at the given offset
fn validate_pdf_xref_table(buf: &[u8]) -> bool {
    debug!("PDF: Validating xref table, buffer starts with: {:?}", 
           String::from_utf8_lossy(&buf[..std::cmp::min(20, buf.len())]));
    
    // Look for "xref" at the beginning
    let xref_pattern = b"xref";
    
    // Skip whitespace before xref
    let mut i = 0;
    while i < buf.len() && (buf[i] == b' ' || buf[i] == b'\t' || buf[i] == b'\r' || buf[i] == b'\n') {
        i += 1;
    }
    
    if i + xref_pattern.len() <= buf.len() && buf[i..i + xref_pattern.len()] == *xref_pattern {
        debug!("PDF: Found 'xref' keyword");
        return true;
    }
    
    // Alternative: look for trailer without xref (for compressed xref streams)
    let trailer_pattern = b"trailer";
    if buf.len() >= trailer_pattern.len() && buf.starts_with(trailer_pattern) {
        debug!("PDF: Found 'trailer' keyword");
        return true;
    }
    
    // Also check for xref stream objects (newer PDF format)
    if find_first_pattern(buf, b"/Type/XRef").is_some() || find_first_pattern(buf, b"/Type /XRef").is_some() {
        debug!("PDF: Found xref stream object");
        return true;
    }
    
    debug!("PDF: No valid xref table found");
    false
}

/// Write extracted file to disk
async fn write_to_disk(
    state: &State,
    spec: &SearchSpec,
    data: &[u8],
    offset: u64,
    file_info: &mut FileInfo,
    total_input_files: usize,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    // Increment per-file counter
    file_info.per_file_counter += 1;

    // Determine if we should include filename prefix
    let should_prefix = state.config.prefix_filenames || total_input_files > 1;

    let filename = if should_prefix {
        let cleaned_input_name = if file_info.filename == "stdin" {
            "stdin".to_string()
        } else {
            clean_filename(&file_info.filename, 30)
        };
        format!(
            "{}-{}-{}.{}",
            cleaned_input_name, file_info.per_file_counter, offset, spec.suffix
        )
    } else {
        format!("{}-{}.{}", file_info.per_file_counter, offset, spec.suffix)
    };

    let filepath = format!("{}/{}", state.config.output_directory, filename);

    let mut file = tokio::fs::File::create(&filepath)
        .await
        .with_context(|| format!("Failed to create output file: {}", filepath))?;

    file.write_all(data)
        .await
        .with_context(|| format!("Failed to write data to file: {}", filepath))?;

    file.flush()
        .await
        .with_context(|| format!("Failed to flush file: {}", filepath))?;

    info!(
        "Extracted {} ({} bytes) at offset {}",
        filename,
        data.len(),
        offset
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FileType, SearchSpec, SearchType, StateConfig};
    use tempfile::TempDir;
    use tokio::fs;

    async fn create_test_state() -> (State, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let config = StateConfig {
            output_directory: temp_dir.path().to_string_lossy().to_string(),
            debug: false,
            prefix_filenames: false,
            chunk_size: None,
            block_size: None,
            skip: None,
            disable_validation: false,
        };
        let state = State::new(config).await.unwrap();
        (state, temp_dir)
    }

    #[tokio::test]
    async fn test_search_buffer_basic() {
        let (state, _temp_dir) = create_test_state().await;

        // Create a simple test buffer with JPEG signature
        let buffer = vec![
            0x00, 0x00, 0x00, 0x00, // padding
            0xFF, 0xD8, 0xFF, 0xE0, // JPEG signature at offset 4
            0x00, 0x10, 0x4A, 0x46, // JFIF marker
            0x49, 0x46, 0x00, 0x01, // rest of JFIF
            0xFF, 0xD9, // JPEG end marker
        ];

        let mut file_info = FileInfo {
            filename: "test.dat".to_string(),
            total_bytes: buffer.len(),
            total_megs: 0,
            bytes_read: 0,
            per_file_counter: 0,
        };

        // Set up JPEG search spec
        let jpeg_spec = SearchSpec::new(
            FileType::Jpeg,
            "jpg",
            &[0xFF, 0xD8, 0xFF],
            Some(&[0xFF, 0xD9]),
            1024 * 1024,
            true,
            SearchType::Forward,
        );
        state.set_search_specs(vec![jpeg_spec]).await;

        let result = search_buffer(&buffer, &state, &mut file_info, 0, 1).await;
        assert!(result.is_ok());
        assert_eq!(file_info.bytes_read, buffer.len());
    }

    #[tokio::test]
    async fn test_search_buffer_no_matches() {
        let (state, _temp_dir) = create_test_state().await;

        // Create a buffer without any recognizable signatures
        let buffer = vec![0x00; 100];

        let mut file_info = FileInfo {
            filename: "test.dat".to_string(),
            total_bytes: buffer.len(),
            total_megs: 0,
            bytes_read: 0,
            per_file_counter: 0,
        };

        // Set up JPEG search spec (won't find anything)
        let jpeg_spec = SearchSpec::new(
            FileType::Jpeg,
            "jpg",
            &[0xFF, 0xD8, 0xFF],
            None,
            1024 * 1024,
            true,
            SearchType::Forward,
        );
        state.set_search_specs(vec![jpeg_spec]).await;

        let result = search_buffer(&buffer, &state, &mut file_info, 0, 1).await;
        assert!(result.is_ok());
        assert_eq!(file_info.bytes_read, buffer.len());
        assert_eq!(state.get_fileswritten().await, 0);
    }

    #[tokio::test]
    async fn test_search_stream_with_progress() {
        let (state, _temp_dir) = create_test_state().await;

        // Create a temporary file with test data
        let temp_file = tempfile::NamedTempFile::new().unwrap();
        let test_data = vec![
            0x00, 0x00, 0x00, 0x00, // padding
            0xFF, 0xD8, 0xFF, 0xE0, // JPEG signature
            0x00, 0x10, 0x4A, 0x46, // JFIF
            0x49, 0x46, 0x00, 0x01, // more data
            0xFF, 0xD9, // end marker
        ];

        fs::write(temp_file.path(), &test_data).await.unwrap();
        let mut file = fs::File::open(temp_file.path()).await.unwrap();

        let mut file_info = FileInfo {
            filename: temp_file.path().to_string_lossy().to_string(),
            total_bytes: test_data.len(),
            total_megs: 0,
            bytes_read: 0,
            per_file_counter: 0,
        };

        // Set up JPEG search spec
        let jpeg_spec = SearchSpec::new(
            FileType::Jpeg,
            "jpg",
            &[0xFF, 0xD8, 0xFF],
            Some(&[0xFF, 0xD9]),
            1024 * 1024,
            true,
            SearchType::Forward,
        );
        state.set_search_specs(vec![jpeg_spec]).await;

        let progress_calls = std::sync::Arc::new(std::sync::Mutex::new(0));
        let progress_calls_clone = progress_calls.clone();
        let progress_callback = move |_position: u64| {
            *progress_calls_clone.lock().unwrap() += 1;
        };

        let result =
            search_stream_with_progress(&mut file, &state, &mut file_info, progress_callback, 1)
                .await;

        assert!(result.is_ok());
        assert!(*progress_calls.lock().unwrap() > 0);
    }

    #[tokio::test]
    async fn test_determine_file_size_heuristic() {
        // Test BMP file size determination
        let mut bmp_data = vec![0x42, 0x4D]; // BMP signature
        bmp_data.extend(&[0x36, 0x00, 0x00, 0x00]); // File size (54 bytes) in little endian
        bmp_data.resize(100, 0x00); // Pad with zeros

        let spec = SearchSpec::new(
            FileType::Bmp,
            "bmp",
            &[0x42, 0x4D],
            None,
            1024 * 1024,
            true,
            SearchType::Forward,
        );

        let size = determine_file_size_heuristic(&spec, &bmp_data);
        assert_eq!(size, 54);

        // Test EXE file (should use default heuristic)
        let exe_data = vec![0x4D, 0x5A]; // MZ signature
        let exe_spec = SearchSpec::new(
            FileType::Exe,
            "exe",
            &[0x4D, 0x5A],
            None,
            1024 * 1024,
            true,
            SearchType::Forward,
        );

        let exe_size = determine_file_size_heuristic(&exe_spec, &exe_data);
        assert_eq!(exe_size, 2); // Should be the buffer size since it's smaller than 64KB
    }

    #[tokio::test]
    async fn test_find_footer() {
        let data = b"Some data here\xFF\xD9and more data";
        let footer = &[0xFF, 0xD9];

        let pos = find_footer(data, footer, true);
        assert_eq!(pos, Some(14));

        // Test case insensitive (though not applicable to binary data)
        let pos_case_insensitive = find_footer(data, footer, false);
        assert_eq!(pos_case_insensitive, Some(14));

        // Test footer not found
        let pos_not_found = find_footer(b"no footer here", footer, true);
        assert_eq!(pos_not_found, None);
    }

    #[tokio::test]
    async fn test_extract_basic_file() {
        let (state, _temp_dir) = create_test_state().await;

        let test_data = b"test file content with footer\xFF\xD9";
        let spec = SearchSpec::new(
            FileType::Jpeg,
            "jpg",
            &[0xFF, 0xD8, 0xFF],
            Some(&[0xFF, 0xD9]),
            1024 * 1024,
            true,
            SearchType::Forward,
        );

        let mut file_info = FileInfo {
            filename: "test.dat".to_string(),
            total_bytes: test_data.len(),
            total_megs: 0,
            bytes_read: 0,
            per_file_counter: 0,
        };

        let result = extract_basic_file(&state, &spec, test_data, 0, &mut file_info, 1).await;
        assert!(result.is_ok());

        let extracted_size = result.unwrap();
        assert_eq!(extracted_size, 31); // Up to and including the footer
    }

    #[tokio::test]
    async fn test_write_to_disk() {
        let (state, temp_dir) = create_test_state().await;

        let test_data = b"test file content";
        let spec = SearchSpec::new(
            FileType::Jpeg,
            "jpg",
            &[0xFF, 0xD8, 0xFF],
            None,
            1024 * 1024,
            true,
            SearchType::Forward,
        );

        let mut file_info = FileInfo {
            filename: "input.dat".to_string(),
            total_bytes: 1000,
            total_megs: 0,
            bytes_read: 0,
            per_file_counter: 0,
        };

        let result = write_to_disk(&state, &spec, test_data, 42, &mut file_info, 1).await;
        assert!(result.is_ok());
        assert_eq!(file_info.per_file_counter, 1);

        // Check that file was written
        let expected_filename = "1-42.jpg";
        let filepath = temp_dir.path().join(expected_filename);
        assert!(filepath.exists());

        let written_content = fs::read(filepath).await.unwrap();
        assert_eq!(written_content, test_data);
    }

    #[tokio::test]
    async fn test_write_to_disk_with_prefix() {
        let (mut state, temp_dir) = create_test_state().await;

        // Enable filename prefixes
        state.config.prefix_filenames = true;

        let test_data = b"test file content";
        let spec = SearchSpec::new(
            FileType::Pdf,
            "pdf",
            b"%PDF-",
            None,
            1024 * 1024,
            true,
            SearchType::Forward,
        );

        let mut file_info = FileInfo {
            filename: "input_file.dat".to_string(),
            total_bytes: 1000,
            total_megs: 0,
            bytes_read: 0,
            per_file_counter: 0,
        };

        let result = write_to_disk(&state, &spec, test_data, 100, &mut file_info, 1).await;
        assert!(result.is_ok());

        // Check that file was written with prefix
        let expected_filename = "input_file_dat-1-100.pdf";
        let filepath = temp_dir.path().join(expected_filename);
        assert!(filepath.exists());
    }

    #[tokio::test]
    async fn test_setup_stream_info() {
        let (state, _temp_dir) = create_test_state().await;

        let file_info = FileInfo {
            filename: "test.dat".to_string(),
            total_bytes: 1024,
            total_megs: 1,
            bytes_read: 0,
            per_file_counter: 0,
        };

        let result = setup_stream_info(&state, &file_info).await;
        assert!(result.is_ok());

        // Test with unknown size
        let file_info_unknown = FileInfo {
            filename: "test.dat".to_string(),
            total_bytes: 0,
            total_megs: 0,
            bytes_read: 0,
            per_file_counter: 0,
        };

        let result_unknown = setup_stream_info(&state, &file_info_unknown).await;
        assert!(result_unknown.is_ok());
    }

    #[tokio::test]
    async fn test_audit_layout() {
        let (state, _temp_dir) = create_test_state().await;

        let result = audit_layout(&state).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_search_chunk_with_multiple_specs() {
        let (state, _temp_dir) = create_test_state().await;

        // Create buffer with both JPEG and PDF signatures
        let buffer = vec![
            0xFF, 0xD8, 0xFF, 0xE0, // JPEG signature at offset 0
            0x00, 0x10, 0x4A, 0x46, // JFIF
            b'%', b'P', b'D', b'F', b'-', b'1', b'.', b'4', // PDF signature at offset 8
            0xFF, 0xD9, // JPEG end
        ];

        let mut file_info = FileInfo {
            filename: "test.dat".to_string(),
            total_bytes: buffer.len(),
            total_megs: 0,
            bytes_read: 0,
            per_file_counter: 0,
        };

        // Set up both JPEG and PDF search specs
        let specs = vec![
            SearchSpec::new(
                FileType::Jpeg,
                "jpg",
                &[0xFF, 0xD8, 0xFF],
                Some(&[0xFF, 0xD9]),
                1024 * 1024,
                true,
                SearchType::Forward,
            ),
            SearchSpec::new(
                FileType::Pdf,
                "pdf",
                b"%PDF-",
                None,
                10 * 1024 * 1024,
                true,
                SearchType::Forward,
            ),
        ];
        state.set_search_specs(specs.clone()).await;
        let search_specs = state.get_search_specs().await;

        let result = search_chunk(&state, &search_specs, &buffer, &mut file_info, buffer.len(), 0, 1).await;
        assert!(result.is_ok());

        // Should have found both signatures
        assert!(state.get_fileswritten().await >= 1);
    }

    #[test]
    fn test_validate_exe_file_valid() {
        // Create a minimal valid PE executable structure
        let mut data = vec![0u8; 0x200]; // 512 bytes
        
        // DOS header starts with "MZ"
        data[0] = b'M';
        data[1] = b'Z';
        
        // Set e_lfanew to point to offset 0x100 (little-endian)
        data[0x3C] = 0x00;
        data[0x3D] = 0x01;
        data[0x3E] = 0x00;
        data[0x3F] = 0x00;
        
        // Place PE signature at offset 0x100
        data[0x100] = b'P';
        data[0x101] = b'E';
        data[0x102] = 0x00;
        data[0x103] = 0x00;
        
        assert!(validate_exe_file(&data));
    }

    #[test]
    fn test_validate_exe_file_invalid_pe_signature() {
        let mut data = vec![0u8; 0x200];
        
        // DOS header
        data[0] = b'M';
        data[1] = b'Z';
        
        // Set e_lfanew to point to offset 0x100
        data[0x3C] = 0x00;
        data[0x3D] = 0x01;
        data[0x3E] = 0x00;
        data[0x3F] = 0x00;
        
        // Place wrong signature at offset 0x100
        data[0x100] = b'X';
        data[0x101] = b'Y';
        data[0x102] = b'Z';
        data[0x103] = b'W';
        
        assert!(!validate_exe_file(&data));
    }

    #[test]
    fn test_validate_exe_file_invalid_offset() {
        let mut data = vec![0u8; 0x200];
        
        // DOS header
        data[0] = b'M';
        data[1] = b'Z';
        
        // Set e_lfanew to point beyond file end (little-endian)
        data[0x3C] = 0xFF;
        data[0x3D] = 0xFF;
        data[0x3E] = 0xFF;
        data[0x3F] = 0xFF;
        
        assert!(!validate_exe_file(&data));
    }

    #[test]
    fn test_validate_exe_file_too_small() {
        let data = vec![0u8; 0x30]; // Too small to contain e_lfanew
        assert!(!validate_exe_file(&data));
    }

    #[test]
    fn test_validate_file_candidate_exe() {
        use crate::types::{FileType, SearchSpec, SearchType};
        
        let spec = SearchSpec::new(
            FileType::Exe,
            "exe",
            b"MZ",
            None,
            1024 * 1024,
            true,
            SearchType::Forward,
        );
        
        // Valid EXE data
        let mut valid_data = vec![0u8; 0x200];
        valid_data[0] = b'M';
        valid_data[1] = b'Z';
        valid_data[0x3C] = 0x00;
        valid_data[0x3D] = 0x01;
        valid_data[0x3E] = 0x00;
        valid_data[0x3F] = 0x00;
        valid_data[0x100] = b'P';
        valid_data[0x101] = b'E';
        valid_data[0x102] = 0x00;
        valid_data[0x103] = 0x00;
        
        assert!(validate_file_candidate(&spec, &valid_data));
        
        // Invalid data
        let invalid_data = vec![0u8; 0x30];
        assert!(!validate_file_candidate(&spec, &invalid_data));
    }

    #[test]
    fn test_validate_file_candidate_other_types() {
        use crate::types::{FileType, SearchSpec, SearchType};
        
        let jpeg_spec = SearchSpec::new(
            FileType::Jpeg,
            "jpg",
            &[0xFF, 0xD8, 0xFF],
            Some(&[0xFF, 0xD9]),
            10 * 1024 * 1024,
            true,
            SearchType::Forward,
        );
        
        let data = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0xFF, 0xD9];
        
        // Should return true for non-EXE types (no validation yet)
        assert!(validate_file_candidate(&jpeg_spec, &data));
    }

    #[tokio::test]
    async fn test_validation_can_be_disabled() {
        use crate::types::{FileType, SearchSpec, SearchType, StateConfig};
        
        let temp_dir = TempDir::new().unwrap();
        
        // Create state with validation disabled
        let config = StateConfig {
            output_directory: temp_dir.path().to_string_lossy().to_string(),
            debug: false,
            prefix_filenames: false,
            chunk_size: None,
            block_size: None,
            skip: None,
            disable_validation: true,
        };
        let state = State::new(config).await.unwrap();
        
        // Create fake EXE data that would normally fail validation
        let mut fake_exe_data = vec![0u8; 0x200];
        fake_exe_data[0] = b'M';
        fake_exe_data[1] = b'Z';
        fake_exe_data[0x3C] = 0x00;
        fake_exe_data[0x3D] = 0x01;
        fake_exe_data[0x3E] = 0x00;
        fake_exe_data[0x3F] = 0x00;
        // Place invalid signature at offset 0x100
        fake_exe_data[0x100] = b'F';
        fake_exe_data[0x101] = b'A';
        fake_exe_data[0x102] = b'K';
        fake_exe_data[0x103] = b'E';
        
        let spec = SearchSpec::new(
            FileType::Exe,
            "exe",
            b"MZ",
            None,
            1024 * 1024,
            true,
            SearchType::Forward,
        );
        
        // Set search specs on the state
        state.set_search_specs(vec![spec.clone()]).await;
        
        let mut file_info = FileInfo {
            filename: "test.dat".to_string(),
            total_bytes: fake_exe_data.len(),
            total_megs: 0,
            bytes_read: 0,
            per_file_counter: 0,
        };
        
        // This should succeed because validation is disabled
        let result = extract_basic_file(&state, &spec, &fake_exe_data, 0, &mut file_info, 1).await;
        assert!(result.is_ok());
        let extracted_size = result.unwrap();
        
        // The key test: extraction should succeed when validation is disabled
        assert!(extracted_size > 0, "Should extract the file when validation is disabled");
        
        // Note: Files written counter is incremented in search_chunk, not extract_basic_file,
        // so we only check that the file was extracted (size > 0)
    }

    #[test]
    fn test_determine_zip_file_size_with_eocd() {
        use crate::types::{FileType, SearchSpec, SearchType};
        
        // Create a minimal ZIP file structure with EOCD
        let mut zip_data = Vec::new();
        
        // Local file header (PK\x03\x04)
        zip_data.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]); // Signature
        zip_data.extend_from_slice(&[0x14, 0x00]); // Version needed
        zip_data.extend_from_slice(&[0x00, 0x00]); // General purpose flag
        zip_data.extend_from_slice(&[0x00, 0x00]); // Compression method
        zip_data.extend_from_slice(&[0x00, 0x00]); // Last mod time
        zip_data.extend_from_slice(&[0x00, 0x00]); // Last mod date
        zip_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // CRC-32
        zip_data.extend_from_slice(&[0x05, 0x00, 0x00, 0x00]); // Compressed size (5 bytes)
        zip_data.extend_from_slice(&[0x05, 0x00, 0x00, 0x00]); // Uncompressed size (5 bytes)
        zip_data.extend_from_slice(&[0x08, 0x00]); // Filename length (8 bytes)
        zip_data.extend_from_slice(&[0x00, 0x00]); // Extra field length (0)
        zip_data.extend_from_slice(b"test.txt"); // Filename
        zip_data.extend_from_slice(b"hello"); // File data (5 bytes)
        
        // Central directory entry (PK\x01\x02)
        let central_dir_start = zip_data.len();
        zip_data.extend_from_slice(&[0x50, 0x4B, 0x01, 0x02]); // Signature
        zip_data.extend_from_slice(&[0x14, 0x00]); // Version made by
        zip_data.extend_from_slice(&[0x14, 0x00]); // Version needed
        zip_data.extend_from_slice(&[0x00, 0x00]); // General purpose flag
        zip_data.extend_from_slice(&[0x00, 0x00]); // Compression method
        zip_data.extend_from_slice(&[0x00, 0x00]); // Last mod time
        zip_data.extend_from_slice(&[0x00, 0x00]); // Last mod date
        zip_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // CRC-32
        zip_data.extend_from_slice(&[0x05, 0x00, 0x00, 0x00]); // Compressed size
        zip_data.extend_from_slice(&[0x05, 0x00, 0x00, 0x00]); // Uncompressed size
        zip_data.extend_from_slice(&[0x08, 0x00]); // Filename length
        zip_data.extend_from_slice(&[0x00, 0x00]); // Extra field length
        zip_data.extend_from_slice(&[0x00, 0x00]); // File comment length
        zip_data.extend_from_slice(&[0x00, 0x00]); // Disk number start
        zip_data.extend_from_slice(&[0x00, 0x00]); // Internal file attributes
        zip_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // External file attributes
        zip_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Relative offset of local header
        zip_data.extend_from_slice(b"test.txt"); // Filename
        
        // End of Central Directory (PK\x05\x06)
        let eocd_start = zip_data.len();
        zip_data.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]); // Signature
        zip_data.extend_from_slice(&[0x00, 0x00]); // Number of this disk
        zip_data.extend_from_slice(&[0x00, 0x00]); // Disk where central directory starts
        zip_data.extend_from_slice(&[0x01, 0x00]); // Number of central directory records on this disk
        zip_data.extend_from_slice(&[0x01, 0x00]); // Total number of central directory records
        
        let central_dir_size = eocd_start - central_dir_start;
        zip_data.extend_from_slice(&(central_dir_size as u32).to_le_bytes()); // Size of central directory
        zip_data.extend_from_slice(&(central_dir_start as u32).to_le_bytes()); // Offset of central directory
        zip_data.extend_from_slice(&[0x0A, 0x00]); // ZIP file comment length (10 bytes)
        zip_data.extend_from_slice(b"Test ZIP!!"); // ZIP file comment
        
        let expected_size = zip_data.len();
        
        let spec = SearchSpec::new(
            FileType::Zip,
            "zip",
            &[0x50, 0x4B, 0x03, 0x04],
            Some(&[0x50, 0x4B, 0x05, 0x06]),
            100 * 1024 * 1024,
            true,
            SearchType::Forward,
        );
        
        let calculated_size = determine_file_size_heuristic(&spec, &zip_data);
        assert_eq!(calculated_size, expected_size, "ZIP file size should be calculated correctly");
    }

    #[test]
    fn test_determine_zip_file_size_fallback() {
        use crate::types::{FileType, SearchSpec, SearchType};
        
        // Create ZIP data with local file header but no EOCD (corrupted/truncated)
        let mut zip_data = Vec::new();
        
        // Local file header (PK\x03\x04)
        zip_data.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]); // Signature
        zip_data.extend_from_slice(&[0x14, 0x00]); // Version needed
        zip_data.extend_from_slice(&[0x00, 0x00]); // General purpose flag
        zip_data.extend_from_slice(&[0x00, 0x00]); // Compression method
        zip_data.extend_from_slice(&[0x00, 0x00]); // Last mod time
        zip_data.extend_from_slice(&[0x00, 0x00]); // Last mod date
        zip_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // CRC-32
        zip_data.extend_from_slice(&[0x05, 0x00, 0x00, 0x00]); // Compressed size (5 bytes)
        zip_data.extend_from_slice(&[0x05, 0x00, 0x00, 0x00]); // Uncompressed size (5 bytes)
        zip_data.extend_from_slice(&[0x08, 0x00]); // Filename length (8 bytes)
        zip_data.extend_from_slice(&[0x00, 0x00]); // Extra field length (0)
        zip_data.extend_from_slice(b"test.txt"); // Filename
        zip_data.extend_from_slice(b"hello"); // File data (5 bytes)
        
        // Add some padding/garbage after the file
        zip_data.extend_from_slice(&[0x00; 100]);
        
        let expected_size = 30 + 8 + 5; // Header + filename + data
        
        let spec = SearchSpec::new(
            FileType::Zip,
            "zip",
            &[0x50, 0x4B, 0x03, 0x04],
            Some(&[0x50, 0x4B, 0x05, 0x06]),
            100 * 1024 * 1024,
            true,
            SearchType::Forward,
        );
        
        let calculated_size = determine_zip_file_size(&zip_data, spec.max_len);
        assert_eq!(calculated_size, expected_size, "ZIP fallback parsing should find end of last file");
    }

    #[test]
    fn test_parse_zip_local_header() {
        // Create a valid local file header
        let mut header_data = Vec::new();
        header_data.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]); // Signature
        header_data.extend_from_slice(&[0x14, 0x00]); // Version needed
        header_data.extend_from_slice(&[0x00, 0x00]); // General purpose flag
        header_data.extend_from_slice(&[0x00, 0x00]); // Compression method
        header_data.extend_from_slice(&[0x00, 0x00]); // Last mod time
        header_data.extend_from_slice(&[0x00, 0x00]); // Last mod date
        header_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // CRC-32
        header_data.extend_from_slice(&[0x0A, 0x00, 0x00, 0x00]); // Compressed size (10 bytes)
        header_data.extend_from_slice(&[0x0A, 0x00, 0x00, 0x00]); // Uncompressed size (10 bytes)
        header_data.extend_from_slice(&[0x04, 0x00]); // Filename length (4 bytes)
        header_data.extend_from_slice(&[0x02, 0x00]); // Extra field length (2 bytes)
        header_data.extend_from_slice(b"test"); // Filename (4 bytes)
        header_data.extend_from_slice(&[0x00, 0x00]); // Extra field (2 bytes)
        header_data.extend_from_slice(b"1234567890"); // File data (10 bytes)
        
        let result = parse_zip_local_header(&header_data, 0);
        assert!(result.is_some());
        
        let file_end = result.unwrap();
        let expected_end = 30 + 4 + 2 + 10; // Header + filename + extra + data
        assert_eq!(file_end, expected_end);
    }

    #[test]
    fn test_parse_zip_eocd_record() {
        // Create a valid EOCD record with comment
        let mut eocd_data = Vec::new();
        eocd_data.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]); // Signature
        eocd_data.extend_from_slice(&[0x00, 0x00]); // Number of this disk
        eocd_data.extend_from_slice(&[0x00, 0x00]); // Disk where central directory starts
        eocd_data.extend_from_slice(&[0x01, 0x00]); // Number of central directory records on this disk
        eocd_data.extend_from_slice(&[0x01, 0x00]); // Total number of central directory records
        eocd_data.extend_from_slice(&[0x2E, 0x00, 0x00, 0x00]); // Size of central directory
        eocd_data.extend_from_slice(&[0x43, 0x00, 0x00, 0x00]); // Offset of central directory
        eocd_data.extend_from_slice(&[0x05, 0x00]); // ZIP file comment length (5 bytes)
        eocd_data.extend_from_slice(b"hello"); // ZIP file comment
        
        let eocd_offset = 100;
        let result = parse_zip_eocd_record(&eocd_data, eocd_offset, 1000);
        
        let expected_size = eocd_offset + 22 + 5; // EOCD offset + EOCD header + comment
        assert_eq!(result, expected_size);
    }
}

