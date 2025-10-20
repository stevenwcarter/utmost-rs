use crate::{
    search::BoyerMoore,
    types::{FileInfo, Mode, SearchSpec, SearchType, State},
};
use anyhow::{Context, Result};
use indicatif::ProgressBar;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tracing::{debug, info};

/// Process a buffer directly (useful for stdin)
pub async fn search_buffer(
    buffer: &[u8],
    state: &mut State,
    file_info: &mut FileInfo,
    f_offset: u64,
    total_input_files: usize,
) -> Result<()> {
    setup_stream_info(state, file_info).await?;
    audit_layout(state).await?;

    info!("Searching buffer for file signatures...");
    debug!("Buffer size: {} bytes", buffer.len());

    // Search the buffer directly
    search_chunk(state, buffer, file_info, buffer.len(), f_offset, total_input_files).await?;

    file_info.bytes_read = buffer.len();
    debug!("Completed processing {} bytes", file_info.bytes_read);
    Ok(())
}

/// Set up stream information without file operations
async fn setup_stream_info(
    state: &State,
    file_info: &FileInfo,
) -> Result<()> {
    info!("Setting up stream for processing...");
    
    if file_info.total_bytes != 0 {
        state.audit_entry(&format!(
            "Length: {} ({} MB)",
            file_info.total_bytes,
            file_info.total_megs
        )).await?;
    } else {
        state.audit_entry("Length: Unknown").await?;
    }

    state.audit_entry(" ").await?;
    Ok(())
}
/// Process a file by searching for file signatures in chunks
pub async fn search_stream(
    input_file: &mut tokio::fs::File,
    state: &mut State,
    file_info: &mut FileInfo,
    total_input_files: usize,
) -> Result<()> {
    setup_stream(state, file_info, input_file).await?;
    audit_layout(state).await?;

    let chunk_size = state.chunk_size;
    let mut f_offset = 0u64;
    let mut buffer = vec![0u8; chunk_size];

    info!("Starting file signature search...");
    debug!("Chunk size: {} bytes", chunk_size);

    loop {
        // Read chunk from file
        let bytes_read = input_file.read(&mut buffer).await
            .context("Failed to read from input file")?;

        if bytes_read == 0 {
            break; // EOF reached
        }

        debug!("Read {} bytes at offset {}", bytes_read, f_offset);

        // Search this chunk for file signatures
        search_chunk(state, &buffer[..bytes_read], file_info, bytes_read, f_offset, total_input_files).await?;

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

/// Process a stream with progress bar support
pub async fn search_stream_with_progress(
    input_file: &mut tokio::fs::File,
    state: &mut State,
    file_info: &mut FileInfo,
    progress_bar: &ProgressBar,
    total_input_files: usize,
) -> Result<()> {
    setup_stream(state, file_info, input_file).await?;
    audit_layout(state).await?;

    let chunk_size = state.chunk_size;
    let mut f_offset = 0u64;
    let mut buffer = vec![0u8; chunk_size];

    info!("Starting file signature search...");
    debug!("Chunk size: {} bytes", chunk_size);

    loop {
        // Read chunk from file
        let bytes_read = input_file.read(&mut buffer).await
            .context("Failed to read from input file")?;

        if bytes_read == 0 {
            break; // EOF reached
        }

        debug!("Read {} bytes at offset {}", bytes_read, f_offset);

        // Search this chunk for file signatures
        search_chunk(state, &buffer[..bytes_read], file_info, bytes_read, f_offset, total_input_files).await?;

        f_offset += bytes_read as u64;
        file_info.bytes_read += bytes_read;

        // Update progress bar instead of printing * characters
        progress_bar.set_position(f_offset);

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
        state.audit_entry(&format!(
            "Length: {} ({} MB)",
            file_info.total_bytes,
            file_info.total_megs
        )).await?;
    } else {
        state.audit_entry("Length: Unknown").await?;
    }

    if state.skip > 0 {
        let skip_bytes = (state.skip as u64) * (state.block_size as u64);
        state.audit_entry(&format!("Skipping first {} bytes", skip_bytes)).await?;
        
        input_file.seek(tokio::io::SeekFrom::Start(skip_bytes)).await
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
    state.audit_entry(&format!(
        "Num\t {} (bs={})\t {}\t {}\t {} \n",
        "Name",
        state.block_size,
        "Size",
        "File Offset", 
        "Comment"
    )).await?;
    Ok(())
}

/// Search a chunk of data for file signatures
async fn search_chunk(
    state: &mut State,
    buf: &[u8],
    file_info: &mut FileInfo,
    chunk_size: usize,
    f_offset: u64,
    total_input_files: usize,
) -> Result<()> {
    debug!("Searching chunk of {} bytes at offset {}", chunk_size, f_offset);
    debug!("Number of search specs: {}", state.search_specs.len());

    // Check mode once to avoid borrowing issues
    let quick_mode = state.get_mode(Mode::Quick);
    let block_size = state.block_size;
    
    // Process each search spec
    let mut i = 0;
    while i < state.search_specs.len() {
        debug!("Processing search spec {}: {}", i, state.search_specs[i].suffix);
        let mut search_pos = 0;

        while search_pos < buf.len() {
            // Reset per-search state
            state.search_specs[i].written = false;
            state.search_specs[i].comment.clear();

            let found_pos = if quick_mode {
                // Quick mode: search only on block boundaries
                search_quick_mode(&state.search_specs[i], buf, search_pos, block_size)
            } else {
                // Standard Boyer-Moore search
                search_standard_mode(&state.search_specs[i], buf, search_pos)
            };

            if let Some(pos) = found_pos {
                // Clone the spec to avoid borrowing issues
                let spec = state.search_specs[i].clone();
                process_found_signature(state, &spec, buf, pos, f_offset, file_info, total_input_files).await?;
                search_pos = pos + spec.header_len;
            } else {
                break;
            }
        }
        i += 1;
    }

    Ok(())
}

/// Quick mode search (block-aligned)
fn search_quick_mode(spec: &SearchSpec, buf: &[u8], start_pos: usize, block_size: usize) -> Option<usize> {
    let mut pos = start_pos;
    
    // Align to block boundary
    let remainder = pos % block_size;
    if remainder != 0 {
        pos += block_size - remainder;
    }

    while pos + spec.header_len <= buf.len() {
        if crate::search::memwildcardcmp(&spec.header, &buf[pos..pos + spec.header_len], spec.case_sensitive) {
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

    debug!("Searching for {} header in {} bytes starting at pos {}", 
           spec.suffix, buf.len() - start_pos, start_pos);
    debug!("Header bytes: {:?}", spec.header);

    let searcher = BoyerMoore::new(&spec.header, spec.case_sensitive, spec.search_type);
    let result = searcher.search_from(&buf[start_pos..], 0).map(|pos| pos + start_pos);
    
    if let Some(pos) = result {
        debug!("Found {} header at position {}", spec.suffix, pos);
    } else {
        debug!("No {} header found", spec.suffix);
    }
    
    result
}

/// Process a found file signature
async fn process_found_signature(
    state: &mut State,
    spec: &SearchSpec,
    buf: &[u8],
    found_pos: usize,
    f_offset: u64,
    file_info: &mut FileInfo,
    total_input_files: usize,
) -> Result<()> {
    let absolute_offset = f_offset + found_pos as u64;
    
    debug!("Found {} signature at offset {}", spec.suffix, absolute_offset);
    
    // For now, just extract a basic header-based file
    let extracted_size = extract_basic_file(state, spec, buf, found_pos, file_info, total_input_files).await?;
    
    if extracted_size > 0 {
        let filename = format!("{}.{}", state.fileswritten + 1, spec.suffix);
        state.audit_entry(&format!(
            "{}\t {}\t {}\t {}\t {}",
            state.fileswritten + 1,
            filename,
            extracted_size,
            absolute_offset,
            spec.comment
        )).await?;
        
        state.fileswritten += 1;
        // Find the spec index and update found count
        for search_spec in &mut state.search_specs {
            if search_spec.file_type == spec.file_type {
                search_spec.found += 1;
                break;
            }
        }
    }

    Ok(())
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
    
    // Determine file size based on footer or max length
    let file_size = if let Some(ref footer) = spec.footer {
        if let Some(footer_pos) = find_footer(remaining_buf, footer, spec.case_sensitive) {
            footer_pos + footer.len()
        } else {
            // Fallback to maximum length or remaining buffer
            std::cmp::min(spec.max_len, remaining_buf.len())
        }
    } else {
        // No footer, use heuristics or max length
        determine_file_size_heuristic(spec, remaining_buf)
    };

    if file_size > 0 && file_size <= remaining_buf.len() {
        // Write file to disk
        write_to_disk(state, spec, &remaining_buf[..file_size], found_pos as u64, file_info, total_input_files).await?;
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
    use crate::types::clean_filename;

    // Increment per-file counter
    file_info.per_file_counter += 1;
    
    // Determine if we should include filename prefix
    let should_prefix = state.args.prefix_filenames || total_input_files > 1;
    
    let filename = if should_prefix {
        let cleaned_input_name = if file_info.filename == "stdin" {
            "stdin".to_string()
        } else {
            clean_filename(&file_info.filename, 30)
        };
        format!("{}-{}-{}.{}", cleaned_input_name, file_info.per_file_counter, offset, spec.suffix)
    } else {
        format!("{}-{}.{}", file_info.per_file_counter, offset, spec.suffix)
    };
    
    let filepath = format!("{}/{}", state.args.output_directory, filename);
    
    let mut file = tokio::fs::File::create(&filepath).await
        .with_context(|| format!("Failed to create output file: {}", filepath))?;
    
    file.write_all(data).await
        .with_context(|| format!("Failed to write data to file: {}", filepath))?;
    
    file.flush().await
        .with_context(|| format!("Failed to flush file: {}", filepath))?;

    info!("Extracted {} ({} bytes) at offset {}", filename, data.len(), offset);
    Ok(())
}