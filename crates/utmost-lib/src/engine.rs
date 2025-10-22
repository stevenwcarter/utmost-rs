use crate::{
    FileType,
    search::{BoyerMoore, memwildcardcmp},
    types::{FileInfo, Mode, SearchSpec, SearchType, State, clean_filename},
};
use anyhow::{Context, Result};
use std::{
    cmp,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
};
use tracing::{debug, info};

mod bmp;
mod exe;
mod mpg;
mod mov;
mod pdf;
mod zip;

use bmp::{bmp_file_size_heuristic, validate_bmp_file};
use exe::validate_exe_file;
use mpg::{mpg_file_size_heuristic, validate_mpg_file};
use mov::{mov_file_size_heuristic, validate_mov_file};
use pdf::determine_pdf_file_size;
use zip::determine_zip_file_size;

/// Process a buffer directly (useful for stdin)
pub fn search_buffer(
    buffer: &[u8],
    state: &State,
    file_info: &mut FileInfo,
    f_offset: u64,
    total_input_files: usize,
) -> Result<()> {
    setup_stream_info(state, file_info)?;
    audit_layout(state)?;

    info!("Searching buffer for file signatures...");
    debug!("Buffer size: {} bytes", buffer.len());

    // Get search specs once for buffer processing
    let search_specs = state.get_search_specs();

    // Search the buffer directly
    search_chunk(
        state,
        &search_specs,
        buffer,
        file_info,
        buffer.len(),
        f_offset,
        total_input_files,
    )?;

    file_info.bytes_read = buffer.len();
    debug!("Completed processing {} bytes", file_info.bytes_read);
    Ok(())
}

/// Set up stream information without file operations
fn setup_stream_info(state: &State, file_info: &FileInfo) -> Result<()> {
    info!("Setting up stream for processing...");

    if file_info.total_bytes != 0 {
        state.audit_entry(&format!(
            "Length: {} ({} MB)",
            file_info.total_bytes, file_info.total_megs
        ))?;
    } else {
        state.audit_entry("Length: Unknown")?;
    }

    state.audit_entry(" ")?;
    Ok(())
}

/// Process a file by searching for file signatures in chunks
pub fn search_stream(
    input_file: &mut File,
    state: &State,
    file_info: &mut FileInfo,
    total_input_files: usize,
) -> Result<()> {
    setup_stream(state, file_info, input_file)?;
    audit_layout(state)?;

    let chunk_size = state.chunk_size;
    let mut f_offset = 0u64;
    let mut buffer = vec![0u8; chunk_size];

    // Get search specs once at the beginning to avoid locking on every chunk
    let search_specs = state.get_search_specs();

    info!("Starting file signature search...");
    debug!("Chunk size: {} bytes", chunk_size);

    loop {
        // Read chunk from file
        let bytes_read = input_file
            .read(&mut buffer)
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
        )?;

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
pub fn search_stream_with_progress<F>(
    input_file: &mut File,
    state: &State,
    file_info: &mut FileInfo,
    progress_callback: F,
    total_input_files: usize,
) -> Result<()>
where
    F: Fn(u64) + Send + Sync,
{
    setup_stream(state, file_info, input_file)?;
    audit_layout(state)?;

    let chunk_size = state.chunk_size;
    let mut f_offset = 0u64;
    let mut buffer = vec![0u8; chunk_size];

    // Get search specs once at the beginning to avoid locking on every chunk
    let search_specs = state.get_search_specs();

    info!("Starting file signature search...");
    debug!("Chunk size: {} bytes", chunk_size);

    loop {
        // Read chunk from file
        let bytes_read = input_file
            .read(&mut buffer)
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
        )?;

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
fn setup_stream(state: &State, file_info: &mut FileInfo, input_file: &mut File) -> Result<()> {
    info!("Setting up stream for processing...");

    if file_info.total_bytes != 0 {
        state.audit_entry(&format!(
            "Length: {} ({} MB)",
            file_info.total_bytes, file_info.total_megs
        ))?;
    } else {
        state.audit_entry("Length: Unknown")?;
    }

    if state.skip > 0 {
        let skip_bytes = (state.skip as u64) * (state.block_size as u64);
        state.audit_entry(&format!("Skipping first {} bytes", skip_bytes))?;

        input_file
            .seek(SeekFrom::Start(skip_bytes))
            .context("Failed to seek to skip position")?;

        if file_info.total_bytes > skip_bytes as usize {
            file_info.total_bytes -= skip_bytes as usize;
        }
    }

    state.audit_entry(" ")?;
    Ok(())
}

/// Write audit layout header
fn audit_layout(state: &State) -> Result<()> {
    state.audit_entry(&format!(
        "Num\t {} (bs={})\t {}\t {}\t {} \n",
        "Name", state.block_size, "Size", "File Offset", "Comment"
    ))?;
    Ok(())
}

/// Search a chunk of data for file signatures
fn search_chunk(
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
                )?;

                // For ZIP files, skip ahead by the extracted size to avoid
                // finding internal PK signatures within the same ZIP file
                let advance_by = if extracted_size > 0 && spec.file_type == FileType::Zip {
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
        if memwildcardcmp(
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
fn process_found_signature(
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
        extract_basic_file(state, spec, buf, found_pos, file_info, total_input_files)?;

    if extracted_size > 0 {
        let new_file_number = state.increment_fileswritten();
        let filename = format!("{}.{}", new_file_number, spec.suffix);
        state.audit_entry(&format!(
            "{}\t {}\t {}\t {}\t {}",
            new_file_number, filename, extracted_size, absolute_offset, spec.comment
        ))?;

        // Update found count for this file type
        state.increment_found_count(spec.file_type);
    }

    Ok(extracted_size)
}

/// Perform additional validation checks for specific file types
/// Returns true if the file passes validation, false otherwise
fn validate_file_candidate(spec: &SearchSpec, data: &[u8]) -> bool {
    match spec.file_type {
        FileType::Exe => validate_exe_file(data),
        FileType::Bmp => validate_bmp_file(data),
        FileType::Mpg => validate_mpg_file(data),
        FileType::Mov => validate_mov_file(data),
        // Add more validation functions here as needed
        _ => true,
    }
}

/// Basic file extraction (simplified version)
fn extract_basic_file(
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
        FileType::Zip => {
            // ZIP files need special parsing to find the actual end
            determine_zip_file_size(remaining_buf, spec.max_len)
        }
        FileType::Pdf => {
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
                    cmp::min(spec.max_len, remaining_buf.len())
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
        )?;
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
        FileType::Bmp => bmp_file_size_heuristic(spec, buf),
        FileType::Mpg => mpg_file_size_heuristic(spec, buf),
        FileType::Mov => mov_file_size_heuristic(spec, buf),
        FileType::Exe => {
            // For EXE files, use a conservative estimate
            cmp::min(64 * 1024, buf.len()) // 64KB default
        }
        _ => {
            // Default: search up to max_len or use remaining buffer
            cmp::min(spec.max_len, buf.len())
        }
    }
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
    (0..=buf.len().saturating_sub(pattern.len())).find(|&i| buf[i..i + pattern.len()] == *pattern)
}

/// Write extracted file to disk
fn write_to_disk(
    state: &State,
    spec: &SearchSpec,
    data: &[u8],
    offset: u64,
    file_info: &mut FileInfo,
    total_input_files: usize,
) -> Result<()> {
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

    let mut file = File::create(&filepath)
        .with_context(|| format!("Failed to create output file: {}", filepath))?;

    file.write_all(data)
        .with_context(|| format!("Failed to write data to file: {}", filepath))?;

    file.flush()
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
    use std::fs;
    use tempfile::TempDir;

    fn create_test_state() -> (State, TempDir) {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let config = StateConfig {
            output_directory: temp_dir.path().to_string_lossy().to_string(),
            debug: false,
            prefix_filenames: false,
            chunk_size: Some(1), // 1MB for testing
            block_size: Some(512),
            skip: Some(0),
            disable_validation: false,
        };

        let state = State::new(config).expect("Failed to create state");
        (state, temp_dir)
    }

    #[test]
    fn test_search_buffer_basic() {
        let (state, _temp_dir) = create_test_state();

        // Create a test buffer with a JPEG signature
        let mut buffer = vec![0u8; 1024];
        // JPEG header: FF D8 FF E0
        buffer[100] = 0xFF;
        buffer[101] = 0xD8;
        buffer[102] = 0xFF;
        buffer[103] = 0xE0;
        // JPEG footer: FF D9
        buffer[200] = 0xFF;
        buffer[201] = 0xD9;

        let mut file_info = FileInfo {
            filename: "test.jpg".to_string(),
            total_bytes: buffer.len(),
            total_megs: 1,
            bytes_read: 0,
            per_file_counter: 0,
        };

        let jpeg_spec = SearchSpec::new(
            FileType::Jpeg,
            "jpg",
            &[0xFF, 0xD8, 0xFF, 0xE0],
            Some(&[0xFF, 0xD9]),
            10 * 1024 * 1024,
            true,
            SearchType::Forward,
        );

        state.set_search_specs(vec![jpeg_spec]);

        let result = search_buffer(&buffer, &state, &mut file_info, 0, 1);
        assert!(result.is_ok());
        assert_eq!(file_info.bytes_read, buffer.len());
        assert!(state.get_fileswritten() > 0);
    }

    #[test]
    fn test_search_buffer_no_matches() {
        let (state, _temp_dir) = create_test_state();

        // Create a test buffer with no signatures
        let buffer = vec![0u8; 1024];

        let mut file_info = FileInfo {
            filename: "test.bin".to_string(),
            total_bytes: buffer.len(),
            total_megs: 1,
            bytes_read: 0,
            per_file_counter: 0,
        };

        let jpeg_spec = SearchSpec::new(
            FileType::Jpeg,
            "jpg",
            &[0xFF, 0xD8, 0xFF, 0xE0],
            Some(&[0xFF, 0xD9]),
            10 * 1024 * 1024,
            true,
            SearchType::Forward,
        );

        state.set_search_specs(vec![jpeg_spec]);

        let result = search_buffer(&buffer, &state, &mut file_info, 0, 1);
        assert!(result.is_ok());
        assert_eq!(file_info.bytes_read, buffer.len());
        assert_eq!(state.get_fileswritten(), 0);
    }

    #[test]
    fn test_search_stream_with_progress() {
        let (state, temp_dir) = create_test_state();

        // Create a test file with a JPEG signature
        let test_file_path = temp_dir.path().join("test.bin");
        let mut test_data = vec![0u8; 2048];
        // JPEG header: FF D8 FF E0
        test_data[500] = 0xFF;
        test_data[501] = 0xD8;
        test_data[502] = 0xFF;
        test_data[503] = 0xE0;
        // JPEG footer: FF D9
        test_data[600] = 0xFF;
        test_data[601] = 0xD9;

        fs::write(&test_file_path, &test_data).expect("Failed to write test file");

        let mut file = File::open(&test_file_path).expect("Failed to open test file");

        let mut file_info = FileInfo {
            filename: "test.bin".to_string(),
            total_bytes: test_data.len(),
            total_megs: 1,
            bytes_read: 0,
            per_file_counter: 0,
        };

        let jpeg_spec = SearchSpec::new(
            FileType::Jpeg,
            "jpg",
            &[0xFF, 0xD8, 0xFF, 0xE0],
            Some(&[0xFF, 0xD9]),
            10 * 1024 * 1024,
            true,
            SearchType::Forward,
        );

        state.set_search_specs(vec![jpeg_spec]);

        let progress_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let progress_calls_clone = progress_calls.clone();
        let progress_callback = move |_offset: u64| {
            progress_calls_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        };

        let result =
            search_stream_with_progress(&mut file, &state, &mut file_info, progress_callback, 1);

        assert!(result.is_ok());
        assert_eq!(file_info.bytes_read, test_data.len());
        assert!(state.get_fileswritten() > 0);
    }

    #[test]
    fn test_determine_file_size_heuristic() {
        // Test BMP file size determination
        let mut bmp_data = vec![0u8; 100];
        // BMP signature
        bmp_data[0] = b'B';
        bmp_data[1] = b'M';
        // File size at offset 2 (little-endian)
        bmp_data[2] = 0x64; // 100 bytes
        bmp_data[3] = 0x00;
        bmp_data[4] = 0x00;
        bmp_data[5] = 0x00;

        let bmp_spec = SearchSpec::new(
            FileType::Bmp,
            "bmp",
            b"BM",
            None,
            10 * 1024 * 1024,
            true,
            SearchType::Forward,
        );

        let size = determine_file_size_heuristic(&bmp_spec, &bmp_data);
        assert_eq!(size, 100);

        // Test EXE file size determination (should be conservative)
        let exe_data = vec![0u8; 1024];
        let exe_spec = SearchSpec::new(
            FileType::Exe,
            "exe",
            b"MZ",
            None,
            10 * 1024 * 1024,
            true,
            SearchType::Forward,
        );

        let size = determine_file_size_heuristic(&exe_spec, &exe_data);
        assert_eq!(size, 1024); // Should use remaining buffer size
    }

    #[test]
    fn test_find_footer() {
        let data = b"Hello World\xFF\xD9End";
        let footer = &[0xFF, 0xD9];

        let pos = find_footer(data, footer, true);
        assert_eq!(pos, Some(11));

        // Test case insensitive
        let data = b"hello world\xff\xd9end";
        let pos = find_footer(data, footer, false);
        assert_eq!(pos, Some(11));

        // Test not found
        let data = b"Hello World End";
        let pos = find_footer(data, footer, true);
        assert_eq!(pos, None);
    }

    #[test]
    fn test_extract_basic_file() {
        let (state, _temp_dir) = create_test_state();

        // Create test data with JPEG signature and footer
        let mut buffer = vec![0u8; 1024];
        buffer[0] = 0xFF;
        buffer[1] = 0xD8;
        buffer[2] = 0xFF;
        buffer[3] = 0xE0;
        buffer[100] = 0xFF; // Footer
        buffer[101] = 0xD9;

        let jpeg_spec = SearchSpec::new(
            FileType::Jpeg,
            "jpg",
            &[0xFF, 0xD8, 0xFF, 0xE0],
            Some(&[0xFF, 0xD9]),
            10 * 1024 * 1024,
            true,
            SearchType::Forward,
        );

        let mut file_info = FileInfo {
            filename: "test.bin".to_string(),
            total_bytes: buffer.len(),
            total_megs: 1,
            bytes_read: 0,
            per_file_counter: 0,
        };

        let size = extract_basic_file(&state, &jpeg_spec, &buffer, 0, &mut file_info, 1);
        assert!(size.is_ok());
        let extracted_size = size.unwrap();
        assert_eq!(extracted_size, 102); // Header to footer + footer length
    }

    #[test]
    fn test_write_to_disk() {
        let (state, temp_dir) = create_test_state();

        let test_data = b"Test file content";
        let jpeg_spec = SearchSpec::new(
            FileType::Jpeg,
            "jpg",
            &[0xFF, 0xD8, 0xFF, 0xE0],
            Some(&[0xFF, 0xD9]),
            10 * 1024 * 1024,
            true,
            SearchType::Forward,
        );

        let mut file_info = FileInfo {
            filename: "test.bin".to_string(),
            total_bytes: 1024,
            total_megs: 1,
            bytes_read: 0,
            per_file_counter: 0,
        };

        let result = write_to_disk(&state, &jpeg_spec, test_data, 100, &mut file_info, 1);
        assert!(result.is_ok());

        // Check that file was created
        let expected_filename = "1-100.jpg";
        let file_path = temp_dir.path().join(expected_filename);
        assert!(file_path.exists());

        let written_data = fs::read(&file_path).expect("Failed to read written file");
        assert_eq!(written_data, test_data);
    }

    #[test]
    fn test_write_to_disk_with_prefix() {
        let (mut state, temp_dir) = create_test_state();
        state.config.prefix_filenames = true;

        let test_data = b"Test file content";
        let jpeg_spec = SearchSpec::new(
            FileType::Jpeg,
            "jpg",
            &[0xFF, 0xD8, 0xFF, 0xE0],
            Some(&[0xFF, 0xD9]),
            10 * 1024 * 1024,
            true,
            SearchType::Forward,
        );

        let mut file_info = FileInfo {
            filename: "input_file.dat".to_string(),
            total_bytes: 1024,
            total_megs: 1,
            bytes_read: 0,
            per_file_counter: 0,
        };

        let result = write_to_disk(&state, &jpeg_spec, test_data, 100, &mut file_info, 1);
        assert!(result.is_ok());

        // Check that file was created with prefix
        let expected_filename = "input_file_dat-1-100.jpg";
        let file_path = temp_dir.path().join(expected_filename);
        assert!(file_path.exists());

        let written_data = fs::read(&file_path).expect("Failed to read written file");
        assert_eq!(written_data, test_data);
    }

    #[test]
    fn test_setup_stream_info() {
        let (state, _temp_dir) = create_test_state();

        let file_info = FileInfo {
            filename: "test.bin".to_string(),
            total_bytes: 1024,
            total_megs: 1,
            bytes_read: 0,
            per_file_counter: 0,
        };

        let result = setup_stream_info(&state, &file_info);
        assert!(result.is_ok());
    }

    #[test]
    fn test_audit_layout() {
        let (state, _temp_dir) = create_test_state();
        let result = audit_layout(&state);
        assert!(result.is_ok());
    }

    #[test]
    fn test_search_chunk_with_multiple_specs() {
        let (state, _temp_dir) = create_test_state();

        // Create test buffer with multiple file signatures
        let mut buffer = vec![0u8; 2048];

        // JPEG signature at offset 100
        buffer[100] = 0xFF;
        buffer[101] = 0xD8;
        buffer[102] = 0xFF;
        buffer[103] = 0xE0;

        // PDF signature at offset 500
        buffer[500] = b'%';
        buffer[501] = b'P';
        buffer[502] = b'D';
        buffer[503] = b'F';
        buffer[504] = b'-';

        let mut file_info = FileInfo {
            filename: "test.bin".to_string(),
            total_bytes: buffer.len(),
            total_megs: 2,
            bytes_read: 0,
            per_file_counter: 0,
        };

        let jpeg_spec = SearchSpec::new(
            FileType::Jpeg,
            "jpg",
            &[0xFF, 0xD8, 0xFF, 0xE0],
            Some(&[0xFF, 0xD9]),
            10 * 1024 * 1024,
            true,
            SearchType::Forward,
        );

        let pdf_spec = SearchSpec::new(
            FileType::Pdf,
            "pdf",
            b"%PDF-",
            None,
            10 * 1024 * 1024,
            true,
            SearchType::Forward,
        );

        let search_specs = vec![jpeg_spec, pdf_spec];

        let result = search_chunk(
            &state,
            &search_specs,
            &buffer,
            &mut file_info,
            buffer.len(),
            0,
            1,
        );

        assert!(result.is_ok());
        // Should find both signatures
        assert!(state.get_fileswritten() >= 2);
    }

    #[test]
    fn test_validate_exe_file_valid() {
        // Create a minimal valid PE file structure
        let mut exe_data = vec![0u8; 0x100];

        // DOS header
        exe_data[0] = b'M';
        exe_data[1] = b'Z';

        // e_lfanew at offset 0x3C points to PE header at offset 0x80
        exe_data[0x3C] = 0x80;
        exe_data[0x3D] = 0x00;
        exe_data[0x3E] = 0x00;
        exe_data[0x3F] = 0x00;

        // PE signature at offset 0x80
        exe_data[0x80] = b'P';
        exe_data[0x81] = b'E';
        exe_data[0x82] = 0x00;
        exe_data[0x83] = 0x00;

        assert!(validate_exe_file(&exe_data));
    }

    #[test]
    fn test_validate_exe_file_invalid_pe_signature() {
        // Create an invalid PE file with wrong signature
        let mut exe_data = vec![0u8; 0x100];

        // DOS header
        exe_data[0] = b'M';
        exe_data[1] = b'Z';

        // e_lfanew at offset 0x3C
        exe_data[0x3C] = 0x80;
        exe_data[0x3D] = 0x00;
        exe_data[0x3E] = 0x00;
        exe_data[0x3F] = 0x00;

        // Invalid PE signature at offset 0x80
        exe_data[0x80] = b'X';
        exe_data[0x81] = b'Y';
        exe_data[0x82] = 0x00;
        exe_data[0x83] = 0x00;

        assert!(!validate_exe_file(&exe_data));
    }

    #[test]
    fn test_validate_exe_file_invalid_offset() {
        // Create an invalid PE file with out-of-bounds e_lfanew
        let mut exe_data = vec![0u8; 0x50];

        // DOS header
        exe_data[0] = b'M';
        exe_data[1] = b'Z';

        // e_lfanew pointing beyond buffer
        exe_data[0x3C] = 0xFF;
        exe_data[0x3D] = 0xFF;
        exe_data[0x3E] = 0xFF;
        exe_data[0x3F] = 0xFF;

        assert!(!validate_exe_file(&exe_data));
    }

    #[test]
    fn test_validate_exe_file_too_small() {
        let exe_data = vec![0u8; 0x30]; // Too small for DOS header
        assert!(!validate_exe_file(&exe_data));
    }

    #[test]
    fn test_validate_file_candidate_exe() {
        // Create a valid EXE file candidate
        let mut exe_data = vec![0u8; 0x100];

        // DOS header
        exe_data[0] = b'M';
        exe_data[1] = b'Z';

        // e_lfanew
        exe_data[0x3C] = 0x80;
        exe_data[0x3D] = 0x00;
        exe_data[0x3E] = 0x00;
        exe_data[0x3F] = 0x00;

        // PE signature
        exe_data[0x80] = b'P';
        exe_data[0x81] = b'E';
        exe_data[0x82] = 0x00;
        exe_data[0x83] = 0x00;

        let exe_spec = SearchSpec::new(
            FileType::Exe,
            "exe",
            b"MZ",
            None,
            10 * 1024 * 1024,
            true,
            SearchType::Forward,
        );

        assert!(validate_file_candidate(&exe_spec, &exe_data));

        // Test with invalid EXE
        let invalid_exe_data = vec![0u8; 0x30];
        assert!(!validate_file_candidate(&exe_spec, &invalid_exe_data));
    }

    #[test]
    fn test_validate_file_candidate_bmp() {
        // Create a valid BMP file candidate
        let mut valid_bmp_data = vec![0u8; 54];
        
        // BMP signature
        valid_bmp_data[0] = b'B';
        valid_bmp_data[1] = b'M';
        
        // File size (54 bytes)
        valid_bmp_data[2] = 54;
        valid_bmp_data[3] = 0;
        valid_bmp_data[4] = 0;
        valid_bmp_data[5] = 0;
        
        // Offset to pixel data (54 bytes)
        valid_bmp_data[10] = 54;
        valid_bmp_data[11] = 0;
        valid_bmp_data[12] = 0;
        valid_bmp_data[13] = 0;
        
        // DIB header size (40 bytes)
        valid_bmp_data[14] = 40;
        valid_bmp_data[15] = 0;
        valid_bmp_data[16] = 0;
        valid_bmp_data[17] = 0;
        
        // Width (100 pixels)
        valid_bmp_data[18] = 100;
        valid_bmp_data[19] = 0;
        valid_bmp_data[20] = 0;
        valid_bmp_data[21] = 0;
        
        // Height (100 pixels)
        valid_bmp_data[22] = 100;
        valid_bmp_data[23] = 0;
        valid_bmp_data[24] = 0;
        valid_bmp_data[25] = 0;
        
        // Color planes (1)
        valid_bmp_data[26] = 1;
        valid_bmp_data[27] = 0;
        
        // Bits per pixel (24)
        valid_bmp_data[28] = 24;
        valid_bmp_data[29] = 0;

        let bmp_spec = SearchSpec::new(
            FileType::Bmp,
            "bmp",
            b"BM",
            None,
            10 * 1024 * 1024,
            true,
            SearchType::Forward,
        );

        assert!(validate_file_candidate(&bmp_spec, &valid_bmp_data));

        // Test with invalid BMP (too small)
        let invalid_bmp_data = vec![b'B', b'M', 0, 0]; // Only 4 bytes
        assert!(!validate_file_candidate(&bmp_spec, &invalid_bmp_data));

        // Test with invalid BMP (wrong signature in validation, though this shouldn't happen in practice)
        let mut invalid_bmp_data2 = valid_bmp_data.clone();
        invalid_bmp_data2[0] = b'X';
        assert!(!validate_file_candidate(&bmp_spec, &invalid_bmp_data2));
    }

    #[test]
    fn test_validate_file_candidate_mpg() {
        // Create a valid MPEG-1 file candidate
        let valid_mpg_data = vec![
            0x00, 0x00, 0x01, 0xBA, // Pack start code
            0x21,                   // '0010' + SCR bits + marker
            0x00, 0x01,            // SCR + marker
            0x80, 0x01,            // SCR + marker  
            0x00, 0x01,            // mux_rate + marker
            0x00,                   // mux_rate continued
            // Additional data to make it look like a real stream
            0x00, 0x00, 0x01, 0xE0, // Video stream start
            0x00, 0x10,            // Packet length
            0x80, 0x00, 0x05,      // Packet header
            0x00, 0x00, 0x00, 0x00, 0x00, // Dummy data
        ];

        let mpg_spec = SearchSpec::new(
            FileType::Mpg,
            "mpg",
            &[0x00, 0x00, 0x01, 0xBA],
            Some(&[0x00, 0x00, 0x01, 0xB9]),
            50 * 1024 * 1024,
            true,
            SearchType::Forward,
        );

        assert!(validate_file_candidate(&mpg_spec, &valid_mpg_data));

        // Test with invalid MPG (too small)
        let invalid_mpg_data = vec![0x00, 0x00, 0x01, 0xBA, 0x20]; // Only 5 bytes
        assert!(!validate_file_candidate(&mpg_spec, &invalid_mpg_data));

        // Test with invalid MPG (wrong start code)
        let mut invalid_mpg_data2 = valid_mpg_data.clone();
        invalid_mpg_data2[3] = 0xBB; // Wrong start code
        assert!(!validate_file_candidate(&mpg_spec, &invalid_mpg_data2));
    }

    #[test]
    fn test_validate_file_candidate_mov() {
        // Create a valid MOV file candidate - this is complex, so let's simplify
        let mut valid_mov_data = Vec::new();
        
        // Simple but valid moov atom with minimal structure
        // moov atom size: 8 (header) + 108 (mvhd) + 48 (trak) = 164
        valid_mov_data.extend_from_slice(&164u32.to_be_bytes()); // moov size
        valid_mov_data.extend_from_slice(b"moov");               // moov type
        
        // mvhd atom (simplified)
        valid_mov_data.extend_from_slice(&108u32.to_be_bytes()); // mvhd size
        valid_mov_data.extend_from_slice(b"mvhd");               // mvhd type
        valid_mov_data.push(0);                                  // version
        valid_mov_data.extend_from_slice(&[0, 0, 0]);           // flags
        valid_mov_data.extend_from_slice(&123456u32.to_be_bytes()); // creation_time
        valid_mov_data.extend_from_slice(&123457u32.to_be_bytes()); // modification_time
        valid_mov_data.extend_from_slice(&1000u32.to_be_bytes());   // time_scale
        valid_mov_data.extend_from_slice(&30000u32.to_be_bytes());  // duration
        valid_mov_data.extend_from_slice(&[0; 80]);              // Fill remaining mvhd fields
        
        // Simplified trak atom (needs to be bigger to accommodate tkhd minimum 32 bytes)
        valid_mov_data.extend_from_slice(&48u32.to_be_bytes());  // trak size (increased)
        valid_mov_data.extend_from_slice(b"trak");               // trak type
        
        // Simplified tkhd within trak (minimum 32 bytes)
        valid_mov_data.extend_from_slice(&32u32.to_be_bytes());  // tkhd size  
        valid_mov_data.extend_from_slice(b"tkhd");               // tkhd type
        valid_mov_data.extend_from_slice(&[0; 24]);              // tkhd data (24 bytes)
        
        // Simplified mdia within trak  
        valid_mov_data.extend_from_slice(&8u32.to_be_bytes());   // mdia size
        valid_mov_data.extend_from_slice(b"mdia");               // mdia type

        let mov_spec = SearchSpec::new(
            FileType::Mov,
            "mov",
            b"moov",
            None,
            40 * 1024 * 1024,
            true,
            SearchType::Forward,
        );

        assert!(validate_file_candidate(&mov_spec, &valid_mov_data));

        // Test with invalid MOV (too small)
        let invalid_mov_data = vec![b'm', b'o', b'o', b'v']; // Only 4 bytes
        assert!(!validate_file_candidate(&mov_spec, &invalid_mov_data));

        // Test with invalid MOV (no valid moov structure)
        let invalid_mov_data2 = vec![
            0x00, 0x00, 0x00, 0x10, // size
            b'f', b'r', b'e', b'e', // type (not moov)
            0x00, 0x00, 0x00, 0x00, // data
            0x00, 0x00, 0x00, 0x00,
        ];
        assert!(!validate_file_candidate(&mov_spec, &invalid_mov_data2));
    }

    #[test]
    fn test_validate_file_candidate_other_types() {
        // For file types without specific validation (non-EXE, non-BMP, non-MPG, non-MOV), validation should always pass
        let test_data = vec![0u8; 100];

        let jpeg_spec = SearchSpec::new(
            FileType::Jpeg,
            "jpg",
            &[0xFF, 0xD8, 0xFF, 0xE0],
            Some(&[0xFF, 0xD9]),
            10 * 1024 * 1024,
            true,
            SearchType::Forward,
        );

        assert!(validate_file_candidate(&jpeg_spec, &test_data));

        let pdf_spec = SearchSpec::new(
            FileType::Pdf,
            "pdf",
            b"%PDF-",
            None,
            10 * 1024 * 1024,
            true,
            SearchType::Forward,
        );

        assert!(validate_file_candidate(&pdf_spec, &test_data));
    }

    #[test]
    fn test_validation_can_be_disabled() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let config = StateConfig {
            output_directory: temp_dir.path().to_string_lossy().to_string(),
            debug: false,
            prefix_filenames: false,
            chunk_size: Some(1),
            block_size: Some(512),
            skip: Some(0),
            disable_validation: true, // Validation disabled
        };

        let state = State::new(config).expect("Failed to create state");

        // Create invalid EXE data
        let invalid_exe_data = [0u8; 0x30];

        let exe_spec = SearchSpec::new(
            FileType::Exe,
            "exe",
            b"MZ",
            None,
            10 * 1024 * 1024,
            true,
            SearchType::Forward,
        );

        let mut file_info = FileInfo {
            filename: "test.exe".to_string(),
            total_bytes: invalid_exe_data.len(),
            total_megs: 1,
            bytes_read: 0,
            per_file_counter: 0,
        };

        // Create buffer with MZ signature but invalid PE structure
        let mut buffer = vec![0u8; 1024];
        buffer[0] = b'M';
        buffer[1] = b'Z';
        // Rest is zeros (invalid)

        let result = extract_basic_file(&state, &exe_spec, &buffer, 0, &mut file_info, 1);
        assert!(result.is_ok());

        // With validation disabled, the file should be extracted even if invalid
        let extracted_size = result.unwrap();
        assert!(extracted_size > 0);
    }
}
