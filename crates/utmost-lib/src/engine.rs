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

    // Search the buffer directly
    search_chunk(
        state,
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

    let search_specs = state.get_search_specs().await;
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
                process_found_signature(
                    state,
                    &spec_clone,
                    buf,
                    pos,
                    f_offset,
                    file_info,
                    total_input_files,
                )
                .await?;
                search_pos = pos + spec.header_len;
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
async fn process_found_signature(
    state: &State,
    spec: &SearchSpec,
    buf: &[u8],
    found_pos: usize,
    f_offset: u64,
    file_info: &mut FileInfo,
    total_input_files: usize,
) -> Result<()> {
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
        write_to_disk(
            state,
            spec,
            &remaining_buf[..file_size],
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
        state.set_search_specs(specs).await;

        let result = search_chunk(&state, &buffer, &mut file_info, buffer.len(), 0, 1).await;
        assert!(result.is_ok());

        // Should have found both signatures
        assert!(state.get_fileswritten().await >= 1);
    }
}

