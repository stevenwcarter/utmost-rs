use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Instant};
use tokio::sync::Mutex;

// Custom serialization helpers for byte arrays
mod serde_bytes_as_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(bytes.iter())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<u8>::deserialize(deserializer)
    }
}

mod serde_optional_bytes_as_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(b) => serializer.collect_seq(b.iter()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<Vec<u8>>::deserialize(deserializer)
    }
}

mod serde_marker_bytes_as_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(bytes.iter())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<u8>::deserialize(deserializer)
    }
}

/// Configuration for creating a State
#[derive(Debug, Clone)]
pub struct StateConfig {
    pub output_directory: String,
    pub debug: bool,
    pub prefix_filenames: bool,
    pub chunk_size: Option<usize>,
    pub block_size: Option<usize>,
    pub skip: Option<usize>,
}

/// Core state structure that mirrors the C f_state
#[derive(Clone)]
pub struct State {
    pub config: StateConfig,
    pub audit_file: Arc<Mutex<tokio::fs::File>>,
    pub chunk_size: usize,
    pub fileswritten: Arc<Mutex<usize>>,
    pub block_size: usize,
    pub skip: usize,
    pub start_time: Instant,
    pub time_stamp: Instant,
    pub num_builtin: usize,
    pub search_specs: Arc<Mutex<Vec<SearchSpec>>>,
}

/// File information structure that mirrors the C f_info
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub filename: String,
    pub total_bytes: usize,
    pub total_megs: usize,
    pub bytes_read: usize,
    pub per_file_counter: usize,
}

/// Search specification for file types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchSpec {
    pub file_type: FileType,
    pub suffix: String,
    pub max_len: usize,
    #[serde(with = "serde_bytes_as_vec")]
    pub header: Vec<u8>,
    pub header_len: usize,
    #[serde(with = "serde_optional_bytes_as_vec")]
    pub footer: Option<Vec<u8>>,
    pub footer_len: usize,
    pub case_sensitive: bool,
    pub search_type: SearchType,
    pub markers: Vec<Marker>,
    #[serde(default)]
    pub found: usize,
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub written: bool,
}

/// File type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum FileType {
    Jpeg,
    Gif,
    Bmp,
    Mpg,
    Pdf,
    Doc,
    Avi,
    Wmv,
    Htm,
    Zip,
    Mov,
    Xls,
    Ppt,
    Wpd,
    Cpp,
    Ole,
    Gzip,
    Riff,
    Wav,
    VJpeg,
    Sxw,
    Sxc,
    Sxi,
    Png,
    Rar,
    Exe,
    Elf,
    Reg,
    Docx,
    Xlsx,
    Pptx,
    Mp4,
    Config,
}

/// Search type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum SearchType {
    Forward,
    Reverse,
    ForwardNext,
    Ascii,
}

/// Marker for additional search patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Marker {
    #[serde(with = "serde_marker_bytes_as_vec")]
    pub value: Vec<u8>,
    pub len: usize,
}

/// Endianness for multi-byte value extraction
#[derive(Debug, Clone, Copy)]
pub enum Endianness {
    Little,
    Big,
}

/// Constants
pub const MEGABYTE: usize = 1024 * 1024;
pub const KILOBYTE: usize = 1024;
pub const DEFAULT_CHUNK_SIZE: usize = 100; // MB
pub const WILDCARD: u8 = b'?';

impl State {
    pub async fn new(config: StateConfig) -> Result<Self> {
        let audit_log_path = format!("{}/audit_log.txt", config.output_directory);
        let audit_file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&audit_log_path)
            .await?;

        let audit_file = Arc::new(Mutex::new(audit_file));

        Ok(Self {
            chunk_size: config.chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE) * MEGABYTE,
            block_size: config.block_size.unwrap_or(512),
            skip: config.skip.unwrap_or(0),
            config,
            audit_file,
            fileswritten: Arc::new(Mutex::new(0)),
            start_time: Instant::now(),
            time_stamp: Instant::now(),
            num_builtin: 0,
            search_specs: Arc::new(Mutex::new(Vec::new())),
        })
    }

    pub async fn audit_entry(&self, message: &str) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        tracing::debug!("Audit: {}", message);
        self.audit_file
            .lock()
            .await
            .write_all(format!("{}\n", message).as_bytes())
            .await?;

        Ok(())
    }

    pub async fn audit_finish(&self, file_info: &FileInfo) -> Result<()> {
        self.audit_entry(&format!(
            "Finished carving {}. Total bytes read: {}",
            file_info.filename, file_info.bytes_read
        ))
        .await
    }

    pub fn get_mode(&self, mode: Mode) -> bool {
        // Implement mode checking based on config flags
        match mode {
            Mode::Verbose => self.config.debug,
            Mode::Quiet => false,      // Add quiet flag to config if needed
            Mode::WriteAll => false,   // Add write_all flag to config if needed
            Mode::WriteAudit => false, // Add write_audit flag to config if needed
            Mode::Quick => false,      // Add quick flag to config if needed
        }
    }

    /// Thread-safe increment of files written counter
    pub async fn increment_fileswritten(&self) -> usize {
        let mut counter = self.fileswritten.lock().await;
        *counter += 1;
        *counter
    }

    /// Thread-safe read of files written counter
    pub async fn get_fileswritten(&self) -> usize {
        *self.fileswritten.lock().await
    }

    /// Thread-safe access to search specs
    pub async fn get_search_specs(&self) -> Vec<SearchSpec> {
        self.search_specs.lock().await.clone()
    }

    /// Thread-safe update of search specs
    pub async fn set_search_specs(&self, specs: Vec<SearchSpec>) {
        *self.search_specs.lock().await = specs;
    }

    /// Thread-safe increment of found count for a specific file type
    pub async fn increment_found_count(&self, file_type: FileType) {
        let mut specs = self.search_specs.lock().await;
        for spec in specs.iter_mut() {
            if spec.file_type == file_type {
                spec.found += 1;
                break;
            }
        }
    }
}

/// Mode flags
#[derive(Debug, Clone, Copy)]
pub enum Mode {
    Verbose,
    Quiet,
    WriteAll,
    WriteAudit,
    Quick,
}

impl SearchSpec {
    pub fn new(
        file_type: FileType,
        suffix: &str,
        header: &[u8],
        footer: Option<&[u8]>,
        max_len: usize,
        case_sensitive: bool,
        search_type: SearchType,
    ) -> Self {
        Self {
            file_type,
            suffix: suffix.to_string(),
            max_len,
            header: header.to_vec(),
            header_len: header.len(),
            footer: footer.map(|f| f.to_vec()),
            footer_len: footer.map(|f| f.len()).unwrap_or(0),
            case_sensitive,
            search_type,
            markers: Vec::new(),
            found: 0,
            comment: String::new(),
            written: false,
        }
    }

    pub fn add_marker(&mut self, marker: &[u8]) {
        self.markers.push(Marker {
            value: marker.to_vec(),
            len: marker.len(),
        });
    }
}

/// Utility functions for endianness conversion
pub fn bytes_to_u16(bytes: &[u8], endianness: Endianness) -> u16 {
    if bytes.len() < 2 {
        return 0;
    }

    match endianness {
        Endianness::Little => u16::from_le_bytes([bytes[0], bytes[1]]),
        Endianness::Big => u16::from_be_bytes([bytes[0], bytes[1]]),
    }
}

pub fn bytes_to_u32(bytes: &[u8], endianness: Endianness) -> u32 {
    if bytes.len() < 4 {
        return 0;
    }

    match endianness {
        Endianness::Little => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        Endianness::Big => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
    }
}

pub fn bytes_to_u64(bytes: &[u8], endianness: Endianness) -> u64 {
    if bytes.len() < 8 {
        return 0;
    }

    match endianness {
        Endianness::Little => u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]),
        Endianness::Big => u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]),
    }
}

/// Clean a filename for use in output filenames
/// - Replace special characters with underscores
/// - Limit to max_length characters
/// - Convert to lowercase for consistency
pub fn clean_filename(filename: &str, max_length: usize) -> String {
    let name = std::path::Path::new(filename)
        .file_stem()
        .unwrap_or_else(|| std::ffi::OsStr::new(filename))
        .to_string_lossy();

    let extension = std::path::Path::new(filename)
        .extension()
        .unwrap_or_else(|| std::ffi::OsStr::new(""))
        .to_string_lossy();

    // Combine name and extension with underscore
    let full_name = if extension.is_empty() {
        name.to_string()
    } else {
        format!("{}_{}", name, extension)
    };

    // Clean the filename: replace non-alphanumeric chars with underscores
    let cleaned: String = full_name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();

    // Remove consecutive underscores and trim
    let cleaned = cleaned
        .split('_')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("_");

    // Truncate to max length
    if cleaned.len() > max_length {
        cleaned[..max_length].to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test;

    #[tokio::test]
    async fn test_state_new() {
        let config = StateConfig {
            output_directory: "test_output".to_string(),
            debug: true,
            prefix_filenames: false,
            chunk_size: Some(50),
            block_size: Some(1024),
            skip: Some(100),
        };

        let temp_dir = tempfile::tempdir().unwrap();
        let config = StateConfig {
            output_directory: temp_dir.path().to_string_lossy().to_string(),
            ..config
        };

        let state = State::new(config.clone()).await.unwrap();

        assert_eq!(state.config.output_directory, config.output_directory);
        assert!(state.config.debug);
        assert!(!state.config.prefix_filenames);
        assert_eq!(state.chunk_size, 50 * MEGABYTE);
        assert_eq!(state.block_size, 1024);
        assert_eq!(state.skip, 100);
        assert_eq!(state.get_fileswritten().await, 0);
    }

    #[tokio::test]
    async fn test_state_default_values() {
        let config = StateConfig {
            output_directory: "test_output".to_string(),
            debug: false,
            prefix_filenames: true,
            chunk_size: None,
            block_size: None,
            skip: None,
        };

        let temp_dir = tempfile::tempdir().unwrap();
        let config = StateConfig {
            output_directory: temp_dir.path().to_string_lossy().to_string(),
            ..config
        };

        let state = State::new(config).await.unwrap();

        assert_eq!(state.chunk_size, DEFAULT_CHUNK_SIZE * MEGABYTE);
        assert_eq!(state.block_size, 512);
        assert_eq!(state.skip, 0);
    }

    #[tokio::test]
    async fn test_state_fileswritten_operations() {
        let config = StateConfig {
            output_directory: "test_output".to_string(),
            debug: false,
            prefix_filenames: false,
            chunk_size: None,
            block_size: None,
            skip: None,
        };

        let temp_dir = tempfile::tempdir().unwrap();
        let config = StateConfig {
            output_directory: temp_dir.path().to_string_lossy().to_string(),
            ..config
        };

        let state = State::new(config).await.unwrap();

        assert_eq!(state.get_fileswritten().await, 0);

        let count1 = state.increment_fileswritten().await;
        assert_eq!(count1, 1);
        assert_eq!(state.get_fileswritten().await, 1);

        let count2 = state.increment_fileswritten().await;
        assert_eq!(count2, 2);
        assert_eq!(state.get_fileswritten().await, 2);
    }

    #[tokio::test]
    async fn test_state_search_specs_operations() {
        let config = StateConfig {
            output_directory: "test_output".to_string(),
            debug: false,
            prefix_filenames: false,
            chunk_size: None,
            block_size: None,
            skip: None,
        };

        let temp_dir = tempfile::tempdir().unwrap();
        let config = StateConfig {
            output_directory: temp_dir.path().to_string_lossy().to_string(),
            ..config
        };

        let state = State::new(config).await.unwrap();

        let initial_specs = state.get_search_specs().await;
        assert!(initial_specs.is_empty());

        let test_specs = vec![
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

        state.set_search_specs(test_specs.clone()).await;
        let retrieved_specs = state.get_search_specs().await;
        assert_eq!(retrieved_specs.len(), 2);
        assert_eq!(retrieved_specs[0].file_type, FileType::Jpeg);
        assert_eq!(retrieved_specs[1].file_type, FileType::Pdf);
    }

    #[tokio::test]
    async fn test_state_increment_found_count() {
        let config = StateConfig {
            output_directory: "test_output".to_string(),
            debug: false,
            prefix_filenames: false,
            chunk_size: None,
            block_size: None,
            skip: None,
        };

        let temp_dir = tempfile::tempdir().unwrap();
        let config = StateConfig {
            output_directory: temp_dir.path().to_string_lossy().to_string(),
            ..config
        };

        let state = State::new(config).await.unwrap();

        let test_spec = SearchSpec::new(
            FileType::Jpeg,
            "jpg",
            &[0xFF, 0xD8, 0xFF],
            None,
            1024 * 1024,
            true,
            SearchType::Forward,
        );

        assert_eq!(test_spec.found, 0);

        state.set_search_specs(vec![test_spec.clone()]).await;
        state.increment_found_count(FileType::Jpeg).await;

        let specs = state.get_search_specs().await;
        assert_eq!(specs[0].found, 1);
    }

    #[tokio::test]
    async fn test_state_audit_operations() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = StateConfig {
            output_directory: temp_dir.path().to_string_lossy().to_string(),
            debug: false,
            prefix_filenames: false,
            chunk_size: None,
            block_size: None,
            skip: None,
        };

        let state = State::new(config).await.unwrap();

        state.audit_entry("Test audit message").await.unwrap();

        let file_info = FileInfo {
            filename: "test.dat".to_string(),
            total_bytes: 1024,
            total_megs: 1,
            bytes_read: 1024,
            per_file_counter: 1,
        };

        state.audit_finish(&file_info).await.unwrap();

        // Check that audit file was created
        let audit_path = format!("{}/audit_log.txt", temp_dir.path().to_string_lossy());
        assert!(std::path::Path::new(&audit_path).exists());
    }

    #[test]
    fn test_mode_checking() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = StateConfig {
            output_directory: temp_dir.path().to_string_lossy().to_string(),
            debug: true,
            prefix_filenames: false,
            chunk_size: None,
            block_size: None,
            skip: None,
        };

        let state_config = config.clone();
        tokio_test::block_on(async {
            let state = State::new(state_config).await.unwrap();
            assert!(state.get_mode(Mode::Verbose));
            assert!(!state.get_mode(Mode::Quiet));
            assert!(!state.get_mode(Mode::WriteAll));
            assert!(!state.get_mode(Mode::WriteAudit));
            assert!(!state.get_mode(Mode::Quick));
        });
    }

    #[test]
    fn test_search_spec_new() {
        let spec = SearchSpec::new(
            FileType::Jpeg,
            "jpg",
            &[0xFF, 0xD8, 0xFF],
            Some(&[0xFF, 0xD9]),
            1024 * 1024,
            true,
            SearchType::Forward,
        );

        assert_eq!(spec.file_type, FileType::Jpeg);
        assert_eq!(spec.suffix, "jpg");
        assert_eq!(spec.header, vec![0xFF, 0xD8, 0xFF]);
        assert_eq!(spec.header_len, 3);
        assert_eq!(spec.footer, Some(vec![0xFF, 0xD9]));
        assert_eq!(spec.footer_len, 2);
        assert_eq!(spec.max_len, 1024 * 1024);
        assert!(spec.case_sensitive);
        assert_eq!(spec.search_type, SearchType::Forward);
        assert_eq!(spec.found, 0);
        assert!(spec.comment.is_empty());
        assert!(!spec.written);
    }

    #[test]
    fn test_search_spec_add_marker() {
        let mut spec = SearchSpec::new(
            FileType::Jpeg,
            "jpg",
            &[0xFF, 0xD8, 0xFF],
            None,
            1024 * 1024,
            true,
            SearchType::Forward,
        );

        assert!(spec.markers.is_empty());

        spec.add_marker(&[0xFF, 0xE0]);
        assert_eq!(spec.markers.len(), 1);
        assert_eq!(spec.markers[0].value, vec![0xFF, 0xE0]);
        assert_eq!(spec.markers[0].len, 2);

        spec.add_marker(&[0xFF, 0xE1]);
        assert_eq!(spec.markers.len(), 2);
    }

    #[test]
    fn test_bytes_to_u16() {
        let bytes_le = [0x34, 0x12];
        assert_eq!(bytes_to_u16(&bytes_le, Endianness::Little), 0x1234);
        assert_eq!(bytes_to_u16(&bytes_le, Endianness::Big), 0x3412);

        // Test with insufficient bytes
        let short_bytes = [0x34];
        assert_eq!(bytes_to_u16(&short_bytes, Endianness::Little), 0);
    }

    #[test]
    fn test_bytes_to_u32() {
        let bytes_le = [0x78, 0x56, 0x34, 0x12];
        assert_eq!(bytes_to_u32(&bytes_le, Endianness::Little), 0x12345678);
        assert_eq!(bytes_to_u32(&bytes_le, Endianness::Big), 0x78563412);

        // Test with insufficient bytes
        let short_bytes = [0x34, 0x12];
        assert_eq!(bytes_to_u32(&short_bytes, Endianness::Little), 0);
    }

    #[test]
    fn test_bytes_to_u64() {
        let bytes_le = [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01];
        assert_eq!(
            bytes_to_u64(&bytes_le, Endianness::Little),
            0x0123456789ABCDEF
        );
        assert_eq!(bytes_to_u64(&bytes_le, Endianness::Big), 0xEFCDAB8967452301);

        // Test with insufficient bytes
        let short_bytes = [0x34, 0x12, 0x78, 0x56];
        assert_eq!(bytes_to_u64(&short_bytes, Endianness::Little), 0);
    }

    #[test]
    fn test_clean_filename() {
        // Basic filename
        assert_eq!(clean_filename("test.txt", 50), "test_txt");

        // Filename with special characters
        assert_eq!(clean_filename("test file!@#.txt", 50), "test_file_txt");

        // Long filename truncation
        let long_name = "this_is_a_very_long_filename_that_should_be_truncated.txt";
        let cleaned = clean_filename(long_name, 20);
        assert_eq!(cleaned.len(), 20);
        assert_eq!(cleaned, "this_is_a_very_long_");

        // Filename with path
        assert_eq!(clean_filename("/path/to/file.dat", 50), "file_dat");

        // Filename without extension
        assert_eq!(clean_filename("filename", 50), "filename");

        // Empty filename
        assert_eq!(clean_filename("", 50), "");

        // Filename with consecutive special characters
        assert_eq!(clean_filename("test---file...txt", 50), "test_file_txt");

        // Case conversion
        assert_eq!(clean_filename("UPPERCASE.TXT", 50), "uppercase_txt");

        // Mixed case and numbers
        assert_eq!(clean_filename("File123.dat", 50), "file123_dat");
    }

    #[test]
    fn test_file_info_creation() {
        let file_info = FileInfo {
            filename: "test.dat".to_string(),
            total_bytes: 1024,
            total_megs: 1,
            bytes_read: 512,
            per_file_counter: 5,
        };

        assert_eq!(file_info.filename, "test.dat");
        assert_eq!(file_info.total_bytes, 1024);
        assert_eq!(file_info.total_megs, 1);
        assert_eq!(file_info.bytes_read, 512);
        assert_eq!(file_info.per_file_counter, 5);
    }

    #[test]
    fn test_file_type_equality() {
        assert_eq!(FileType::Jpeg, FileType::Jpeg);
        assert_ne!(FileType::Jpeg, FileType::Pdf);
    }

    #[test]
    fn test_search_type_equality() {
        assert_eq!(SearchType::Forward, SearchType::Forward);
        assert_ne!(SearchType::Forward, SearchType::Reverse);
    }

    #[test]
    fn test_constants() {
        assert_eq!(MEGABYTE, 1024 * 1024);
        assert_eq!(KILOBYTE, 1024);
        assert_eq!(DEFAULT_CHUNK_SIZE, 100);
        assert_eq!(WILDCARD, b'?');
    }
}

