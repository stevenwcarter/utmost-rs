use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Instant};
use tokio::sync::Mutex;

// Custom serialization helpers for byte arrays
mod serde_bytes_as_vec {
    use serde::{Deserializer, Serializer, Deserialize};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
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
    use serde::{Deserializer, Serializer, Deserialize};

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
    use serde::{Deserializer, Serializer, Deserialize};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
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

/// Core state structure that mirrors the C f_state
#[derive(Clone)]
pub struct State {
    pub args: crate::Args,
    pub audit_file: Arc<Mutex<tokio::fs::File>>,
    pub chunk_size: usize,
    pub fileswritten: usize,
    pub block_size: usize,
    pub skip: usize,
    pub start_time: Instant,
    pub time_stamp: Instant,
    pub num_builtin: usize,
    pub search_specs: Vec<SearchSpec>,
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
    pub async fn new(args: &crate::Args) -> Result<Self> {
        let audit_log_path = format!("{}/audit_log.txt", args.output_directory);
        let audit_file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&audit_log_path)
            .await?;

        let audit_file = Arc::new(Mutex::new(audit_file));

        Ok(Self {
            args: args.clone(),
            audit_file,
            chunk_size: DEFAULT_CHUNK_SIZE * MEGABYTE,
            fileswritten: 0,
            block_size: 512,
            skip: 0,
            start_time: Instant::now(),
            time_stamp: Instant::now(),
            num_builtin: 0,
            search_specs: Vec::new(),
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
        // Implement mode checking based on args flags
        match mode {
            Mode::Verbose => self.args.debug,
            Mode::Quiet => false, // Add quiet flag to args if needed
            Mode::WriteAll => false, // Add write_all flag to args if needed
            Mode::WriteAudit => false, // Add write_audit flag to args if needed
            Mode::Quick => false, // Add quick flag to args if needed
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
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]),
        Endianness::Big => u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
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