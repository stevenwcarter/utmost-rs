//! Reporting module for file carving results
//! 
//! This module provides a trait-based system for generating reports about
//! carved files. Different report formats can be implemented by creating
//! types that implement the `Reporter` trait.

use anyhow::Result;
use serde_json;
use std::fs::File;
use std::io::Write;
use std::sync::{Arc, Mutex};

use crate::types::{CarveReport, FileObject, ByteRun, FileType};

/// Trait for different reporting implementations
pub trait Reporter {
    /// Initialize the reporter with source file information
    fn initialize(&mut self, source_filename: &str, source_size: u64) -> Result<()>;
    
    /// Add a carved file to the report
    fn add_file(&mut self, file_object: FileObject) -> Result<()>;
    
    /// Finalize and write the report
    fn finalize(&mut self) -> Result<()>;
}

/// JSON reporter that outputs a structured JSON report similar to PhotoRec's XML format
pub struct JsonReporter {
    report: Option<CarveReport>,
    output_path: String,
}

impl JsonReporter {
    /// Create a new JSON reporter with a default report
    pub fn new(output_directory: &str) -> Self {
        let output_path = format!("{}/carve_report.json", output_directory);
        Self {
            report: None,
            output_path,
        }
    }

    /// Create a new JSON reporter with a pre-configured CarveReport
    pub fn new_with_report(output_directory: &str, report: CarveReport) -> Self {
        let output_path = format!("{}/carve_report.json", output_directory);
        Self {
            report: Some(report),
            output_path,
        }
    }
}

impl Reporter for JsonReporter {
    fn initialize(&mut self, source_filename: &str, source_size: u64) -> Result<()> {
        if self.report.is_none() {
            self.report = Some(CarveReport::new(source_filename, source_size));
        } else {
            // If we already have a report, just update the source info
            if let Some(ref mut report) = self.report {
                report.source.image_filename = source_filename.to_string();
                report.source.image_size = source_size;
                report.source.volume.byte_runs = vec![ByteRun {
                    offset: 0,
                    img_offset: 0,
                    len: source_size,
                }];
            }
        }
        Ok(())
    }
    
    fn add_file(&mut self, file_object: FileObject) -> Result<()> {
        if let Some(ref mut report) = self.report {
            report.add_file_object(file_object);
        }
        Ok(())
    }
    
    fn finalize(&mut self) -> Result<()> {
        if let Some(ref report) = self.report {
            let json_output = serde_json::to_string_pretty(report)?;
            let mut file = File::create(&self.output_path)?;
            file.write_all(json_output.as_bytes())?;
            file.flush()?;
            
            tracing::info!("Report written to: {}", self.output_path);
        }
        Ok(())
    }
}

/// Thread-safe wrapper for a Reporter
pub struct ThreadSafeReporter {
    inner: Arc<Mutex<Box<dyn Reporter + Send>>>,
}

impl ThreadSafeReporter {
    /// Create a new thread-safe reporter
    pub fn new(reporter: Box<dyn Reporter + Send>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(reporter)),
        }
    }
    
    /// Initialize the reporter
    pub fn initialize(&self, source_filename: &str, source_size: u64) -> Result<()> {
        let mut reporter = self.inner.lock()
            .map_err(|_| anyhow::anyhow!("Failed to acquire reporter lock"))?;
        reporter.initialize(source_filename, source_size)
    }
    
    /// Add a file to the report
    pub fn add_file(&self, file_object: FileObject) -> Result<()> {
        let mut reporter = self.inner.lock()
            .map_err(|_| anyhow::anyhow!("Failed to acquire reporter lock"))?;
        reporter.add_file(file_object)
    }
    
    /// Finalize the report
    pub fn finalize(&self) -> Result<()> {
        let mut reporter = self.inner.lock()
            .map_err(|_| anyhow::anyhow!("Failed to acquire reporter lock"))?;
        reporter.finalize()
    }
}

impl Clone for ThreadSafeReporter {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// Helper function to create a FileObject from carving parameters
pub fn create_file_object(
    filename: &str,
    file_type: FileType,
    file_size: u64,
    img_offset: u64,
) -> FileObject {
    FileObject {
        filename: filename.to_string(),
        filesize: file_size,
        file_type: format!("{:?}", file_type).to_lowercase(),
        byte_runs: vec![ByteRun {
            offset: 0,
            img_offset,
            len: file_size,
        }],
    }
}

/// Extension trait to add reporting capabilities to State
pub trait StateReporting {
    /// Get the reporter if reporting is enabled
    fn get_reporter(&self) -> Option<&ThreadSafeReporter>;
    
    /// Add a carved file to the report (if reporting is enabled)
    fn report_file(&self, filename: &str, file_type: FileType, file_size: u64, img_offset: u64) -> Result<()>;
}

// We'll implement this when we extend the State struct

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    #[test]
    fn test_json_reporter() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let mut reporter = JsonReporter::new(temp_dir.path().to_str().unwrap());
        
        // Initialize reporter
        reporter.initialize("test.img", 1024 * 1024).unwrap();
        
        // Add some test files
        let file1 = FileObject {
            filename: "test1.jpg".to_string(),
            filesize: 2048,
            file_type: "jpeg".to_string(),
            byte_runs: vec![ByteRun {
                offset: 0,
                img_offset: 512,
                len: 2048,
            }],
        };
        
        let file2 = FileObject {
            filename: "test2.pdf".to_string(),
            filesize: 4096,
            file_type: "pdf".to_string(),
            byte_runs: vec![ByteRun {
                offset: 0,
                img_offset: 8192,
                len: 4096,
            }],
        };
        
        reporter.add_file(file1).unwrap();
        reporter.add_file(file2).unwrap();
        
        // Finalize and check output
        reporter.finalize().unwrap();
        
        let report_path = temp_dir.path().join("carve_report.json");
        assert!(report_path.exists());
        
        // Verify the JSON content
        let content = fs::read_to_string(&report_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        
        assert_eq!(parsed["metadata"]["dc_type"], "Carve Report");
        assert_eq!(parsed["creator"]["package"], "Utmost");
        assert_eq!(parsed["source"]["image_filename"], "test.img");
        assert_eq!(parsed["source"]["image_size"], 1024 * 1024);
        assert_eq!(parsed["fileobjects"].as_array().unwrap().len(), 2);
    }
    
    #[test]
    fn test_create_file_object() {
        let file_obj = create_file_object("test.jpg", FileType::Jpeg, 1024, 512);
        
        assert_eq!(file_obj.filename, "test.jpg");
        assert_eq!(file_obj.filesize, 1024);
        assert_eq!(file_obj.file_type, "jpeg");
        assert_eq!(file_obj.byte_runs.len(), 1);
        assert_eq!(file_obj.byte_runs[0].offset, 0);
        assert_eq!(file_obj.byte_runs[0].img_offset, 512);
        assert_eq!(file_obj.byte_runs[0].len, 1024);
    }
    
    #[test]
    fn test_thread_safe_reporter() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let json_reporter = JsonReporter::new(temp_dir.path().to_str().unwrap());
        let reporter = ThreadSafeReporter::new(Box::new(json_reporter));
        
        // Test initialization
        reporter.initialize("test.img", 1024).unwrap();
        
        // Test adding a file
        let file_obj = create_file_object("test.jpg", FileType::Jpeg, 512, 256);
        reporter.add_file(file_obj).unwrap();
        
        // Test finalization
        reporter.finalize().unwrap();
        
        let report_path = temp_dir.path().join("carve_report.json");
        assert!(report_path.exists());
    }
}