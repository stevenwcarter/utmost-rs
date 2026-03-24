//! JPEG fragment recovery engine.
//!
//! This module provides a second-pass recovery process for incomplete JPEG
//! files identified by a prior [`crate::engine`] carve run.  It reads the
//! `carve_report.json` produced by that run, locates every JPEG whose
//! [`crate::types::JpegScanStatus`] is not `Complete`, then attempts to find
//! and stitch together a continuation fragment from elsewhere in the source
//! image using byte-entropy scoring.
//!
//! # Algorithm overview
//!
//! 1. Load the carve report and filter for incomplete JPEGs.
//! 2. For each incomplete JPEG:
//!    a. Determine the truncation point (end of the carved fragment).
//!    b. Enumerate sector-aligned candidate blocks within a configurable search window.
//!    c. Score each block by Shannon byte entropy (high entropy ≈ compressed scan data).
//!    d. For the top-`max_candidates` blocks, splice with the header and search for EOI.
//!    e. Write each valid reassembly as `{original_stem}_recovered_{n}.jpg`.
//!
//! 3. Emit a `recover_report.json` summarising what was recovered.

use std::{
    cmp,
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::types::{CarveReport, JpegScanStatus};

// ── Configuration ────────────────────────────────────────────────────────────

/// Tuning knobs for the recovery pass.
#[derive(Debug, Clone)]
pub struct RecoveryConfig {
    /// Sector / block alignment used when enumerating candidate continuation
    /// blocks (bytes, default 512).
    pub block_size: usize,
    /// How far from the truncation point to search for candidate blocks
    /// (bytes, default 50 MB).
    pub search_window: usize,
    /// Maximum number of candidate reassemblies to write per incomplete JPEG
    /// (default 3).
    pub max_candidates: usize,
    /// Minimum Shannon entropy (bits/byte, 0.0 – 8.0) for a block to be
    /// considered a plausible continuation (default 7.0).
    pub min_entropy_score: f64,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            block_size: 512,
            search_window: 50 * 1024 * 1024,
            max_candidates: 3,
            min_entropy_score: 7.0,
        }
    }
}

// ── Output types ─────────────────────────────────────────────────────────────

/// How a particular JPEG was reassembled.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryMethod {
    /// The continuation was found immediately after the carved file's end
    /// offset (contiguous on-disk, just past the max_len cutoff).
    DirectContinuation,
    /// The continuation was found at a non-contiguous location via entropy
    /// scan, suggesting true filesystem fragmentation.
    FragmentReassembly,
}

/// A single successfully recovered JPEG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredFile {
    /// Filename of the original (incomplete) carved JPEG.
    pub original_filename: String,
    /// Filename written to the output directory.
    pub recovered_filename: String,
    /// Method used to locate the continuation.
    pub recovery_method: RecoveryMethod,
    /// Entropy score of the winning continuation block (0.0 – 8.0).
    pub entropy_score: f64,
    /// Absolute offset in the source image where the JPEG header begins.
    pub header_img_offset: u64,
    /// Absolute offset in the source image where the continuation block begins.
    pub continuation_img_offset: u64,
    /// Total size of the recovered file in bytes.
    pub recovered_size: usize,
}

/// Top-level summary written as `recover_report.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryReport {
    /// Path to the source disk image that was searched.
    pub source_image: String,
    /// Path to the `carve_report.json` that was consumed.
    pub source_report: String,
    /// Number of incomplete JPEGs found in the report.
    pub incomplete_jpegs: usize,
    /// Successfully recovered files.
    pub recovered: Vec<RecoveredFile>,
}

// ── Public entry point ───────────────────────────────────────────────────────

/// Attempt recovery of fragmented / truncated JPEGs identified by a prior
/// carve run.
///
/// # Arguments
///
/// * `image_path`  – path to the original source disk image
/// * `report_path` – path to the `carve_report.json` from the carve run
/// * `output_dir`  – directory where recovered files and the recovery report
///   will be written (created if absent)
/// * `config`      – tuning parameters; use [`RecoveryConfig::default`] for
///   sensible defaults
pub fn recover_fragmented_jpegs(
    image_path: &str,
    report_path: &str,
    output_dir: &str,
    config: &RecoveryConfig,
) -> Result<RecoveryReport> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output directory: {output_dir}"))?;

    // ── Load carve report ────────────────────────────────────────────────────
    let report_json = fs::read_to_string(report_path)
        .with_context(|| format!("Failed to read report: {report_path}"))?;
    let report: CarveReport = serde_json::from_str(&report_json)
        .with_context(|| format!("Failed to parse report: {report_path}"))?;

    // ── Collect incomplete JPEG file objects ─────────────────────────────────
    let incomplete: Vec<_> = report
        .fileobjects
        .iter()
        .filter(|fo| {
            fo.file_type == "jpeg"
                && fo
                    .jpeg_scan
                    .as_ref()
                    .map(|js| js.status != JpegScanStatus::Complete)
                    .unwrap_or(false)
        })
        .collect();

    let incomplete_count = incomplete.len();

    // ── Open source image ────────────────────────────────────────────────────
    let mut image = File::open(image_path)
        .with_context(|| format!("Failed to open source image: {image_path}"))?;
    let image_size = image
        .metadata()
        .with_context(|| "Failed to read image metadata")?
        .len();

    let mut recovered_files: Vec<RecoveredFile> = Vec::new();

    for fo in &incomplete {
        // The first byte_run holds the absolute image offset and fragment size.
        let Some(run) = fo.byte_runs.first() else {
            continue;
        };
        let header_img_offset = run.img_offset;
        let fragment_size = run.len as usize;

        // ── Read the header fragment ─────────────────────────────────────────
        image
            .seek(SeekFrom::Start(header_img_offset))
            .with_context(|| "Failed to seek in image")?;
        let mut header_fragment = vec![0u8; fragment_size];
        let n = image
            .read(&mut header_fragment)
            .with_context(|| "Failed to read header fragment")?;
        header_fragment.truncate(n);

        if header_fragment.len() < 4 {
            continue; // too short to be a useful JPEG fragment
        }

        // Determine where we should start searching for continuations.
        // For fragmented files, prefer starting from the detected fragmentation
        // point; for truncated files, start from the end of the carved fragment.
        let scan_info = fo.jpeg_scan.as_ref().unwrap();
        let search_start_offset: u64 =
            scan_info.fragmentation_point_img_offset.unwrap_or_else(|| {
                // Truncated: continue from end of fragment
                header_img_offset + fragment_size as u64
            });

        // ── Score candidate continuation blocks ──────────────────────────────
        let block_size = config.block_size as u64;
        // Align search_start to block boundary
        let aligned_start = (search_start_offset / block_size) * block_size;

        // Collect (entropy, absolute_offset) pairs for all candidate blocks.
        let mut candidates: Vec<(f64, u64)> = Vec::new();

        let window_end = cmp::min(
            aligned_start + config.search_window as u64,
            image_size.saturating_sub(block_size),
        );

        let mut block_offset = aligned_start;
        let mut block_buf = vec![0u8; config.block_size];

        while block_offset < window_end {
            // Skip the block that contains the original fragment to avoid
            // re-splicing the same data.
            let in_original = block_offset >= header_img_offset
                && block_offset < header_img_offset + fragment_size as u64;

            if !in_original && image.seek(SeekFrom::Start(block_offset)).is_ok() {
                let read_n = image.read(&mut block_buf).unwrap_or(0);
                if read_n >= 16 {
                    let entropy = byte_entropy(&block_buf[..read_n]);
                    if entropy >= config.min_entropy_score {
                        candidates.push((entropy, block_offset));
                    }
                }
            }

            block_offset += block_size;
        }

        // Sort descending by entropy; keep top N.
        candidates.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        candidates.truncate(config.max_candidates);

        // Also always try the direct continuation block (just past the fragment).
        let direct_offset = header_img_offset + fragment_size as u64;
        if direct_offset < image_size && !candidates.iter().any(|&(_, o)| o == direct_offset) {
            candidates.insert(0, (0.0_f64, direct_offset)); // ensure it's first
        }

        // ── Attempt reassembly ───────────────────────────────────────────────
        let mut rank = 0usize;
        for (entropy_score, cont_offset) in candidates {
            if rank >= config.max_candidates {
                break;
            }

            image
                .seek(SeekFrom::Start(cont_offset))
                .with_context(|| "Failed to seek to continuation block")?;
            let mut cont_buf =
                vec![0u8; cmp::min(config.search_window, (image_size - cont_offset) as usize)];
            let cont_n = image
                .read(&mut cont_buf)
                .with_context(|| "Failed to read continuation")?;
            cont_buf.truncate(cont_n);

            if cont_n == 0 {
                continue;
            }

            // Reassemble: header_fragment + continuation, then look for EOI.
            let mut reassembled = Vec::with_capacity(header_fragment.len() + cont_buf.len());
            reassembled.extend_from_slice(&header_fragment);
            reassembled.extend_from_slice(&cont_buf);

            if let Some(eoi_pos) = find_eoi(&reassembled) {
                let valid_data = &reassembled[..eoi_pos + 2]; // include FF D9

                let original_stem = Path::new(&fo.filename)
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| fo.filename.clone());
                rank += 1;
                let recovered_filename = format!("{original_stem}_recovered_{rank}.jpg");
                let out_path = format!("{output_dir}/{recovered_filename}");

                let mut out_file = File::create(&out_path)
                    .with_context(|| format!("Failed to create output file: {out_path}"))?;
                out_file
                    .write_all(valid_data)
                    .with_context(|| format!("Failed to write recovered file: {out_path}"))?;
                out_file.flush()?;

                let method = if cont_offset == direct_offset {
                    RecoveryMethod::DirectContinuation
                } else {
                    RecoveryMethod::FragmentReassembly
                };

                recovered_files.push(RecoveredFile {
                    original_filename: fo.filename.clone(),
                    recovered_filename,
                    recovery_method: method,
                    entropy_score,
                    header_img_offset,
                    continuation_img_offset: cont_offset,
                    recovered_size: valid_data.len(),
                });
            }
        }
    }

    // ── Write recovery report ────────────────────────────────────────────────
    let recovery_report = RecoveryReport {
        source_image: image_path.to_string(),
        source_report: report_path.to_string(),
        incomplete_jpegs: incomplete_count,
        recovered: recovered_files,
    };

    let report_out = format!("{output_dir}/recover_report.json");
    let json = serde_json::to_string_pretty(&recovery_report)?;
    let mut f = File::create(&report_out)
        .with_context(|| format!("Failed to create recover_report.json at {report_out}"))?;
    f.write_all(json.as_bytes())?;
    f.flush()?;

    Ok(recovery_report)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Calculate the Shannon entropy of a byte slice in bits per byte (0.0 – 8.0).
///
/// Higher values (approaching 8.0) indicate compressed or encrypted data;
/// JPEG compressed scan data typically scores above 7.5.
pub fn byte_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Find the offset of the first FFD9 (EOI) byte pair in `data`.
fn find_eoi(data: &[u8]) -> Option<usize> {
    if data.len() < 2 {
        return None;
    }
    (0..=data.len() - 2).find(|&i| data[i] == 0xFF && data[i + 1] == 0xD9)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_entropy_uniform() {
        // All bytes equal → entropy = 0
        let data = vec![0x42u8; 256];
        assert!(byte_entropy(&data) < 0.001);
    }

    #[test]
    fn test_byte_entropy_max() {
        // One of each byte value → maximum entropy ≈ 8.0
        let data: Vec<u8> = (0..=255u8).collect();
        let e = byte_entropy(&data);
        assert!((e - 8.0_f64).abs() < 0.001);
    }

    #[test]
    fn test_byte_entropy_empty() {
        assert_eq!(byte_entropy(&[]), 0.0);
    }

    #[test]
    fn test_find_eoi_present() {
        let data = [0x12, 0x34, 0xFF, 0xD9, 0x56];
        assert_eq!(find_eoi(&data), Some(2));
    }

    #[test]
    fn test_find_eoi_absent() {
        let data = [0x12, 0x34, 0x56, 0x78];
        assert_eq!(find_eoi(&data), None);
    }

    #[test]
    fn test_find_eoi_at_start() {
        let data = [0xFF, 0xD9, 0x00];
        assert_eq!(find_eoi(&data), Some(0));
    }
}
