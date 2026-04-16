use anyhow::{Context, Result, bail};
use clap::Parser;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;
use std::thread::{self, JoinHandle};
use std::time::SystemTime;
use std::{cmp, fs, sync::Arc};
use sysinfo::System;
use tracing::{debug, error, info};

use utmost_lib::{
    engine,
    jpeg_recover::{DEFAULT_SEARCH_WINDOW_BYTES, RecoveryConfig, recover_fragmented_jpegs},
    reporting::{JsonReporter, ThreadSafeReporter},
    search_specs::{get_combined_search_specs, init_all_search_specs, save_specs_to_toml},
    types::{
        DEFAULT_BLOCK_SIZE, ExecutionEnvironment, FileInfo, State, StateConfig, format_timestamp,
    },
};

const PROGRESS_BAR_TEMPLATE: &str =
    "{prefix:.cyan.bold} |{wide_bar:.cyan/blue}| {percent:>3}% {bytes}/{total_bytes} ({eta})";

/// Calculate default number of concurrent files based on CPU cores
fn calculate_default_concurrent_files() -> usize {
    cmp::max(1, num_cpus::get().saturating_sub(1))
}

/// Create an ExecutionEnvironment with real system information
fn create_execution_environment() -> ExecutionEnvironment {
    ExecutionEnvironment {
        os_sysname: std::env::consts::OS.to_string(),
        os_release: System::kernel_version().unwrap_or_else(|| "Unknown".to_string()),
        os_version: System::os_version().unwrap_or_else(|| "Unknown".to_string()),
        host: gethostname::gethostname().to_string_lossy().to_string(),
        arch: std::env::consts::ARCH.to_string(),
        uid: {
            #[cfg(unix)]
            {
                unsafe { libc::getuid() }
            }
            #[cfg(not(unix))]
            {
                0u32
            }
        },
        start_time: format_timestamp(SystemTime::now()),
    }
}

#[derive(Parser, Debug, Clone)]
#[command(
    author,
    version,
    about = "Recover fragmented JPEG files using a prior carve report",
    name = "recover"
)]
pub struct RecoverArgs {
    /// Source disk image to search for continuation fragments
    #[arg(short, long)]
    pub image: String,

    /// Path to carve_report.json produced by a prior utmost run
    #[arg(short, long)]
    pub report: String,

    /// Output directory for recovered files and recover_report.json
    #[arg(short, long, default_value = "recovered")]
    pub output: String,

    /// Block / sector size for fragment alignment (bytes)
    #[arg(short, long, default_value_t = 512)]
    pub block_size: usize,

    /// Search window around each fragmentation point (bytes)
    #[arg(short = 'w', long, default_value_t = DEFAULT_SEARCH_WINDOW_BYTES)]
    pub search_window: usize,

    /// Maximum candidate reassemblies to attempt per incomplete JPEG
    #[arg(short = 'n', long, default_value_t = 3)]
    pub candidates: usize,

    /// Minimum entropy score (0.0–8.0) for a block to be considered scan data
    #[arg(long, default_value_t = 7.0)]
    pub min_entropy: f64,

    /// Activate debug mode
    #[arg(short, long)]
    pub debug: bool,
}

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "Carves files to extract other file types", name="utmost", long_about = None)]
pub struct CarveArgs {
    /// Activate debug mode
    #[arg(short, long)]
    pub debug: bool,

    /// File types to search for (e.g., jpeg, pdf, zip)
    #[arg(short, long, value_delimiter = ',')]
    pub types: Vec<String>,

    /// Output directory for extracted files
    #[arg(short, long, default_value_t = String::from("output"))]
    pub output_directory: String,

    /// Always include input filename prefix in output filenames (even for single file or stdin)
    #[arg(long)]
    pub prefix_filenames: bool,

    /// Disable built-in search specifications
    #[arg(long)]
    pub disable_builtin: bool,

    /// Load search specifications from TOML config file
    #[arg(short, long)]
    pub config_file: Option<String>,

    /// Save current built-in search specifications to TOML file and exit
    #[arg(long)]
    pub save_config: Option<String>,

    /// Number of files to process concurrently (default: CPU cores - 1, minimum 1)
    #[arg(short = 'j', long, default_value_t = calculate_default_concurrent_files())]
    pub concurrent_files: usize,

    /// Disable additional file validation checks (faster but less accurate)
    #[arg(long)]
    pub disable_validation: bool,

    /// Only generate report without extracting files
    #[arg(long)]
    pub report_only: bool,

    /// Disable generation of JSON carve report
    #[arg(long)]
    pub disable_report: bool,

    /// Disable generation of audit log
    #[arg(long)]
    pub disable_audit: bool,

    /// Enable quick mode: only search on block-aligned boundaries
    #[arg(short = 'q', long)]
    pub quick: bool,

    /// Block size in bytes for quick mode and skip calculations (default: 512)
    #[arg(short = 'b', long, default_value_t = DEFAULT_BLOCK_SIZE)]
    pub block_size: usize,

    /// Write all found headers as files even when no footer/validation (header dump mode)
    #[arg(short = 'a', long)]
    pub write_all: bool,

    /// Input files to process (if none specified, reads from stdin)
    pub input_files: Vec<String>,
}

fn main() -> Result<()> {
    // Manual subcommand dispatch: `utmost recover …` invokes the recovery
    // engine; everything else is handled by the normal carve path.
    let argv: Vec<String> = std::env::args().collect();
    if argv.get(1).map(String::as_str) == Some("recover") {
        // Strip the "recover" word so clap sees a clean argv for RecoverArgs.
        let recover_argv: Vec<String> = argv[..1].iter().chain(argv[2..].iter()).cloned().collect();
        let recover_args = RecoverArgs::parse_from(recover_argv);
        return run_recover(recover_args);
    }

    let args = CarveArgs::parse();
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_max_level(if args.debug {
            tracing::Level::TRACE
        } else {
            tracing::Level::WARN
        })
        .init();

    if args.debug {
        debug!("Debug mode is on");
    }

    // Handle save-config option - save built-in specs and exit
    if let Some(save_path) = &args.save_config {
        info!("Saving built-in search specifications to: {}", save_path);
        let builtin_specs = init_all_search_specs();
        save_specs_to_toml(&builtin_specs, save_path)
            .with_context(|| format!("Failed to save specs to file: {}", save_path))?;
        info!(
            "Successfully saved {} search specifications to {}",
            builtin_specs.len(),
            save_path
        );
        return Ok(());
    }

    info!("Output directory: {}", args.output_directory);

    // ensure output directory exists BEFORE creating State (which creates audit file)
    fs::create_dir_all(&args.output_directory).with_context(|| {
        format!(
            "Failed to create output directory: {}",
            args.output_directory
        )
    })?;

    let config = StateConfig {
        output_directory: args.output_directory.clone(),
        debug: args.debug,
        prefix_filenames: args.prefix_filenames,
        chunk_size: None,
        block_size: Some(args.block_size),
        skip: None,
        disable_validation: args.disable_validation,
        report_only: args.report_only,
        disable_report: args.disable_report,
        disable_audit: args.disable_audit,
        quick: args.quick,
        write_all: args.write_all,
    };

    let mut state = State::new(config)?;

    // If reporting is enabled, create a reporter with real system information
    if !args.disable_report {
        let exec_env = create_execution_environment();
        let report = utmost_lib::CarveReport::new_with_env("", 0, exec_env);
        let json_reporter = JsonReporter::new_with_report(&args.output_directory, report);
        state.set_reporter(ThreadSafeReporter::new(Box::new(json_reporter)));
    }

    // Initialize search specifications using the new combined approach
    let combined_specs = get_combined_search_specs(
        &args.types,
        args.disable_builtin,
        args.config_file.as_deref(),
    )
    .context("Failed to initialize search specifications")?;

    state.set_search_specs(combined_specs);

    state.num_builtin = state.get_search_specs().len();
    debug!("Loaded {} search specifications", state.num_builtin);
    for (i, spec) in state.get_search_specs().iter().enumerate() {
        debug!("Spec {}: {} (header: {:?})", i, spec.suffix, spec.header);
    }

    // Process files
    if args.input_files.is_empty() {
        // No files specified, read from stdin
        info!("No input files specified, reading from stdin");
        process_stdin(&state).context("processing stdin")?;
    } else {
        // Process multiple files with controlled concurrency
        process_files_parallel(&state, &args.input_files, args.concurrent_files)
            .context("processing input files")?;
    }

    // print stats
    print_stats(&state).context("printing stats")?;

    Ok(())
}

fn process_stdin(state: &State) -> Result<()> {
    info!("Starting file carving from stdin");
    let mut file_info = FileInfo {
        filename: "stdin".to_string(),
        total_bytes: 0,
        total_megs: 0,
        bytes_read: 0,
        per_file_counter: 0,
    };

    // Create a stdin reader
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin.lock());

    // Read all data from stdin into a buffer
    let mut buffer = Vec::new();
    reader
        .read_to_end(&mut buffer)
        .context("reading from stdin")?;

    file_info.total_bytes = buffer.len();
    file_info.total_megs = file_info.total_bytes / (1024 * 1024);
    debug!(
        "Stdin data size: {} bytes ({} MB)",
        file_info.total_bytes, file_info.total_megs
    );

    // Process buffer directly (stdin counts as 1 input file)
    engine::search_buffer(&buffer, state, &mut file_info, 0, 1)
        .context("searching stdin buffer")?;

    state.audit_finish(&file_info).context("finishing audit")?;

    info!("File carving completed for stdin");
    Ok(())
}

fn print_stats(state: &State) -> Result<()> {
    let duration = state.start_time.elapsed();
    info!("Carving completed in {:.2?}", duration);
    info!("Total files written: {}", state.get_fileswritten());
    Ok(())
}

/// Process multiple files in parallel with controlled concurrency
fn process_files_parallel(
    state: &State,
    input_files: &[String],
    max_concurrent: usize,
) -> Result<()> {
    info!(
        "Processing {} files with max {} concurrent",
        input_files.len(),
        max_concurrent
    );

    // Create multi-progress for handling multiple files
    let multi_progress = Arc::new(MultiProgress::new());

    // Use a simple approach with thread spawning and joining
    // For a more sophisticated approach, we could use a thread pool
    let total_files = input_files.len();

    // Process files in batches to limit concurrency
    for chunk in input_files.chunks(max_concurrent) {
        let mut batch_handles: Vec<JoinHandle<()>> = Vec::new();

        for input_file in chunk {
            // Clone data needed in the thread
            let input_file = input_file.clone();
            let state_clone = state.clone();
            let multi_progress_clone = multi_progress.clone();

            let handle = thread::spawn(move || {
                if let Err(e) =
                    process_single_file(&input_file, multi_progress_clone, state_clone, total_files)
                {
                    error!("failed to process file: {:?}", e);
                }
            });

            batch_handles.push(handle);
        }

        // Wait for this batch to complete before starting the next
        for handle in batch_handles {
            if let Err(e) = handle.join() {
                error!("Thread panicked: {:?}", e);
            }
        }
    }

    Ok(())
}

fn process_single_file(
    input_file: &str,
    multi_progress_clone: Arc<MultiProgress>,
    state_clone: State,
    total_files: usize,
) -> Result<()> {
    debug!("Processing file: {}", input_file);

    // Check if file exists
    if !Path::new(&input_file).exists() {
        bail!("Input file does not exist: {}", input_file);
    }

    // Get file size for progress bar
    let file_size = match fs::metadata(input_file) {
        Ok(metadata) => metadata.len(),
        Err(_) => {
            bail!("Cannot read file metadata: {}", input_file);
        }
    };

    // Create progress bar for this file
    let pb = multi_progress_clone.add(ProgressBar::new(file_size));
    pb.set_style(
        ProgressStyle::default_bar()
            .template(PROGRESS_BAR_TEMPLATE)
            .expect("valid progress bar template")
            .progress_chars("█▉▊▋▌▍▎▏ "),
    );

    // Set filename as prefix (truncate if too long)
    let filename = Path::new(&input_file)
        .file_name()
        .unwrap_or_else(|| OsStr::new(&input_file))
        .to_string_lossy();
    let truncated_name = if filename.len() > 15 {
        format!("{}...", &filename[..12])
    } else {
        filename.to_string()
    };
    pb.set_prefix(format!("{:15}", truncated_name));

    // Process file with progress bar
    if let Err(e) = process_file_with_progress_parallel(&state_clone, input_file, &pb, total_files)
    {
        pb.finish_with_message("Errored");
        bail!("Failed to process file {}: {}", input_file, e);
    }

    pb.finish_with_message("Complete");

    Ok(())
}

/// Process a single file with progress bar (parallel-safe version)
fn process_file_with_progress_parallel(
    state: &State,
    filename: &str,
    pb: &ProgressBar,
    total_input_files: usize,
) -> Result<()> {
    let mut file_info = FileInfo {
        filename: filename.to_string(),
        total_bytes: 0,
        total_megs: 0,
        bytes_read: 0,
        per_file_counter: 0,
    };

    // open input file
    let mut input_file = File::open(filename).context("opening input file")?;

    file_info.total_bytes = input_file
        .metadata()
        .context("getting file metadata")?
        .len() as usize;
    file_info.total_megs = file_info.total_bytes / (1024 * 1024);

    // Use progress callback to update progress bar
    let progress_callback = |position: u64| {
        pb.set_position(position);
    };

    engine::search_stream_with_progress(
        &mut input_file,
        state,
        &mut file_info,
        progress_callback,
        total_input_files,
    )
    .context("searching stream")?;

    state.audit_finish(&file_info).context("finishing audit")?;

    Ok(())
}

/// Entry point for `utmost recover …`
fn run_recover(args: RecoverArgs) -> Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_max_level(if args.debug {
            tracing::Level::TRACE
        } else {
            tracing::Level::WARN
        })
        .init();

    let config = RecoveryConfig {
        block_size: args.block_size,
        search_window: args.search_window,
        max_candidates: args.candidates,
        min_entropy_score: args.min_entropy,
        ..RecoveryConfig::default()
    };

    eprintln!(
        "Recovering fragmented JPEGs from {} using report {} → {}",
        args.image, args.report, args.output
    );

    let report = recover_fragmented_jpegs(&args.image, &args.report, &args.output, &config)
        .context("JPEG fragment recovery failed")?;

    eprintln!(
        "Recovery complete: {}/{} incomplete JPEGs yielded {} recovered file(s)",
        report.recovered.len(),
        report.incomplete_jpegs,
        report.recovered.len(),
    );
    eprintln!("Report written to {}/recover_report.json", args.output);

    Ok(())
}
