use anyhow::{Context, Result};
use clap::Parser;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{debug, error, info};

use utmost_lib::{
    engine, search_specs::{get_combined_search_specs, init_all_search_specs, save_specs_to_toml},
    types::{FileInfo, State, StateConfig},
};

/// Calculate default number of concurrent files based on CPU cores
fn calculate_default_concurrent_files() -> usize {
    std::cmp::max(1, num_cpus::get().saturating_sub(1))
}

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "Carves files to extract other file types", name="utmost", long_about = None)]
pub struct Args {
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

    /// Input files to process (if none specified, reads from stdin)
    pub input_files: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
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
        info!("Successfully saved {} search specifications to {}", builtin_specs.len(), save_path);
        return Ok(());
    }

    info!("Output directory: {}", args.output_directory);

    // ensure output directory exists BEFORE creating State (which creates audit file)
    std::fs::create_dir_all(&args.output_directory).unwrap_or_else(|e| {
        error!("Failed to create output directory: {}", e);
        std::process::exit(1);
    });

    let config = StateConfig {
        output_directory: args.output_directory.clone(),
        debug: args.debug,
        prefix_filenames: args.prefix_filenames,
        chunk_size: None,
        block_size: None,
        skip: None,
    };

    let mut state = State::new(config).await?;

    // Initialize search specifications using the new combined approach
    let combined_specs = get_combined_search_specs(
        &args.types, 
        args.disable_builtin, 
        args.config_file.as_deref()
    ).context("Failed to initialize search specifications")?;

    state.set_search_specs(combined_specs).await;

    state.num_builtin = state.get_search_specs().await.len();
    debug!("Loaded {} search specifications", state.num_builtin);
    for (i, spec) in state.get_search_specs().await.iter().enumerate() {
        debug!("Spec {}: {} (header: {:?})", i, spec.suffix, spec.header);
    }

    // Process files
    if args.input_files.is_empty() {
        // No files specified, read from stdin
        info!("No input files specified, reading from stdin");
        process_stdin(&state)
            .await
            .context("processing stdin")?;
    } else {
        // Process multiple files with controlled concurrency
        process_files_parallel(&state, &args.input_files, args.concurrent_files)
            .await
            .context("processing input files")?;
    }

    // print stats
    print_stats(&state).await.context("printing stats")?;

    Ok(())
}

async fn process_stdin(state: &State) -> Result<()> {
    use tokio::io::{AsyncReadExt, BufReader};

    info!("Starting file carving from stdin");
    let mut file_info = FileInfo {
        filename: "stdin".to_string(),
        total_bytes: 0,
        total_megs: 0,
        bytes_read: 0,
        per_file_counter: 0,
    };

    // Create a stdin reader
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);

    // Read all data from stdin into a buffer
    let mut buffer = Vec::new();
    reader
        .read_to_end(&mut buffer)
        .await
        .context("reading from stdin")?;

    file_info.total_bytes = buffer.len();
    file_info.total_megs = file_info.total_bytes / (1024 * 1024);
    debug!(
        "Stdin data size: {} bytes ({} MB)",
        file_info.total_bytes, file_info.total_megs
    );

    // Process buffer directly (stdin counts as 1 input file)
    engine::search_buffer(&buffer, state, &mut file_info, 0, 1)
        .await
        .context("searching stdin buffer")?;

    state
        .audit_finish(&file_info)
        .await
        .context("finishing audit")?;

    info!("File carving completed for stdin");
    Ok(())
}

async fn print_stats(state: &State) -> Result<()> {
    let duration = state.start_time.elapsed();
    info!("Carving completed in {:.2?}", duration);
    info!("Total files written: {}", state.get_fileswritten().await);
    Ok(())
}

/// Process multiple files in parallel with controlled concurrency
async fn process_files_parallel(
    state: &State,
    input_files: &[String],
    max_concurrent: usize,
) -> Result<()> {
    info!("Processing {} files with max {} concurrent", input_files.len(), max_concurrent);
    
    // Create multi-progress for handling multiple files
    let multi_progress = MultiProgress::new();
    
    // Create semaphore to limit concurrent file processing
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    
    // Create tasks for all files
    let mut tasks = Vec::new();
    
    for input_file in input_files {
        // Clone data needed in the task
        let input_file = input_file.clone();
        let state_clone = state.clone();
        let semaphore_clone = semaphore.clone();
        let multi_progress_clone = multi_progress.clone();
        let total_files = input_files.len();
        
        let task = tokio::spawn(async move {
            // Acquire semaphore permit
            let _permit = semaphore_clone.acquire().await.unwrap();
            
            debug!("Processing file: {}", input_file);

            // Check if file exists
            if !std::path::Path::new(&input_file).exists() {
                error!("Input file does not exist: {}", input_file);
                return;
            }

            // Get file size for progress bar
            let file_size = match std::fs::metadata(&input_file) {
                Ok(metadata) => metadata.len(),
                Err(_) => {
                    error!("Cannot read file metadata: {}", input_file);
                    return;
                }
            };

            // Create progress bar for this file
            let pb = multi_progress_clone.add(ProgressBar::new(file_size));
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{prefix:.cyan.bold} |{bar:60.cyan/blue}| {percent:>3}% {bytes}/{total_bytes} ({eta})")
                    .unwrap()
                    .progress_chars("█▉▊▋▌▍▎▏ ")
            );

            // Set filename as prefix (truncate if too long)
            let filename = std::path::Path::new(&input_file)
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new(&input_file))
                .to_string_lossy();
            let truncated_name = if filename.len() > 15 {
                format!("{}...", &filename[..12])
            } else {
                filename.to_string()
            };
            pb.set_prefix(format!("{:15}", truncated_name));

            // Process file with progress bar
            if let Err(e) = process_file_with_progress_parallel(&state_clone, &input_file, &pb, total_files).await {
                error!("Failed to process file {}: {}", input_file, e);
            } else {
                pb.finish_with_message("Complete");
            }
        });
        
        tasks.push(task);
    }
    
    // Wait for all tasks to complete
    for task in tasks {
        if let Err(e) = task.await {
            error!("Task failed: {}", e);
        }
    }
    
    Ok(())
}

/// Process a single file with progress bar (parallel-safe version)
async fn process_file_with_progress_parallel(
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
    let mut input_file = tokio::fs::File::open(filename)
        .await
        .context("opening input file")?;

    file_info.total_bytes = input_file
        .metadata()
        .await
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
    .await
    .context("searching stream")?;

    state
        .audit_finish(&file_info)
        .await
        .context("finishing audit")?;

    Ok(())
}