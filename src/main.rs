use anyhow::{Context, Result};
use clap::Parser;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use tracing::{debug, error, info};

mod engine;
mod search;
mod search_specs;
mod types;

use search_specs::{get_combined_search_specs, init_all_search_specs, save_specs_to_toml};
use types::{FileInfo, State};

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

    let mut state = State::new(&args).await?;

    // Initialize search specifications using the new combined approach
    state.search_specs = get_combined_search_specs(
        &args.types, 
        args.disable_builtin, 
        args.config_file.as_deref()
    ).context("Failed to initialize search specifications")?;

    state.num_builtin = state.search_specs.len();
    debug!("Loaded {} search specifications", state.num_builtin);
    for (i, spec) in state.search_specs.iter().enumerate() {
        debug!("Spec {}: {} (header: {:?})", i, spec.suffix, spec.header);
    }

    // Process files
    if args.input_files.is_empty() {
        // No files specified, read from stdin
        info!("No input files specified, reading from stdin");
        process_stdin(&mut state)
            .await
            .context("processing stdin")?;
    } else {
        // Create multi-progress for handling multiple files
        let multi_progress = MultiProgress::new();

        // Process each file sequentially with progress bars
        for input_file in &args.input_files {
            debug!("Processing file: {}", input_file);

            // Check if file exists
            if !std::path::Path::new(input_file).exists() {
                error!("Input file does not exist: {}", input_file);
                continue; // Skip this file and continue with the next one
            }

            // Get file size for progress bar
            let file_size = match std::fs::metadata(input_file) {
                Ok(metadata) => metadata.len(),
                Err(_) => {
                    error!("Cannot read file metadata: {}", input_file);
                    continue;
                }
            };

            // Create progress bar for this file
            let pb = multi_progress.add(ProgressBar::new(file_size));
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{prefix:.cyan.bold} |{bar:60.cyan/blue}| {percent:>3}% {bytes}/{total_bytes} ({eta})")
                    .unwrap()
                    .progress_chars("█▉▊▋▌▍▎▏ ")
            );

            // Set filename as prefix (truncate if too long)
            let filename = std::path::Path::new(input_file)
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new(input_file))
                .to_string_lossy();
            let truncated_name = if filename.len() > 15 {
                format!("{}...", &filename[..12])
            } else {
                filename.to_string()
            };
            pb.set_prefix(format!("{:15}", truncated_name));

            // Process file with progress bar
            process_file_with_progress(&mut state, input_file, &pb, args.input_files.len())
                .await
                .with_context(|| format!("processing file: {}", input_file))?;

            pb.finish_with_message("Complete");
        }
    }

    // print stats
    print_stats(&state).await.context("printing stats")?;

    Ok(())
}

async fn process_file_with_progress(
    state: &mut State,
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

    engine::search_stream_with_progress(
        &mut input_file,
        state,
        &mut file_info,
        pb,
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

async fn process_file(state: &mut State, filename: &str, total_input_files: usize) -> Result<()> {
    info!("Starting file carving for: {}", filename);
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
    debug!(
        "Input file size: {} bytes ({} MB)",
        file_info.total_bytes, file_info.total_megs
    );

    engine::search_stream(&mut input_file, state, &mut file_info, total_input_files)
        .await
        .context("searching stream")?;

    state
        .audit_finish(&file_info)
        .await
        .context("finishing audit")?;

    info!("File carving completed for: {}", filename);
    Ok(())
}

async fn process_stdin(state: &mut State) -> Result<()> {
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

    // Process the buffer directly (stdin counts as 1 input file)
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
    info!("Total files written: {}", state.fileswritten);
    Ok(())
}
