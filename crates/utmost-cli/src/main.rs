mod config;
mod output_layout;
mod sinks;

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

    /// Keep incomplete JPEGs (fragmented or truncated — EOI marker not found).
    /// By default these are skipped to avoid writing thousands of 50MB junk files.
    #[arg(long)]
    pub keep_incomplete_jpeg: bool,

    /// Enable Slint GUI for live progress display (overrides config file)
    #[arg(long, conflicts_with = "no_gui")]
    pub gui: bool,

    /// Disable Slint GUI even if enabled in config file
    #[arg(long)]
    pub no_gui: bool,

    /// Disable writing carve_events.bin (the bincode event log)
    #[arg(long)]
    pub disable_export: bool,

    /// Forensic case identifier
    #[arg(long)]
    pub case_id: Option<String>,

    /// Examiner name for forensic case metadata
    #[arg(long)]
    pub examiner: Option<String>,

    /// Evidence identifier for forensic case metadata
    #[arg(long)]
    pub evidence_id: Option<String>,

    /// Free-form notes attached to the run
    #[arg(long)]
    pub notes: Option<String>,

    /// Input files to process (if none specified, reads from stdin)
    pub input_files: Vec<String>,
}

struct EffectiveSettings {
    gui_enabled: bool,
    export_enabled: bool,
    case: utmost_lib::events::CaseMetadata,
}

fn resolve_settings(args: &CarveArgs, user_cfg: &config::UserConfig) -> EffectiveSettings {
    let gui_enabled = if args.gui {
        true
    } else if args.no_gui {
        false
    } else {
        user_cfg.gui.enabled
    };

    let export_enabled = if args.disable_export {
        false
    } else {
        user_cfg.export.enabled
    };

    // CLI flags override config-file values per-field.
    let mut case = user_cfg.case.to_metadata();
    if let Some(v) = args.case_id.clone() {
        case.case_id = Some(v);
    }
    if let Some(v) = args.examiner.clone() {
        case.examiner = Some(v);
    }
    if let Some(v) = args.evidence_id.clone() {
        case.evidence_id = Some(v);
    }
    if let Some(v) = args.notes.clone() {
        case.notes = Some(v);
    }

    EffectiveSettings {
        gui_enabled,
        export_enabled,
        case,
    }
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

    // Load user config (~/.config/utmost/config.toml) then resolve effective settings.
    let user_cfg = match config::default_path() {
        Some(path) => config::load_from(&path).unwrap_or_else(|e| {
            tracing::warn!("Failed to load user config ({}); using defaults", e);
            config::UserConfig::default()
        }),
        None => config::UserConfig::default(),
    };
    let settings = resolve_settings(&args, &user_cfg);

    if settings.gui_enabled {
        #[cfg(feature = "gui")]
        {
            tracing::info!("GUI mode requested");
            // wiring happens in Task 36
        }
        #[cfg(not(feature = "gui"))]
        {
            anyhow::bail!("--gui requested but this build of utmost was compiled without the `gui` feature");
        }
    }

    info!("Output directory: {}", args.output_directory);

    // ensure output directory exists BEFORE creating State (which creates audit file)
    fs::create_dir_all(&args.output_directory).with_context(|| {
        format!(
            "Failed to create output directory: {}",
            args.output_directory
        )
    })?;

    // Build the per-source plan: Vec<(source_id, input_path, subdir)>.
    // Single source uses the flat layout (empty subdir); multi-source derives unique
    // subdir names under the output root.
    let mut plan: Vec<(usize, String, String)> = Vec::new();
    if !args.input_files.is_empty() {
        let multi = args.input_files.len() > 1;
        let mut taken: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for (idx, input) in args.input_files.iter().enumerate() {
            let subdir = if multi {
                let s = output_layout::derive_subdir(input, &taken)
                    .with_context(|| format!("deriving output subdir for {}", input))?;
                taken.insert(s.clone());
                s
            } else {
                String::new()
            };
            if !subdir.is_empty() {
                let abs = Path::new(&args.output_directory).join(&subdir);
                fs::create_dir_all(&abs).with_context(|| {
                    format!("Failed to create output subdir: {}", abs.display())
                })?;
            }
            plan.push((idx, input.clone(), subdir));
        }
    }

    let base_config = StateConfig {
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
        keep_incomplete_jpeg: args.keep_incomplete_jpeg,
    };

    // Initialize search specifications using the new combined approach
    let combined_specs = get_combined_search_specs(
        &args.types,
        args.disable_builtin,
        args.config_file.as_deref(),
    )
    .context("Failed to initialize search specifications")?;

    debug!("Loaded {} search specifications", combined_specs.len());
    for (i, spec) in combined_specs.iter().enumerate() {
        debug!("Spec {}: {} (header: {:?})", i, spec.suffix, spec.header);
    }

    // Process files
    if args.input_files.is_empty() {
        // No files specified, read from stdin — legacy single-State path.
        info!("No input files specified, reading from stdin");
        let mut state = State::new(base_config)?;
        if !args.disable_report {
            let exec_env = create_execution_environment();
            let report = utmost_lib::CarveReport::new_with_env("", 0, exec_env);
            let json_reporter = JsonReporter::new_with_report(&args.output_directory, report);
            state.set_reporter(ThreadSafeReporter::new(Box::new(json_reporter)));
        }
        state.set_search_specs(combined_specs);
        state.num_builtin = state.get_search_specs().len();
        process_stdin(&state).context("processing stdin")?;
        print_stats_total(state.get_fileswritten(), state.start_time.elapsed());
        return Ok(());
    }

    // Build sources descriptor list for RunStarted, using metadata for total_bytes.
    let sources_descriptors: Vec<utmost_lib::events::SourceDescriptor> = plan
        .iter()
        .map(|(id, input, subdir)| {
            let total_bytes = std::fs::metadata(input).map(|m| m.len()).unwrap_or(0);
            utmost_lib::events::SourceDescriptor {
                source_id: *id as u32,
                filename: input.clone(),
                total_bytes,
                output_subdir: subdir.clone(),
            }
        })
        .collect();

    let cli_snapshot = utmost_lib::events::CliConfigSnapshot {
        output_directory: args.output_directory.clone(),
        types: args.types.clone(),
        disable_builtin: args.disable_builtin,
        config_file: args.config_file.clone(),
        concurrent_files: args.concurrent_files,
        disable_validation: args.disable_validation,
        report_only: args.report_only,
        disable_report: args.disable_report,
        disable_audit: args.disable_audit,
        disable_export: !settings.export_enabled,
        gui_enabled: settings.gui_enabled,
        quick: args.quick,
        block_size: args.block_size,
        prefix_filenames: args.prefix_filenames,
        write_all: args.write_all,
        keep_incomplete_jpeg: args.keep_incomplete_jpeg,
    };

    let run_started = utmost_lib::events::CarveEvent::RunStarted {
        utmost_version: env!("CARGO_PKG_VERSION").into(),
        format_version: utmost_lib::events::CURRENT_FORMAT_VERSION,
        started_at: format_timestamp(SystemTime::now()),
        command_line: std::env::args().collect(),
        working_directory: std::env::current_dir()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default(),
        execution_environment: create_execution_environment(),
        cli_config: cli_snapshot,
        case: if settings.case.is_empty() {
            None
        } else {
            Some(settings.case.clone())
        },
        configured_types: vec![], // populated later from search specs (TODO)
        sources: sources_descriptors,
        output_root: args.output_directory.clone(),
    };

    process_files_parallel(
        &base_config,
        &args.output_directory,
        &plan,
        args.concurrent_files,
        settings.export_enabled,
        None,
        &run_started,
        &combined_specs,
    )
    .context("processing input files")?;

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
        source_id: 0,
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

fn print_stats_total(total_files_written: usize, duration: std::time::Duration) {
    info!("Carving completed in {:.2?}", duration);
    info!("Total files written: {}", total_files_written);
}

/// Process multiple files in parallel with controlled concurrency.
///
/// Each entry in `plan` (`(source_id, input_path, subdir)`) gets its own
/// `State` rooted at `<output_root>/<subdir>` (or `<output_root>` when subdir
/// is empty), its own reporter, audit log, and event sink. `RunStarted` is
/// emitted per-source before processing begins; `RunFinished` is emitted
/// per-source after all carve threads have joined.
#[allow(clippy::too_many_arguments)]
fn process_files_parallel(
    base_config: &StateConfig,
    output_root: &str,
    plan: &[(usize, String, String)],
    max_concurrent: usize,
    export_enabled: bool,
    extra_sink_per_source: Option<Arc<dyn utmost_lib::events::EventSink>>,
    run_started: &utmost_lib::events::CarveEvent,
    combined_specs: &[utmost_lib::types::SearchSpec],
) -> Result<()> {
    info!(
        "Processing {} files with max {} concurrent",
        plan.len(),
        max_concurrent
    );

    let multi_progress = Arc::new(MultiProgress::new());
    let total_files = plan.len();

    // Build a per-source State for each entry in the plan. Each one carries its
    // own sink so events land in the right output directory.
    let mut per_source_states: Vec<State> = Vec::with_capacity(plan.len());
    for (_id, _input, subdir) in plan {
        let source_dir = sinks::source_output_dir(Path::new(output_root), subdir);
        fs::create_dir_all(&source_dir)
            .with_context(|| format!("Failed to create source dir: {}", source_dir.display()))?;

        let mut cfg = base_config.clone();
        cfg.output_directory = source_dir.to_string_lossy().to_string();
        let mut state = State::new(cfg)?;

        if !state.config.disable_report {
            let exec_env = create_execution_environment();
            let report = utmost_lib::CarveReport::new_with_env("", 0, exec_env);
            let json_reporter =
                JsonReporter::new_with_report(&state.config.output_directory, report);
            state.set_reporter(ThreadSafeReporter::new(Box::new(json_reporter)));
        }

        let extra: Vec<Arc<dyn utmost_lib::events::EventSink>> =
            extra_sink_per_source.iter().cloned().collect();
        if let Some(sink) = sinks::build_source_sink(&source_dir, export_enabled, extra)? {
            state.set_event_sink(sink);
        }

        state.set_search_specs(combined_specs.to_vec());
        state.num_builtin = combined_specs.len();

        // Emit RunStarted before launching any carve threads so the event
        // appears at the head of each source's event log.
        state.emit(run_started.clone());

        per_source_states.push(state);
    }

    // Run carve threads in batches of `max_concurrent`.
    let max_concurrent = max_concurrent.max(1);
    let mut idx = 0;
    while idx < plan.len() {
        let end = (idx + max_concurrent).min(plan.len());
        let mut batch_handles: Vec<JoinHandle<()>> = Vec::new();
        for i in idx..end {
            let (source_id, input_file, _subdir) = plan[i].clone();
            let state_clone = per_source_states[i].clone();
            let multi_progress_clone = multi_progress.clone();
            let handle = thread::spawn(move || {
                if let Err(e) = process_single_file(
                    &input_file,
                    multi_progress_clone,
                    state_clone,
                    total_files,
                    source_id as u32,
                ) {
                    error!("failed to process file: {:?}", e);
                }
            });
            batch_handles.push(handle);
        }
        for handle in batch_handles {
            if let Err(e) = handle.join() {
                error!("Thread panicked: {:?}", e);
            }
        }
        idx = end;
    }

    // Emit RunFinished per source after all threads have joined; aggregate stats.
    let mut total_written: usize = 0;
    let mut max_duration = std::time::Duration::from_millis(0);
    for state in &per_source_states {
        let dur = state.start_time.elapsed();
        if dur > max_duration {
            max_duration = dur;
        }
        let written = state.get_fileswritten();
        total_written += written;
        state.emit(utmost_lib::events::CarveEvent::RunFinished {
            duration_ms: dur.as_millis() as u64,
            total_files_written: written as u64,
        });
    }

    print_stats_total(total_written, max_duration);

    Ok(())
}

fn process_single_file(
    input_file: &str,
    multi_progress_clone: Arc<MultiProgress>,
    state_clone: State,
    total_files: usize,
    source_id: u32,
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
    if let Err(e) =
        process_file_with_progress_parallel(&state_clone, input_file, &pb, total_files, source_id)
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
    source_id: u32,
) -> Result<()> {
    let mut file_info = FileInfo {
        filename: filename.to_string(),
        total_bytes: 0,
        total_megs: 0,
        bytes_read: 0,
        per_file_counter: 0,
        source_id,
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

#[cfg(test)]
mod settings_tests {
    use super::*;
    use clap::Parser;

    fn parse(extra: &[&str]) -> CarveArgs {
        let mut argv = vec!["utmost"];
        argv.extend(extra);
        argv.push("dummy.img");
        CarveArgs::parse_from(argv)
    }

    #[test]
    fn gui_flag_overrides_disabled_config() {
        let cfg = config::UserConfig::default();
        let args = parse(&["--gui"]);
        assert!(resolve_settings(&args, &cfg).gui_enabled);
    }

    #[test]
    fn no_gui_flag_overrides_enabled_config() {
        let mut cfg = config::UserConfig::default();
        cfg.gui.enabled = true;
        let args = parse(&["--no-gui"]);
        assert!(!resolve_settings(&args, &cfg).gui_enabled);
    }

    #[test]
    fn disable_export_overrides_enabled_config() {
        let cfg = config::UserConfig::default(); // export.enabled default = true
        let args = parse(&["--disable-export"]);
        assert!(!resolve_settings(&args, &cfg).export_enabled);
    }

    #[test]
    fn cli_case_id_overrides_config() {
        let mut cfg = config::UserConfig::default();
        cfg.case.case_id = Some("from-config".into());
        let args = parse(&["--case-id", "from-cli"]);
        let s = resolve_settings(&args, &cfg);
        assert_eq!(s.case.case_id.as_deref(), Some("from-cli"));
    }
}
