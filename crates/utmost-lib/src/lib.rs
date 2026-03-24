//! # Utmost Library
//!
//! Core file carving functionality for recovering files from binary data by identifying file signatures.
//!
//! ## Architecture
//!
//! - **Engine**: Main file processing engine using Boyer-Moore algorithm
//! - **Search**: Boyer-Moore string search with wildcard support  
//! - **Search Specs**: File type definitions and configuration
//! - **Types**: Core data structures for state management
//!
//! ## Usage
//!
//! ```rust,no_run
//! use utmost_lib::{State, FileInfo, search_specs::init_all_search_specs};
//!
//! // Initialize search specifications
//! let specs = init_all_search_specs();
//!
//! // Create state for file processing
//! // let state = State::new(&args).await?;
//! ```

pub mod engine;
pub mod reporting;
pub mod search;
pub mod search_specs;
pub mod types;

// Re-export commonly used types
pub use engine::{search_buffer, search_stream_with_progress};
pub use reporting::{
    JsonReporter, Reporter, StateReporting, ThreadSafeReporter, create_file_object,
};
pub use search_specs::{get_combined_search_specs, init_all_search_specs, save_specs_to_toml};
pub use types::{
    ByteRun, CarveReport, ExecutionEnvironment, FileInfo, FileObject, FileType, Mode, SearchSpec,
    SearchType, State,
};
