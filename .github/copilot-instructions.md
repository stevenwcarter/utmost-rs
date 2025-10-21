# Utmost - File Carving Tool

Utmost is a Rust reimplementation of the Foremost file carving tool, designed to recover files from binary data by identifying file signatures (headers/footers).

## Workspace Architecture

The project is organized as a Cargo workspace with two main crates:

- **utmost-lib** (`crates/utmost-lib/`): Core library containing all file carving functionality
- **utmost-cli** (`crates/utmost-cli/`): Command-line interface that uses the library

This separation enables the library to be used in other contexts, including future WASM applications for browser-based file carving.

### Core Components (in utmost-lib)

- **Engine** (`crates/utmost-lib/src/engine.rs`): Main file processing engine that searches for file signatures in data chunks using Boyer-Moore algorithm
- **Search** (`crates/utmost-lib/src/search.rs`): Boyer-Moore string search implementation with wildcard and case-insensitive support
- **Search Specs** (`crates/utmost-lib/src/search_specs.rs`): File type definitions and configuration management (built-in + TOML)
- **Types** (`crates/utmost-lib/src/types.rs`): Core data structures including `State`, `SearchSpec`, and `FileInfo`
- **Lib** (`crates/utmost-lib/src/lib.rs`): Public API interface exposing core functionality

### Data Flow

1. Input files are processed in configurable chunks (default 100MB)
2. Each chunk is searched for file signatures using Boyer-Moore algorithm
3. Found signatures trigger file extraction based on footer detection or heuristics
4. Extracted files are written to `output/` directory with structured naming
5. All operations are logged to `output/audit_log.txt`

## Key Patterns

### Search Specifications

File types are defined as `SearchSpec` structs containing:

```rust
pub struct SearchSpec {
    pub file_type: FileType,
    pub header: Vec<u8>,           // Required signature bytes
    pub footer: Option<Vec<u8>>,   // Optional end marker
    pub max_len: usize,            // Maximum file size
    pub case_sensitive: bool,
    pub search_type: SearchType,   // Forward/Reverse/Ascii
    pub markers: Vec<Marker>,      // Additional validation patterns
}
```

Built-in specs are in `init_all_search_specs()` in `crates/utmost-lib/src/search_specs.rs`. Custom specs load from TOML files with format matching `sample_specs.toml`.

### Parallel Processing

- Supports concurrent processing of multiple input files with `--concurrent-files/-j` option
- Default concurrency is CPU cores - 1 (minimum 1)
- Uses Semaphore for limiting concurrent file operations
- Thread-safe state management with `Arc<Mutex<>>`

### Async Processing

- Uses Tokio for async I/O with configurable chunk sizes
- Progress bars via `indicatif` for multi-file processing
- Audit logging is async and thread-safe using `Arc<Mutex<File>>`

### File Naming Convention

Output files use pattern: `[input_prefix-]counter-offset.extension`

- Input prefix included when processing multiple files or using `--prefix-filenames`
- Counter is per-input-file incremental
- Offset is byte position where signature was found

## Development Commands

### Build & Run

```bash
cargo build --release          # Production build (both crates)
cargo build -p utmost-cli --release  # CLI only
cargo build -p utmost-lib       # Library only
cargo run -- --help           # View CLI options
cargo run -- -t jpeg,pdf file.img  # Search specific types
cargo run -- -j 4 file1.img file2.img  # Process 4 files concurrently
cargo run -- --save-config specs.toml  # Export built-in specs
```

### Testing

```bash
cargo test                     # Run all tests
cargo test -p utmost-lib       # Library tests only
cargo test -p utmost-cli       # CLI tests only
```

### Testing with Sample Data

```bash
# Create test data with JPEG signature
echo -e "\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\xff\xd9" > test.bin
cargo run -- test.bin
ls output/  # Check extracted files and audit_log.txt
```

### Configuration

- Use `--config-file` to load custom TOML specifications
- Use `--disable-builtin` to only use config file specs
- Combine built-in and custom specs by default

## Important Implementation Details

### Boyer-Moore Search

The search implementation supports:

- Wildcard matching using `WILDCARD` byte (`b'?'`)
- Case-insensitive search for text-based formats
- Reverse search for footer-first detection
- ASCII search mode for text file recovery

### File Extraction Logic

1. **Header-only files** (like EXE): Use heuristics or max_len
2. **Header+footer files** (like JPEG): Search for footer within max_len
3. **Structured files** (like BMP): Parse header for embedded size information

### Cross-platform Considerations

- Uses `tokio::fs` for async file operations
- Filename cleaning via `clean_filename()` for cross-platform compatibility
- Block size defaults to 512 bytes (disk sector size)

## File Type Extensions

To add new file types:

1. Add enum variant to `FileType` in `crates/utmost-lib/src/types.rs`
2. Add parsing case in `crates/utmost-lib/src/search_specs.rs` TOML conversion
3. Create `SearchSpec` in `init_all_search_specs()` in `crates/utmost-lib/src/search_specs.rs`
4. Add extraction heuristics to `determine_file_size_heuristic()` in `crates/utmost-lib/src/engine.rs` if needed

Focus on understanding the signature-based detection flow and chunk-based processing when making changes to core functionality.
