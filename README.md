# Utmost - File Carving Tool

Utmost is a Rust reimplementation of the Foremost file carving tool, designed to recover files from binary data by identifying file signatures (headers/footers).

## Workspace Structure

This project is organized as a Cargo workspace with separate crates:

- **`crates/utmost-lib/`** - Core file carving library
- **`crates/utmost-cli/`** - Command-line interface

### Library Crate (`utmost-lib`)

Contains the core functionality that can be reused in different contexts:

- **Engine** (`src/engine.rs`) - Main file processing engine with Boyer-Moore algorithm
- **Search** (`src/search.rs`) - Boyer-Moore string search with wildcard support
- **Search Specs** (`src/search_specs.rs`) - File type definitions and configuration
- **Types** (`src/types.rs`) - Core data structures and state management

The library is designed to be used in various contexts, including future WASM implementations for browser-based file carving.

### CLI Crate (`utmost-cli`)

Contains the command-line interface with features like:

- Parallel file processing (configurable concurrency)
- Progress bars for multiple files
- TOML configuration support
- Comprehensive logging and audit trails

## Building and Running

```bash
# Build the entire workspace
cargo build --release

# Run the CLI tool
cargo run -- --help
cargo run -- -j 4 input1.dat input2.dat input3.dat

# Build just the library
cargo build -p utmost-lib

# Build just the CLI
cargo build -p utmost-cli
```

## Key Features

### Parallel Processing

Process multiple files simultaneously with configurable concurrency:

```bash
# Use default concurrency (CPU cores - 1)
cargo run -- file1.dat file2.dat file3.dat

# Limit to 2 concurrent files
cargo run -- -j 2 file1.dat file2.dat file3.dat

# Sequential processing
cargo run -- -j 1 file1.dat file2.dat file3.dat
```

### File Type Support

Built-in support for common file types:
- Images: JPEG, PNG, GIF, BMP
- Documents: PDF, DOC, XLS, PPT
- Archives: ZIP, RAR, GZIP
- Media: AVI, WMV, MOV, MP4, WAV
- Executables: EXE, ELF
- And many more...

### Configuration

- **TOML Config**: Load custom file specifications from TOML files
- **Built-in Specs**: Comprehensive set of built-in file type definitions
- **Flexible Output**: Configurable output directory and filename patterns

## Architecture

### Data Flow

1. Input files are processed in configurable chunks (default 100MB)
2. Each chunk is searched for file signatures using Boyer-Moore algorithm
3. Found signatures trigger file extraction based on footer detection or heuristics
4. Extracted files are written to `output/` directory with structured naming
5. All operations are logged to `output/audit_log.txt`

### Thread Safety

The library is designed for concurrent processing:
- Thread-safe state management using `Arc<Mutex<>>`
- Parallel file processing with semaphore-controlled concurrency
- Shared audit logging across multiple worker tasks

## Usage Examples

### Basic File Carving

```bash
# Carve all supported file types
cargo run -- disk_image.dd

# Carve specific file types
cargo run -- -t jpeg,pdf,zip disk_image.dd

# Process multiple files in parallel
cargo run -- -j 4 *.dd
```

### Advanced Configuration

```bash
# Use custom configuration file
cargo run -- -c custom_specs.toml disk_image.dd

# Save built-in specifications to file
cargo run -- --save-config builtin_specs.toml

# Include input filename in output filenames
cargo run -- --prefix-filenames disk1.dd disk2.dd
```

### Development

```bash
# Enable debug logging
cargo run -- -d disk_image.dd

# Build for release
cargo build --release
```

## Developer Setup

After cloning, run once to activate the committed git hooks:

```bash
just setup
```

This configures git to use `.githooks/pre-commit`, which automatically runs
`cargo fmt` (reformatting staged files and re-staging them) and `cargo clippy`
(blocking the commit if any warnings are present) before every commit.

## Future Enhancements

The workspace structure enables easy addition of new crates:

- **`utmost-wasm`** - Browser-based file carving using WebAssembly
- **`utmost-gui`** - Graphical user interface
- **`utmost-server`** - Web service for remote file carving

## License

MIT OR Apache-2.0