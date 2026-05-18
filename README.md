# Utmost - File Carving Tool

Utmost is a Rust reimplementation of the Foremost file carving tool, designed to recover files from binary data by identifying file signatures (headers/footers).

## Workspace Structure

This project is organized as a Cargo workspace with separate crates:

- **`crates/utmost-lib/`** - Core file carving library
- **`crates/utmost-cli/`** - Command-line interface
- **`crates/utmost-gui/`** - Slint GUI library (live progress + replay viewer)
- **`crates/utmost-viewer/`** - `utmost-viewer` binary for replaying saved event logs

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

### Slint GUI Mode

When built with the default `gui` feature, utmost can show a live Slint progress
window while carving:

```bash
# Launch GUI window alongside carve
cargo run -- --gui disk_image.dd

# Disable GUI even if enabled in config file
cargo run -- --no-gui disk_image.dd
```

The GUI can also be enabled by default in `~/.config/utmost/config.toml` (see
[Config File](#config-file) below).

### Forensic Case Metadata

Attach case metadata to each run for chain-of-custody purposes:

```bash
cargo run -- \
  --case-id "CASE-2026-001" \
  --examiner "Jane Doe" \
  --evidence-id "HDD-01" \
  --notes "Suspect laptop primary drive" \
  disk_image.dd
```

These values are embedded in `carve_events.bin` and in `carve_report.json`.

### Export Control

By default utmost writes a binary event log (`carve_events.bin`) alongside each
output directory. Pass `--disable-export` to skip writing it:

```bash
cargo run -- --disable-export disk_image.dd
```

### Multi-Source Output Layout

When two or more input files are provided, each source gets its own subdirectory
under the output root named after the source file:

```
output/
  disk1/
    00000001-0x00001234.jpg
    carve_events.bin
    audit_log.txt
    carve_report.json
  disk2/
    00000001-0x000056ab.pdf
    carve_events.bin
    audit_log.txt
    carve_report.json
```

Single-input runs use the flat layout (files directly in `output/`).

### Config File

Persistent defaults can be set in `~/.config/utmost/config.toml`:

```toml
[gui]
enabled = true

[export]
enabled = true

[case]
examiner = "Jane Doe"
```

CLI flags always override config-file values.

### utmost-viewer

The `utmost-viewer` binary replays a saved `carve_events.bin` in the Slint GUI
without re-running a carve:

```bash
# Replay from an explicit file
utmost-viewer path/to/output/carve_events.bin

# Replay all sources in a multi-source output directory
utmost-viewer path/to/output/
```

Build and install it from the workspace:

```bash
cargo build -p utmost-viewer --release
cargo install --path crates/utmost-viewer
```

### GUI Annotations & JPEG Variant Review

When opening a carve session in the GUI (`utmost --gui …` or
`utmost-viewer ./output`), you can:

- **Bookmark a file** — press `b` on the selected file, or click the ★ in
  the side panel. The **Bookmarked** filter chip narrows the grid to flagged
  files.
- **Add a note** — press `n` in the lightbox to open the inline note input,
  or click **+ Note** in the side panel. Notes are append-only — forensic
  chain-of-custody is preserved; correct a note by writing a follow-up note.
- **JPEG recovery variants** — for any partial JPEG (`Truncated` or
  `Fragmented` scan status), the side panel shows a vertical-scroll mini-grid
  of recovery candidates if recovery has been run for the session. Click
  **Open variant viewer** for a full-size 3-column gallery; open one in the
  previewer to compare. Press `m` (or click **★ Mark as best variant**) in
  the lightbox to record your canonical choice.
- **Run recovery from the GUI** — the side panel shows a **Run recovery**
  button and a **Keep** stepper (default 5, max 10) when a session has
  partial JPEGs and recovery has not yet run. Recovery runs in the background
  and streams events into the GUI (persisted to `carve_events.bin`).

Annotations are persisted to `carve_events.bin` (or staged in
`carve_events.pending` mid-run and folded in at `RunFinished`). They survive
viewer relaunches and machine moves.

> **Note for repositories that check in carve output:** add
> `carve_events.pending` to your `.gitignore` — this sidecar file is only
> present while a recovery run is in progress and is not meaningful outside
> that window.

#### utmost recover — multiple candidates

`utmost recover -n N` writes up to N candidate JPEGs per partial original,
using the filename pattern `<stem>_recovered_<rank>.jpg`. Previous versions
wrote only the single best candidate.

### Development

```bash
# Enable debug logging
cargo run -- -d disk_image.dd

# Build for release
cargo build --release
```

## Release Process

One-time setup: `cargo install git-cliff`

```bash
just release-update    # Apply changes locally, then `git diff` to review
just release           # Full cycle: commit, tag, push → triggers CI release build
```

Versions are derived automatically from [Conventional Commits](https://www.conventionalcommits.org/):
- `feat:` → minor bump
- `fix:`, `chore:`, `perf:`, etc. → patch bump
- `feat!:` or `BREAKING CHANGE:` footer → major bump

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
- **`utmost-server`** - Web service for remote file carving

## License

MIT OR Apache-2.0