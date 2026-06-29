# Utmost - File Carving Tool

Utmost is a Rust reimplementation of the Foremost file carving tool, designed to recover files from binary data by identifying file signatures (headers/footers).

## Workspace Structure

This project is organized as a Cargo workspace with separate crates:

- **`crates/utmost-lib/`** - Core file carving library (WASM-safe; no turso/candle)
- **`crates/utmost-index/`** - Native-only layer: turso index store, preview generation, CLIP embedder, case discovery
- **`crates/utmost-cli/`** - Command-line interface
- **`crates/utmost-gui/`** - Slint GUI library (live progress + replay viewer)
- **`crates/utmost-viewer/`** - `utmost-viewer` binary for replaying saved event logs

The index store is **turso** (pure-Rust SQLite with a vector extension). No special system libraries or SQLite installation required — turso is a pure-Rust crate.

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
# Build the entire workspace (includes CLIP embedder by default)
cargo build --release

# Lean build — omits CLIP, candle, hf-hub, and tokenizers; no model download
cargo build --release --no-default-features

# Run the CLI tool
cargo run -- --help
cargo run -- -j 4 input1.dat input2.dat input3.dat

# Build just the library
cargo build -p utmost-lib

# Build just the CLI
cargo build -p utmost-cli
```

The default build includes the `clip` feature, which compiles in the CLIP semantic
search embedder. The model (~1.5 GB) is downloaded automatically on first use and
cached in `~/.cache/huggingface/hub/`. Pass `--no-default-features` for a lean
binary that omits CLIP, candle, hf-hub, and tokenizers entirely.

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

### Post-Carve Processing: `utmost process`

After a carve run completes, `utmost process` generates image previews and
CLIP semantic-search embeddings for all cases found under an output directory:

```bash
# Scan the default "output/" directory
utmost process

# Scan a specific output directory
utmost process -o /path/to/output

# Larger batch size (default is 64)
utmost process --count 128

# Generate previews only — skip CLIP embedding
utmost process --no-embeddings
```

This command is Slint-free and designed for headless or scripted workflows.
The first run that generates embeddings downloads the CLIP model (~1.5 GB) from
HuggingFace and caches it in `~/.cache/huggingface/hub/`. Subsequent runs reuse
the cached model.

### CLIP Semantic Search (GUI)

When a case is open in the GUI, a semantic search box appears in the detail
toolbar (between "Hide no-preview" and the sort dropdown). Type a text query and
the results are ranked by cosine similarity to the query embedding. The search
respects all active filter chips.

- The search box is disabled until the CLIP model finishes loading in the
  background. While embeddings are still being generated it shows an
  "N still indexing" hint.
- The query is transient — it is not saved to the per-case UI state.

**Status panel** (`\` key, suppressed while a text field has focus): shows
Previews and Embeddings progress, a Running/Paused/Idle indicator, and a
Pause/Resume button for the background process worker. The worker also runs
automatically while a case is open, so embeddings build up over time without
running `utmost process` separately.

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

These values are embedded in the per-source `<stem>-events.bin` log and in
`carve_report.json`.

### Export Control

By default utmost writes a binary event log named `<stem>-events.bin` into each
source's output directory, where `<stem>` is derived from the source filename
(see [Multi-Source Output Layout](#multi-source-output-layout) below). Pass
`--disable-export` to skip writing it:

```bash
cargo run -- --disable-export disk_image.dd
```

### Multi-Source Output Layout

When two or more input files are provided, each source gets its own subdirectory
under the output root named `output-<stem>/`, and the event log inside each
subdirectory is named `<stem>-events.bin`:

```
output/
  output-disk1_dd/
    00000001-0x00001234.jpg
    disk1_dd-events.bin
    disk1_dd-events.pending   # only while a recovery run is in progress
    audit_log.txt
    carve_report.json
  output-disk2_dd/
    00000001-0x000056ab.pdf
    disk2_dd-events.bin
    audit_log.txt
    carve_report.json
```

The `<stem>` is derived from the source filename: it is lowercased, every
non-alphanumeric character (including `.`) is replaced with `_`, and the
result is truncated to 32 characters. For example, `disk1.dd` becomes
`disk1_dd`, producing `disk1_dd-events.bin` (and, once a SQLite index has
been built by the GUI, `disk1_dd-index.sqlite`). This source-stem-first
naming means a file copied out of context retains its provenance in the
name, and `ls` groups all artifacts for a given source together.

Single-input runs use the flat layout (files directly in `output/`); the
event log for a single-input run is still named after the source stem
(e.g. `output/disk_image_dd-events.bin`).

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

The `utmost-viewer` binary replays a saved `<stem>-events.bin` in the Slint
GUI without re-running a carve:

```bash
# Replay from an explicit file
utmost-viewer path/to/output/disk1_dd-events.bin

# Replay all sources in a multi-source output directory — every
# output-<stem>/<stem>-events.bin under the directory is discovered and merged.
utmost-viewer path/to/output/
```

Build and install it from the workspace:

```bash
cargo build -p utmost-viewer --release
cargo install --path crates/utmost-viewer
```

### GUI Logging and Performance Telemetry

The GUI writes a daily-rolling log file. Default locations:

- macOS: `~/Library/Logs/utmost/utmost-gui.log`
- Linux: `${XDG_STATE_HOME:-$HOME/.local/state}/utmost/utmost-gui.log`
- Windows: `%LOCALAPPDATA%\utmost\logs\utmost-gui.log`

Override with `UTMOST_LOG_DIR=<dir>`.

To enable per-phase tick timing in the log:

```
UTMOST_PERF_TRACE=1 cargo run -- gui <case>
# or equivalently:
RUST_LOG=utmost_gui::perf=info cargo run -- gui <case>
```

Adjust the summary cadence with `UTMOST_PERF_TICKS=<n>` (default 100 ticks ≈ 10 seconds at 10 Hz).

### Windowed Case Loading

The GUI loads cases of 250k+ files via a turso (pure-Rust SQLite)-backed
match-ids vector and a windowed `BTreeMap` of hydrated rows. Filter and sort
changes run as SQL queries on a background thread, so large cases stay responsive
without paying to materialize every row up front. CLIP semantic search uses
`vector_distance_cos` on a `clip_embedding` table in the same turso database.

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
- **Per-image recovery from the GUI** — when you select a partial JPEG
  (`Truncated` or `Fragmented`), the side panel shows a **Recover this
  image** button (or **Re-run recovery for this image** once variants exist
  for it) and a **Keep** stepper (default 5, max 10). Clicking runs recovery
  against that one image only; the recovered candidates appear as variants
  of the selected file in the side panel's mini-grid and the variant viewer,
  **not** in the main file grid. Recovery runs in the background and streams
  events into the GUI (persisted to the source's `<stem>-events.bin`). To
  recover another partial, select it and click again.

Annotations are persisted to the source's `<stem>-events.bin` (or staged in
the sibling `<stem>-events.pending` mid-run and folded in at `RunFinished`).
They survive viewer relaunches and machine moves.

> **Note for repositories that check in carve output:** add
> `*-events.pending` to your `.gitignore` — these sidecar files are only
> present while a recovery run is in progress and are not meaningful outside
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

### Benchmarks

The GUI ships two opt-in Criterion benchmarks that exercise the SQLite
index's hot paths:

- `cold_rebuild_286k` — full build of the index from a 286k-event log.
- `warm_hydrate_286k` — populate the in-memory `ViewModel` from an
  already-built index.

They generate ~43 MB of synthetic input on each run, so they're gated by
an environment variable to keep `cargo bench` cheap by default:

```bash
UTMOST_BENCH=1 cargo bench -p utmost-gui --bench index_load
```

Without `UTMOST_BENCH`, the benches are skipped.

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