# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

**Utmost** is a Rust reimplementation of the Foremost file carving tool — it recovers files from binary data (disk images, memory dumps) by identifying file signatures (headers/footers) using the Boyer-Moore algorithm.

## Commands

```bash
# Build
cargo build --release              # Production build (LTO, codegen-units=1)
cargo build -p utmost-lib          # Library only
cargo build -p utmost-cli --release

# Test
cargo test                         # All tests
cargo test -p utmost-lib           # Library tests only
cargo test some_test_name          # Single test by name

# Lint
cargo clippy --all-targets

# Coverage (requires cargo-llvm-cov)
just cover                         # Outputs lcov.info

# Watch tests
just test                          # Uses watchexec

# Benchmarks
cargo bench -p utmost-lib          # Criterion benchmarks in src/benches/

# Run
cargo run -- --help
cargo run -- -t jpeg,pdf file.img  # Carve specific types
cargo run -- -j 4 f1.img f2.img   # 4 concurrent files
cargo run -- --save-config specs.toml  # Export built-in specs to TOML
cargo run -- -c custom.toml file.img   # Use custom specs
```

## Architecture

The project is a Cargo workspace with two crates:

- **`crates/utmost-lib/`** — Core library (all carving logic); designed to be reusable in WASM/GUI/server contexts (_only use WASM-safe crates and code here_)
- **`crates/utmost-cli/`** — CLI wrapper using `clap`, `indicatif` progress bars, Tokio async I/O, and `sysinfo` for report metadata

### Core components in `utmost-lib`

| File | Purpose |
|------|---------|
| `src/engine.rs` | Main processing loop: chunk reading, signature matching, file extraction, output writing |
| `src/search.rs` | Boyer-Moore implementation with wildcard (`b'?'`) and case-insensitive support |
| `src/search_specs.rs` | Built-in file type database (`init_all_search_specs()`); TOML load/save |
| `src/types.rs` | All core structs: `State`, `SearchSpec`, `FileInfo`, `SearchType`, `CarveReport`, etc. |
| `src/reporting.rs` | `Reporter` trait; `JsonReporter`; DFXML-compatible XML output |
| `src/engine/` | Per-format size/validation heuristics (bmp, jpg, pdf, zip, exe, gz, mov, mpg) |

### Processing pipeline

1. Input files → read in configurable chunks (~100MB default)
2. Each chunk → Boyer-Moore search for all spec headers simultaneously
3. Hit found → determine file size via: footer search, format-specific heuristic, or `max_len` fallback
4. Format-specific validation (e.g., BMP dimensions sanity check, GZIP magic bytes)
5. Write extracted file: `output/[prefix-]counter-offset.ext`
6. Log to `output/audit_log.txt`; generate `carve_report.json` / `carve_report.xml`

### Concurrency

Multiple input files processed concurrently via Tokio + Semaphore. Default concurrency = `max(CPU cores - 1, 1)`. State shared as `Arc<Mutex<State>>`.

### `SearchSpec` structure

```rust
pub struct SearchSpec {
    pub file_type: FileType,
    pub header: Vec<u8>,
    pub footer: Option<Vec<u8>>,
    pub max_len: usize,
    pub case_sensitive: bool,
    pub search_type: SearchType,   // Forward | Reverse | Ascii | ForwardNext
    pub markers: Vec<Marker>,
}
```

Custom specs can be loaded from TOML (see `sample_specs.toml`).

## Adding a New File Type

1. Add variant to `FileType` enum in `crates/utmost-lib/src/types.rs`
2. Add TOML parsing case in `crates/utmost-lib/src/search_specs.rs`
3. Add `SearchSpec` in `init_all_search_specs()` in the same file
4. Add format-specific size heuristic in `determine_file_size_heuristic()` in `engine.rs` if needed (otherwise footer or `max_len` is used)
5. Optionally add a validator module in `src/engine/` and wire it into the extraction path in `engine.rs`
