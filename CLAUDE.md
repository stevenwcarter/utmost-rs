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

The project is a Cargo workspace with four crates:

- **`crates/utmost-lib/`** — Core library (all carving logic); designed to be reusable in WASM/GUI/server contexts (_only use WASM-safe crates and code here_)
- **`crates/utmost-cli/`** — CLI wrapper using `clap`, `indicatif` progress bars, Tokio async I/O, and `sysinfo` for report metadata
- **`crates/utmost-gui/`** — Slint-based GUI library; renders the case-selection picker and per-case detail views
- **`crates/utmost-viewer/`** — Thin binary that points at an output directory and launches the GUI picker against the historical cases it finds there

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

## Code Quality Rule

After completing any code changes, always run `cargo fmt` followed by `cargo clippy --all-targets` and fix every warning before considering the work done. The pre-commit hook enforces this — clean fmt and clippy runs are required for commits to succeed.

## Developer Documentation Rule

Any time you add, change, or discover details about how to set up, test, build, or run this project — including new commands, required tools, one-time setup steps, or workflow changes — add a corresponding note for developers in the **README.md**. Keep the README the authoritative reference for anyone getting started with the project.

## GUI: case model

The GUI's home screen is a **case picker**. One `<slug>-events.bin` = one case = one row on the picker. Multiple `utmost` invocations into the same output dir produce multiple cases. Multi-source invocations (e.g. `utmost f1.img f2.img -o out/`) also produce multiple cases — one per source. Each case has its own sibling `<slug>-index.sqlite` next to its events.bin.

**Entry modes:**

- `utmost-viewer <dir>` — recursively scans `<dir>` (depth 8, skips hidden dirs + symlinked dirs) for every `<slug>-events.bin`. Each becomes a picker row. See `crates/utmost-gui/src/discover.rs`.
- `utmost --gui ...` — does **not** scan. The CLI builds a `Vec<CaseSource::Historical>` from its plan (one per source) and hands it to `run_picker`. The carve runs on a **joined** background thread, so closing the GUI window does NOT abort the carve — the process stays alive until all sources finish writing their events.bin.

**Per-case state lives in `crates/utmost-gui/src/case.rs`:**

- `CaseSource::Historical(PathBuf)` — the only variant. Both viewer mode and `--gui` live mode use it; "live" vs "historical" is observable only via events.bin growth.
- `CaseHandle` — owns the case's `ViewModel`, indexer-writer + query-loop threads, journal, preview-outcomes writer, and `<slug>-index.sqlite` path. Created by `open_case`, destroyed by `close_case`. **One case open at a time per process** — re-opening tears down the previous handle first.

**Picker reads minimal metadata per row** (`crates/utmost-gui/src/picker.rs`):

1. Prefer `<slug>-index.sqlite`'s `run` row + `meta.last_event_offset` via `picker_metadata_row`.
2. Fall back to `head_read_events_bin` (reads `RunStarted` from the head, `RunFinished` from the tail) when the sqlite is absent.
3. On unrecoverable failure: `PickerStatus::Corrupt`, dimmed row, not clickable.

The picker itself never opens `IndexDb` — that's deferred to `open_case` so clicking into an unindexed case is the only place that pays the migration/fold cost.

**Status values:** `Running` | `Finished` | `Interrupted` | `Indexing…` | `Unindexed` | `Corrupt`. `Unindexed`/`Indexing…` warn the user that clicking in pays an index-build cost.

**Live picker updates** (`crates/utmost-gui/src/picker.rs`, `crates/utmost-gui/src/lib.rs::run_picker`):

- For each Running case, the picker holds a `PickerRowTailer` that incrementally reads new events from the case's events.bin. A 1 Hz Slint timer polls all active tailers, advances `files_seen` / `last_offset` / status, and rebuilds the Slint model when anything changed.
- Tailers are dropped when the user clicks a case (`on_case_clicked`) and recreated when they back out (`on_back_to_picker`) using the persisted `PickerRowState` (which survives across detail-view transitions).
- A row that fails to open initially (the events.bin's RunStarted hasn't been written yet, or the file is briefly mid-frame) gets 3 retry attempts on subsequent 1 Hz ticks before being marked permanently Corrupt for the session.
- The indexer-writer thread (spawned by `open_case` for the case under the user's detail view) tails the same events.bin past EOF until `shutdown_signal` is set, with the same 500ms poll cadence + 10-error retry cap. The shared `tail_loop` helper in `indexer_thread.rs` switches between tail-mode (when `shutdown: Some`) and bounded-mode (when `shutdown: None`, used by the synchronous `run_blocking` entry — exits at EOF for tests and cold-build paths).

**Per-case UI-state persistence** (`crates/utmost-gui/src/view_model.rs`, `index_db/writer.rs`):

- The user's filter chips, sort key/dir, layout toggles, selected group tab, and current selection are saved per case as a versioned JSON blob in `meta.ui_state` on that case's `<slug>-index.sqlite`.
- Hydration is synchronous in `open_case`: `read_ui_state` populates `CaseHandle.ui_state_on_open`. `UiState::new` calls `UiStateSnapshot::into_runtime` against the live `RunSummary`/sources, applies the result to the VM (guarded by `hydrating: Rc<Cell<bool>>` so the apply doesn't trigger a re-save), and stashes `selection` on `pending_scroll_to_selection` for the post-Requery scroll step in the `MatchIds` arm.
- Save is debounced ~500ms via a single-shot Slint timer + `ui_state_dirty: Rc<Cell<bool>>`. Every mutation handler calls `dirty_marker.clone().mark()` after applying; the timer body builds a fresh `UiStateSnapshot` and sends `IndexerCommand::PersistUiState(snap)` on the per-case command channel. The query-loop thread does the actual `write_ui_state`.
- On case-close (back button, reopen, window close), `flush_pending_ui_state()` queues one final write before `shutdown_query_loop` drains the indexer thread. FIFO command processing guarantees the final save lands before `Shutdown` breaks the loop.
- Validation lives only in `UiStateSnapshot::into_runtime`: unknown file-type strings, off-configuration filter entries, missing source-filter source ids, invalid size ranges, and unknown sort strings are all silently dropped to safe defaults. Corrupt blobs in `meta.ui_state` return `Ok(None)` from `read_ui_state` and let the next debounced save overwrite them.
- The on-disk schema (`UiStateSnapshot.v: u32`) is at v=1. Per-field `#[serde(default)]` allows additive forward-compatibility: a future task can add fields without bumping `v`. Non-additive changes (rename/remove/retype) require bumping `CURRENT_VERSION` and adding a migration arm in `into_runtime`.

**Specs and plans:**

- Design (case picker): `docs/superpowers/specs/2026-05-20-case-selection-screen-design.md`
- Plan 1 (viewer-mode case picker): `docs/superpowers/plans/2026-05-20-case-selection-screen-viewer-mode.md`
- Design (per-case UI-state): `docs/superpowers/specs/2026-05-20-persist-ui-state-design.md`
- Plan (per-case UI-state): `docs/superpowers/plans/2026-05-20-persist-ui-state.md`
- Design (live-carve refactor): `docs/superpowers/specs/2026-05-20-live-carve-cli-refactor-design.md`
- Plan 2 (live-carve refactor): `docs/superpowers/plans/2026-05-20-live-carve-cli-refactor.md`

## Adding a New File Type

1. Add variant to `FileType` enum in `crates/utmost-lib/src/types.rs`
2. Add TOML parsing case in `crates/utmost-lib/src/search_specs.rs`
3. Add `SearchSpec` in `init_all_search_specs()` in the same file
4. Add format-specific size heuristic in `determine_file_size_heuristic()` in `engine.rs` if needed (otherwise footer or `max_len` is used)
5. Optionally add a validator module in `src/engine/` and wire it into the extraction path in `engine.rs`
