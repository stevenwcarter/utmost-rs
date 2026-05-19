# Source-byte Thumbnails + Always-track Partials Design

**Date:** 2026-05-18
**Branch target:** `feature/utmost-gui-slint` (or a new feature branch off it)
**Scope:** Three coordinated changes across `utmost-lib`, `utmost-gui`, and `utmost-viewer` so the viewer can render thumbnails when no on-disk carved file exists, and so partial JPEGs are always recorded in the event log regardless of CLI flags.

## Goals

1. **Source-byte thumbnail fallback.** When `--report-only` was used at carve time, or when the carved output files are otherwise unavailable, the GUI/viewer generates thumbnails and full-resolution previews by reading the original byte range from the source image. Failure to locate the source falls back silently to the existing icon placeholder.
2. **Always track incomplete JPEGs.** The bincoded event log records every detected partial JPEG (`Truncated` or `Fragmented`) regardless of `--keep-incomplete-jpeg`. The flag still controls whether the partial file is written to disk.
3. **Viewer source-path resolution.** `utmost-viewer` accepts repeatable `--source <path>` arguments (files or directories) as search locations, with a sensible default lookup when omitted.

## Non-goals

- A new error/badge UI for "source missing" cases. Icon fallback only.
- Per-source-id CLI flags (e.g. `--source 0=/path/a --source 1=/path/b`). Multiple `--source` entries are search locations, not explicit per-id mappings.
- Loading and replaying multiple bincoded event logs in a single viewer session. The viewer still takes a single `target` argument; `--source` repeats are meant for the case where one event log contains multiple `SourceDescriptor` entries.
- Pinch-to-zoom or any zoom/UI changes (those were the previous spec's territory).
- Schema versioning of the event log. The event payload shape doesn't change; only which events are emitted under which CLI flags.

---

## Section 1 — Source-byte thumbnail fallback

### Current code

| Path | What it does today |
|---|---|
| `crates/utmost-gui/src/preview/mod.rs:54` | `PreviewRenderer::render(&self, path: &Path, file: &FoundFile)` decodes from a filesystem path. |
| `crates/utmost-gui/src/preview/jpeg.rs:13-19` | `decode_image(path)` calls `image::ImageReader::open(path)`. |
| `crates/utmost-gui/src/thumb_worker.rs:55` | Worker calls `registry.render_for(req.file_type, &req.path, &req.file)` where `req.path` is `FoundFile.written_path`. |
| `crates/utmost-gui/src/slint_adapter.rs:510, 607` | Both the full-resolution lightbox path and the thumb-request path pass `f.written_path`. |
| `crates/utmost-lib/src/engine.rs:1029` | In report-only mode, `written_path` is set to the *would-be* filename but no file is written to disk. |

### Proposed change

#### 1a. Renderer trait gains byte-based methods

In `crates/utmost-gui/src/preview/mod.rs`, extend `PreviewRenderer`:

```rust
pub trait PreviewRenderer: Send + Sync {
    fn supports(&self, ft: FileType) -> bool;
    fn render(&self, path: &Path, file: &FoundFile) -> Result<PreviewOutput>;
    fn render_full(&self, path: &Path, file: &FoundFile) -> Result<PreviewOutput> {
        self.render(path, file)
    }
    fn render_side_panel_metadata(&self, file: &FoundFile) -> Vec<(String, String)>;

    /// Byte-based decode for cases where no on-disk file exists (report-only
    /// carves, moved output dirs). Default impl returns `Err`; renderers that
    /// can decode in-memory override this.
    fn render_from_bytes(&self, _bytes: &[u8], _file: &FoundFile) -> Result<PreviewOutput> {
        anyhow::bail!("byte-based decode not supported for this renderer")
    }

    fn render_full_from_bytes(&self, bytes: &[u8], file: &FoundFile) -> Result<PreviewOutput> {
        self.render_from_bytes(bytes, file)
    }
}
```

`PreviewRegistry` gains matching dispatch helpers `render_from_bytes_for` and `render_full_from_bytes_for` that look up the renderer for the given `FileType` and call into the byte-based methods.

#### 1b. JPEG renderer override

In `crates/utmost-gui/src/preview/jpeg.rs`, add:

```rust
fn decode_image_from_bytes(bytes: &[u8]) -> Result<image::DynamicImage> {
    ImageReader::new(std::io::Cursor::new(bytes))
        .with_guessed_format()
        .context("guess format from bytes")?
        .decode()
        .context("decode bytes")
}

impl PreviewRenderer for JpegPreview {
    // existing methods unchanged ...

    fn render_from_bytes(&self, bytes: &[u8], _file: &FoundFile) -> Result<PreviewOutput> {
        let img = decode_image_from_bytes(bytes)?;
        let (w, h) = (img.width(), img.height());
        let scale = (MAX_EDGE as f32 / w.max(h) as f32).min(1.0);
        let (nw, nh) = ((w as f32 * scale) as u32, (h as f32 * scale) as u32);
        let resized = if scale < 1.0 {
            img.resize(nw.max(1), nh.max(1), FilterType::Triangle).to_rgba8()
        } else {
            img.to_rgba8()
        };
        Ok(PreviewOutput::Image(resized))
    }

    fn render_full_from_bytes(&self, bytes: &[u8], _file: &FoundFile) -> Result<PreviewOutput> {
        Ok(PreviewOutput::Image(decode_image_from_bytes(bytes)?.to_rgba8()))
    }
}
```

`GenericIcon` does not override; it returns icons regardless of input, so the default `Err`-returning impl is fine (the caller checks the path-based `render` first for non-image types, and bytes-based decode for non-image types is meaningless).

#### 1c. Source resolver

New module `crates/utmost-gui/src/source_resolver.rs`:

```rust
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::collections::HashMap;

pub struct SourceResolver {
    /// User-supplied `--source` entries from utmost-viewer, in order.
    search_locations: Vec<PathBuf>,
    /// Path the bincoded event log was loaded from. Used to derive the
    /// "parent of output dir" default search location.
    event_log_path: Option<PathBuf>,
    /// Per-source-id resolution cache: source_id -> Some(resolved_path) or
    /// None if we've already failed to resolve.
    cache: Mutex<HashMap<u32, Option<PathBuf>>>,
}

impl SourceResolver {
    pub fn new(search_locations: Vec<PathBuf>, event_log_path: Option<PathBuf>) -> Self {
        Self {
            search_locations,
            event_log_path,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Resolves a source by its id, looking up the recorded filename in
    /// `SourceRow` and walking the search locations.
    pub fn resolve(&self, source_id: u32, recorded_filename: &str) -> Option<PathBuf> {
        if let Some(hit) = self.cache.lock().unwrap().get(&source_id) {
            return hit.clone();
        }
        let resolved = self.resolve_uncached(recorded_filename);
        self.cache.lock().unwrap().insert(source_id, resolved.clone());
        resolved
    }

    fn resolve_uncached(&self, recorded_filename: &str) -> Option<PathBuf> {
        let basename = Path::new(recorded_filename)
            .file_name()
            .map(|s| s.to_owned())?;

        // 1. Walk user-supplied search locations in order.
        for loc in &self.search_locations {
            if loc.is_file() {
                if loc.file_name() == Some(basename.as_os_str()) && loc.exists() {
                    return Some(loc.clone());
                }
            } else if loc.is_dir() {
                let candidate = loc.join(&basename);
                if candidate.exists() {
                    return Some(candidate);
                }
            }
        }

        // 2. Path recorded in the log, as-is.
        let recorded = PathBuf::from(recorded_filename);
        if recorded.exists() {
            return Some(recorded);
        }

        // 3. Parent of the event log's directory + basename.
        if let Some(log_path) = &self.event_log_path {
            if let Some(log_parent) = log_path.parent().and_then(|p| p.parent()) {
                let candidate = log_parent.join(&basename);
                if candidate.exists() {
                    return Some(candidate);
                }
            }
        }

        None
    }
}
```

The resolver lives in `Arc<SourceResolver>` and is cloned into the thumb worker on construction (and held by the slint adapter for the full-resolution path).

#### 1d. Thumb worker fallback wiring

In `crates/utmost-gui/src/thumb_worker.rs`, the worker thread changes from:

```rust
let out = registry.render_for(req.file_type, &req.path, &req.file);
```

to:

```rust
let out = render_with_fallback(
    &registry,
    &resolver,
    &sources_by_id,
    req.file_type,
    &req.path,
    &req.file,
);
```

where `render_with_fallback` is a free function in `preview/mod.rs`:

```rust
pub fn render_with_fallback(
    registry: &PreviewRegistry,
    resolver: &SourceResolver,
    sources_by_id: &HashMap<u32, String>, // source_id -> recorded filename
    ft: FileType,
    path: &Path,
    file: &FoundFile,
) -> Result<PreviewOutput> {
    // 1. Try on-disk first.
    if path.exists() {
        match registry.render_for(ft, path, file) {
            Ok(out) => return Ok(out),
            Err(e) => tracing::debug!("path-based render failed for {}: {}", path.display(), e),
        }
    }

    // 2. Byte-range fallback.
    let Some(recorded) = sources_by_id.get(&file.source_id) else {
        anyhow::bail!("no recorded source filename for source_id {}", file.source_id);
    };
    let Some(src_path) = resolver.resolve(file.source_id, recorded) else {
        anyhow::bail!("source not resolvable for source_id {}", file.source_id);
    };
    if file.file.byte_runs.is_empty() {
        anyhow::bail!("file has no byte_runs");
    }

    // Read ALL byte_runs and concatenate. Single-run files (complete JPEGs,
    // most carved formats) read one range; recovered JPEGs with a header
    // fragment + continuation read both ranges into one buffer.
    let mut f = std::fs::File::open(&src_path)
        .with_context(|| format!("open source {}", src_path.display()))?;
    let total_len: u64 = file.file.byte_runs.iter().map(|r| r.len).sum();
    let mut buf = Vec::with_capacity(total_len as usize);
    for run in &file.file.byte_runs {
        f.seek(SeekFrom::Start(run.img_offset))
            .with_context(|| format!("seek to {:#x} in {}", run.img_offset, src_path.display()))?;
        let mut chunk = vec![0u8; run.len as usize];
        let n = f.read(&mut chunk).with_context(|| "read source bytes")?;
        chunk.truncate(n);
        buf.extend_from_slice(&chunk);
    }

    registry.render_from_bytes_for(ft, &buf, file)
}
```

`render_full_with_fallback` is the same structure but calls `render_full_for` / `render_full_from_bytes_for`. Used by `slint_adapter.rs:510` (the lightbox / large-preview path).

The `sources_by_id` map is built once per sync from `vm.sources` and passed in (Arc-shared between the worker thread and the adapter). It maps `source_id -> SourceRow.filename` (the recorded path).

#### 1e. Adapter changes

In `crates/utmost-gui/src/slint_adapter.rs`:
- Construct the `SourceResolver` from CLI args (passed in via the new `launch_ui` signature, Section 3).
- Build `sources_by_id` from `vm.sources` inside `sync()` and pass it to thumb-worker requests and the full-res path.
- Both `full_res_image` (~line 504) and the thumb-request site (~line 607) call into `render_with_fallback` / `render_full_with_fallback` rather than the registry directly.

### Testing

- `crates/utmost-gui/src/source_resolver.rs` unit tests:
  - `resolves_to_supplied_file_when_basename_matches`
  - `resolves_to_search_dir_when_file_present`
  - `falls_back_to_recorded_path_when_supplied_locations_miss`
  - `falls_back_to_parent_of_event_log_dir`
  - `returns_none_when_nothing_resolves`
  - `cache_returns_same_result_on_second_call`
- `crates/utmost-gui/src/preview/mod.rs` unit tests:
  - `render_with_fallback_uses_path_when_present`
  - `render_with_fallback_uses_bytes_when_path_missing`
  - `render_with_fallback_returns_err_when_neither_works`
- `crates/utmost-gui/src/preview/jpeg.rs`:
  - `jpeg_renders_from_bytes` — load a small jpeg via `include_bytes!`, assert `render_from_bytes` returns an `Image` of expected dimensions.

Integration test in `crates/utmost-gui/tests/`:
- `source_bytes_thumb_fallback.rs` — synthesize a tiny test source containing one JPEG, build a fake bincoded event log that points at it via byte_runs, delete the would-be `written_path`, drive the viewer, assert a thumbnail buffer materialises.

---

## Section 2 — Always track incomplete JPEGs in the event log

### Current code

`crates/utmost-lib/src/engine.rs:846-857`:

```rust
// Skip incomplete JPEGs by default to avoid flooding output with
// max-size junk files.  Both --keep-incomplete-jpeg and --write-all
// opt back in to writing them.
if status != JpegScanStatus::Complete
    && !state.config.keep_incomplete_jpeg
    && !state.config.write_all
{
    debug!(
        "Skipping incomplete JPEG ({:?}) at offset {} (would be {} bytes)",
        status, abs_offset, size
    );
    return Ok((0, false, None));
}
```

Returning here means the `JpegScanInfo` is built but discarded, and no `FileFound` event is emitted. The bincoded event log never records the partial.

`crates/utmost-lib/src/engine.rs:1032-1041` (the report-only short-circuit inside `write_to_disk`):

```rust
if state.config.report_only {
    info!(
        "Found {} ({} bytes) at offset {} [report-only mode]",
        filename, data.len(), offset
    );
    return Ok(file_id);
}
```

By the time we get here, the `FileFound` event has already been emitted (it's emitted unconditionally at `engine.rs:1020-1030` before this check). So report-only already records the entry without writing.

### Proposed change

#### 2a. Remove the extraction-time skip

Delete the guard at `engine.rs:846-857`. Let the function fall through to validation + `write_to_disk` for every detected file regardless of `JpegScanStatus`.

#### 2b. Add a write-time skip mirror to the report-only one

Inside `write_to_disk` at `engine.rs:~1032`, extend the short-circuit:

```rust
// Skip the actual write for partial JPEGs when the user hasn't asked
// for them. The FileFound event has already been emitted above, so
// the viewer still sees the entry — it just isn't on disk.
let is_partial = matches!(
    jpeg_scan_info,
    Some(info) if info.status != JpegScanStatus::Complete
);
let skip_partial_write = is_partial
    && !state.config.keep_incomplete_jpeg
    && !state.config.write_all;

if state.config.report_only || skip_partial_write {
    info!(
        "Found {} ({} bytes) at offset {} [{}]",
        filename,
        data.len(),
        offset,
        if state.config.report_only { "report-only" } else { "partial-skip" }
    );
    return Ok(file_id);
}
```

The check runs after the `FileFound` event emit (line 1020-1030), so the bincoded log always records the partial.

#### 2c. Adjust the "Skipped N partial JPEGs" report stat

`crates/utmost-cli/src/main.rs:779` prints `report.incomplete_jpegs`. That value comes from the recovery pipeline (`jpeg_recover.rs`) and counts partials by reading `report.fileobjects`. With the new behavior, `fileobjects` already contains partials, so the count remains accurate without code changes. Worth verifying with a test.

### Migration / compatibility

- **Event schema:** Unchanged. `FileFound.file.jpeg_scan.status` already distinguishes Complete/Truncated/Fragmented.
- **Existing bincoded logs:** No partials in old logs — that's by design (they were never emitted). Loading old logs continues to work. The viewer's "Partial JPEG" chip will read 0 for old logs, same as today.
- **Carve report JSON/XML:** Will now contain `<fileobject>` entries for partials whose write was skipped. Tools that consume `carve_report.json` and assume "presence implies on-disk file" need to check `jpeg_scan.status`. This is the only consumer-facing change.
- **`audit_log.txt` + counters:** The audit line is written by the caller of `extract_basic_file` at `engine.rs:649-656`, gated on `extracted_size > 0`. The same block also calls `state.increment_fileswritten()` and `state.increment_found_count(spec.file_type)`. With Section 2's change, an emitted-but-not-written partial would also reach this block (since the function will return its size). Resolve by adding a `was_written: bool` to the `extract_basic_file` return tuple — making it `(extracted_size, needs_bridge, was_written, opt_file_id)`. Then in the caller:
  - `extracted_size` still advances the read position (we don't want to re-detect the same header).
  - `increment_found_count` is called whenever `opt_file_id.is_some()` (a candidate was detected — populates the GUI's "Partial JPEG" chip).
  - `increment_fileswritten` and `audit_entry` are gated on `was_written` (files physically on disk).
  - Partial-skip and report-only both return `was_written = false`.

  This keeps `audit_log.txt` and the "files written" counter aligned with what's on disk while the bincoded event log and the GUI's partial-count chip record every detected partial.

### Test fixups

- `crates/utmost-lib/src/engine.rs:2245 test_write_to_disk_report_only` — likely fine; asserts no `.pdf` files were written in report-only mode. Independent of the partial-skip path.
- Any test that asserts "with default flags, no partial JPEG file objects exist in the report" will need to invert: assert the file objects are present but no file is on disk.
- New tests in `crates/utmost-lib/src/engine.rs`:
  - `partial_jpeg_emits_file_found_when_flag_off`
  - `partial_jpeg_does_not_write_to_disk_when_flag_off`
  - `partial_jpeg_writes_to_disk_when_flag_on`
  - `partial_jpeg_writes_to_disk_when_write_all`

---

## Section 3 — Viewer source-path CLI

### Current code

`crates/utmost-viewer/src/main.rs`:

```rust
struct Args {
    target: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    utmost_gui::run_from_file(&args.target)
}
```

`utmost_gui::run_from_file` (`crates/utmost-gui/src/lib.rs:17`) takes a single `Path`, loads either a directory or a `carve_events.bin`, and launches the UI.

### Proposed change

#### 3a. CLI

```rust
#[derive(Parser, Debug)]
#[command(author, version, about = "Replay a utmost carve event log")]
struct Args {
    /// Path to either a directory or a carve_events.bin file.
    target: PathBuf,

    /// Search location for the original source image. May be a file (used
    /// directly if its basename matches a recorded source) or a directory
    /// (scanned by basename). May be repeated; entries are tried left to
    /// right. If omitted, falls back to the path recorded in the event log
    /// and then to the parent of the log's directory.
    #[arg(long, action = clap::ArgAction::Append)]
    source: Vec<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    utmost_gui::run_from_file(&args.target, args.source)
}
```

#### 3b. Library entry-point signature

In `crates/utmost-gui/src/lib.rs`, change `run_from_file`:

```rust
pub fn run_from_file(target: &Path, sources: Vec<PathBuf>) -> Result<()> { ... }
```

The function constructs a `SourceResolver` from `sources` and the event-log path, then passes it through to `launch_ui_with_journal`. The journal-recovery code path (`recovery.rs`) also receives the resolver since recovered runs can have the same source-missing situation.

#### 3c. Resolution semantics (recap from Section 1c)

Per source_id:
1. Walk `args.source` left-to-right:
   - File: matches if basename matches `SourceDescriptor.filename`'s basename.
   - Directory: matches if `<dir>/<basename>` exists.
2. `SourceDescriptor.filename` as-is.
3. `<parent of event log's parent>/<basename>` (i.e. the directory containing the output directory).
4. Otherwise `None` → icon fallback.

### Testing

Covered by the `source_resolver` tests in Section 1d. Additionally:

- `utmost-viewer` integration test that constructs a minimal bincoded log + a fake source image, invokes the binary with `--source <file>` and asserts the resolution succeeds. (Optional if Section 1's integration test already exercises this path through the library API.)

---

## Architecture impact

- `utmost-lib`: ~10 lines of behavioral change in `engine.rs`. No new modules, no schema change.
- `utmost-gui`:
  - New module: `source_resolver.rs` (~80 lines + tests).
  - Trait extension in `preview/mod.rs` (2 new methods with default impls).
  - JPEG renderer override in `preview/jpeg.rs` (~15 lines).
  - New `render_with_fallback` / `render_full_with_fallback` helpers in `preview/mod.rs` (~50 lines).
  - `thumb_worker.rs` thread body calls into the fallback helper.
  - `slint_adapter.rs` constructs the resolver, builds `sources_by_id` once per sync, threads it into both preview call sites.
  - `lib.rs::run_from_file` signature gains `Vec<PathBuf>`. Internal `launch_ui_with_journal` likewise.
- `utmost-viewer`: CLI gains repeatable `--source`. ~10 lines of `main.rs` change.

No new dependencies. No event schema change. No event-log format-version bump (existing logs continue to load; new logs contain more entries under default flags but use the same event types).

## Risk and rollout

- **Most disruptive:** Section 2's removal of the extraction-time partial-skip. Reports will gain entries that weren't there before for default-flag runs. Documented in the `migration` subsection above; the change is contained behind the existing `jpeg_scan.status` field that the viewer already consumes.
- **Source-bytes fallback:** Adds I/O to the thumb worker for some workloads (always-on whenever the on-disk file is missing). Worst case: a directory of recovered files where the user moved the output dir, every thumb request re-reads ~256 KB from the source. Acceptable; thumb worker is already off the Slint thread.
- **CLI compatibility:** `--source` is a new flag with a default empty `Vec`. No breaking change to existing viewer invocations.

## Out of scope / follow-ups

- A "source missing" badge or banner in the GUI for users debugging why thumbnails aren't appearing.
- Per-source-id explicit mapping (`--source <id>=<path>`).
- Loading multiple bincoded event logs simultaneously in one viewer session.
- A `utmost --rebuild-thumbnails` CLI mode that pre-populates the GUI thumb cache from the source on disk.
- Treating non-JPEG file types (PDF first pages, etc.) as image-renderable — the byte-range read works the same way; the trait only needs more renderers to override `render_from_bytes`.

## Validation

After implementation:

1. `cargo fmt && cargo clippy --all-targets -- -D warnings`.
2. `cargo test` (all crates).
3. Manual: run `cargo run -p utmost -- --report-only -t jpeg tests/fixtures/<image>`, then `cargo run -p utmost-viewer -- ./output --source tests/fixtures/<image>`, confirm JPEG thumbnails appear in the gallery.
4. Manual: run a carve without `--keep-incomplete-jpeg` against an image known to contain truncated JPEGs, open the result in the viewer, confirm the "Partial JPEG" filter chip is populated and the partials have thumbnails (rendered via Section 1's source-byte path).
