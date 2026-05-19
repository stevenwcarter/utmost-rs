# GUI Windowed File Loading — Scaling the Tile Grid to 250k+ Files

**Status:** Approved
**Date:** 2026-05-19
**Author:** Steve Carter
**Closes:** [#2](https://github.com/stevenwcarter/utmost-rs/issues/2)

## Problem

The Utmost GUI currently holds the full set of carved files in `ViewModel::files: Vec<FoundFile>` after hydration, computes filter and sort in Rust over that vector, and pushes the entire filtered set as `Vec<FileTileData>` to a Slint `VecModel`. The Slint grid then iterates `for tile[i] in root.tiles` inside a `Flickable` with absolute positioning — which instantiates every tile element, including those scrolled off-screen.

On a 250 000-file carve (which is a realistic forensic workload), this combination produces three compounding costs:

1. The match-ids `Vec<FileTileData>` materialization on every sync tick allocates and copies a quarter-million rows.
2. Slint instantiates a quarter-million tile rectangles, even though only ~30 are visible.
3. The thumbnail worker pipeline gets asked to render previews for files that will never enter the viewport in the user's session.

The result is a gallery that is slow to load and choppy to scroll once it's up. The SQLite index landed in the previous spec ([2026-05-19-gui-sqlite-index-design.md](2026-05-19-gui-sqlite-index-design.md)) made the index itself fast to read, but the UI path still holds and renders everything in memory.

## Goals

- Open and scroll a 250 000+ file case as smoothly as a 1 000-file case.
- Move filter and sort computation onto SQLite, leveraging the indexes already in place from the previous spec.
- Keep the in-RAM cost proportional to the visible viewport (plus a fixed annotation overhead), not the file count.
- Lay groundwork for ongoing perf work: file-backed structured logging and a periodic per-phase tick timer that can be toggled on without a rebuild.

## Non-Goals

- Replacing the in-memory `ViewModel` outright. Annotations (bookmarks, notes, best-choice, variants) and a small ID list still live in memory; the windowed `FoundFile` cache and all filter/sort work are what move behind SQLite.
- FTS5 search, multi-source `ATTACH DATABASE`, cancellable indexing, in-app telemetry UI, persisted user preferences. Each is tracked separately (see Out of Scope).
- WASM support for the new SQLite query paths. SQLite/Diesel remain `utmost-gui`-only; `utmost-lib` stays WASM-safe.

## Architecture Overview

```
┌──────────────────── ViewModel ────────────────────┐
│  match_ids:  Vec<FileStub>  ← full filter+sort    │
│              result, ~64 B/row (~16 MB for 250k)  │
│  window:     BTreeMap<u64, FoundFile>             │
│              window-size entries, on-demand       │
│  window_range: Range<usize>  // indices into      │
│                              // match_ids         │
│  bookmarks, notes, best_choice, variants_by_id:   │
│              kept in RAM (small even at 250k)     │
└──────────────────────────────────────────────────┘
        ▲                              ▲
        │ on filter/sort change:       │ on viewport scroll:
        │ run match-ids query;         │ if visible rows leave
        │ keep selection if it         │ the window, fetch the
        │ survives the filter          │ new slice from SQLite
        │                              │
┌─────────── index_db / queries.rs (new) ───────────┐
│  query_match_ids(filter, sort) -> Vec<FileStub>   │
│  fetch_window(ids[lo..hi])    -> Vec<FoundFile>   │
│  set_preview_status(id, status)                   │
└───────────────────────────────────────────────────┘
```

On open the indexer thread hydrates run/source/bookmark/note/best/variant data into the VM (unchanged from the previous spec), then runs `query_match_ids` for the initial filter+sort and fetches the first window. Slint's grid sees only the windowed tiles, positioned at their absolute row/col within the full grid. The `Flickable`'s `viewport-height` reflects all matched rows, so the scrollbar and scroll distance feel like a 250 000-row gallery.

The existing 100 ms Slint timer in `UiState::sync` gains one extra responsibility: read `viewport-y` and `cols` from the Slint grid, compute the visible row range, and if it strays outside `window_range ± SLIDE_MARGIN`, recompute and refetch.

### Threading model

Unchanged from the previous spec, with one new channel:

- The indexer thread is the **only** SQLite reader and writer for index data.
- One `IndexerCommand` channel UI → indexer for `Requery`, `FetchWindow`, `WritePreviewStatus`.
- One `IndexerEvent` channel indexer → UI for `MatchIds`, `WindowFilled`, `PreviewStatusVersion`, and the existing progress signals.
- Thumb workers post `PreviewOutcome { file_id, status }` to a third channel that the indexer drains and batches.

All channels are `crossbeam_channel`. Commands carry an `epoch: u64` so stale responses (e.g. a live-mode auto-requery in flight when the user changes a filter chip) can be ignored.

## SQL Layer

All SQLite reads and writes for windowed loading live in a new `crates/utmost-gui/src/index_db/queries.rs` module.

### Migration `0002_preview_status`

```sql
ALTER TABLE file ADD COLUMN preview_status TEXT NOT NULL DEFAULT 'unknown';
-- values: 'unknown' | 'has_preview' | 'no_preview'
CREATE INDEX idx_file_preview ON file(preview_status);
```

`meta` gains one new key: `preview_status_version` (monotonic counter, bumped inside the same transaction as any `preview_status` write).

### `query_match_ids`

Returns a `Vec<FileStub>` ordered by the active sort key. `FileStub` is just enough to render placeholder tiles: `{ file_id: u64, file_type: FileType, filename: String, filesize: u64 }` — roughly 64 bytes per row.

Skeleton SQL (Diesel composes WHERE clauses only for active filters, keeping the query index-eligible):

```sql
SELECT file_id, file_type, filename, filesize
FROM file
LEFT JOIN bookmark USING (file_id)              -- only when bookmarked_first
WHERE source_id = ?                              -- when source_filter is set
  AND file_id IN (SELECT file_id FROM bookmark) -- when bookmarked_only
  AND filesize BETWEEN ? AND ?                   -- when size_range set
  AND file_type IN (?, ?, ...)                   -- enabled_types
  AND preview_status != 'no_preview'             -- when hide_no_preview
  AND (jpeg_status = 'truncated' OR jpeg_status = 'fragmented')
                                                 -- when partial_types filter
ORDER BY
  (bookmark.file_id IS NOT NULL) DESC,           -- when bookmarked_first
  <sort_column> <asc|desc>,
  file_id ASC                                    -- stable tiebreaker
```

`<sort_column>` is one of `filename`, `filesize`, `file_type`, `img_offset`. All four are indexed by the previous spec's migration.

### `fetch_window`

```sql
SELECT * FROM file WHERE file_id IN (?, ?, ?, …)
```

The result is reordered Rust-side to match the input slice order (the `IN` set is unordered). The slice is bounded to ~2 500 ids, comfortably within SQLite's 32 766 parameter limit.

### `set_preview_status`

Single-row update; runs inside the indexer thread's batched-write transaction along with any other pending writes. Bumps `preview_status_version` in the same transaction.

### Filtered total

`match_ids.len()` is the total. No separate `COUNT(*)`.

## ViewModel Changes

### Dropped state

- `files: Vec<FoundFile>` (the in-memory full set).
- `visible_files: Vec<FileId>` (the post-filter ID vector — supplanted by `match_ids`).
- `thumbnail_ready: BTreeSet<FileId>` (replaced by SQL `preview_status`).
- `next_file_id` and the GUI-local `FileId` counter — see FileId unification below.

### New state

- `match_ids: Vec<FileStub>` — full filter+sort result. Cleared on filter/sort change and rebuilt from `IndexerEvent::MatchIds`.
- `window: BTreeMap<u64, FoundFile>` — file_id → full data, populated from `IndexerEvent::WindowFilled`. Bounded; rows outside `window_range` are dropped on each slide.
- `window_range: Range<usize>` — indices into `match_ids` of the rows currently materialized.
- `preview_status_version: u64` — last value observed; the sync tick triggers a debounced requery when this advances and `hide_no_preview` is active.

### Behavioral changes

- `recompute_visible()` becomes a no-op. Filter and sort changes post `IndexerCommand::Requery { filter, sort, epoch }` instead.
- Selection-by-id survives filter changes only if the id is still in the new `match_ids`. Same policy as today.
- Keyboard nav (`j`/`k`/arrow keys) and lightbox prev/next walk `match_ids` (in-memory), not `window`. If selection lands outside `window_range`, the next sync tick slides the window.

### FileId unification

The previous spec flagged the dual ID space (engine-allocated `file.file_id` vs. GUI-local `FoundFile.id`) as a follow-up refactor. This work does it: every UI state is keyed on `file.file_id`. Affected sites:

- `image_cache: HashMap<u64, slint::Image>` (was `HashMap<FileId, _>`).
- `bookmarks: BTreeSet<u64>`, `notes: BTreeMap<u64, Vec<NoteEntry>>`, `best_choice: BTreeMap<u64, u64>` (already used the engine id, no change).
- `variant_of: BTreeMap<u64, u64>`, `variants_by_id: BTreeMap<u64, VariantGroup>` (already engine id).
- `vm.selection: Option<u64>` (was `Option<FileId>`).
- `vm.lightbox_*` fields that referenced the GUI-local id.

A separate GitHub issue does not exist for the unification; this work bundles it.

## Slint-Side Windowed Rendering

The grid keeps its current shape — a `Flickable` containing manually-positioned tile rectangles — but the model is now the window only. Each tile carries its absolute row/col in the full filtered grid.

### New properties

```slint
in property <int> total-rows;           // ceil(match_ids.len() / cols)
in property <int> grid-cols;            // computed Slint-side, mirrored to Rust
in-out property <length> viewport-y;    // Flickable's viewport-y, exposed
in property <bool> requery-active;      // light overlay while requery runs >250ms
```

`FileTileData` gains `absolute-row: int` and `absolute-col: int`. The grid pane:

```slint
property <int> cols: max(1, floor((self.width + self.gap) / (self.tile_w + self.gap)));
property <int> total-rows: root.total-rows;
property <length> tile-pitch-y: self.tile_h + self.gap;

changed cols => { root.grid-cols-changed(self.cols); }

grid_flick := Flickable {
    viewport-width:  parent.cols * (parent.tile_w + parent.gap);
    viewport-height: parent.total-rows * parent.tile-pitch-y;

    for tile[i] in root.tiles: Rectangle {
        x: tile.absolute-col * (grid_pane.tile_w + grid_pane.gap);
        y: tile.absolute-row * grid_pane.tile-pitch-y;
        // … unchanged tile body
    }
}
```

`cols` is the source of truth: Slint computes it from the pane width and notifies Rust on change. Rust observes the most recent value and uses it when computing `absolute_row` and `absolute_col` for each window slot.

### Window-slide policy

- `visible_tile_count = cols × ceil(viewport_h / tile_pitch_y)`.
- `window_size = clamp(25 × visible_tile_count, 500, 5000)`.
- `slide_margin = (window_size - visible_tile_count) / 2` rows above and below the visible viewport.
- Slide trigger (evaluated each sync tick): if `visible_first_row - SLIDE_TRIGGER < window_range.start` or `visible_last_row + SLIDE_TRIGGER > window_range.end` (with `SLIDE_TRIGGER = 4` rows), recompute `window_range` centered on the visible viewport, post `IndexerCommand::FetchWindow { range, epoch }`.

During the fetch, tiles in `vm.window` continue to render normally; tiles in `match_ids[range]` but not yet in `vm.window` render with placeholder thumbnails using their `FileStub` data so the grid never flashes empty.

### Thumb requests

`sync()` iterates `vm.window` (not `match_ids`) when building the tile model and when requesting thumbnails. At most ~2 500 in-flight requests, vs. the unbounded request stream we have today.

## Lifecycle

### Cold and warm open

Same path. After the indexer thread finishes the existing hydration (run + sources + annotations), it runs `query_match_ids(filter, sort)` and posts `IndexerEvent::MatchIds`. The UI installs `match_ids`, computes the initial `window_range`, and posts back `IndexerCommand::FetchWindow`. First paint of the windowed grid happens on the second sync tick after open.

### Filter or sort change

1. UI sets the new `FilterState`, increments `epoch`, posts `IndexerCommand::Requery { filter, sort, epoch }`.
2. Indexer runs `query_match_ids` (target <50 ms for 250k rows on indexed queries — verified by `bench_match_ids_250k`).
3. Indexer returns `IndexerEvent::MatchIds`. UI installs, resets `window_range` to `0..window_size`, posts `FetchWindow`.
4. If the requery exceeds 250 ms, the lightweight `requery-active` overlay appears (a thin progress strip, not the full-grid overlay used during initial indexing). Filters and sort controls remain interactive; the user can override an in-flight requery, which bumps the epoch and drops the stale response.

### Scroll

Per sync tick:

1. Read `viewport-y` and `grid-cols`.
2. Compute `visible_first_row = floor(-viewport-y / tile_pitch_y)` and `visible_last_row = visible_first_row + ceil(viewport_h / tile_pitch_y)`.
3. Compare to `window_range`. Slide if needed.

### Live mode

`run_live` is unchanged at the engine and writer level. After each indexer-batch commit, if live mode is active and new files were inserted, schedule a debounced (~500 ms) `query_match_ids` rerun and broadcast a fresh `IndexerEvent::MatchIds`. The UI installs it, preserves selection, and only refetches the window if the visible range now extends past `match_ids.len()`. No `requery-active` overlay for live-mode auto-refreshes — they happen quietly.

### Preview-status writes

Thumb workers send `PreviewOutcome { file_id, status }` to the indexer thread. Indexer batches them (≤100 outcomes or 500 ms, whichever first) and writes via one transaction that updates each row's `preview_status` and bumps `meta.preview_status_version`. On the UI thread's next sync tick the version is observed; if it advanced and `hide_no_preview` is on, a debounced (~1 s) requery is scheduled. Selection is preserved if its id is still in the new list.

## Performance Instrumentation

A new `crates/utmost-gui/src/telemetry.rs` module provides:

### File-backed `tracing` subscriber

`telemetry::init_subscriber()` is called from `utmost-gui`'s GUI entry path. The CLI's existing `tracing_subscriber::fmt()` call is skipped for GUI runs (CLI carve runs are unchanged).

- **Log file path:** `${UTMOST_LOG_DIR:-<platform default>}/utmost-gui.log`
  - macOS: `~/Library/Logs/utmost/utmost-gui.log`
  - Linux: `${XDG_STATE_HOME:-$HOME/.local/state}/utmost/utmost-gui.log`
  - Windows: `%LOCALAPPDATA%\utmost\logs\utmost-gui.log`
- **Rolling:** `tracing-appender` daily roller, last 7 files retained.
- **Level filter:** `EnvFilter::from_default_env().or("warn")` (honors `RUST_LOG`).
- **Stderr mirror:** ERROR-level only.
- **Boot announcement:** one INFO line on startup with the resolved log path, also echoed to stderr once.

### `PerfRecorder`

Owned by `UiState`, instruments hot paths inside `UiState::sync` and on the indexer thread. Activation is opt-in:

- Off without `UTMOST_PERF_TRACE` and without `utmost_gui::perf=info` in `RUST_LOG`.
- On with `UTMOST_PERF_TRACE=1`, or with `RUST_LOG=utmost_gui::perf=info`.

Activation is checked once at init.

**Instrumented phases on `UiState::sync`:**

| Phase | What it measures |
|---|---|
| `drain_events` | Pulling `IndexerEvent`s from the channel and applying them. |
| `viewport_read` | Reading `viewport-y` / `grid-cols` from Slint. |
| `slide_decide` | Computing whether to slide the window and issuing the fetch. |
| `build_tiles` | Constructing `Vec<FileTileData>` from `vm.window`. |
| `replace_tiles_model` | `replace_model` call against `tiles_model`. |
| `build_metadata` | Selected-file detail-panel row construction. |
| `chips_refresh` | Filter / group chip rebuilds when filter state changed. |
| `total` | Whole tick. |

**Indexer-thread phases** (target `utmost_gui::perf::indexer`): `query_match_ids`, `fetch_window`, `batch_flush`, `preview_status_write`.

### Aggregation and emit

Per-phase samples accumulate into a simple struct: `{ count: u64, sum_us: u64, max_us: u64 }` plus an 8-bucket exponential histogram for a cheap p95 estimate. No external dependency unless `hdrhistogram` is already pulled in transitively (check during implementation; the simple struct is enough).

Every `UTMOST_PERF_TICKS` ticks (default 100 — 10 s at 10 Hz) the recorder emits one structured log line and resets:

```
INFO utmost_gui::perf window=10.0s ticks=100 \
  build_tiles{p50=180us p95=620us max=2.1ms} \
  replace_tiles_model{p50=410us p95=1.2ms max=3.8ms} \
  drain_events{p50=8us p95=120us max=900us} \
  total{p50=1.9ms p95=4.4ms max=11.7ms}
```

Fields ordered slowest-mean-first so bottlenecks are immediately legible.

### Cost when disabled

The `phase()` guard's body is `#[inline(always)]` and starts with an `AtomicBool::load(Relaxed)` fast-path check; if disabled, returns a no-op guard. No `Instant::now`, no atomics-write, no log-macro expansion. A microbench (`bench_perf_disabled_zero_cost`) confirms ≤1 ns added per phase when off.

## Error Handling

| Failure | Behavior |
|---|---|
| `query_match_ids` errors (SQL/IO) | `tracing::error!`; keep previous `match_ids`; transient banner ("Filter failed; showing previous results"). No crash. |
| `fetch_window` errors | Tiles in the missing range render as `FileStub` placeholders. Retry once on next sync; after two consecutive failures, stop retrying for that window. |
| Selection no longer in `match_ids` after requery | Clear `vm.selection`. Detail panel empty. Lightbox closes if open. |
| Window slides past `match_ids.len()` | Clamp `window_range` to `0..min(window_size, match_ids.len())`. |
| `match_ids` empty | Hide grid, show existing "no matches" empty-state. Filter chips remain interactive. |
| Live-mode auto-requery in flight when user changes filter | User command bumps epoch; stale auto-requery response is dropped. |
| `cols` changes mid-fetch (window resize) | Window data unchanged (keyed on file_id). Next sync recomputes `absolute_row` / `absolute_col` from new `cols`. No refetch. |
| Preview-status write fails | `tracing::warn!`; status stays `unknown`. Worker retries on the next decode. |
| Multi-source merged case | Each per-source SQLite is queried sequentially; results merged in indexer thread by sort key. Sub-50 ms total at 250k thanks to indexes. (Per-source `ATTACH DATABASE`, Issue #4, would tighten this further.) |
| Log file directory not writable | Subscriber init falls back to stderr; one warning printed. App continues. |
| `tracing-appender` write failure | Internal to the crate — line is dropped. Acceptable. |

## Memory Ceiling

Dominant in-RAM cost scales with `match_ids.len()`, not file content.

- `FileStub` ≈ 64 bytes (file_id + small-enum FileType + ~40 B heap for filename + filesize). 250 000 entries ≈ 16 MB; 1 000 000 ≈ 64 MB.
- `window` bounded at ~2 500 `FoundFile` entries (~256 B each) ≈ 640 KB.
- Bookmarks / notes / best / variants in aggregate < 10 MB even at 1 M scale.

The Issue #2 acceptance criterion (< 100 MB at 1 M rows) is met with margin.

## Testing Strategy

### Unit tests

**`crates/utmost-gui/src/index_db/queries.rs`:**

- `query_match_ids` over a 10k-row fixture: each filter chip in isolation returns correct ids; multiple chips compose with AND; sort by each `SortKey` is stable on file_id; `bookmarked_first` puts bookmarked rows first.
- `fetch_window` returns rows in input-slice order, not natural table order.
- `set_preview_status` updates the column and bumps `meta.preview_status_version`.

**`crates/utmost-gui/src/view_model.rs`:**

- `apply_match_ids` installs the new vector and resets `window_range` to start.
- Filter change preserves selection if its id is still in `match_ids`; clears otherwise.
- Window-slide decision: crossing `SLIDE_TRIGGER` rows of either window edge triggers a new range centered on the viewport; staying inside does not.
- FileId unification: `image_cache` keys, `bookmarks`, `notes`, `best_choice`, selection, lightbox nav all use `file.file_id`.

**`crates/utmost-gui/src/telemetry.rs`:**

- Aggregator math (count/sum/max correct after a known sample stream).
- Activation gate: off without env or `RUST_LOG`, on with `UTMOST_PERF_TRACE=1`, on with `RUST_LOG=utmost_gui::perf=info`.
- Emit cadence: 101 phase samples → exactly one summary line; counters reset to zero after.

### Integration tests in `crates/utmost-gui/tests/`

- `windowed_load_cold.rs` — open a synthetic 50k-file case; assert initial sync materializes only `window_size` rows in `vm.window`, but `match_ids.len() == 50000`.
- `windowed_filter_change.rs` — toggle a type chip; assert match-ids requery fires once, `match_ids.len()` matches expected, window refetched.
- `windowed_scroll_slides.rs` — simulate viewport-y changes crossing both ends of the window; assert window slides and stale tiles drop.
- `windowed_keyboard_nav.rs` — `j` 5000 times; assert selection advances across slides without losing track.
- `windowed_live_mode.rs` — append files mid-session via a live writer; assert debounced auto-requery extends `match_ids`.
- `preview_status_persist.rs` — render thumbs (some succeed, some fail), restart loader, assert previous failures are filtered out under `hide_no_preview`.
- `telemetry_log_smoke.rs` — set env var, run a 200-tick synthetic sync, assert log file contains a `utmost_gui::perf` line with expected fields.

### Benchmarks in `crates/utmost-gui/benches/` (`#[ignore]` in CI)

- `bench_match_ids_250k` — full filter+sort query on a 250k-row DB. Target < 50 ms.
- `bench_window_fetch_2500` — fetch 2 500 rows by id slice. Target < 10 ms.
- `bench_sync_tick_window` — full `UiState::sync` over a 250k case with a populated window. Target < 5 ms.
- `bench_perf_disabled_zero_cost` — `PerfRecorder::phase()` when off. Target ≤ 1 ns / call.

### Not tested

- SQLite-level concurrency (trusted upstream).
- `tracing-appender` rolling correctness (trusted upstream).
- Visual rendering of the windowed grid (not part of existing conventions). We test the Slint property bindings, not pixel output.

## File Inventory

### New files

| Path | Purpose |
|---|---|
| `crates/utmost-gui/migrations/0002_preview_status/up.sql` | Add `preview_status` column + index. |
| `crates/utmost-gui/migrations/0002_preview_status/down.sql` | Drop index + column. |
| `crates/utmost-gui/src/index_db/queries.rs` | `query_match_ids`, `fetch_window`, `set_preview_status`. |
| `crates/utmost-gui/src/telemetry.rs` | File subscriber init + `PerfRecorder` + aggregator. |
| `crates/utmost-gui/tests/windowed_load_cold.rs` | Cold-open windowing test. |
| `crates/utmost-gui/tests/windowed_filter_change.rs` | Filter change requery test. |
| `crates/utmost-gui/tests/windowed_scroll_slides.rs` | Scroll-induced window slide test. |
| `crates/utmost-gui/tests/windowed_keyboard_nav.rs` | Keyboard nav across slides. |
| `crates/utmost-gui/tests/windowed_live_mode.rs` | Live-mode auto-requery test. |
| `crates/utmost-gui/tests/preview_status_persist.rs` | Preview-status persistence test. |
| `crates/utmost-gui/tests/telemetry_log_smoke.rs` | Telemetry log smoke test. |
| `crates/utmost-gui/benches/windowed_load.rs` | Four ignored Criterion benches. |

### Modified files

| Path | Change |
|---|---|
| `crates/utmost-gui/Cargo.toml` | Add `tracing-appender`, `dirs` (or `directories`). |
| `Cargo.toml` (workspace) | Workspace deps for the above. |
| `crates/utmost-gui/src/index_db/mod.rs` | Expose `queries` submodule. |
| `crates/utmost-gui/src/index_db/schema.rs` | Regenerate against new migration. |
| `crates/utmost-gui/src/index_db/models.rs` | `FileRow` gains `preview_status`. |
| `crates/utmost-gui/src/index_db/hydrate.rs` | No longer hydrates `vm.files`; hydrates run/source/annotations only. |
| `crates/utmost-gui/src/indexer_thread.rs` | New `IndexerCommand::{Requery, FetchWindow, WritePreviewStatus}`; new `IndexerEvent::{MatchIds, WindowFilled, PreviewStatusVersion}`; epoch counter on commands. |
| `crates/utmost-gui/src/view_model.rs` | Drop `Vec<FoundFile> files` and GUI-local `FileId` counter. Add `match_ids`, `window`, `window_range`, `preview_status_version`. `recompute_visible` becomes a no-op. |
| `crates/utmost-gui/src/thumb_worker.rs` | Key on `file.file_id`; on decode outcome, send `PreviewOutcome` to indexer thread. |
| `crates/utmost-gui/src/slint_adapter.rs` | Read `viewport-y` / `grid-cols` from Slint in sync tick; issue slide commands; build tile data from `vm.window` with absolute row/col; wire `PerfRecorder` phases; new `requery-active` overlay property. |
| `crates/utmost-gui/src/preview/*` | Any code keyed on the old `FileId` switches to `file.file_id`. |
| `crates/utmost-gui/src/lib.rs` | Call `telemetry::init_subscriber()` for GUI runs; thread `PerfRecorder` into `UiState`. |
| `crates/utmost-gui/ui/main.slint` | New `total-rows`, `grid-cols`, `requery-active` properties; expose `viewport-y` via the grid. |
| `crates/utmost-gui/ui/detail.slint` | Tile loop uses each tile's `absolute-row` / `absolute-col`; viewport-height bound to `total-rows * tile-pitch-y`; `changed cols => grid-cols-changed(...)`. |
| `crates/utmost-cli/src/main.rs` | GUI launch path skips `tracing_subscriber::fmt()`; carve path unchanged. |
| `README.md` | Document `UTMOST_LOG_DIR`, `UTMOST_PERF_TRACE`, `UTMOST_PERF_TICKS`, log file location. |

## Rollout

Eight ordered steps. Each leaves the workspace compiling and existing tests green:

1. **Telemetry subscriber + `PerfRecorder` skeleton.** File-backed tracing, env-var gate, zero-cost-when-off recorder. CLI path untouched. Lands first so subsequent steps can measure baseline perf.
2. **Migration `0002_preview_status` + thumb worker writes.** New column, indexer-thread batched writes from `PreviewOutcome` channel, schema regen. `preview_status_persist` test green.
3. **FileId unification.** Drop GUI-local `FileId`; key all in-memory state on `file.file_id`. Existing tests stay green after fixture updates. No behavior change yet.
4. **`queries.rs` + `FileStub` + `query_match_ids` / `fetch_window`.** Unit tests for both. Not wired to UI yet.
5. **Indexer thread command/event extensions + epoch.** Indexer accepts `Requery` / `FetchWindow`, returns `MatchIds` / `WindowFilled`. No UI use yet.
6. **ViewModel migration.** `vm.match_ids` + `vm.window` + `vm.window_range`. `recompute_visible` becomes a no-op. UI temporarily reads `match_ids[0..window_size]` materialized eagerly so the workspace compiles before the Slint side changes. Existing integration tests adjusted.
7. **Slint windowed grid.** Absolute-row positioning, viewport-y bridge, sync-tick slide. `windowed_load_cold`, `windowed_filter_change`, `windowed_scroll_slides`, `windowed_keyboard_nav` green. Manual smoke against the 286k test case.
8. **Live-mode debounced refresh + `hide_no_preview` requery on `preview_status_version` bump.** `windowed_live_mode` green; preview-status filter behaves under load.

The feature ships behind no flag; step 8 is the default loader path. The final commit message references **`Closes #2`**.

## Out of Scope (deferred to follow-up issues)

- FTS5 search across filenames and notes. **[Issue #3](https://github.com/stevenwcarter/utmost-rs/issues/3).**
- Multi-source aggregated SQL queries via `ATTACH DATABASE`. **[Issue #4](https://github.com/stevenwcarter/utmost-rs/issues/4).**
- Cancel button on the indexing overlay. **[Issue #5](https://github.com/stevenwcarter/utmost-rs/issues/5).**
- Perf-tripwire / visual regression CI for the loading UI. **[Issue #6](https://github.com/stevenwcarter/utmost-rs/issues/6).**
- Graceful cancellation when the window closes mid-carve. **[Issue #7](https://github.com/stevenwcarter/utmost-rs/issues/7).**
- In-app perf telemetry UI (FPS / phase timings). **[Issue #8](https://github.com/stevenwcarter/utmost-rs/issues/8).**
- Persisted user preferences for window size, slide margin, perf-trace state. **[Issue #9](https://github.com/stevenwcarter/utmost-rs/issues/9).**
