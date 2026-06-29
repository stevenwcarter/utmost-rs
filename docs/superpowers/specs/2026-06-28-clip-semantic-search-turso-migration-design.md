# CLIP Semantic Search + turso Migration — Design

**Date:** 2026-06-28
**Status:** Approved (brainstorm → spec)
**Topic:** Add CLIP semantic image search to the utmost GUI, mirroring imgfind.
This requires first migrating the per-case index from Diesel/SQLite to `turso`
(pure-Rust SQLite with a vector extension), then building the embedding +
search feature on top of it. The work is split into two sequential phases:
**Phase 1 — turso migration** (behavior-preserving), **Phase 2 — CLIP search**.

## Problem

utmost carves files and the GUI lets an examiner browse, filter, and sort the
recovered images per case. There is no way to find images by *content* ("a
person holding a sign", "a beach at sunset"). imgfind already solved this with
CLIP embeddings + cosine-distance KNN over a `turso` vector column, plus a
background processing job and a `\`-toggled status panel. We want the same
capability in utmost, reusing the public `clipper` crate and the higher-fidelity
model imgfind uses.

utmost's index layer is Diesel/`rusqlite` (bundled `libsqlite3-sys`), which has
no vector type or `vector_distance_cos` function. Brute-forcing cosine
similarity in Rust over Diesel rows would work but diverges from imgfind and
scales poorly. Migrating to `turso` first gives us the same `F32_BLOB` vector
column and `vector_distance_cos()` KNN that imgfind uses, so Phase 2 is a close
port rather than a reinvention.

## Goals

- **Phase 1:** Replace utmost-gui's Diesel index layer with `turso`, preserving
  all current behavior. The same per-case `<slug>-index.sqlite` semantics, the
  same public read/write API, all existing tests green (ported to turso).
- **Phase 1:** Extract the index layer (DB + preview generation) out of
  `utmost-gui` into a new native crate `utmost-index`, so a headless CLI
  `process` run never links Slint. `utmost-lib` remains WASM-safe and untouched.
- **Phase 2:** Compute CLIP embeddings for every preview-able image in a case
  (from its persisted preview), stored as `turso` vectors, via either an
  explicit `utmost process` CLI command or an auto-starting, pausable GUI
  background job.
- **Phase 2:** A semantic search box + clear button in the detail toolbar that
  ranks the case's images by similarity to a text query (`vector_distance_cos`),
  respecting the other active filters.
- **Phase 2:** A `\`-toggled status panel showing per-phase background-job
  progress (Previews, Embeddings) with Running/Paused/Idle and Pause/Resume.
- The GUI stays usable (browse, filter, sort, open, and search the
  already-embedded subset) while processing runs.

## Non-Goals

- **No migration framework / no versioned schema.** The per-case index is a
  derived cache rebuildable from `<slug>-events.bin`; schema is created with
  idempotent `CREATE TABLE IF NOT EXISTS` on open. A schema change means
  rebuild, not migrate. (This mirrors imgfind's migration retirement.)
- **No re-embedding** of images already embedded for the active model. Switching
  models legitimately makes all rows "missing embedding" again; the processing
  job then backfills.
- **No ETA/throughput readout** and **no Stop/cancel** control in the status
  panel v1 — Pause/Resume only (matching imgfind's v1).
- **No bulk-recovery or other carving changes.** Carve output and `utmost-lib`
  are unchanged.
- **No image-vector search inside `utmost-lib`** (it must stay WASM-safe; CLIP
  deps are native-only and live in `utmost-index` behind a feature).
- **Phase 1 introduces no user-visible behavior change.** New tables/columns for
  CLIP are created but unused until Phase 2.

---

# Phase 1 — turso migration

## Crate extraction

A new native crate **`utmost-index`** is added to the workspace
(`crates/utmost-index/`). It owns:

- The turso connection/pool layer + sync `block_on` bridge.
- The schema (`create_schema`) and all read/write functions currently in
  `crates/utmost-gui/src/index_db/` (`mod.rs`, `schema.rs`, `models.rs`,
  `queries.rs`, `writer.rs`, `hydrate.rs`).
- The preview-generation code currently in `crates/utmost-gui/src/preview/`
  (`render_with_fallback`, `render_full_with_fallback`, `encode_thumb_to_jpeg`,
  the `PreviewRegistry`, `PreviewOutput`, format renderers). This is Slint-free
  (returns `image::RgbaImage` / `Vec<u8>`), so it moves cleanly.

Dependency graph after extraction:

```
utmost-lib    (WASM-safe core, unchanged)
utmost-index  (NEW: turso DB + preview gen; native-only) → depends on utmost-lib
utmost-gui    → depends on utmost-index (+ utmost-lib)
utmost-cli    → depends on utmost-lib; gains an optional dep on utmost-index
utmost-viewer → depends on utmost-gui (unchanged)
```

`utmost-gui` keeps everything Slint-coupled: `view_model.rs`, `slint_adapter.rs`,
`thumb_worker.rs`, `picker.rs`, `case.rs`, `indexer_thread.rs`, `lib.rs`, the
`.slint` markup. These call into `utmost-index` for DB + preview operations
(re-exported types keep call sites stable). Things that move retain their module
paths under the new crate; `utmost-gui` adds `use utmost_index::...` and, where
helpful, a thin `pub use` shim so the diff at call sites stays minimal.

**`PreviewOutcome` / `PreviewStatus` / `PreviewCodec`**: these types are shared
between the preview producer (now in `utmost-index`) and the thumb worker /
writer. They move to `utmost-index` and are re-exported from `utmost-gui`.

## Dependencies

Workspace `Cargo.toml`: **remove** `diesel`, `diesel_migrations`, and the
direct `libsqlite3-sys` (bundled) dependency. **Add**:

```toml
turso     = { version = "0.7.0-pre.10", default-features = false }
deadpool  = { version = "0.13", features = ["managed"] }
tokio     = { version = "1", features = ["rt-multi-thread"] }
```

Pin `turso` to exactly `0.7.0-pre.10` (the version imgfind ships and has
validated; it is pre-release). `utmost-index` depends on all three. `utmost-gui`
no longer needs Diesel.

## Connection layer (`utmost-index/src/db/`)

Mirror imgfind's `db_pool.rs` + `lib.rs::block_on`:

- **`block_on`** — a process-wide `static RUNTIME: LazyLock<tokio::runtime::Runtime>`
  (multi-thread, `enable_all`) with `pub fn block_on<F: Future>(f: F) -> F::Output`.
  All sync call sites in utmost-gui's threads call DB functions that internally
  `block_on` the async turso calls, so the existing synchronous threading model
  (indexer-writer thread, query-loop thread, thumb-worker, picker reads on the
  UI thread) is unchanged.
- **`TursoPool`** — wraps `turso::Database` (from
  `turso::Builder::new_local(path).build().await`) in a `deadpool` managed pool.
  The `Manager::create` hook applies per-connection PRAGMAs:
  `busy_timeout = 5000`, `journal_mode = WAL`, `foreign_keys = ON` (drain the
  `PRAGMA journal_mode` result rows, as imgfind does). `get().await` checks out a
  connection.
- **`IndexDb`** — keeps its current public constructors (`open(path)`,
  `open_in_memory()`) and `conn()`-style access, but now holds a `TursoPool` (or
  a single checked-out connection for the simple cases). `open` runs
  `create_schema` (CREATE IF NOT EXISTS) instead of `run_pending_migrations`. The
  process-wide `OPEN_GUARD` mutex is removed — the pool + turso's WAL handling
  cover concurrent opens; the existing `concurrent_open_on_same_path_does_not_lock`
  test is ported to prove it.
- **In-memory test DBs:** use `turso::Builder::new_local(":memory:")` if turso
  supports it; otherwise fall back to a per-test temp-file path. (The
  implementer verifies which works against `0.7.0-pre.10` and picks one; tests
  must not share a path.)

### Pool ownership

`CaseHandle` (in utmost-gui) owns the per-case `TursoPool` and shares clones with
its indexer-writer and query-loop threads (deadpool `Pool` is cheaply cloneable).
The picker opens short-lived pools/connections per row read and drops them. The
thumb worker uses a pool clone for `preview_blob_lookup`. This replaces the
prior pattern of each thread independently `IndexDb::open`-ing the same path.

## Schema (`utmost-index/src/db/schema_sql.rs`)

Replace the three Diesel embedded migrations with one idempotent
`create_schema(conn) -> Result<()>` that issues `CREATE TABLE IF NOT EXISTS` +
`CREATE INDEX IF NOT EXISTS` for the full schema. The table set and columns are
**identical** to today's (so existing on-disk caches keep working — turso reads
the SQLite file; an existing `__diesel_schema_migrations` table is harmless and
ignored). Tables: `meta`, `run`, `source`, `file`, `bookmark`, `note`,
`best_choice`, `recovery_run`, `variant`, `preview_blob`. Indexes:
`file(source_id, file_type, filesize, img_offset)`, `note(file_id)`,
`variant(candidate_file_id)`, `file(preview_status)`.

`file.preview_status TEXT NOT NULL DEFAULT 'unknown'` is part of the base
`CREATE TABLE` (the old 0002 migration's column is now inline). The old
back-fill steps (0002 `preview_status_version` seed, 0003 `has_preview→unknown`
backfill) are dropped: a fresh schema is already correct, and pre-existing
caches already ran those migrations. `preview_status_version` is seeded lazily
by the existing meta-upsert path the first time a preview is written (or seeded
to `'0'` in `create_schema` via `INSERT OR IGNORE INTO meta`).

The Phase-2 `clip_embedding` table is added to `create_schema` in Phase 2 (see
below); Phase 1 does not create it.

## Porting the read/write API

Every function in `queries.rs` (5) and `writer.rs` (11) is rewritten to use
turso's async API wrapped in `block_on`, **keeping the same public sync
signatures** so the 9 call sites need only minimal edits (mostly the `use` path
change to `utmost_index`):

- `query_match_ids`, `fetch_window`, `read_output_root`, `set_preview_status`,
  `picker_metadata_row`.
- `IndexDbWriter::{new, apply, flush}`, `apply_event` (all 13 `CarveEvent`
  variants), `write_preview_outcomes`, `apply_annotation_event`,
  `write_ui_state`, `read_ui_state`, `preview_blob_lookup`, plus the internal
  `upsert_meta`, `read_meta_i64`, `read_meta_str`.

Translation rules (from imgfind's patterns):

- **Row mapping:** replace `#[derive(Queryable/QueryableByName)]` with manual
  helpers `col_i64`, `col_text`, `col_blob`, `col_opt_*` over `turso::Row`
  (`row.get_value(idx)` + `as_integer/as_text/as_blob`).
- **Inserts/updates:** raw SQL with `?N` placeholders and tuple params, or
  `turso::params_from_iter(Vec<turso::Value>)` for variable-length `IN (...)`
  lists (used by `fetch_window`).
- **Upserts:** `INSERT ... ON CONFLICT(pk) DO UPDATE SET ...` raw SQL (replaces
  Diesel `.on_conflict().do_update().set()`).
- **Transactions:** `let tx = conn.transaction().await?; ...; tx.commit().await?;`
  wrapping the multi-statement ops (`flush`, `write_preview_outcomes`,
  `write_ui_state`, `set_preview_status`).
- **`query_match_ids`** keeps building its dynamic WHERE/ORDER SQL string from
  `FilterState`; the bound-param `Param::{Int,Big,Str}` enum maps to
  `turso::Value`. Behavior (filters, sort, bookmark-first) is unchanged.
- **`hydrate.rs::snapshot_from_db`** reads all tables into `ViewModelSnapshot`;
  ported row-by-row with the manual mappers, same output.

`models.rs`'s Diesel derive structs become plain structs (no derives) or are
folded into the mapper functions; `file_row_to_found_file` is preserved.

## Testing (Phase 1)

Port all 22 existing index_db tests to turso (in-memory or temp-file). They are
the behavior-preservation harness:

- `mod.rs` (7): open/pragmas, concurrent open, schema creation.
- `queries.rs` (11): `query_match_ids` filter/sort matrix (incl. the 1500-row
  fixture), `fetch_window` ordering, preview-status filter, `picker_metadata_row`.
- `writer.rs` (4): event apply/flush round-trips, `write_preview_outcomes`,
  `write_ui_state`/`read_ui_state` round-trip incl. corrupt-blob → `Ok(None)`,
  upsert idempotency.

Add a focused test that an **existing pre-turso SQLite file opens and reads
correctly** (create a fixture with the old table shape — or assert that
`create_schema` over a populated DB is a no-op preserving rows). The migration
is "done" when the full GUI behaves identically and `cargo test` is green.

## Phase 1 verification

- `cargo build` (all crates, default features) and `cargo build -p utmost-cli`.
- `cargo test` green (ported suite).
- `cargo clippy --all-targets` clean, `cargo fmt` clean.
- Manual smoke: open the viewer against an existing output dir; picker rows,
  case open, filter/sort, preview thumbnails, bookmarks/notes, UI-state
  persistence all behave as before. An existing Diesel-era index cache opens
  without rebuild.

---

# Phase 2 — CLIP semantic search

## `clip` cargo feature

A new **`clip`** feature, **enabled by default**, gates all CLIP code + heavy
deps. Declared on `utmost-index` (owns the engine) and re-exposed by `utmost-gui`
and `utmost-cli`:

```toml
# utmost-index/Cargo.toml
[features]
default = ["clip"]
clip = ["dep:clipper"]   # image/turso are always-on deps (preview gen, DB)

[dependencies]
clipper = { git = "https://github.com/stevenwcarter/clipper-rs", optional = true }
```

`--no-default-features` yields a lean build with no candle/hf-hub/tokenizers and
no model download path. `utmost-lib` never gets these deps. When `clip` is off:
the `process` CLI command and the GUI background-embedding phase compile out (the
search box is hidden / disabled, the preview-only processing still works).

## Embedder wrapper (`utmost-index/src/clip/`, `#[cfg(feature = "clip")]`)

- **Model:** `laion/CLIP-ViT-L-14-laion2B-s32B-b82K` (768-dim) — the
  higher-fidelity model imgfind activates. A `pub const ACTIVE_MODEL: &str` and
  `pub const ACTIVE_DIM: usize = 768`.
- **Loading:** lazy via `Arc<OnceLock<ClipEmbedder>>`, populated on a background
  thread (mirrors imgfind's `start_loading_model`). `ClipEmbedder::from_model(
  ACTIVE_MODEL, /*use_cpu=*/false)`. Weights auto-download from HF Hub on first
  use, cached in `~/.cache/huggingface/hub/` (~1.5 GB; documented).
- **API:** thin helpers — `embed_image_from_bytes(&[u8]) -> Result<Vec<f32>>`
  (decode the persisted preview JPEG → `get_image_embedding_from_bytes`),
  `embed_text(&str) -> Result<Vec<f32>>`, `normalize_vector(&[f32]) -> Vec<f32>`
  (L2), and `to_le_bytes(&[f32]) -> Vec<u8>` (vector blob serialization, matching
  imgfind exactly). Embeddings are L2-normalized before storage and before query.

## Schema additions (Phase 2)

`create_schema` gains (under `#[cfg(feature = "clip")]`, or unconditionally —
the table is cheap and lets a `clip`-off build still read a `clip`-on cache):

```sql
CREATE TABLE IF NOT EXISTS clip_embedding (
    file_id   INTEGER PRIMARY KEY REFERENCES file(file_id) ON DELETE CASCADE,
    model     TEXT    NOT NULL,
    dim       INTEGER NOT NULL,
    embedding F32_BLOB(768) NOT NULL
);
```

Model-relative, like imgfind: "missing embedding" = no `clip_embedding` row for
`(file_id)` with `model = ACTIVE_MODEL`. Storing `model`/`dim` lets a future
model switch be detected (rows with a different `model` are treated as missing
for the active model and re-embedded).

## Processing engine (`utmost-index/src/processing.rs`)

A single module both the CLI and GUI drive, so results are identical (imgfind's
shared-engine pattern):

- **`ProcessPhase`** enum: `Previews`, `Embeddings`. (utmost has one preview
  size, so two phases vs imgfind's three.)
- **`ProcessCounts`**: remaining counts per phase —
  `count_files_without_preview()` (preview-able `file_type`, `preview_status =
  'unknown'`) and `count_files_without_embedding()` (has `preview_blob`, no
  `clip_embedding` for `ACTIVE_MODEL`; active-model-aware `LEFT JOIN`).
- **Preview-able types**: `Jpeg | Gif | Bmp | Png | VJpeg` (the existing
  `preview::Kind::Image` set) — reuse that classifier, do not duplicate it.
- **`process_next_batch(pool, embedder, phase, batch_size) -> BatchOutcome`** —
  one batch of one phase, returns `{ processed, remaining }`:
  - **Previews:** enumerate files missing a preview → for each, resolve bytes via
    the existing `SourceResolver` + `render_with_fallback` → `encode_thumb_to_jpeg`
    → `write_preview_outcomes` (reuses the existing write path, which sets
    `preview_status` and bumps `preview_status_version`). Files that fail to
    render are marked `no_preview` (existing behavior), so they are not retried
    forever.
  - **Embeddings** (`#[cfg(feature = "clip")]`): enumerate files that have a
    `preview_blob` but no active-model `clip_embedding` → decode the blob JPEG →
    `embed_image_from_bytes` → `normalize_vector` → `set_clip_embedding(file_id,
    ACTIVE_MODEL, &vec)`. `embedder` is only required for this phase.
- **`run_to_completion(pool, opts, progress_cb)`** — the CLI loop: walk phases
  in order (Previews then Embeddings), batch until each drains, invoking
  `progress_cb` between batches. The GUI does **not** call this; it drives
  `process_next_batch` itself to interleave its pause flag and progress channel.

New DB methods (in `utmost-index`): `get_files_without_preview(limit) ->
Vec<FoundFile>`, `count_files_without_preview()`, `get_files_without_embedding(
limit) -> Vec<(u64, PreviewBlobRow)>` (or file_id + blob), `count_files_without_
embedding()`, `set_clip_embedding(file_id, model, &[f32])` (upsert: DELETE +
INSERT or `ON CONFLICT(file_id) DO UPDATE`).

### Unified embedding source (load-bearing invariant)

Embeddings are computed from the **persisted `preview_blob` JPEG**, never by
re-decoding the carved source. The Previews phase guarantees the blob exists
before the Embeddings phase runs for that file. CLIP downsizes to 224px
internally, so the preview resolution is ample. **Invariant this depends on:**
the bytes embedded are exactly the bytes in `preview_blob` for that `file_id`.
A characterization test pins this (embedding a file with a known preview blob
produces a normalized 768-dim vector derived from that blob, and re-running the
Embeddings phase is a no-op once the row exists). Per the project's spec
discipline, this is the load-bearing test, written explicitly rather than
assumed from "render is verbatim."

## CLI `process` command (`utmost-cli`)

Add a `process` subcommand following the existing manual `recover` argv-dispatch
convention (argv-sniff in `main.rs` before clap parses `CarveArgs`), so the CLI
shape stays consistent and the change is low-risk:

```
utmost process [-o <output_dir>] [--count <N>] [--no-embeddings]
```

- Discovers cases under `-o <output_dir>` the same way `utmost-viewer` does
  (recursive scan for `<slug>-events.bin`, via `utmost-gui::discover` — or, to
  keep `process` Slint-free, move the discovery scan into `utmost-index` and have
  the viewer call it). For each case, opens its `TursoPool` and calls
  `run_to_completion`, printing per-phase progress lines (mirrors imgfind
  `process`). `--count` sizes batches; `--no-embeddings` runs the Previews phase
  only (also the behavior when built `--no-default-features`).
- `process` depends on `utmost-index` only (no Slint). Under `--no-default-
  features` (clip off) it still runs the Previews phase and prints a note that
  embeddings are disabled in this build.

**Discovery placement:** the recursive `<slug>-events.bin` scanner currently in
`utmost-gui/src/discover.rs` moves to `utmost-index` (it is Slint-free) so both
`utmost-cli process` and the viewer use it; the viewer re-exports/calls it.

## GUI background job (`utmost-gui/src/processor.rs`, new)

A dedicated `process-worker` thread, **separate** from `ThumbWorker`, so bulk
work never starves viewport-priority grid loading:

- Spawned by `open_case` when `ProcessCounts` shows remaining work. Loops
  `process_next_batch` across `Previews` then `Embeddings`, reusing the
  lazily-loaded `Arc<OnceLock<ClipEmbedder>>`; the Embeddings phase waits until
  the model is ready (`OnceLock` populated).
- **Pause:** `Arc<AtomicBool>` checked between batches; paused → park on a
  channel/condvar until resumed.
- **Progress:** after each batch, send `ProcessProgress { phase, counts }` over a
  channel; the UI thread applies it via the existing Slint timer / `invoke_from_
  event_loop` pattern. Counts are re-read from the DB each batch so a parallel
  CLI `process` run is reflected.
- **Shutdown:** reuses the existing `CaseHandle.shutdown_signal` (`Arc<AtomicBool>`)
  set by the close paths in `lib.rs` *before* `drop(ui)`, exactly like
  `ThumbWorker`, so closing the case/window tears the worker down promptly and
  doesn't block `close_case`.
- **Single heavy writer:** the process-worker is the only bulk writer; GUI
  `ui_state`/interactive preview writes stay short and batched, keeping WAL
  contention within the 5 s busy timeout.
- On caught-up (all counts zero), the worker parks; state shows **Idle**.
- New embeddings produced by the worker can feed a live re-query if a search is
  active (the search results widen as embeddings land — implemented as a periodic
  re-query while a search query is active and embeddings remain).

Pure logic (pause-flag transitions, phase selection, progress→panel mapping) is
factored into testable helpers off the UI thread (mirroring existing
`*_ui.rs`/pure-helper conventions).

## Status panel + `\` toggle (`utmost-gui/ui/`)

- A new panel (reuse the existing side/detail-panel chrome; reflow, not overlay)
  with three labeled rows — **Previews** `done / total` + bar, **Embeddings**
  `done / total` + bar — plus an overall **Running / Paused / Idle** state line
  and a **Pause/Resume** button. Closing the panel does not stop the job.
- **`\`** toggles the panel, wired into the `outer_focus` `FocusScope`
  `key-pressed` handler in `detail.slint` (a new `if (event.text == "\\")` arm →
  `root.toggle-process-panel()`). **Suppressed while a text field is focused**
  (the search box / note editor), like the other chord keys.
- **Glyph caution** (per the project's Slint-font memory): if a status/gear glyph
  tofus, fall back to ASCII (`P:`, `[ ]`) and the default font.
- Properties/callbacks (`process-panel-open: bool`, `process-running-state:
  string`, `previews-done/total`, `embeddings-done/total`, `process-paused:
  bool`, `toggle-process-panel()`, `process-pause-toggle()`) are declared on
  `DetailPage`, mirrored on `MainWindow`, and wired in `slint_adapter.rs`.

## Search box + clear button (`utmost-gui/ui/detail.slint`)

- Inserted in the toolbar **immediately after the "Hide no-preview" `Rectangle`
  and before the `horizontal-stretch: 1` spacer** (so it sits between
  "Hide no-preview" and the sort `ComboBox`, per the request). A `LineEdit`
  (placeholder "Search images…") + a "Clear" `Button`.
- **Wiring:** `search-query: string` (in-out) property + `search-query-changed(
  string)` and `search-cleared()` callbacks on `DetailPage`, mirrored on
  `MainWindow`, handled in `slint_adapter.rs`:
  - On change (on Enter / commit; a short debounce is acceptable), set
    `vm.filter.search_query = Some(text)` (None if empty), `requery(...)`. The
    Clear button sets it to `None`, clears the LineEdit, and requeries → normal
    browse.
  - Search input is **disabled until the model is ready** (`set_can_search(false)`
    until the `OnceLock` is populated), mirroring imgfind.
  - When `count_files_without_embedding() > 0`, show a subtle "N still indexing"
    hint near the box so partial results are understood.

### Search query path

`FilterState` gains `pub search_query: Option<String>`. In the query-loop thread
(`indexer_thread.rs`), `query_match_ids` branches:

- **No query (`None`):** existing filter+sort SQL (unchanged).
- **Query (`Some(text)`):** embed the text once via the shared embedder
  (`embed_text` → `normalize_vector`), then run a `vector_distance_cos` KNN that
  **joins `clip_embedding` to the same filtered `file` set** (type/partial-type
  chips, source filter, bookmarked-only, size range, preview-status all still
  applied as WHERE clauses), ordered by `distance` ascending, with a default
  `distance <= 1.3` threshold and a result cap (default 300). Files without an
  embedding simply don't match (no row to join). Returns `FileStub`s in
  similarity order; the existing sort key is overridden while a query is active.

The KNN SQL is built by a helper analogous to imgfind's `knn_query` (a string
builder taking the filter WHERE fragment, threshold, limit, bound to the query
embedding blob via `turso::Value::Blob`). The text embedding is computed on the
query-loop thread (off the UI thread).

### Persistence

The search query is **transient** — **not** added to `UiStateSnapshot` /
`FilterStateSnapshot`. It is not persisted across case reopen (re-running needs
the model loaded; a stale persisted query would surprise the user). All other
filter/sort persistence is unchanged. (`FilterState.search_query` is reset to
`None` on hydrate.)

## Testing (Phase 2)

Following TDD; tests beside the code they cover.

- **Processing engine:** `ProcessCounts`/phase-selection logic; a
  `process_next_batch` round-trip against a temp DB seeded with a few files —
  assert the Previews phase drains and is idempotent, then the Embeddings phase
  drains and is idempotent (re-running does nothing). (Embeddings assertions
  gated on the `clip` feature; use a tiny stub/seeded blob so the test does not
  download the real model — if the real model is unavoidable, gate behind an
  `#[ignore]`d integration test and keep the unit test on the count/selection
  logic + a fake embedder injected via a trait.)
- **DB methods:** `count/get_files_without_preview`,
  `count/get_files_without_embedding` correctness after partial fill;
  `set_clip_embedding` round-trips, flips the missing-embedding count to 0, and
  is model-relative (a row for a different `model` still counts as missing for
  `ACTIVE_MODEL`).
- **Unified embedding source (load-bearing):** characterization test that the
  bytes embedded equal the `preview_blob` bytes for that file and produce a
  normalized `ACTIVE_DIM` vector; re-embedding is a no-op.
- **Search query SQL:** the KNN builder respects the active filter WHERE
  fragment (a file excluded by a type/source/size filter never appears even if
  semantically close), applies the threshold + limit, and orders by distance.
  Use a small fixture with hand-set embedding blobs and assert ranking order via
  `vector_distance_cos`.
- **Filter funnel (per spec discipline):** enumerate the producers that must
  survive the search WHERE fragment — type chips, partial-type chips, source
  filter, bookmarked-only, size range, hide-no-preview — with one assertion each
  that an active search still honors them.
- **GUI pure logic:** pause-flag state transitions; progress→panel mapping
  (done/total per phase); the `\`-suppression-while-typing predicate;
  search-enabled-iff-model-ready predicate. Unit-tested off the UI thread. Slint
  wiring verified by build + manual smoke.

## Caller / doc updates

- **`utmost-viewer`**: now calls the moved discovery scanner from `utmost-index`;
  otherwise unchanged.
- **Docs:** update `CLAUDE.md` (new `utmost-index` crate + dependency graph; the
  turso index layer replacing Diesel; the `clip` feature; the `process` command;
  the GUI background job + status panel + `\` toggle; the search box) and
  `README.md` (build commands incl. `--no-default-features` for a lean build, the
  `process` command, the ~1.5 GB model download + HF cache location, turso as the
  index store). Link this spec.

## Invariants this feature depends on

- The bytes embedded for a file equal that file's `preview_blob` bytes (the
  Previews phase runs before the Embeddings phase). Pinned by the
  unified-embedding-source characterization test.
- "Missing embedding" is model-relative: it means no `clip_embedding` row for
  `ACTIVE_MODEL`. Switching `ACTIVE_MODEL` makes all rows missing again; the
  processing job backfills.
- The per-case index is a derived cache rebuildable from `<slug>-events.bin`; no
  schema migration is needed because a format change is handled by rebuild.
- A search WHERE fragment built from `FilterState` must apply the *same*
  predicates as the non-search path; the filter-funnel tests enumerate every
  producer that must survive it.

## Risks / tradeoffs

- **turso is pre-release (`0.7.0-pre.10`).** Pinned exactly to imgfind's
  validated version. Risk: API churn on a future bump — isolated to
  `utmost-index/src/db`.
- **In-memory test support:** if turso lacks `:memory:` support at this version,
  tests use unique temp files (already the pattern for some tests).
- **On-disk format continuity:** turso reads existing SQLite caches; the schema
  is identical, so existing cases open without rebuild. The stale
  `__diesel_schema_migrations` table is ignored (optional one-line
  `DROP TABLE IF EXISTS` for tidiness).
- **WAL contention:** background process-worker + GUI writes share the case DB.
  Mitigation: single heavy writer, short batched GUI writes, 5 s busy timeout;
  batch size is the tuning knob.
- **CPU + first-run download:** the embedding pass is heavy and the model is
  ~1.5 GB on first use. Mitigations: the visible Pause control, the dedicated
  (non-grid) worker thread, the default-on-but-opt-out `clip` feature, and the
  CLI `process` path for embedding ahead of time / on a server.
- **Crate extraction churn (Phase 1):** moving `index_db` + `preview` +
  `discover` touches many files. Mitigated by keeping public signatures stable
  and adding `pub use` shims; the ported test suite guards behavior.
```

