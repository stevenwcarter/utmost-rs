# Thumbnail cache (persistent, per-case, lazy)

**Status:** Approved — ready for implementation planning.
**Date:** 2026-05-21
**Crate(s):** `utmost-gui`

## Problem

When the user re-opens a case, the visible portion of the file grid is slow to
populate. The current `ThumbWorker`
(`crates/utmost-gui/src/thumb_worker.rs`) caches decoded thumbnails only in
an in-memory `LruCache<FileId, SharedPixelBuffer<Rgba8Pixel>>`; that cache is
discarded on every case-close and never written to disk. Every reopen
re-runs the full decode pipeline against the source image, which is the user-
visible latency they want eliminated.

The negative result is also lost: files known to produce no preview
(`preview_status = 'NoPreview'` on disk) get re-tried and re-fail on every
reopen because the in-memory `failed: HashSet<FileId>` starts empty.

## Goals

1. Thumbnails the user has already scrolled past are restored instantly on
   the next case-open — no decode from source bytes, no re-encode.
2. Files known to be undecodable are skipped on reopen without re-attempting.
3. Zero new dependencies, zero new artifacts in the per-case directory.
4. The change is constrained to `utmost-gui`; no changes to `utmost-lib`,
   `utmost-cli`, or the engine.

## Non-goals (explicit out of scope)

- **Full-resolution / lightbox caching.** The lightbox decodes on demand; a
  full-res RGBA buffer is ~48 MB and does not belong in SQLite blobs.
- **Cross-case / global cache.** `FileId` is engine-allocated per-run and not
  stable across runs; sharing would require content-addressed keying.
- **Eager / background warm-up pass.** Thumbs are only created for files the
  windowed UI actually requests. If a file is never scrolled into view, it
  is never cached.
- **"Clear thumbnail cache" UI surface.** Easy SQL (`DELETE FROM
  preview_blob; VACUUM`) but no menu action in v1.
- **Blob compression beyond JPEG.** The schema reserves a `codec` column for
  future WebP support without a migration; v1 ships JPEG only.

## Approach: extend the existing per-case SQLite index

A new `preview_blob` table on the per-case `<slug>-index.sqlite`. Chosen
over LMDB-via-`heed` because:

- Zero new deps (Diesel + libsqlite3-sys + migrations harness already wired).
- One file per case stays one file per case (`discover.rs`, picker, copy/
  backup paths unchanged).
- Atomic with `file.preview_status`: `'HasPreview'` becomes a guarantee
  that a blob row exists, not a claim about something stored elsewhere.
- Single-writer pattern (the existing query-loop / preview-writer threads)
  is already in place.
- The performance gap LMDB offers at this blob size (~10 KB encoded) is not
  user-visible relative to the cost of the source-bytes decode it replaces.

## Design

### 1. Storage

New table on the existing per-case `<slug>-index.sqlite`. No new files.

```sql
CREATE TABLE preview_blob (
    file_id  BIGINT  PRIMARY KEY,
    codec    TEXT    NOT NULL,    -- 'jpeg' for v1
    width    INTEGER NOT NULL,
    height   INTEGER NOT NULL,
    bytes    BLOB    NOT NULL,
    FOREIGN KEY (file_id) REFERENCES file(file_id) ON DELETE CASCADE
);
```

**Codec.** Lossy JPEG quality ~80 via the existing `image` crate's built-in
encoder. A 256×256 RGBA thumb compresses to ~5–15 KB; zero new deps. The
`codec TEXT` column lets a future migration add `'webp'` as a new value
without schema changes.

**Invariant** (enforced by same-transaction writes, not a CHECK constraint):

| `file.preview_status` | `preview_blob` row |
|---|---|
| `'HasPreview'` | **must** exist |
| `'NoPreview'` | must **not** exist |
| `'Pending'` | must **not** exist |

**Sizing.** ~10 KB × 50k JPEGs = ~500 MB added to the per-case sqlite;
acceptable next to the events.bin that's already hundreds of MB.

**Eviction.** None in v1 — always-keep.

### 2. Write path (lazy, windowed-only)

**Trigger.** The view-model's per-tick sync already calls
`ThumbWorker::request(id, ...)` only for *visible* files lacking an
in-memory image. That stays the **only** entry point. No pass walks the
full file list; off-screen files are never decoded or cached.

**Decode worker steps:**

1. Decode source bytes → `RgbaImage` (unchanged).
2. Downscale to 256-px max edge → 256×N RGBA buffer (unchanged).
3. Put RGBA buffer in in-memory LRU and notify Slint (unchanged).
4. **New:** encode the same RGBA buffer to JPEG q80 on the worker thread.
5. Send enriched outcome over the existing `preview_outcomes_tx`.

**Enriched outcome:**

```rust
pub enum PreviewOutcomeData {
    HasPreview { codec: PreviewCodec, width: u32, height: u32, bytes: Vec<u8> },
    NoPreview,
}

pub struct PreviewOutcome {
    pub file_id: u64,
    pub data: PreviewOutcomeData,
}
```

`NoPreview` carries no payload (same as today).

**Writer thread.** `run_preview_outcomes_writer` continues to batch
outcomes. `write_preview_outcomes` is extended so that within the same
transaction, each `HasPreview` outcome executes:

```sql
UPDATE file SET preview_status = 'HasPreview' WHERE file_id = ?;
INSERT OR REPLACE INTO preview_blob (file_id, codec, width, height, bytes)
    VALUES (?, ?, ?, ?, ?);
```

Both rows commit together or neither does. `INSERT OR REPLACE` handles the
re-decode case cleanly (LRU evicted, file re-requested, source bytes
re-read) without a pre-SELECT.

**No new channel, no new `IndexerCommand` variant.** The blob rides the
existing `preview_outcomes_tx`. The unrelated
`IndexerCommand::WritePreviewStatus` path does not need blob support.

### 3. Read path

**Per-worker SQLite reader.** `ThumbWorker::start` opens one read-only
Diesel `SqliteConnection` per spawned worker thread against the same
per-case sqlite (already in WAL mode). WAL allows the N readers + 1
writer (the query-loop thread) to proceed without blocking.

**Worker hot loop:**

```
recv request →
    if shutdown_signal.load(Relaxed) → break
    if cache.contains(id) → continue
    if failed.contains(id) → continue
    if let Some(row) = preview_blob_lookup(conn, id):
        # FAST PATH (~1 ms): decode cached JPEG, populate LRU, notify UI.
        # No PreviewOutcome sent — preview_status is already correct on disk.
        decode JPEG bytes → RgbaImage → SharedPixelBuffer
        cache.put(id, buf)
        notify Slint
        continue
    # SLOW PATH: decode from source, encode JPEG, send outcome.
    render_with_fallback(...) → ... → cache.put(...) → encode JPEG
    send PreviewOutcome on preview_outcomes_tx
```

**Cache hits do not emit `PreviewOutcome`.** Re-sending would churn the
`preview_status_version` meta key and force the UI poll layer to redraw
unchanged rows.

**`preview_blob_lookup`** is a single prepared-statement point query:
`SELECT codec, width, height, bytes FROM preview_blob WHERE file_id = ?`.
Sub-millisecond on SSD; well below source-bytes decode cost.

### 4. Hydration on case-open

`open_case` performs two hydrations:

- **`failed: HashSet<FileId>`:** populated from
  `SELECT file_id FROM file WHERE preview_status = 'NoPreview'`. This is a
  bug fix folded into this work — today the set starts empty, so NoPreview
  files get re-decoded (and re-fail) on every reopen. Hydration is cheap
  (just file_ids in memory).
- **In-memory LRU cache:** stays empty. Lazy population through the worker
  hot path above. No blob bytes are read until the user scrolls a tile
  into view.

If the `failed` hydration query fails, log a warning and start with an
empty set (today's behavior). The case still opens.

### 5. Failure modes

| Failure | Behavior |
|---|---|
| `preview_blob` read errors (corrupt blob, locked DB) | Worker logs and falls through to slow path; `INSERT OR REPLACE` heals the blob on success. |
| JPEG decode of cached blob fails | Same fallback — slow path overwrites. |
| Source bytes also unavailable | Existing behavior: `NoPreview` outcome, `failed` set updated. |
| Crash mid-transaction | SQLite rolls back; invariant preserved. |
| `failed` hydration query fails | Warning logged; empty set; case opens normally. |

### 6. Migration

`crates/utmost-gui/migrations/0003_preview_blob/`:

- **`up.sql`:**
  ```sql
  CREATE TABLE preview_blob (...);  -- see Section 1
  -- One-time backfill: previously-'HasPreview' rows now violate the
  -- new invariant (no blob exists yet). Force re-decode on next scroll.
  UPDATE file SET preview_status = 'Pending' WHERE preview_status = 'HasPreview';
  ```
- **`down.sql`:** `DROP TABLE preview_blob;`

`schema.rs` is updated by hand: a new `diesel::table!` block for
`preview_blob` and an entry in `allow_tables_to_appear_in_same_query!`,
matching the existing convention in the file's header comment.

The existing `meta.preview_status_version` key is untouched — it
continues to tick on every successful `write_preview_outcomes`
transaction.

## Test coverage (concrete steps deferred to writing-plans)

- **Unit:** RGBA → JPEG → RGBA round-trip preserves dimensions.
- **Unit:** `write_preview_outcomes` writes blob + status atomically; a
  forced rollback leaves neither.
- **Integration:** `open_case` hydrates `failed` from
  `preview_status = 'NoPreview'`; previously-failed files are not
  re-requested by the worker.
- **Integration:** worker fast path (LRU miss + blob hit) populates the
  in-memory LRU and emits **no** `PreviewOutcome`.
- **Integration:** worker slow path (LRU miss + blob miss) decodes from
  source, encodes JPEG, persists the blob, and emits a `PreviewOutcome`.
- **Regression:** migration backfill flips all `HasPreview` rows to
  `Pending` exactly once on upgrade; idempotent re-run is a no-op.

## Files touched (estimate)

- `crates/utmost-gui/migrations/0003_preview_blob/up.sql` (new)
- `crates/utmost-gui/migrations/0003_preview_blob/down.sql` (new)
- `crates/utmost-gui/src/index_db/schema.rs` (add `preview_blob` table)
- `crates/utmost-gui/src/index_db/writer.rs` (extend
  `write_preview_outcomes`; add `preview_blob_lookup`)
- `crates/utmost-gui/src/thumb_worker.rs` (worker hot loop changes;
  per-worker connection; enriched `PreviewOutcome`)
- `crates/utmost-gui/src/indexer_thread.rs` (carry the enriched payload
  through `run_preview_outcomes_writer`)
- `crates/utmost-gui/src/case.rs` and `lib.rs` (hydrate `failed` set at
  `open_case`; pass sqlite path to `ThumbWorker::start`)
