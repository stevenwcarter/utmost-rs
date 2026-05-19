-- key/value bag for cache-staleness tracking and small singletons
CREATE TABLE meta (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);
-- Stored keys: run_started_at, last_event_offset, last_event_count, indexed_at

-- Run metadata (one row per database)
CREATE TABLE run (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    started_at TEXT NOT NULL,
    output_root TEXT NOT NULL,
    source_image_path TEXT NOT NULL,
    configured_types_json TEXT NOT NULL,
    case_id TEXT, examiner TEXT, evidence_id TEXT, case_notes TEXT,
    status TEXT NOT NULL,        -- 'Running' | 'Finished' | 'Interrupted'
    elapsed_ms INTEGER NOT NULL DEFAULT 0,
    total_files INTEGER NOT NULL DEFAULT 0
);

-- Per-source rows; typically one per DB but the table supports merged views
CREATE TABLE source (
    source_id INTEGER PRIMARY KEY NOT NULL,
    filename TEXT NOT NULL,
    output_subdir TEXT NOT NULL,
    total_bytes INTEGER NOT NULL,
    bytes_read INTEGER NOT NULL DEFAULT 0,
    files_found INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    duration_ms INTEGER
);

-- Files: one row per FileFound event
CREATE TABLE file (
    file_id INTEGER PRIMARY KEY NOT NULL,    -- engine-allocated id
    source_id INTEGER NOT NULL REFERENCES source(source_id),
    filename TEXT NOT NULL,
    filesize INTEGER NOT NULL,
    file_type TEXT NOT NULL,
    img_offset INTEGER NOT NULL,
    written_path TEXT NOT NULL,
    byte_runs_json TEXT NOT NULL DEFAULT '[]',
    -- JpegScanInfo flattened; NULL for non-JPEGs
    jpeg_status TEXT,                     -- 'complete' | 'truncated' | 'fragmented'
    jpeg_width INTEGER,                   -- Option<u16> -> INTEGER, NULL if not parsed
    jpeg_height INTEGER,                  -- Option<u16> -> INTEGER, NULL if not parsed
    jpeg_fragmentation_point INTEGER,     -- Option<u64> -> INTEGER (BigInt logically; SQLite is dynamically typed)
    jpeg_has_restart_markers INTEGER      -- bool -> 0 or 1, NULL if non-JPEG
);
CREATE INDEX idx_file_source     ON file(source_id);
CREATE INDEX idx_file_type       ON file(file_type);
CREATE INDEX idx_file_size       ON file(filesize);
CREATE INDEX idx_file_img_offset ON file(img_offset);

-- Annotations.
-- Note: file_id references are NOT declared as foreign keys. SQLite
-- enforces FKs per-statement (not deferred to COMMIT), and the event
-- log does not guarantee that a FileFound row for, say, a recovery
-- candidate has been inserted in the same transaction before a
-- Bookmark/Note/MarkAsBest/variant row that references it. An index
-- still keys these for fast joins.
CREATE TABLE bookmark (
    file_id INTEGER PRIMARY KEY NOT NULL,
    at TEXT NOT NULL
);

CREATE TABLE note (
    note_id INTEGER PRIMARY KEY NOT NULL,
    file_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    at TEXT NOT NULL
);
CREATE INDEX idx_note_file ON note(file_id);

CREATE TABLE best_choice (
    original_file_id INTEGER PRIMARY KEY NOT NULL,
    chosen_file_id INTEGER NOT NULL,
    at TEXT NOT NULL
);

-- Recovery pass
CREATE TABLE recovery_run (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    started_at TEXT NOT NULL,
    keep_candidates INTEGER NOT NULL,
    search_window INTEGER NOT NULL,
    block_size INTEGER NOT NULL,
    min_entropy_score REAL NOT NULL,
    huffman_validation INTEGER NOT NULL,
    finished_duration_ms INTEGER,
    partials_processed INTEGER,
    candidates_written INTEGER
);

CREATE TABLE variant (
    original_file_id INTEGER NOT NULL,
    candidate_file_id INTEGER NOT NULL,
    rank INTEGER NOT NULL,
    method TEXT NOT NULL,    -- 'direct_continuation' | 'fragment_reassembly'
    entropy_score REAL NOT NULL,
    ff_validity_score REAL,
    huffman_mcu_count INTEGER,
    continuation_img_offset INTEGER NOT NULL,
    PRIMARY KEY (original_file_id, candidate_file_id)
);
CREATE INDEX idx_variant_candidate ON variant(candidate_file_id);
