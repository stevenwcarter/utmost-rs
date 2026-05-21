CREATE TABLE preview_blob (
    file_id  BIGINT  PRIMARY KEY,
    codec    TEXT    NOT NULL,
    width    INTEGER NOT NULL,
    height   INTEGER NOT NULL,
    bytes    BLOB    NOT NULL,
    FOREIGN KEY (file_id) REFERENCES file(file_id) ON DELETE CASCADE
);

-- Pre-existing 'has_preview' rows have no blob bytes on disk yet — they
-- violate the new invariant ("has_preview implies a preview_blob row").
-- Reset them to 'unknown' so the next scroll re-decodes and persists.
UPDATE file SET preview_status = 'unknown' WHERE preview_status = 'has_preview';
