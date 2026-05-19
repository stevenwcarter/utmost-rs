ALTER TABLE file ADD COLUMN preview_status TEXT NOT NULL DEFAULT 'unknown';
CREATE INDEX idx_file_preview ON file(preview_status);

INSERT OR IGNORE INTO meta (key, value) VALUES ('preview_status_version', '0');
