DROP INDEX IF EXISTS idx_file_preview;
-- SQLite supports DROP COLUMN since 3.35; project uses libsqlite3-sys 0.30 (bundled SQLite well past 3.35).
ALTER TABLE file DROP COLUMN preview_status;
DELETE FROM meta WHERE key = 'preview_status_version';
