//! Composable SQL queries over the `file` table used by the windowed-files UI.
//!
//! [`query_match_ids`] turns a [`FilterState`] into a single `SELECT` against the
//! `file` table, returning [`FileStub`]s in the requested order. Used to refresh
//! the visible-id list whenever filters or sort change.
//!
//! ## Variant-vs-original distinction
//!
//! The in-memory `recompute_visible` path consults the live `variant_of` map to
//! decide whether a file should be checked against `enabled_types` or
//! `enabled_partial_types`. We do not replicate the variant_of distinction
//! here: variants never appear in the main grid anyway (the UI surfaces them
//! under their parent's "variants" panel via `variant_of` / `variants`). The
//! windowed UI filters out anything in `variant_of` on the Rust side when
//! assembling the visible window.
//!
//! ## Partial-vs-complete distinction
//!
//! `enabled_types` is the "Jpeg" chip and `enabled_partial_types` is the
//! "Partial Jpeg" chip — independent toggles. "Jpeg only" returns complete
//! jpegs (where `jpeg_status = 'complete'`, or NULL for legacy/test rows);
//! "Partial Jpeg only" returns truncated/fragmented jpegs; both-on returns
//! every jpeg. The WHERE clause is built per type with one disjunct each,
//! `OR`-joined.

use std::collections::HashMap;
use std::path::PathBuf;

use diesel::prelude::*;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Integer, Text};
use diesel::sqlite::SqliteConnection;

use utmost_lib::types::FileType;

use crate::index_db::models::{FileRow, file_row_to_found_file};
use crate::index_db::schema;
use crate::view_model::{FilterState, FoundFile, SortDir, SortKey, parse_file_type_pub};

/// Lightweight projection of `file` returned by [`query_match_ids`].
#[derive(Debug, Clone)]
pub struct FileStub {
    pub file_id: u64,
    pub filename: String,
    pub filesize: u64,
    pub file_type: FileType,
}

/// Raw row shape returned by `diesel::sql_query`. `file_type` is the textual
/// suffix stored in the `file` table; we parse it into the enum on the way out.
#[derive(QueryableByName, Debug)]
struct FileStubRow {
    #[diesel(sql_type = BigInt)]
    file_id: i64,
    #[diesel(sql_type = Text)]
    filename: String,
    #[diesel(sql_type = BigInt)]
    filesize: i64,
    #[diesel(sql_type = Text)]
    file_type: String,
}

/// Bound parameter we want to append after building the SQL. We can't keep
/// `Bind`s in a `Vec` easily because diesel's bind trait is parameter-typed,
/// so we hold values in a tagged enum and dispatch when binding.
enum Param {
    Int(i32),
    Big(i64),
    Str(String),
}

/// Build and run the visible-ids query.
///
/// The result is the windowed UI's "match list": rows of the `file` table that
/// satisfy every active filter in `filter`, ordered by
/// `(bookmarked_first?, sort_key sort_dir, file_id ASC)`.
pub fn query_match_ids(
    conn: &mut SqliteConnection,
    filter: &FilterState,
) -> diesel::QueryResult<Vec<FileStub>> {
    let mut sql = String::new();
    let mut params: Vec<Param> = Vec::new();

    // SELECT + optional LEFT JOIN on bookmark for the bookmarked_first sort.
    sql.push_str("SELECT f.file_id AS file_id, f.filename AS filename, ");
    sql.push_str("f.filesize AS filesize, f.file_type AS file_type FROM file f");
    if filter.bookmarked_first {
        sql.push_str(" LEFT JOIN bookmark b ON b.file_id = f.file_id");
    }

    let mut wheres: Vec<String> = Vec::new();

    if let Some(sid) = filter.source_filter {
        wheres.push("f.source_id = ?".into());
        params.push(Param::Int(sid as i32));
    }

    if filter.bookmarked_only {
        wheres.push("f.file_id IN (SELECT file_id FROM bookmark)".into());
    }

    if let Some((lo, hi)) = filter.size_range {
        wheres.push("f.filesize BETWEEN ? AND ?".into());
        params.push(Param::Big(lo as i64));
        params.push(Param::Big(hi as i64));
    }

    if filter.hide_no_preview {
        wheres.push("f.preview_status != 'no_preview'".into());
    }

    // Type chips ("Jpeg") and partial chips ("Partial Jpeg") are independent
    // toggles: "Jpeg only" must show complete jpegs, "Partial Jpeg only" must
    // show partial jpegs, both on shows all jpegs. We build one disjunct per
    // type covering whichever of (full, partial) is currently enabled.
    //
    // Only jpegs carry a `jpeg_status` column in the index; for every other
    // type we ignore partial/complete (the partial chip never appears for
    // non-jpeg types in practice — `partial_counts` is only populated for
    // jpegs). For jpegs with a NULL `jpeg_status` (e.g. legacy rows from
    // before the column was populated, or in-memory test fixtures), treat
    // the row as complete so the "Jpeg" chip continues to surface them.
    let mut type_union: std::collections::BTreeSet<&FileType> = Default::default();
    type_union.extend(filter.enabled_types.iter());
    type_union.extend(filter.enabled_partial_types.iter());
    if !type_union.is_empty() {
        let mut clauses: Vec<String> = Vec::new();
        for ft in &type_union {
            let in_full = filter.enabled_types.contains(*ft);
            let in_partial = filter.enabled_partial_types.contains(*ft);
            let db_str = file_type_to_db_string(**ft).to_string();
            if **ft == FileType::Jpeg && in_full && !in_partial {
                clauses.push(
                    "(f.file_type = ? AND (f.jpeg_status IS NULL OR f.jpeg_status = 'complete'))"
                        .into(),
                );
                params.push(Param::Str(db_str));
            } else if **ft == FileType::Jpeg && !in_full && in_partial {
                clauses.push(
                    "(f.file_type = ? AND f.jpeg_status IN ('truncated', 'fragmented'))".into(),
                );
                params.push(Param::Str(db_str));
            } else {
                // Non-jpeg type, OR both chips on for jpeg → no status filter.
                clauses.push("f.file_type = ?".into());
                params.push(Param::Str(db_str));
            }
        }
        wheres.push(format!("({})", clauses.join(" OR ")));
    }

    if !wheres.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&wheres.join(" AND "));
    }

    // ORDER BY: bookmarked-first (DESC because NULL < non-NULL in SQLite means
    // bookmarked rows -- where b.file_id IS NOT NULL -- need DESC to come up
    // first), then the user-selected sort, then file_id ASC as a tiebreaker.
    sql.push_str(" ORDER BY ");
    if filter.bookmarked_first {
        sql.push_str("(b.file_id IS NOT NULL) DESC, ");
    }
    let col = match filter.sort_key {
        SortKey::Filename => "f.filename",
        SortKey::Size => "f.filesize",
        SortKey::FileType => "f.file_type",
        SortKey::SourceOffset => "f.img_offset",
    };
    let dir = match filter.sort_dir {
        SortDir::Asc => "ASC",
        SortDir::Desc => "DESC",
    };
    sql.push_str(col);
    sql.push(' ');
    sql.push_str(dir);
    sql.push_str(", f.file_id ASC");

    // Bind params in declaration order and run.
    let mut q = sql_query(sql).into_boxed::<diesel::sqlite::Sqlite>();
    for p in params {
        q = match p {
            Param::Int(v) => q.bind::<Integer, _>(v),
            Param::Big(v) => q.bind::<BigInt, _>(v),
            Param::Str(v) => q.bind::<Text, _>(v),
        };
    }
    let rows: Vec<FileStubRow> = q.load(conn)?;
    Ok(rows
        .into_iter()
        .filter_map(|r| match parse_file_type_pub(&r.file_type) {
            Some(ft) => Some(FileStub {
                file_id: r.file_id as u64,
                filename: r.filename,
                filesize: r.filesize as u64,
                file_type: ft,
            }),
            None => {
                tracing::warn!(
                    file_id = %r.file_id,
                    file_type = %r.file_type,
                    "skipping row: unknown file_type"
                );
                None
            }
        })
        .collect())
}

/// Map a [`FileType`] back to the canonical lowercase string stored in the
/// `file.file_type` column. This mirrors the inverse of `parse_file_type_pub`
/// in `view_model.rs`. New variants must be added here too.
fn file_type_to_db_string(ft: FileType) -> &'static str {
    match ft {
        FileType::Jpeg => "jpeg",
        FileType::Gif => "gif",
        FileType::Bmp => "bmp",
        FileType::Mpg => "mpg",
        FileType::Pdf => "pdf",
        FileType::Doc => "doc",
        FileType::Avi => "avi",
        FileType::Wmv => "wmv",
        FileType::Htm => "htm",
        FileType::Zip => "zip",
        FileType::Mov => "mov",
        FileType::Xls => "xls",
        FileType::Ppt => "ppt",
        FileType::Wpd => "wpd",
        FileType::Cpp => "cpp",
        FileType::Ole => "ole",
        FileType::Gzip => "gzip",
        FileType::Riff => "riff",
        FileType::Wav => "wav",
        FileType::VJpeg => "vjpeg",
        FileType::Sxw => "sxw",
        FileType::Sxc => "sxc",
        FileType::Sxi => "sxi",
        FileType::Png => "png",
        FileType::Rar => "rar",
        FileType::Exe => "exe",
        FileType::Elf => "elf",
        FileType::Reg => "reg",
        FileType::Docx => "docx",
        FileType::Xlsx => "xlsx",
        FileType::Pptx => "pptx",
        FileType::Mp4 => "mp4",
        FileType::Config => "config",
    }
}

/// Fetch the `file` rows for `ids`, preserving the order of the input slice.
///
/// SQLite's `IN (...)` clause is unordered — rows come back in natural row
/// order, not the order they appeared in the placeholders. The windowed UI
/// needs them in the *requested* order (which already incorporates the
/// active sort), so we reshuffle on the Rust side via a small lookup map.
///
/// IDs that don't exist in the DB are silently skipped (the returned vec is
/// shorter than `ids` in that case). The `written_path` of each returned
/// [`FoundFile`] is absolute, resolved against the current `run.output_root`
/// the same way [`crate::index_db::hydrate::snapshot_from_db`] does it.
pub fn fetch_window(
    conn: &mut SqliteConnection,
    ids: &[u64],
) -> diesel::QueryResult<Vec<FoundFile>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let output_root = read_output_root(conn)?;

    // SQLite's `IN (...)` returns rows in natural order, not the order of the
    // placeholders. We let diesel emit the `IN (?, ?, …)` clause via the
    // typed dsl and then reshuffle on the Rust side to match `ids`.
    let id_i64s: Vec<i64> = ids.iter().map(|i| *i as i64).collect();
    let rows: Vec<FileRow> = schema::file::table
        .filter(schema::file::file_id.eq_any(&id_i64s))
        .load(conn)?;

    let mut by_id: HashMap<u64, FileRow> =
        rows.into_iter().map(|r| (r.file_id as u64, r)).collect();
    let out: Vec<FoundFile> = ids
        .iter()
        .filter_map(|id| {
            by_id
                .remove(id)
                .map(|r| file_row_to_found_file(r, &output_root))
        })
        .collect();
    Ok(out)
}

/// Read `run.output_root` for the active run. Falls back to an empty
/// [`PathBuf`] when the `run` table is empty (which means no run is in
/// progress yet); in that case the returned `FoundFile.written_path` is the
/// relative path as stored on disk, which is still safe to display.
fn read_output_root(conn: &mut SqliteConnection) -> diesel::QueryResult<PathBuf> {
    let root: Option<String> = schema::run::table
        .select(schema::run::output_root)
        .first(conn)
        .optional()?;
    Ok(root.map(PathBuf::from).unwrap_or_default())
}

/// Update `file.preview_status` for a single row and atomically bump the
/// `preview_status_version` meta key. Same pattern as the batched
/// [`crate::index_db::writer::write_preview_outcomes`], scoped to one row —
/// useful for one-shot test fixtures and ad-hoc scripts.
pub fn set_preview_status(
    conn: &mut SqliteConnection,
    file_id: u64,
    status: &str,
) -> diesel::QueryResult<()> {
    use crate::index_db::schema::file::dsl as f;
    use crate::index_db::schema::meta::dsl as m;
    conn.transaction(|tx| {
        diesel::update(f::file.find(file_id as i64))
            .set(f::preview_status.eq(status))
            .execute(tx)?;
        let cur: String = m::meta
            .find("preview_status_version")
            .select(m::value)
            .first(tx)?;
        let next: u64 = cur.parse::<u64>().unwrap_or(0) + 1;
        diesel::update(m::meta.find("preview_status_version"))
            .set(m::value.eq(next.to_string()))
            .execute(tx)?;
        Ok(())
    })
}

/// Compact row used by the picker to render a case without opening the
/// full ViewModel. Reads only from the `run` and `meta` tables of an
/// already-open `IndexDb`. No fold, no migration.
#[derive(Debug, Clone)]
pub struct PickerMetadataRow {
    pub source_image_path: String,
    pub status: String,     // "Running" | "Finished" | "Interrupted"
    pub started_at: String, // RFC3339 from the `run` table
    pub elapsed_ms: i64,
    pub total_files: i64,
    /// True when meta.last_event_offset is < the on-disk events.bin size,
    /// or when last_event_offset is absent. Caller computes this; the
    /// helper only reports last_event_offset back.
    pub last_event_offset: i64,
}

/// Read a [`PickerMetadataRow`] from a freshly-opened `IndexDb`. Reads only
/// the `run` row (id=1) and `meta.last_event_offset`; no fold, no migration.
/// Used by the case picker to render a row without standing up the full
/// ViewModel.
pub fn picker_metadata_row(
    conn: &mut diesel::sqlite::SqliteConnection,
) -> diesel::QueryResult<PickerMetadataRow> {
    use crate::index_db::schema::{meta, run};
    use diesel::prelude::*;

    let (source_image_path, status, started_at, elapsed_ms, total_files): (
        String,
        String,
        String,
        i64,
        i64,
    ) = run::table
        .filter(run::id.eq(1))
        .select((
            run::source_image_path,
            run::status,
            run::started_at,
            run::elapsed_ms,
            run::total_files,
        ))
        .first(conn)?;

    let last_event_offset: i64 = match meta::table
        .filter(meta::key.eq("last_event_offset"))
        .select(meta::value)
        .first::<String>(conn)
    {
        Ok(v) => v.parse::<i64>().unwrap_or(0),
        Err(diesel::result::Error::NotFound) => 0,
        Err(e) => return Err(e),
    };

    Ok(PickerMetadataRow {
        source_image_path,
        status,
        started_at,
        elapsed_ms,
        total_files,
        last_event_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index_db::IndexDb;
    use crate::index_db::models::{NewBookmark, NewFile, NewSource};

    /// Cycle through enough types to exercise the IN-clause path. Strings here
    /// must match what `file_type_to_db_string` emits for the corresponding
    /// `FileType` variants.
    const TYPE_CYCLE: &[(&str, FileType)] = &[
        ("jpeg", FileType::Jpeg),
        ("png", FileType::Png),
        ("pdf", FileType::Pdf),
        ("gif", FileType::Gif),
        ("bmp", FileType::Bmp),
    ];

    fn seed_sources(db: &mut IndexDb, n: i32) {
        for s in 1..=n {
            let row = NewSource {
                source_id: s,
                filename: format!("img{s}.bin"),
                output_subdir: format!("img{s}"),
                total_bytes: 0,
                bytes_read: 0,
                files_found: 0,
                status: "Finished".into(),
                duration_ms: None,
            };
            diesel::insert_into(schema::source::table)
                .values(&row)
                .execute(db.conn())
                .expect("insert source");
        }
    }

    /// Insert `count` files spread across `num_sources` sources, cycling
    /// through TYPE_CYCLE and assigning monotonically increasing filesizes.
    fn seed_files(db: &mut IndexDb, count: i64, num_sources: i32) {
        db.with_conn::<(), diesel::result::Error, _>(|conn| {
            conn.transaction(|tx| {
                for i in 0..count {
                    let (suffix, _ft) = TYPE_CYCLE[(i as usize) % TYPE_CYCLE.len()];
                    let source_id = ((i as i32) % num_sources) + 1;
                    let row = NewFile {
                        file_id: i + 1,
                        source_id,
                        filename: format!("{:08}.{}", i + 1, suffix),
                        // Filesize jitters so size-range tests can target a slice
                        filesize: 1_000 + i * 17,
                        file_type: suffix.to_string(),
                        img_offset: i * 4096,
                        written_path: format!("img{source_id}/{:08}.{}", i + 1, suffix),
                        byte_runs_json: "[]".into(),
                        jpeg_status: None,
                        jpeg_width: None,
                        jpeg_height: None,
                        jpeg_fragmentation_point: None,
                        jpeg_has_restart_markers: None,
                        preview_status: "unknown".into(),
                    };
                    diesel::insert_into(schema::file::table)
                        .values(&row)
                        .execute(tx)?;
                }
                Ok(())
            })
        })
        .expect("seed files");
    }

    fn add_bookmark(db: &mut IndexDb, file_id: i64) {
        let row = NewBookmark {
            file_id,
            at: "2026-05-19T00:00:00Z".into(),
        };
        diesel::insert_into(schema::bookmark::table)
            .values(&row)
            .execute(db.conn())
            .expect("insert bookmark");
    }

    fn open_db_with_fixture(n_files: i64, n_sources: i32) -> IndexDb {
        let mut db = IndexDb::open_in_memory().expect("open in-memory db");
        seed_sources(&mut db, n_sources);
        seed_files(&mut db, n_files, n_sources);
        db
    }

    #[test]
    fn match_ids_no_filter_returns_all_in_filename_asc() {
        let mut db = open_db_with_fixture(1500, 3);
        let filter = FilterState::default();
        let rows = db
            .with_conn::<_, diesel::result::Error, _>(|c| query_match_ids(c, &filter))
            .expect("query");
        assert_eq!(rows.len(), 1500, "all rows should be returned");
        // Filenames are zero-padded `00000001.jpeg` etc, so file_id order is
        // also filename order — easy to verify monotonicity.
        for w in rows.windows(2) {
            assert!(
                w[0].filename <= w[1].filename,
                "expected filename ASC order, found {} > {}",
                w[0].filename,
                w[1].filename
            );
        }
    }

    #[test]
    fn match_ids_type_filter() {
        let mut db = open_db_with_fixture(1500, 2);
        let mut filter = FilterState::default();
        filter.enabled_types.insert(FileType::Jpeg);
        filter.enabled_types.insert(FileType::Png);
        let rows = db
            .with_conn::<_, diesel::result::Error, _>(|c| query_match_ids(c, &filter))
            .expect("query");
        assert!(!rows.is_empty(), "expected at least some matches");
        for r in &rows {
            assert!(
                matches!(r.file_type, FileType::Jpeg | FileType::Png),
                "got unexpected file_type {:?}",
                r.file_type
            );
        }
        // 5-type cycle ⇒ jpeg + png ≈ 2/5 of 1500.
        assert_eq!(rows.len(), 600);
    }

    /// Seed a DB with three jpegs: one complete, one truncated, one fragmented,
    /// plus one png with NULL `jpeg_status`. Used to exercise the partial chip's
    /// per-type WHERE clause.
    fn seed_jpeg_status_mix(db: &mut IndexDb) {
        seed_sources(db, 1);
        let rows: Vec<NewFile> = vec![
            ("jpeg-complete.jpg", "jpeg", Some("complete")),
            ("jpeg-trunc.jpg", "jpeg", Some("truncated")),
            ("jpeg-frag.jpg", "jpeg", Some("fragmented")),
            ("only.png", "png", None),
        ]
        .into_iter()
        .enumerate()
        .map(|(i, (name, ftype, status))| NewFile {
            file_id: i as i64 + 1,
            source_id: 1,
            filename: name.into(),
            filesize: 1_000 + i as i64,
            file_type: ftype.into(),
            img_offset: 0,
            written_path: format!("img1/{name}"),
            byte_runs_json: "[]".into(),
            jpeg_status: status.map(String::from),
            jpeg_width: None,
            jpeg_height: None,
            jpeg_fragmentation_point: None,
            jpeg_has_restart_markers: None,
            preview_status: "unknown".into(),
        })
        .collect();
        db.with_conn::<(), diesel::result::Error, _>(|conn| {
            diesel::insert_into(schema::file::table)
                .values(&rows)
                .execute(conn)?;
            Ok(())
        })
        .expect("seed jpeg status mix");
    }

    #[test]
    fn match_ids_partial_chip_only_returns_partial_jpegs() {
        let mut db = IndexDb::open_in_memory().expect("open db");
        seed_jpeg_status_mix(&mut db);
        let mut filter = FilterState::default();
        filter.enabled_partial_types.insert(FileType::Jpeg);
        let rows = db
            .with_conn::<_, diesel::result::Error, _>(|c| query_match_ids(c, &filter))
            .expect("query");
        let names: Vec<&str> = rows.iter().map(|r| r.filename.as_str()).collect();
        assert_eq!(
            names,
            vec!["jpeg-frag.jpg", "jpeg-trunc.jpg"],
            "Partial Jpeg chip should match only truncated/fragmented jpegs"
        );
    }

    #[test]
    fn match_ids_jpeg_chip_only_returns_complete_jpegs() {
        let mut db = IndexDb::open_in_memory().expect("open db");
        seed_jpeg_status_mix(&mut db);
        let mut filter = FilterState::default();
        filter.enabled_types.insert(FileType::Jpeg);
        let rows = db
            .with_conn::<_, diesel::result::Error, _>(|c| query_match_ids(c, &filter))
            .expect("query");
        let names: Vec<&str> = rows.iter().map(|r| r.filename.as_str()).collect();
        assert_eq!(
            names,
            vec!["jpeg-complete.jpg"],
            "Jpeg chip alone should match only complete jpegs"
        );
    }

    #[test]
    fn match_ids_both_jpeg_chips_returns_every_jpeg() {
        let mut db = IndexDb::open_in_memory().expect("open db");
        seed_jpeg_status_mix(&mut db);
        let mut filter = FilterState::default();
        filter.enabled_types.insert(FileType::Jpeg);
        filter.enabled_partial_types.insert(FileType::Jpeg);
        let rows = db
            .with_conn::<_, diesel::result::Error, _>(|c| query_match_ids(c, &filter))
            .expect("query");
        let names: Vec<&str> = rows.iter().map(|r| r.filename.as_str()).collect();
        assert_eq!(
            names,
            vec!["jpeg-complete.jpg", "jpeg-frag.jpg", "jpeg-trunc.jpg"],
            "Both jpeg chips on should match every jpeg regardless of status"
        );
    }

    #[test]
    fn match_ids_non_jpeg_chip_ignores_status() {
        let mut db = IndexDb::open_in_memory().expect("open db");
        seed_jpeg_status_mix(&mut db);
        let mut filter = FilterState::default();
        filter.enabled_types.insert(FileType::Png);
        let rows = db
            .with_conn::<_, diesel::result::Error, _>(|c| query_match_ids(c, &filter))
            .expect("query");
        let names: Vec<&str> = rows.iter().map(|r| r.filename.as_str()).collect();
        assert_eq!(
            names,
            vec!["only.png"],
            "Png chip should match the png row even though jpeg_status is NULL"
        );
    }

    #[test]
    fn match_ids_size_range() {
        let mut db = open_db_with_fixture(1500, 2);
        let mut filter = FilterState::default();
        // Filesize for file_id = i+1 is 1_000 + i*17. Pick a slice with i in [10, 19]
        // ⇒ sizes 1170..=1323.
        let lo = 1_170u64;
        let hi = 1_323u64;
        filter.size_range = Some((lo, hi));
        let rows = db
            .with_conn::<_, diesel::result::Error, _>(|c| query_match_ids(c, &filter))
            .expect("query");
        assert_eq!(rows.len(), 10);
        for r in &rows {
            assert!(r.filesize >= lo && r.filesize <= hi);
        }
    }

    #[test]
    fn match_ids_bookmarked_first_puts_marked_at_top() {
        let mut db = open_db_with_fixture(500, 1);
        // Bookmark a few file_ids that would normally land in the middle/end.
        for fid in [100i64, 250, 499] {
            add_bookmark(&mut db, fid);
        }
        let filter = FilterState {
            bookmarked_first: true,
            ..FilterState::default()
        };
        let rows = db
            .with_conn::<_, diesel::result::Error, _>(|c| query_match_ids(c, &filter))
            .expect("query");
        assert_eq!(rows.len(), 500);
        // The first three rows must be the bookmarked ones (sub-sorted by
        // filename ASC then file_id ASC, but the leading bookmark predicate
        // is the dominant key).
        let head_ids: Vec<u64> = rows.iter().take(3).map(|r| r.file_id).collect();
        let mut expected = vec![100u64, 250, 499];
        expected.sort();
        let mut got = head_ids.clone();
        got.sort();
        assert_eq!(got, expected, "first three rows must be the bookmarks");
        // And the fourth row must NOT be bookmarked.
        assert!(![100u64, 250, 499].contains(&rows[3].file_id));
    }

    #[test]
    fn match_ids_sort_stable_on_file_id_for_ties() {
        // Seed 10 files all of the same type — file_type ASC then file_id ASC
        // must yield a strictly increasing file_id sequence.
        let mut db = IndexDb::open_in_memory().expect("open db");
        seed_sources(&mut db, 1);
        db.with_conn::<(), diesel::result::Error, _>(|conn| {
            conn.transaction(|tx| {
                for i in 0..10 {
                    let row = NewFile {
                        file_id: i + 1,
                        source_id: 1,
                        filename: format!("tied-{:02}.jpeg", i + 1),
                        filesize: 4096, // all same, forces tie on Size as well
                        file_type: "jpeg".into(),
                        img_offset: 0,
                        written_path: format!("img1/tied-{:02}.jpeg", i + 1),
                        byte_runs_json: "[]".into(),
                        jpeg_status: None,
                        jpeg_width: None,
                        jpeg_height: None,
                        jpeg_fragmentation_point: None,
                        jpeg_has_restart_markers: None,
                        preview_status: "unknown".into(),
                    };
                    diesel::insert_into(schema::file::table)
                        .values(&row)
                        .execute(tx)?;
                }
                Ok(())
            })
        })
        .expect("seed tied files");

        let filter = FilterState {
            sort_key: SortKey::Size, // all rows tie on filesize
            ..FilterState::default()
        };
        let rows = db
            .with_conn::<_, diesel::result::Error, _>(|c| query_match_ids(c, &filter))
            .expect("query");
        assert_eq!(rows.len(), 10);
        let ids: Vec<u64> = rows.iter().map(|r| r.file_id).collect();
        let expected: Vec<u64> = (1..=10).collect();
        assert_eq!(
            ids, expected,
            "tiebreaker must give strictly increasing file_id"
        );
    }

    /// Seed exactly one file row with explicit id/filename/size. Source 1
    /// must already exist (call [`seed_sources`] first).
    fn seed_file(db: &mut IndexDb, file_id: i64, filename: &str, filesize: i64) {
        let row = NewFile {
            file_id,
            source_id: 1,
            filename: filename.into(),
            filesize,
            file_type: "jpeg".into(),
            img_offset: 0,
            written_path: format!("img1/{filename}"),
            byte_runs_json: "[]".into(),
            jpeg_status: None,
            jpeg_width: None,
            jpeg_height: None,
            jpeg_fragmentation_point: None,
            jpeg_has_restart_markers: None,
            preview_status: "unknown".into(),
        };
        diesel::insert_into(schema::file::table)
            .values(&row)
            .execute(db.conn())
            .expect("insert file row");
    }

    #[test]
    fn fetch_window_returns_rows_in_input_order() {
        let mut db = IndexDb::open_in_memory().expect("open in-memory db");
        seed_sources(&mut db, 1);
        seed_file(&mut db, 10, "a.jpg", 100);
        seed_file(&mut db, 20, "b.jpg", 100);
        seed_file(&mut db, 30, "c.jpg", 100);

        let ids = vec![30u64, 10, 20];
        let rows = db
            .with_conn::<_, diesel::result::Error, _>(|c| fetch_window(c, &ids))
            .expect("fetch_window");

        assert_eq!(
            rows.iter().map(|r| r.id).collect::<Vec<_>>(),
            vec![30, 10, 20],
            "fetch_window must reorder rows to match the input slice"
        );
    }

    #[test]
    fn fetch_window_empty_input_returns_empty() {
        let mut db = IndexDb::open_in_memory().expect("open in-memory db");
        let rows = db
            .with_conn::<_, diesel::result::Error, _>(|c| fetch_window(c, &[]))
            .expect("fetch_window");
        assert!(rows.is_empty());
    }

    #[test]
    fn picker_metadata_row_reads_run_and_last_event_offset() {
        use crate::index_db::IndexDb;
        let mut db = IndexDb::open_in_memory().expect("open in-memory db");

        // Seed minimal run + meta rows.
        diesel::sql_query(
            "INSERT INTO run (id, started_at, output_root, source_image_path, configured_types_json, status, elapsed_ms, total_files) \
             VALUES (1, '2026-05-20T00:00:00Z', '/out', '/sources/l2.img', '[]', 'Finished', 1234, 2036)",
        )
        .execute(db.conn())
        .unwrap();
        diesel::sql_query("INSERT INTO meta(key, value) VALUES ('last_event_offset', '99999')")
            .execute(db.conn())
            .unwrap();

        let row = db
            .with_conn::<_, diesel::result::Error, _>(picker_metadata_row)
            .unwrap();
        assert_eq!(row.source_image_path, "/sources/l2.img");
        assert_eq!(row.status, "Finished");
        assert_eq!(row.elapsed_ms, 1234);
        assert_eq!(row.total_files, 2036);
        assert_eq!(row.last_event_offset, 99999);
    }

    #[test]
    fn picker_metadata_row_missing_meta_returns_zero_offset() {
        use crate::index_db::IndexDb;
        let mut db = IndexDb::open_in_memory().expect("open in-memory db");
        diesel::sql_query(
            "INSERT INTO run (id, started_at, output_root, source_image_path, configured_types_json, status, elapsed_ms, total_files) \
             VALUES (1, '2026-05-20T00:00:00Z', '/out', '/sources/l2.img', '[]', 'Running', 0, 0)",
        )
        .execute(db.conn())
        .unwrap();
        let row = db
            .with_conn::<_, diesel::result::Error, _>(picker_metadata_row)
            .unwrap();
        assert_eq!(row.last_event_offset, 0);
    }

    #[test]
    fn set_preview_status_writes_and_bumps_version() {
        use crate::index_db::models::FileRow;
        let mut db = IndexDb::open_in_memory().expect("open in-memory db");
        seed_sources(&mut db, 1);
        seed_file(&mut db, 1, "a.jpg", 100);

        // Sanity-check the migration seed: version starts at 0, status starts
        // as "unknown".
        let before: FileRow = schema::file::table
            .find(1i64)
            .first(db.conn())
            .expect("read row before");
        assert_eq!(before.preview_status, "unknown");
        let v0: String = schema::meta::table
            .find("preview_status_version")
            .select(schema::meta::value)
            .first(db.conn())
            .expect("read version before");
        assert_eq!(v0, "0");

        db.with_conn::<(), diesel::result::Error, _>(|c| set_preview_status(c, 1, "has_preview"))
            .expect("set_preview_status");

        let after: FileRow = schema::file::table
            .find(1i64)
            .first(db.conn())
            .expect("read row after");
        assert_eq!(after.preview_status, "has_preview");
        let v1: String = schema::meta::table
            .find("preview_status_version")
            .select(schema::meta::value)
            .first(db.conn())
            .expect("read version after");
        assert_eq!(v1, "1", "version should bump by exactly one");
    }
}
