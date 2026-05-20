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
//! `enabled_partial_types`. We do *not* replicate that here: variants never
//! appear in the main grid anyway (the UI surfaces them under their parent's
//! "variants" panel via `variant_of` / `variants`). Instead this query treats
//! both type sets as a single union for the WHERE clause. The windowed UI then
//! filters out anything in `variant_of` on the Rust side when assembling the
//! visible window. See plan task 9 + view_model.rs:351-356 for the original
//! semantics.
//!
//! The simplification means that with only `enabled_partial_types` set (and
//! `enabled_types` empty) the query will return *all* files of those types,
//! including non-partial originals. The UI is expected to either populate
//! `enabled_types` alongside or to apply the partial check during hydration of
//! the visible window.

use diesel::prelude::*;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Integer, Text};
use diesel::sqlite::SqliteConnection;

use utmost_lib::types::FileType;

use crate::view_model::{FilterState, SortDir, SortKey, parse_file_type_pub};

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

    // Union of full + partial type sets. See module-level doc for why we don't
    // try to replicate the variant_of distinction in SQL.
    let mut type_union: std::collections::BTreeSet<&FileType> = Default::default();
    type_union.extend(filter.enabled_types.iter());
    type_union.extend(filter.enabled_partial_types.iter());
    if !type_union.is_empty() {
        let placeholders: Vec<&'static str> = type_union.iter().map(|_| "?").collect();
        wheres.push(format!("f.file_type IN ({})", placeholders.join(", ")));
        for ft in &type_union {
            params.push(Param::Str(file_type_to_db_string(**ft).to_string()));
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index_db::IndexDb;
    use crate::index_db::models::{NewBookmark, NewFile, NewSource};
    use crate::index_db::schema;

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
}
