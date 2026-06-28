// Task 2 implements the full schema DDL.  This stub exists so `mod schema_sql`
// compiles while Task 1 is being integrated.
use anyhow::Result;

/// Apply (or verify) the database schema.  No-op until Task 2.
pub async fn create_schema(_conn: &turso::Connection) -> Result<()> {
    Ok(())
}
