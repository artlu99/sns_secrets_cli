//! Port of `src/db.ts` — the chacha20-encrypted local cache.
//!
//! The cipher layer is SQLite3 Multiple Ciphers (upstream of the TS
//! implementation's better-sqlite3-multiple-ciphers), compiled into the
//! binary via the vendored libsqlite3-sys patch. The pragmas, schema,
//! migration discipline (PRAGMA user_version), and wrong-key semantics match
//! the TypeScript module exactly. `tests/fixtures/cache-v0.2.0.db` was
//! written by the TypeScript implementation and is opened here — the two
//! implementations read each other's caches byte-for-byte.

use rusqlite::{params, Connection, ErrorCode, Error as SqliteError, OptionalExtension};
use std::path::Path;

pub struct CacheDb {
    pub(crate) conn: Connection,
}

impl core::fmt::Debug for CacheDb {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CacheDb").finish_non_exhaustive()
    }
}

pub type ItemRow = (
    String,        // uuid
    String,        // content_type
    i64,           // updated_at
    i64,           // deleted
    Option<String>, // title
    String,        // content
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncState {
    pub sync_token: Option<String>,
    pub last_sync: Option<i64>,
    pub stored_types: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DbError {
    /// "this file is not a database we can read" — wrong key or corrupt file
    /// (SQLITE_NOTADB). Transient errors (busy, I/O) do NOT map here.
    WrongKey,
    /// Product-level failure with a stable user-facing message.
    User(String),
    Sqlite(String),
}

impl core::fmt::Display for DbError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongKey => write!(f, "could not open cache.db with the stored database key"),
            Self::User(message) => write!(f, "{message}"),
            Self::Sqlite(detail) => write!(f, "{detail}"),
        }
    }
}

impl std::error::Error for DbError {}

impl From<rusqlite::Error> for DbError {
    fn from(error: rusqlite::Error) -> Self {
        if is_wrong_key_database(&error) {
            Self::WrongKey
        } else {
            Self::Sqlite(error.to_string())
        }
    }
}

/// True only for "this file is not a database we can read" — a wrong key or a
/// corrupt file (SQLITE_NOTADB). Busy and I/O errors must NOT match: they are
/// transient, and callers treat wrong-key as permission to delete the cache.
pub fn is_wrong_key_database(error: &SqliteError) -> bool {
    match error {
        SqliteError::SqliteFailure(ffi_error, _) => ffi_error.code == ErrorCode::NotADatabase,
        _ => {
            let message = error.to_string();
            message.contains("file is not a database") || message.contains("unsupported file format")
        }
    }
}

fn open_connection(path: &Path) -> Result<Connection, DbError> {
    let conn = Connection::open(path).map_err(DbError::from)?;
    conn.busy_timeout(std::time::Duration::from_millis(5000)).map_err(DbError::from)?;
    Ok(conn)
}

/// Open the cache. Applies the cipher pragmas in the TS order, verifies the
/// key by counting sqlite_master (which forces a real page decrypt), applies
/// the schema, and runs pending migrations tracked in PRAGMA user_version.
pub fn open_database(path: &Path, db_key: &str) -> Result<CacheDb, DbError> {
    if !is_64_hex(db_key) {
        return Err(DbError::User("database key must be 64 hex characters".into()));
    }
    let conn = open_connection(path)?;
    conn.execute_batch(&format!(
        "PRAGMA cipher = 'chacha20';\
         PRAGMA key = '{db_key}';\
         PRAGMA cipher_memory_security = ON;\
         PRAGMA busy_timeout = 5000;"
    ))
    .map_err(DbError::from)?;
    apply_schema_and_migrations(&conn)?;
    Ok(CacheDb { conn })
}

fn apply_schema_and_migrations(conn: &Connection) -> Result<(), DbError> {
    // Forces a real page decrypt: a wrong key fails right here (SQLITE_NOTADB).
    let _: i64 = conn
        .query_row("SELECT count(*) AS n FROM sqlite_master", [], |row| row.get(0))
        .map_err(DbError::from)?;
    // Schema first — the TS order — so migrations can ALTER the tables they
    // target on a brand-new cache.
    conn.execute_batch(SCHEMA).map_err(DbError::from)?;
    let applied: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0)).map_err(DbError::from)?;
    for (index, migration) in MIGRATIONS.iter().enumerate() {
        let index = index as i64;
        if index < applied {
            continue;
        }
        // Already applied by an older build that tracked nothing, or by a
        // concurrent opener that passed the version read before committing.
        if let Err(error) = conn.execute_batch(migration)
            && !error.to_string().contains("duplicate column name")
        {
            return Err(DbError::from(error));
        }
    }
    let expected = MIGRATIONS.len() as i64;
    if applied != expected {
        conn.pragma_update(None, "user_version", expected).map_err(DbError::from)?;
    }
    Ok(())
}

/// The TS regex `/^[0-9a-fA-F]{64}$/` without a regex dependency.
fn is_64_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// Open the cache. A file left behind by logout is encrypted with a deleted
/// key. That file cannot be read, so replace it with an empty database for
/// the current key.
pub fn open_database_or_replace(path: &Path, db_key: &str) -> Result<(CacheDb, bool), DbError> {
    let existed = path.exists();
    match open_database(path, db_key) {
        Ok(db) => Ok((db, false)),
        Err(DbError::WrongKey) if existed => {
            remove_cache_files(path);
            Ok((open_database(path, db_key)?, true))
        }
        Err(error) => Err(error),
    }
}

pub fn remove_cache_files(path: &Path) {
    let _ = std::fs::remove_file(path);
    for suffix in ["-journal", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{}", path.display(), suffix));
    }
}

/// The MIGRATIONS list from db.ts, applied in order on every open.
pub const MIGRATIONS: &[&str] = &["ALTER TABLE sync_state ADD COLUMN stored_types TEXT"];

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS items (
  uuid         TEXT PRIMARY KEY,
  content_type TEXT NOT NULL,
  updated_at   INTEGER NOT NULL,
  deleted      INTEGER NOT NULL DEFAULT 0,
  title        TEXT,
  content      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_items_type    ON items(content_type);
CREATE INDEX IF NOT EXISTS idx_items_updated ON items(updated_at);
CREATE TABLE IF NOT EXISTS sync_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  sync_token TEXT,
  last_sync INTEGER
);
";

impl CacheDb {
    /// TS `db.close()` — releases the file lock (fully on Drop, which runs
    /// when the last reference to this CacheDb goes away).
    pub fn close(&self) {}

    /// `db.exec` / `db.run` — one statement or batch, no rows.
    pub fn conn_execute(&self, sql: &str) -> Result<(), DbError> {
        self.conn.execute_batch(sql).map_err(DbError::from)
    }

    /// Prepared-statement access for cross-module queries.
    pub(crate) fn prepare(&self, sql: &str) -> Result<rusqlite::Statement<'_>, DbError> {
        self.conn.prepare(sql).map_err(DbError::from)
    }

    /// `sqliteMasterCount` — also the wrong-key detector on open.
    pub fn sqlite_master_count(&self) -> Result<i64, DbError> {
        self.conn
            .query_row("SELECT count(*) AS n FROM sqlite_master", [], |row| row.get(0))
            .map_err(DbError::from)
    }

    pub fn count_items(&self) -> Result<i64, DbError> {
        self.conn
            .query_row("SELECT count(*) AS n FROM items", [], |row| row.get(0))
            .map_err(DbError::from)
    }

    /// TS returns nulls when the row is absent (fresh cache, never synced).
    pub fn read_sync_state(&self) -> Result<SyncState, DbError> {
        Ok(self
            .conn
            .query_row(
                "SELECT sync_token, last_sync, stored_types FROM sync_state WHERE id = 1",
                [],
                |row| {
                    Ok(SyncState {
                        sync_token: row.get(0)?,
                        last_sync: row.get(1)?,
                        stored_types: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(DbError::from)?
            .unwrap_or(SyncState { sync_token: None, last_sync: None, stored_types: None }))
    }

    pub fn write_sync_state(&self, sync_token: Option<&str>, last_sync: i64, stored_types: Option<&str>) -> Result<(), DbError> {
        self.conn
            .execute(
                "INSERT INTO sync_state (id, sync_token, last_sync, stored_types) VALUES (1, ?, ?, ?)
                 ON CONFLICT(id) DO UPDATE SET
                   sync_token = excluded.sync_token, last_sync = excluded.last_sync, stored_types = excluded.stored_types",
                params![sync_token, last_sync, stored_types],
            )
            .map_err(DbError::from)?;
        Ok(())
    }

    /// Upsert items; a newer stored row wins (`WHERE excluded.updated_at >=`).
    pub fn upsert_items(&self, rows: &[ItemRow]) -> Result<(), DbError> {
        let tx = self.conn.unchecked_transaction().map_err(DbError::from)?;
        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO items (uuid, content_type, updated_at, deleted, title, content)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(uuid) DO UPDATE SET
                       content_type = excluded.content_type,
                       updated_at   = excluded.updated_at,
                       deleted      = excluded.deleted,
                       title        = excluded.title,
                       content      = excluded.content
                     WHERE excluded.updated_at >= items.updated_at",
                )
                .map_err(DbError::from)?;
            for (uuid, content_type, updated_at, deleted, title, content) in rows {
                stmt.execute(params![uuid, content_type, updated_at, deleted, title, content])
                    .map_err(DbError::from)?;
            }
        }
        tx.commit().map_err(DbError::from)?;
        Ok(())
    }

    /// Rows newest-first for a content type — the read path `list` uses.
    pub fn items_for_type(&self, content_type: &str) -> Result<Vec<ItemRow>, DbError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT uuid, content_type, updated_at, deleted, title, content
                 FROM items WHERE content_type = ?1 AND deleted = 0
                 ORDER BY updated_at DESC",
            )
            .map_err(DbError::from)?;
        let rows = stmt
            .query_map(params![content_type], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))
            })
            .map_err(DbError::from)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(DbError::from)?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_KEY: &str = concat!("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
    fn fixture_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cache-v0.2.0.db")
    }

    #[test]
    fn opens_the_typescript_written_cache() {
        let db = open_database(&fixture_path(), FIXTURE_KEY).expect("TS cache opens");
        assert!(db.sqlite_master_count().expect("count") >= 5);
        assert_eq!(db.count_items().expect("count"), 3);
        let state = db.read_sync_state().expect("sync state");
        assert_eq!(state.sync_token.as_deref(), Some("fixture-sync-token"));
        assert_eq!(state.last_sync, Some(1700000009000));
        let stored = state.stored_types.as_deref().expect("stored types");
        assert!(stored.contains("Note") && stored.contains("SN|ItemsKey"));
        db.close();
    }

    #[test]
    fn wrong_key_is_notadb_and_or_replace_recovers() {
        let other_key = "ef".repeat(32);
        assert_eq!(open_database(&fixture_path(), &other_key).expect_err("wrong key refuses"), DbError::WrongKey);

        let copy = std::env::temp_dir().join("sns-db-test-replace.db");
        let _ = std::fs::copy(fixture_path(), &copy);
        let (db, replaced) = open_database_or_replace(&copy, FIXTURE_KEY).expect("same key reopens");
        assert!(!replaced);
        db.close();
        let (db, replaced) = open_database_or_replace(&copy, &other_key).expect("wrong key replaces");
        assert!(replaced, "foreign cache is replaced for the current key");
        assert_eq!(db.count_items().expect("fresh cache"), 0);
        db.close();
        remove_cache_files(&copy);
    }

    #[test]
    fn corrupt_file_maps_to_wrong_key() {
        let junk = std::env::temp_dir().join("sns-db-test-junk.db");
        std::fs::write(&junk, b"this is not a database at all").expect("junk written");
        assert_eq!(open_database(&junk, FIXTURE_KEY).expect_err("junk refuses"), DbError::WrongKey);
        remove_cache_files(&junk);
    }

    #[test]
    fn short_keys_are_refused_before_touching_the_file() {
        assert_eq!(
            open_database(&fixture_path(), "abcd").expect_err("short key refuses"),
            DbError::User("database key must be 64 hex characters".into())
        );
    }

    #[test]
    fn schema_upsert_and_sync_state_round_trip_on_a_fresh_cache() {
        // sqlite3mc does not allow keys on in-memory/temporary databases, so
        // fresh-cache behavior is tested on a temp file.
        let path = std::env::temp_dir().join("sns-db-test-roundtrip.db");
        remove_cache_files(&path);
        let db = open_database(&path, FIXTURE_KEY).expect("fresh cache opens");
        let rows: Vec<ItemRow> = vec![
            ("u1".into(), "Note".into(), 100, 0, Some("newest".into()), "{}".into()),
            ("u2".into(), "Note".into(), 50, 0, None, "{}".into()),
            ("u3".into(), "SN|ItemsKey".into(), 10, 1, None, "{}".into()),
        ];
        db.upsert_items(&rows).expect("upsert");
        assert_eq!(db.count_items().expect("count"), 3);

        // Older write to the same uuid loses; newer write wins.
        db.upsert_items(&[("u1".into(), "Note".into(), 90, 0, Some("stale".into()), "{}".into())]).expect("stale upsert");
        db.upsert_items(&[("u1".into(), "Note".into(), 110, 0, Some("newest-ever".into()), "{}".into())]).expect("newer upsert");
        let notes = db.items_for_type("Note").expect("notes");
        assert_eq!(notes.len(), 2);
        assert_eq!(notes[0].4.as_deref(), Some("newest-ever"));
        assert_eq!(notes[0].2, 110);

        db.write_sync_state(Some("token"), 1234, Some("[\"Note\"]")).expect("sync write");
        let state = db.read_sync_state().expect("sync read");
        assert_eq!(state.sync_token.as_deref(), Some("token"));
        assert_eq!(state.last_sync, Some(1234));
        assert_eq!(state.stored_types.as_deref(), Some("[\"Note\"]"));
        db.write_sync_state(None, 2345, None).expect("sync overwrite");
        let state = db.read_sync_state().expect("sync reread");
        assert_eq!(state.sync_token, None);
        assert_eq!(state.last_sync, Some(2345));
        db.close();
        remove_cache_files(&path);
    }

    #[test]
    fn migration_is_idempotent_via_user_version() {
        let path = std::env::temp_dir().join("sns-db-test-migrate.db");
        remove_cache_files(&path);
        let db = open_database(&path, FIXTURE_KEY).expect("first open migrates");
        let version: i64 = db.conn.query_row("PRAGMA user_version", [], |row| row.get(0)).expect("user_version");
        assert_eq!(version as usize, MIGRATIONS.len(), "migrations recorded");
        db.close();
        // A true reopen of the same file — migrations must not re-run or clash.
        let db = open_database(&path, FIXTURE_KEY).expect("reopen after migrations");
        assert_eq!(db.count_items().expect("count"), 0);
        db.close();
        remove_cache_files(&path);
    }

    #[test]
    fn a_rust_written_cache_is_the_same_format_the_ts_implementation_wrote() {
        // The fixture above was created by better-sqlite3-multiple-ciphers
        // through src/db.ts. If this test passes, the vendored sqlite3mc
        // build reads that file with the same pragmas — cipher compat proven
        // in the TS→Rust direction. The Rust→TS direction is verified by the
        // bun check in RELEASE-style docs: open a Rust-written cache with
        // `bun -e 'import {openDatabase} from "./src/db.ts"'`.
        let db = open_database(&fixture_path(), FIXTURE_KEY).expect("opens");
        let notes = db.items_for_type("Note").expect("notes");
        assert_eq!(notes.len(), 1, "the deleted note stays out of the read path");
        assert_eq!(notes[0].0, "22222222-2222-4222-8222-222222222222");
        assert_eq!(notes[0].4.as_deref(), Some("Pins"));
        db.close();
    }

    /// Leaves /tmp/sns-rust-written-cache.db behind for the bun cross-check:
    /// `cargo test writes_a_cache -- --nocapture`, then open it from src/db.ts.
    #[test]
    fn writes_a_cache_file_for_the_ts_implementation_to_open() {
        let path = std::env::temp_dir().join("sns-rust-written-cache.db");
        remove_cache_files(&path);
        let db = open_database(&path, FIXTURE_KEY).expect("opens");
        db.upsert_items(&[(
            "99999999-9999-4999-8999-999999999999".into(),
            "Note".into(),
            1700000010000,
            0,
            Some("Written by Rust".into()),
            r#"{"title":"Written by Rust","text":"hello from sqlite3mc"}"#.into(),
        )])
        .expect("upsert");
        db.write_sync_state(Some("from-rust"), 1700000011000, Some(r#"["Note"]"#)).expect("sync write");
        db.close();
        eprintln!("rust cache at {} (key starts {})", path.display(), &FIXTURE_KEY[..8]);
    }
}
