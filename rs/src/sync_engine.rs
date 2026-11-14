//! Port of `src/sync-engine.ts` — pull cursor pages from the API, decrypt
//! with the items keys, and commit each page before fetching the next. The
//! sync token is written only after the cursor is exhausted, so a crash
//! mid-sync retries the same token and upserts already-written rows.

use std::collections::HashMap;

use serde_json::Value;

use crate::db::{CacheDb, DbError, ItemRow};
use crate::proto004::{self, EncryptedItem};
use crate::sn_api::{ApiClientError, SyncPage};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncReport {
    pub upserted: usize,
    pub skipped: usize,
    pub conflicts: usize,
    pub pages: usize,
}

pub const STORED_TYPES: [&str; 3] = ["Note", "SN|ItemsKey", "Tag"];

/// Notes are what we show. Tags come along read-only (titles, parents, note
/// links — the CLI never writes them). Items keys stay so later syncs can
/// decrypt without the password.
pub fn is_stored_type(content_type: &str) -> bool {
    STORED_TYPES.contains(&content_type)
}

/// Recorded in sync_state (with the token it was written for); a mismatch
/// forces a full pull.
pub fn stored_types_version() -> String {
    let mut sorted = STORED_TYPES.to_vec();
    sorted.sort_unstable();
    sorted.join(",")
}

/// Same hidden set as notes.ts — these types never yield a title.
pub const HIDDEN_TYPES: [&str; 3] = ["SN|ItemsKey", "SN|KeySystemItemsKey", "SN|KeySystemRootKey"];

pub fn drop_unstored_types(db: &CacheDb) -> Result<(), DbError> {
    let keep = STORED_TYPES.iter().map(|kind| format!("'{kind}'")).collect::<Vec<_>>().join(", ");
    db.conn_execute(&format!("DELETE FROM items WHERE content_type NOT IN ({keep})"))
}

/// Seconds, milliseconds, or microseconds (what the hosted API sends) →
/// milliseconds.
pub fn to_unix_ms(value: i64) -> i64 {
    let value = value as f64;
    if value < 1e11 {
        (value * 1000.0).round() as i64
    } else if value < 1e14 {
        value.round() as i64
    } else {
        (value / 1000.0).round() as i64
    }
}

/// `updatedAtMs` — the dedicated timestamp field first, then `updated_at` as
/// number (epoch) or string (RFC 3339, what Date.parse handles in practice).
pub fn updated_at_ms(item: &EncryptedItem) -> i64 {
    if let Some(stamp) = item.updated_at_timestamp
        && stamp > 0
    {
        return to_unix_ms(stamp);
    }
    match &item.updated_at {
        Some(Value::Number(number)) => {
            let value = number.as_f64().unwrap_or(0.0) as i64;
            if value > 0 {
                return to_unix_ms(value);
            }
            0
        }
        Some(Value::String(text)) => chrono::DateTime::parse_from_rfc3339(text)
            .map(|parsed| parsed.timestamp_millis())
            .unwrap_or(0),
        _ => 0,
    }
}

fn title_from_content(content_type: &str, content: &str) -> Option<String> {
    if HIDDEN_TYPES.contains(&content_type) {
        return None;
    }
    let parsed: Value = serde_json::from_str(content).ok()?;
    let title = |name: &str| match parsed.get(name) {
        Some(Value::String(text)) if !text.is_empty() => Some(text.clone()),
        _ => None,
    };
    title("title").or_else(|| title("name"))
}

fn tombstone(item: &EncryptedItem) -> ItemRow {
    (
        item.uuid.clone(),
        item.content_type.clone(),
        updated_at_ms(item),
        1,
        None,
        "{}".to_string(),
    )
}

pub fn load_items_keys(db: &CacheDb) -> Result<HashMap<String, String>, DbError> {
    let mut statement = db.prepare(
        "SELECT uuid, content FROM items WHERE content_type = 'SN|ItemsKey' AND deleted = 0",
    )?;
    let rows = statement
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
        .map_err(DbError::from)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(DbError::from)?;
    let mut keys = HashMap::new();
    for (uuid, content) in rows {
        if let Some(key) = proto004::items_key_from_content(&content) {
            keys.insert(uuid, key);
        }
    }
    Ok(keys)
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Row(ItemRow),
    NeedMaster,
    Skip,
}

fn decrypt_one(
    item: &EncryptedItem,
    items_keys: &mut HashMap<String, String>,
    master_key: Option<&str>,
) -> Result<Outcome, proto004::Proto004Error> {
    if item.deleted == Some(true) {
        return Ok(Outcome::Row(tombstone(item)));
    }
    if proto004::is_items_key(&item.content_type) {
        let Some(master) = master_key else {
            return Ok(Outcome::NeedMaster);
        };
        let content = proto004::decrypt_item_content(item, master)?;
        if let Some(items_key) = proto004::items_key_from_content(&content) {
            items_keys.insert(item.uuid.clone(), items_key);
        }
        return Ok(Outcome::Row((
            item.uuid.clone(),
            item.content_type.clone(),
            updated_at_ms(item),
            0,
            None,
            content,
        )));
    }
    let parent = item.items_key_id.as_deref().and_then(|key_id| items_keys.get(key_id));
    let Some(parent) = parent else {
        return Ok(Outcome::Skip);
    };
    let content = proto004::decrypt_item_content(item, parent)?;
    Ok(Outcome::Row((
        item.uuid.clone(),
        item.content_type.clone(),
        updated_at_ms(item),
        0,
        title_from_content(&item.content_type, &content),
        content,
    )))
}

#[derive(Debug, PartialEq, Eq)]
pub enum SyncError {
    Fetch(ApiClientError),
    Db(DbError),
    User(String),
}

impl core::fmt::Display for SyncError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Fetch(error) => write!(f, "{error}"),
            Self::Db(error) => write!(f, "{error}"),
            Self::User(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for SyncError {}

impl From<DbError> for SyncError {
    fn from(error: DbError) -> Self {
        Self::Db(error)
    }
}

pub struct SyncOptions<'a> {
    pub db: &'a CacheDb,
    pub master_key: Option<String>,
    /// TS reads Date.now() here; passed in so tests can pin it.
    pub now_ms: i64,
}

/// Consume one page: items keys first (so their notes can decrypt), then the
/// rest. Notes whose key has not been seen yet are deferred to a retry after
/// the pull. A decrypting items key failing is a hard error; a failed note is
/// skipped and counted.
#[allow(clippy::too_many_arguments)]
fn consume(
    items: &[EncryptedItem],
    items_keys: &mut HashMap<String, String>,
    master_key: &mut Option<String>,
    prompted: &mut bool,
    ensure_master_key: &mut dyn FnMut() -> Result<String, SyncError>,
    deferred: &mut Vec<EncryptedItem>,
    report: &mut SyncReport,
) -> Result<Vec<ItemRow>, SyncError> {
    let mut rows = Vec::new();
    // Items keys first, so their notes can decrypt in the same page.
    let ordered = items
        .iter()
        .filter(|item| proto004::is_items_key(&item.content_type))
        .chain(items.iter().filter(|item| !proto004::is_items_key(&item.content_type)));
    for item in ordered {
        if item.uuid.is_empty() {
            continue;
        }
        if !is_stored_type(&item.content_type) {
            continue;
        }
        let result = match decrypt_one(item, items_keys, master_key.as_deref()) {
            Ok(Outcome::NeedMaster) => {
                if master_key.is_none() {
                    if *prompted {
                        return Err(SyncError::User("that password did not unwrap item keys".into()));
                    }
                    *prompted = true;
                    *master_key = Some(ensure_master_key()?);
                    decrypt_one(item, items_keys, master_key.as_deref())
                } else {
                    Ok(Outcome::NeedMaster)
                }
            }
            other => other,
        };
        match result {
            Ok(Outcome::Row(row)) => rows.push(row),
            Ok(outcome) => {
                if outcome == Outcome::NeedMaster {
                    return Err(SyncError::User("that password did not unwrap item keys".into()));
                }
                if item.deleted != Some(true)
                    && item.items_key_id.is_some()
                    && !items_keys.contains_key(item.items_key_id.as_deref().expect("checked"))
                {
                    deferred.push(item.clone());
                } else {
                    report.skipped += 1;
                }
            }
            Err(error) => {
                if proto004::is_items_key(&item.content_type) {
                    return Err(SyncError::User("that password did not unwrap item keys".into()));
                }
                let _ = error;
                report.skipped += 1;
            }
        }
    }
    Ok(rows)
}

/// Pull every cursor page, decrypt, and commit each page before the next.
/// The sync token is written only after the cursor is exhausted, so a crash
/// mid-sync retries the same token and upserts already-written rows.
pub type FetchPage<'a> = &'a mut dyn FnMut(Option<&str>, Option<&str>) -> Result<SyncPage, ApiClientError>;
type EnsureMasterKey<'a> = &'a mut dyn FnMut() -> Result<String, SyncError>;

pub fn run_sync(
    options: SyncOptions<'_>,
    fetch_page: FetchPage<'_>,
    ensure_master_key: EnsureMasterKey<'_>,
) -> Result<SyncReport, SyncError> {
    let mut items_keys = load_items_keys(options.db)?;
    drop_unstored_types(options.db)?;
    let mut master_key = options.master_key.clone();
    let mut prompted = options.master_key.is_some();
    let state = options.db.read_sync_state()?;
    // The token only applies to the stored-type set that produced it; after a
    // change (e.g. tags newly stored) the incremental feed would never resend
    // what earlier syncs dropped, so fall back to a full pull. The marker also
    // records the token it was written with: an older binary overwrites the
    // token (and purges tag rows) while leaving the marker, and that mismatch
    // is what forces the re-pull.
    let marker = format!("{}|{}", stored_types_version(), state.sync_token.as_deref().unwrap_or(""));
    let sync_token = if state.stored_types.as_deref() == Some(marker.as_str()) {
        state.sync_token.clone()
    } else {
        None
    };
    let mut cursor: Option<String> = None;
    let mut newest_token = sync_token.clone();
    let mut deferred: Vec<EncryptedItem> = Vec::new();
    let mut report = SyncReport::default();

    loop {
        let page = fetch_page(sync_token.as_deref(), cursor.as_deref()).map_err(SyncError::Fetch)?;
        report.pages += 1;
        report.conflicts += page.conflicts;
        if let Some(token) = &page.sync_token {
            newest_token = Some(token.clone());
        }
        let rows = consume(
            &page.items,
            &mut items_keys,
            &mut master_key,
            &mut prompted,
            ensure_master_key,
            &mut deferred,
            &mut report,
        )?;
        if !rows.is_empty() {
            options.db.upsert_items(&rows)?;
            report.upserted += rows.len();
        }
        cursor = page.cursor_token;
        if cursor.is_none() {
            break;
        }
    }

    if !deferred.is_empty() {
        let mut rows = Vec::new();
        for item in &deferred {
            match decrypt_one(item, &mut items_keys, master_key.as_deref()) {
                Ok(Outcome::Row(row)) => rows.push(row),
                _ => report.skipped += 1,
            }
        }
        if !rows.is_empty() {
            options.db.upsert_items(&rows)?;
            report.upserted += rows.len();
        }
    }

    options.db.write_sync_state(
        newest_token.as_deref(),
        options.now_ms,
        Some(&format!("{}|{}", stored_types_version(), newest_token.as_deref().unwrap_or(""))),
    )?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto004::encrypt004;
    use serde_json::json;
    use std::cell::RefCell;
    use std::rc::Rc;

    fn random_hex() -> String {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("system rng");
        hex::encode(bytes)
    }

    fn uuid(seed: u8) -> String {
        format!("{seed:08x}-{seed:02x}{seed:02x}-4{seed:02x}8-{seed:02x}9-{0:02x}{0:02x}{0:02x}{0:02x}{0:02x}{0:02x}", seed)
    }

    struct Fixture {
        master: String,
        items: Vec<EncryptedItem>,
        note_id: String,
        tag_id: String,
    }

    /// The TS test's fixture: one items key wrapping a note and a tag, plus
    /// two foreign-typed items that sync must skip without counting.
    fn fixture() -> Fixture {
        let master = random_hex();
        let items_key = random_hex();
        let wrapping_key = random_hex();
        let items_key_id = uuid(1);
        let note_id = uuid(2);
        let tag_id = uuid(3);
        let note_key = random_hex();
        let tag_key = random_hex();
        let items_aad = json!({ "u": items_key_id, "v": "004" });
        let note_aad = json!({ "u": note_id, "v": "004" });
        let tag_aad = json!({ "u": tag_id, "v": "004" });

        let items = vec![
            EncryptedItem {
                uuid: items_key_id.clone(),
                content_type: "SN|ItemsKey".into(),
                enc_item_key: Some(encrypt004(&wrapping_key, &master, &items_aad).expect("seals")),
                content: Some(
                    encrypt004(&json!({ "itemsKey": items_key, "version": "004" }).to_string(), &wrapping_key, &items_aad)
                        .expect("seals"),
                ),
                items_key_id: None,
                deleted: None,
                updated_at: None,
                updated_at_timestamp: Some(1_000),
            },
            EncryptedItem {
                uuid: note_id.clone(),
                content_type: "Note".into(),
                enc_item_key: Some(encrypt004(&note_key, &items_key, &note_aad).expect("seals")),
                content: Some(
                    encrypt004(&json!({ "title": "Pins", "text": "door code 2468" }).to_string(), &note_key, &note_aad)
                        .expect("seals"),
                ),
                items_key_id: Some(items_key_id.clone()),
                deleted: None,
                updated_at: None,
                updated_at_timestamp: Some(2_000),
            },
            EncryptedItem {
                uuid: tag_id.clone(),
                content_type: "Tag".into(),
                enc_item_key: Some(encrypt004(&tag_key, &items_key, &tag_aad).expect("seals")),
                content: Some(
                    encrypt004(
                        &json!({ "title": "prod", "references": [{ "uuid": note_id, "content_type": "Note" }] }).to_string(),
                        &tag_key,
                        &tag_aad,
                    )
                    .expect("seals"),
                ),
                items_key_id: Some(items_key_id),
                deleted: None,
                updated_at: None,
                updated_at_timestamp: Some(5_000),
            },
            EncryptedItem {
                uuid: uuid(4),
                content_type: "SN|UserPreferences".into(),
                content: Some("not-a-note".into()),
                enc_item_key: None,
                items_key_id: None,
                deleted: None,
                updated_at: None,
                updated_at_timestamp: Some(3_000),
            },
            EncryptedItem {
                uuid: uuid(5),
                content_type: "SN|File".into(),
                content: Some("not-a-note".into()),
                enc_item_key: None,
                items_key_id: None,
                deleted: None,
                updated_at: None,
                updated_at_timestamp: Some(4_000),
            },
        ];
        Fixture { master, items, note_id, tag_id }
    }

    fn fresh_db(tag: &str) -> (CacheDb, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("sns-sync-{tag}-{}.db", std::process::id()));
        crate::db::remove_cache_files(&path);
        let db = crate::db::open_database(&path, &random_hex()).expect("opens");
        (db, path)
    }

    fn row_count(db: &CacheDb, sql: &str) -> i64 {
        db.conn
            .query_row(sql, [], |row| row.get(0))
            .expect("count query")
    }

    #[test]
    fn server_timestamps_become_unix_milliseconds() {
        assert_eq!(to_unix_ms(1_794_530_346_281_266), 1_794_530_346_281);
        assert_eq!(to_unix_ms(1_794_530_346_281), 1_794_530_346_281);
        assert_eq!(to_unix_ms(1_794_530_346), 1_794_530_346_000);
    }

    #[test]
    fn updated_at_iso_strings_and_epoch_numbers_both_yield_ms() {
        let iso = EncryptedItem {
            uuid: "u".into(),
            content_type: "Note".into(),
            content: None,
            enc_item_key: None,
            items_key_id: None,
            deleted: None,
            updated_at: Some(json!("2024-01-02T03:04:05.678Z")),
            updated_at_timestamp: None,
        };
        assert_eq!(updated_at_ms(&iso), 1_704_164_645_678);
        let epoch = EncryptedItem {
            uuid: "u".into(),
            content_type: "Note".into(),
            content: None,
            enc_item_key: None,
            items_key_id: None,
            deleted: None,
            updated_at: Some(json!(1_794_530_346_281_266_i64)),
            updated_at_timestamp: None,
        };
        assert_eq!(updated_at_ms(&epoch), 1_794_530_346_281);
        assert_eq!(updated_at_ms(&EncryptedItem {
            uuid: "u".into(),
            content_type: "Note".into(),
            content: None,
            enc_item_key: None,
            items_key_id: None,
            deleted: None,
            updated_at: None,
            updated_at_timestamp: None,
        }), 0);
    }

    #[test]
    fn sync_writes_decrypted_notes_then_an_incremental_pull_is_empty() {
        let (db, path) = fresh_db("full");
        let fx = fixture();
        let pages: Rc<RefCell<Vec<SyncPage>>> = Rc::new(RefCell::new(vec![
            SyncPage { items: fx.items.clone(), sync_token: Some("sync-1".into()), cursor_token: Some("cursor-1".into()), conflicts: 1 },
            SyncPage { items: Vec::new(), sync_token: Some("sync-1".into()), cursor_token: None, conflicts: 0 },
        ]));
        let calls = Rc::new(RefCell::new(0));
        let pages_seen = pages.clone();
        let calls_seen = calls.clone();
        let mut fetch_page = move |sync_token: Option<&str>, cursor: Option<&str>| {
            *calls_seen.borrow_mut() += 1;
            let call = *calls_seen.borrow();
            if call == 1 {
                assert!(sync_token.is_none());
                assert!(cursor.is_none());
            }
            if call == 2 {
                assert_eq!(cursor, Some("cursor-1"));
            }
            let page = {
                let mut queue = pages_seen.borrow_mut();
                if queue.is_empty() {
                    queue.last().cloned().expect("a page is queued")
                } else {
                    queue.remove(0)
                }
            };
            Ok(page)
        };
        let mut ensure = || Err(SyncError::User("should already have the master key".into()));
        let report = run_sync(
            SyncOptions { db: &db, master_key: Some(fx.master.clone()), now_ms: 1_700_000_000_000 },
            &mut fetch_page,
            &mut ensure,
        )
        .expect("sync succeeds");
        assert_eq!(report.upserted, 3);
        assert_eq!(report.conflicts, 1);
        assert_eq!(report.pages, 2);
        assert_eq!(row_count(&db, "SELECT count(*) FROM items"), 3);

        let notes = db.items_for_type("Note").expect("notes");
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].0, fx.note_id);
        assert_eq!(notes[0].4.as_deref(), Some("Pins"));
        assert!(notes[0].5.contains("door code 2468"));
        let tags = db.items_for_type("Tag").expect("tags");
        assert_eq!(tags[0].4.as_deref(), Some("prod"));

        let state = db.read_sync_state().expect("state");
        assert_eq!(state.sync_token.as_deref(), Some("sync-1"));
        assert_eq!(
            state.stored_types.as_deref(),
            Some("Note,SN|ItemsKey,Tag|sync-1"),
            "the marker names the token it was written for"
        );

        // Incremental pull reuses the token and writes nothing new.
        let calls_second = Rc::new(RefCell::new(0));
        let calls_second_seen = calls_second.clone();
        let mut fetch_second = move |sync_token: Option<&str>, _cursor: Option<&str>| {
            *calls_second_seen.borrow_mut() += 1;
            assert_eq!(sync_token, Some("sync-1"));
            Ok(SyncPage { items: Vec::new(), sync_token: Some("sync-1".into()), cursor_token: None, conflicts: 0 })
        };
        let mut ensure_ok = || Ok(fx.master.clone());
        let second = run_sync(
            SyncOptions { db: &db, master_key: Some(fx.master.clone()), now_ms: 1_700_000_100_000 },
            &mut fetch_second,
            &mut ensure_ok,
        )
        .expect("incremental succeeds");
        assert_eq!(second.upserted, 0);
        drop(calls);

        db.close();
        crate::db::remove_cache_files(&path);
    }

    #[test]
    fn a_failed_page_does_not_advance_the_sync_token() {
        let (db, path) = fresh_db("crash");
        let fx = fixture();
        let calls = Rc::new(RefCell::new(0));
        let seen = calls.clone();
        let items_key_item = fx.items[0].clone();
        let mut fetch_page = move |_: Option<&str>, _: Option<&str>| {
            *seen.borrow_mut() += 1;
            if *seen.borrow() == 1 {
                return Ok(SyncPage {
                    items: vec![items_key_item.clone()],
                    sync_token: Some("sync-1".into()),
                    cursor_token: Some("more".into()),
                    conflicts: 0,
                });
            }
            Err(ApiClientError::User("killed".into()))
        };
        let mut ensure = || Ok(fx.master.clone());
        let error = run_sync(
            SyncOptions { db: &db, master_key: Some(fx.master.clone()), now_ms: 1 },
            &mut fetch_page,
            &mut ensure,
        )
        .expect_err("fetch failure propagates");
        assert!(error.to_string().contains("killed"));
        assert_eq!(row_count(&db, "SELECT count(*) FROM items"), 1, "page one committed");
        let state = db.read_sync_state().expect("state readable");
        assert_eq!(state.sync_token, None, "no token was written");
        db.close();
        crate::db::remove_cache_files(&path);
    }

    #[test]
    fn missing_master_key_is_requested_once() {
        let (db, path) = fresh_db("pw");
        let fx = fixture();
        let prompts = Rc::new(RefCell::new(0));
        let seen = prompts.clone();
        let master = fx.master.clone();
        let mut fetch_page = move |_: Option<&str>, _: Option<&str>| {
            Ok(SyncPage { items: fx.items.clone(), sync_token: Some("sync-1".into()), cursor_token: None, conflicts: 0 })
        };
        let mut ensure = move || {
            *seen.borrow_mut() += 1;
            Ok(master.clone())
        };
        let report = run_sync(
            SyncOptions { db: &db, master_key: None, now_ms: 1 },
            &mut fetch_page,
            &mut ensure,
        )
        .expect("sync succeeds after prompting");
        assert_eq!(*prompts.borrow(), 1);
        assert_eq!(report.upserted, 3);
        assert_eq!(row_count(&db, "SELECT count(*) FROM items WHERE content_type = 'Note'"), 1);
        db.close();
        crate::db::remove_cache_files(&path);
    }

    #[test]
    fn a_wrong_password_is_a_hard_error() {
        let (db, path) = fresh_db("wrongpw");
        let fx = fixture();
        let wrong_master = random_hex();
        let mut fetch_page = move |_: Option<&str>, _: Option<&str>| {
            Ok(SyncPage { items: fx.items.clone(), sync_token: Some("sync-1".into()), cursor_token: None, conflicts: 0 })
        };
        let mut ensure = || Ok(wrong_master.clone());
        let error = run_sync(
            SyncOptions { db: &db, master_key: None, now_ms: 1 },
            &mut fetch_page,
            &mut ensure,
        )
        .expect_err("wrong password refuses");
        assert_eq!(error, SyncError::User("that password did not unwrap item keys".into()));
        db.close();
        crate::db::remove_cache_files(&path);
    }

    #[test]
    fn a_sync_token_from_a_different_stored_type_set_is_ignored() {
        let (db, path) = fresh_db("migrate");
        let fx = fixture();
        db.write_sync_state(Some("old-token"), 1, Some("Note,SN|ItemsKey")).expect("stale state");
        let calls: Rc<RefCell<Vec<Option<String>>>> = Rc::new(RefCell::new(Vec::new()));
        let seen_full = calls.clone();
        let items = fx.items.clone();
        let mut fetch_page = move |sync_token: Option<&str>, _: Option<&str>| {
            seen_full.borrow_mut().push(sync_token.map(str::to_string));
            Ok(SyncPage { items: items.clone(), sync_token: Some("new-token".into()), cursor_token: None, conflicts: 0 })
        };
        let mut ensure = || Ok(fx.master.clone());
        run_sync(SyncOptions { db: &db, master_key: Some(fx.master.clone()), now_ms: 1 }, &mut fetch_page, &mut ensure)
            .expect("full pull succeeds");
        assert_eq!(
            *calls.borrow(),
            vec![None],
            "the stale token was never sent — the pull started from scratch"
        );
        let state = db.read_sync_state().expect("state");
        assert_eq!(state.sync_token.as_deref(), Some("new-token"));
        assert_ne!(state.stored_types.as_deref(), Some("Note,SN|ItemsKey"));

        let seen_incr = calls.clone();
        let mut fetch_incremental = move |sync_token: Option<&str>, _: Option<&str>| {
            seen_incr.borrow_mut().push(sync_token.map(str::to_string));
            Ok(SyncPage { items: Vec::new(), sync_token: Some("new-token".into()), cursor_token: None, conflicts: 0 })
        };
        let mut ensure = || Ok(fx.master.clone());
        run_sync(SyncOptions { db: &db, master_key: Some(fx.master.clone()), now_ms: 2 }, &mut fetch_incremental, &mut ensure)
            .expect("incremental succeeds");
        assert_eq!(*calls.borrow(), vec![None, Some("new-token".into())], "the next pull is incremental again");
        db.close();
        crate::db::remove_cache_files(&path);
    }

    #[test]
    fn a_marker_written_for_an_older_token_forces_a_full_pull() {
        let (db, path) = fresh_db("wedge");
        let fx = fixture();
        // an older binary overwrites the sync token (and purges tag rows) while
        // leaving the stored_types marker behind — the mismatch must full-pull
        db.write_sync_state(Some("token-current"), 1, Some(&format!("{}|token-older", stored_types_version())))
            .expect("wedge state");
        let calls: Rc<RefCell<Vec<Option<String>>>> = Rc::new(RefCell::new(Vec::new()));
        let seen_full = calls.clone();
        let items = fx.items.clone();
        let mut fetch_full = move |sync_token: Option<&str>, _: Option<&str>| {
            seen_full.borrow_mut().push(sync_token.map(str::to_string));
            Ok(SyncPage { items: items.clone(), sync_token: Some("token-current".into()), cursor_token: None, conflicts: 0 })
        };
        let mut ensure = || Ok(fx.master.clone());
        run_sync(SyncOptions { db: &db, master_key: Some(fx.master.clone()), now_ms: 1 }, &mut fetch_full, &mut ensure)
            .expect("full pull succeeds");
        assert_eq!(*calls.borrow(), vec![None]);

        let seen_incremental = calls.clone();
        let mut fetch_incremental = move |sync_token: Option<&str>, _: Option<&str>| {
            seen_incremental.borrow_mut().push(sync_token.map(str::to_string));
            Ok(SyncPage { items: Vec::new(), sync_token: Some("token-current".into()), cursor_token: None, conflicts: 0 })
        };
        let mut ensure = || Ok(fx.master.clone());
        run_sync(SyncOptions { db: &db, master_key: Some(fx.master.clone()), now_ms: 2 }, &mut fetch_incremental, &mut ensure)
            .expect("incremental succeeds");
        assert_eq!(*calls.borrow(), vec![None, Some("token-current".into())], "repaired — incremental again");
        db.close();
        crate::db::remove_cache_files(&path);
    }

    #[test]
    fn deleted_items_arrive_as_tombstones_and_foreign_types_are_dropped() {
        let (db, path) = fresh_db("tomb");
        let master = random_hex();
        let items_key = random_hex();
        let wrapping_key = random_hex();
        let items_key_id = uuid(1);
        let aad = json!({ "u": items_key_id, "v": "004" });
        let deleted_note = EncryptedItem {
            uuid: uuid(7),
            content_type: "Note".into(),
            content: Some("{}".into()),
            enc_item_key: None,
            items_key_id: Some(items_key_id.clone()),
            deleted: Some(true),
            updated_at: None,
            updated_at_timestamp: Some(6_000),
        };
        let items = vec![
            EncryptedItem {
                uuid: items_key_id.clone(),
                content_type: "SN|ItemsKey".into(),
                enc_item_key: Some(encrypt004(&wrapping_key, &master, &aad).expect("seals")),
                content: Some(encrypt004(&json!({ "itemsKey": items_key, "version": "004" }).to_string(), &wrapping_key, &aad).expect("seals")),
                items_key_id: None,
                deleted: None,
                updated_at: None,
                updated_at_timestamp: Some(1_000),
            },
            deleted_note,
        ];
        let mut fetch_page = move |_: Option<&str>, _: Option<&str>| {
            Ok(SyncPage { items: items.clone(), sync_token: Some("t".into()), cursor_token: None, conflicts: 0 })
        };
        let mut ensure = || Ok(master.clone());
        let report = run_sync(
            SyncOptions { db: &db, master_key: None, now_ms: 1 },
            &mut fetch_page,
            &mut ensure,
        )
        .expect("sync succeeds");
        assert_eq!(report.upserted, 2);
        let deleted: i64 = db
            .conn
            .query_row("SELECT deleted FROM items WHERE uuid = ?1", [uuid(7)], |row| row.get(0))
            .expect("tombstone row");
        assert_eq!(deleted, 1);
        let content: String = db
            .conn
            .query_row("SELECT content FROM items WHERE uuid = ?1", [uuid(7)], |row| row.get(0))
            .expect("tombstone content");
        assert_eq!(content, "{}");

        db.conn_execute("INSERT INTO items (uuid, content_type, updated_at, deleted, title, content) VALUES ('x', 'SN|UserPreferences', 1, 0, NULL, '{}')").expect("foreign row");
        drop_unstored_types(&db).expect("drops");
        assert_eq!(row_count(&db, "SELECT count(*) FROM items WHERE content_type = 'SN|UserPreferences'"), 0);
        db.close();
        crate::db::remove_cache_files(&path);
    }
}
