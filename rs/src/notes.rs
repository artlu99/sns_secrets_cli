//! Port of `src/notes.ts` — everything the reading commands do with the
//! decrypted cache: listing, search with value-proof snippets, the tag
//! graph, note bodies, the copy planner, and the show inventory's pure
//! renderer.

use std::collections::{HashMap, HashSet};

use fancy_regex::Regex as FancyRegex;
use regex::Regex as StdRegex;
use serde_json::Value;

use crate::db::{CacheDb, DbError, ItemRow};
use crate::errors::UserError;
use crate::note_env::{self, NoteScan, Settings};

/// Key-bearing items are stored for decrypt and never listed.
pub const HIDDEN_TYPES: [&str; 3] = ["SN|ItemsKey", "SN|KeySystemItemsKey", "SN|KeySystemRootKey"];

const REDACTED_FIELDS: [&str; 7] =
    ["itemsKey", "items_key", "key", "enc_item_key", "serverPassword", "masterKey", "privateKey"];

/// Content types whose prose `text` carries the env-style settings the list
/// counts.
pub const PROSE_TYPES: [&str; 1] = ["Note"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedNote {
    pub uuid: String,
    pub content_type: String,
    pub updated_at: i64,
    pub title: String,
    pub trashed: bool,
    /// env-style settings parsed from the note's prose body (0 when none).
    pub settings: usize,
}

/// A Note row's prose `text`, or None for other types and unparseable content.
fn prose_text(content_type: &str, content: &str) -> Option<String> {
    if !PROSE_TYPES.contains(&content_type) {
        return None;
    }
    let parsed: Value = serde_json::from_str(content).ok()?;
    parsed.get("text").and_then(Value::as_str).map(str::to_string)
}

/// Env-style settings parsed from a row's prose body. Notes parse their
/// `text`; anything else (and any unparseable content) has none.
pub fn note_settings(content_type: &str, content: &str) -> Settings {
    settings_from(content_type, &parse_content(content))
}

/// Full scan of a row's prose body — settings, comments, and the skipped
/// lines — for the show inventory. One walk per show; the hot paths use
/// `note_settings` instead.
pub fn note_scan(content_type: &str, content: &str) -> NoteScan {
    match prose_text(content_type, content) {
        None => NoteScan { settings: Settings::new(), comments: Settings::new(), prose: String::new() },
        Some(text) => note_env::scan_note(&text, true),
    }
}

/// Standard Notes keeps trashed notes in the account with `trashed: true` on
/// the decrypted content.
pub fn is_trashed(content: &str) -> bool {
    trashed_from(&parse_content(content))
}

/// The content JSON parsed once per row; the per-row helpers read the value.
/// Unparseable content reads as an empty object everywhere — the same
/// defaults the string-level helpers produced by tolerating parse errors.
fn parse_content(content: &str) -> Value {
    serde_json::from_str(content).unwrap_or(Value::Null)
}

fn trashed_from(parsed: &Value) -> bool {
    parsed.get("trashed").and_then(Value::as_bool).unwrap_or(false)
}

/// Env-style settings parsed from an already-parsed content body. Notes parse
/// their `text`; anything else (and anything without one) has none.
fn settings_from(content_type: &str, parsed: &Value) -> Settings {
    if !PROSE_TYPES.contains(&content_type) {
        return Settings::new();
    }
    match parsed.get("text").and_then(Value::as_str) {
        // list and search call this for every cached row: skip the prose they
        // never show
        None => Settings::new(),
        Some(text) => note_env::scan_note(text, false).settings,
    }
}

/// The five columns the reading queries share, mapped by index once.
fn content_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(String, String, i64, Option<String>, String)> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ListOptions<'a> {
    pub kind: Option<&'a str>,
    pub limit: usize,
    pub all: bool,
    pub tag_uuids: Option<&'a HashSet<String>>,
    pub env: bool,
    pub regex: bool,
}

pub fn list_notes(db: &CacheDb, options: ListOptions<'_>) -> Result<Vec<ListedNote>, DbError> {
    // No json_extract here: a cached row whose content is not valid JSON
    // would make SQLite raise mid-query and kill the whole listing. Trashed
    // is filtered in code, where every other parser tolerates bad content.
    let mut clauses = vec!["deleted = 0".to_string()];
    if let Some(kind) = options.kind {
        clauses.push(format!("content_type = '{}'", kind.replace('\'', "''")));
    } else if options.all {
        // --all means "plus key-bearing items" — never tag rows, which would
        // otherwise land in the (untagged) group as junk
        let types = ["Note"].iter().chain(HIDDEN_TYPES.iter()).map(|kind| format!("'{kind}'")).collect::<Vec<_>>().join(", ");
        clauses.push(format!("content_type IN ({types})"));
    } else {
        clauses.push("content_type = 'Note'".to_string());
    }
    let mut statement = db.prepare(&format!(
        "SELECT uuid, content_type, updated_at, title, content FROM items
         WHERE {}
         ORDER BY updated_at DESC",
        clauses.join(" AND ")
    ))?;
    // Rows stream lazily so the limit stops the scan — a 2,000-note cache
    // never materializes behind `limit 100`.
    let rows = statement.query_map([], content_row).map_err(db_error)?;
    let mut listed = Vec::new();
    for row in rows {
        let (uuid, content_type, updated_at, title, content) = row.map_err(db_error)?;
        let parsed = parse_content(&content);
        if trashed_from(&parsed) {
            continue;
        }
        if let Some(tag_uuids) = options.tag_uuids
            && !tag_uuids.contains(&uuid)
        {
            continue;
        }
        let settings = settings_from(&content_type, &parsed).len();
        // env view: the limit applies after filtering, so prose-only notes
        // never crowd out a settings note
        if options.env && settings == 0 {
            continue;
        }
        let title = title.unwrap_or_else(|| label(&content_type));
        listed.push(ListedNote {
            uuid,
            content_type,
            updated_at,
            title,
            trashed: false,
            settings,
        });
        if listed.len() >= options.limit {
            break;
        }
    }
    Ok(listed)
}

fn db_error(error: rusqlite::Error) -> DbError {
    DbError::Sqlite(error.to_string())
}

fn label(content_type: &str) -> String {
    if HIDDEN_TYPES.contains(&content_type) {
        content_type.to_string()
    } else {
        "(untitled)".to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    pub note: ListedNote,
    pub snippet: String,
}

pub fn search_notes(db: &CacheDb, query: &str, options: ListOptions<'_>) -> Result<Vec<SearchHit>, UserError> {
    let pattern = if options.regex {
        // JS-flavored semantics (lookarounds and friends): fancy-regex.
        Some(
            FancyRegex::new(&format!("(?i){query}"))
                .map_err(|_| UserError("that regular expression is invalid".into()))?,
        )
    } else {
        None
    };
    let needle = query.to_lowercase();
    let mut visible_types = vec!["Note"];
    if options.all {
        visible_types.extend(HIDDEN_TYPES);
    }
    let mut statement = db.prepare(
        "SELECT uuid, content_type, updated_at, title, content FROM items
         WHERE deleted = 0
         ORDER BY updated_at DESC",
    )?;
    let rows = statement.query_map([], content_row).map_err(|error| UserError::from(db_error(error)))?;
    let mut hits = Vec::new();
    for row in rows {
        let (uuid, content_type, updated_at, title, content) =
            row.map_err(|error| UserError::from(db_error(error)))?;
        let parsed = parse_content(&content);
        if trashed_from(&parsed) {
            continue;
        }
        if !visible_types.contains(&content_type.as_str()) {
            continue;
        }
        let title = title.unwrap_or_default();
        let haystack = format!("{title}\n{content}");
        let matched = match &pattern {
            Some(pattern) => pattern.is_match(&haystack).unwrap_or(false),
            None => haystack.to_lowercase().contains(&needle),
        };
        if !matched {
            continue;
        }
        let row: ItemRow = (uuid, content_type, updated_at, 0, Some(title.clone()), content);
        let hit = SearchHit {
            note: ListedNote {
                uuid: row.0.clone(),
                content_type: row.1.clone(),
                updated_at: row.2,
                title: if title.is_empty() { label(&row.1) } else { title },
                trashed: false,
                settings: settings_from(&row.1, &parsed).len(),
            },
            snippet: snippet(&snippet_source(&row), pattern.as_ref(), &needle),
        };
        hits.push(hit);
        if hits.len() >= options.limit {
            break;
        }
    }
    Ok(hits)
}

fn snippet(haystack: &str, pattern: Option<&FancyRegex>, needle: &str) -> String {
    let flat = whitespace_collapse(haystack);
    let index: Option<usize> = match pattern {
        Some(pattern) => pattern.find(&flat).ok().flatten().map(|match_| match_.start()),
        None => flat.to_lowercase().find(needle),
    };
    let Some(index) = index else {
        return flat.chars().take(80).collect();
    };
    let char_len = flat.chars().count();
    // TS slices by UTF-16 units; tests use ASCII, so chars are the honest unit.
    let start_usize = index.saturating_sub(20);
    let start_byte = flat.char_indices().nth(start_usize).map(|(byte, _)| byte).unwrap_or(flat.len());
    let end_char = (index + 60).min(char_len);
    let end_byte = flat.char_indices().nth(end_char).map(|(byte, _)| byte).unwrap_or(flat.len());
    let slice = &flat[start_byte..end_byte];
    let mut out = String::new();
    if start_usize > 0 {
        out.push('…');
    }
    out.push_str(slice);
    if end_char < char_len {
        out.push('…');
    }
    out.chars().take(80).collect()
}

fn whitespace_collapse(text: &str) -> String {
    static WHITESPACE_RUN: std::sync::OnceLock<StdRegex> = std::sync::OnceLock::new();
    WHITESPACE_RUN.get_or_init(|| StdRegex::new(r"\s+").expect("static pattern")).replace_all(text, " ").into_owned()
}

/// An assignment line as the parser sees one: optional `export`, the key
/// charset, `=`, then a quoted span (which may cross lines) or the line's
/// rest.
///
/// Collapse every assignment-shaped line to `KEY=[redacted]` — quoted spans,
/// unclosed quotes, and unquoted values included — then mask rejected inline
/// fragments the way the show inventory does. The line-level pass runs first
/// because the fragment mask cannot catch a quoted value's continuation
/// lines: masking the decoded body this way is what lets a snippet be cut
/// from text a value may have once been in.
fn mask_assignments(text: &str) -> String {
    static ASSIGNMENT_LINE: std::sync::OnceLock<StdRegex> = std::sync::OnceLock::new();
    let pattern = ASSIGNMENT_LINE.get_or_init(|| {
        StdRegex::new(r#"(?m)^[ \t]*(?:export[ \t]+)?([A-Za-z0-9_.-]+)[ \t]*=(?:"[^"]*"|'[^']*'|`[^`]*`|[^\n]*)"#)
            .expect("static pattern")
    });
    redact_assignments(&pattern.replace_all(text, "${1}=[redacted]"))
}

/// The only text a search snippet may be cut from, so matching full content
/// never puts a value on stdout. Notes: the decoded body, every assignment
/// collapsed (`mask_assignments`) — a hit on a value shows `KEY=[redacted]`,
/// never the value. Other rows (the key-bearing items `--all` can surface):
/// the JSON body `note_body` already field-redacts.
fn snippet_source(row: &ItemRow) -> String {
    match prose_text(&row.1, &row.5) {
        Some(decoded) => mask_assignments(&decoded),
        None => redact_assignments(&note_body(row).body),
    }
}

/// One prefix resolver for notes and tags: exact uuid, then uuid prefix (when
/// the query looks like one), then unique title prefix. Ambiguity is an error
/// listing the first few matches; `kind` is singular ("note", "tag").
fn resolve_by_prefix<T: Clone>(
    items: &[T],
    query: &str,
    kind: &str,
    key: impl Fn(&T) -> (String, String),
) -> Result<T, UserError> {
    if let Some(exact) = items.iter().find(|item| key(item).0 == query) {
        return Ok(exact.clone());
    }
    let looks_like_uuid_prefix = query.len() >= 8 && query.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    if looks_like_uuid_prefix {
        let lowered = query.to_lowercase();
        let by_prefix: Vec<&T> = items.iter().filter(|item| key(item).0.to_lowercase().starts_with(&lowered)).collect();
        if by_prefix.len() == 1 {
            return Ok(by_prefix[0].clone());
        }
        if by_prefix.len() > 1 {
            return Err(ambiguous_items(&by_prefix, kind, &key));
        }
    }
    let prefix = query.to_lowercase();
    let by_title: Vec<&T> = items.iter().filter(|item| key(item).1.to_lowercase().starts_with(&prefix)).collect();
    if by_title.len() == 1 {
        return Ok(by_title[0].clone());
    }
    if by_title.len() > 1 {
        return Err(ambiguous_items(&by_title, kind, &key));
    }
    Err(UserError(format!("no {kind} matches {}", json_string(query))))
}

fn ambiguous_items<T: Clone>(matches: &[&T], kind: &str, key: &dyn Fn(&T) -> (String, String)) -> UserError {
    let sample = matches
        .iter()
        .take(8)
        .map(|item| {
            let (uuid, title) = key(item);
            format!("{}  {}", uuid.chars().take(8).collect::<String>(), title)
        })
        .collect::<Vec<_>>()
        .join("\n");
    UserError(format!(
        "that matches {} {kind}s; be more specific:\n{sample}",
        matches.len()
    ))
}

pub(crate) fn json_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serialization is infallible")
}

pub fn resolve_note(db: &CacheDb, query: &str, all: bool) -> Result<ItemRow, UserError> {
    // A full-uuid query is a primary-key lookup; only when the exact row is
    // absent or invisible does the prefix scan run — the same passes, and the
    // same ambiguity errors, as before.
    if let Some(row) = exact_visible_note(db, query, all)? {
        return Ok(row);
    }
    let mut statement = db
        .prepare("SELECT uuid, content_type, updated_at, deleted, title, content FROM items WHERE deleted = 0")
        .map_err(|error| UserError(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?, row.get::<_, Option<String>>(4)?, row.get::<_, String>(5)?))
        })
        .map_err(|error| UserError(error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| UserError(error.to_string()))?;
    let mut visible_types = vec!["Note"];
    if all {
        visible_types.extend(HIDDEN_TYPES);
    }
    let visible: Vec<ItemRow> = rows
        .into_iter()
        .filter(|row| visible_types.contains(&row.1.as_str()) && !is_trashed(&row.5))
        .collect();
    resolve_by_prefix(
        &visible,
        query,
        "note",
        |row: &ItemRow| (row.0.clone(), row.4.clone().unwrap_or_else(|| "(untitled)".into())),
    )
}

/// The exact-uuid pass of `resolve_by_prefix` as a point query. None when the
/// uuid is not in the cache, or when it is there but invisible to the current
/// selector (wrong type for `all`, trashed) — the scan then decides.
fn exact_visible_note(db: &CacheDb, query: &str, all: bool) -> Result<Option<ItemRow>, UserError> {
    use rusqlite::OptionalExtension as _;
    let mut statement = db
        .prepare("SELECT uuid, content_type, updated_at, deleted, title, content FROM items WHERE deleted = 0 AND uuid = ?1")
        .map_err(|error| UserError(error.to_string()))?;
    let row = statement
        .query_row([query], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?, row.get::<_, Option<String>>(4)?, row.get::<_, String>(5)?))
        })
        .optional()
        .map_err(|error| UserError(error.to_string()))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let mut visible_types = vec!["Note"];
    if all {
        visible_types.extend(HIDDEN_TYPES);
    }
    if visible_types.contains(&row.1.as_str()) && !is_trashed(&row.5) {
        Ok(Some(row))
    } else {
        Ok(None)
    }
}

/// Tag→note and tag→parent links live in the encrypted content's references
/// array.
fn content_references(content: &str) -> Vec<(String, String)> {
    let parsed: Value = match serde_json::from_str(content) {
        Ok(parsed) => parsed,
        Err(_) => return Vec::new(),
    };
    let mut refs = Vec::new();
    if let Some(array) = parsed.get("references").and_then(Value::as_array) {
        for entry in array {
            let uuid = entry.get("uuid").and_then(Value::as_str);
            let content_type = entry.get("content_type").and_then(Value::as_str);
            if let (Some(uuid), Some(content_type)) = (uuid, content_type) {
                refs.push((uuid.to_string(), content_type.to_string()));
            }
        }
    }
    refs
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedTag {
    pub uuid: String,
    pub title: String,
    pub parent: Option<String>,
    pub notes: usize,
}

#[derive(Debug, Default)]
pub struct TagLinks {
    pub title_of: HashMap<String, String>,
    pub parent_of: HashMap<String, Option<String>>,
    pub tag_to_notes: HashMap<String, HashSet<String>>,
}

/// The tag graph, resolved once per command: links plus inferred/explicit
/// parents.
pub struct TagGraph {
    pub links: TagLinks,
    pub parent_of: HashMap<String, Option<String>>,
}

/// Tag titles render and resolve everywhere, so whitespace is normalized
/// once here.
fn normalize_title(title: Option<&str>) -> String {
    let normalized = whitespace_collapse(title.unwrap_or_default());
    if normalized.trim().is_empty() {
        "(untitled)".to_string()
    } else {
        normalized.trim().to_string()
    }
}

/// `localeCompare` approximation: case-folded first, then code points. For
/// ASCII titles this matches the JS collation the TS implementation relies
/// on; non-ASCII ordering may differ from ICU.
pub fn locale_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let a_folded = a.to_lowercase();
    let b_folded = b.to_lowercase();
    a_folded.cmp(&b_folded).then_with(|| a.cmp(b))
}

/// Both link sides are unioned — the tag's references and the note's — since
/// the app keeps them in sync but either side can lag mid-update. References
/// are filtered to notes the cache can actually show (a hard-deleted note
/// leaves a deleted=1 tombstone that the tag's references still name).
/// Parents only count when the parent tag itself exists, so a dangling
/// parent renders top-level.
fn tag_links(db: &CacheDb) -> Result<TagLinks, DbError> {
    let mut statement = db.prepare(
        "SELECT uuid, title, content FROM items WHERE content_type = 'Tag' AND deleted = 0",
    )?;
    let tag_rows = statement
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?, row.get::<_, String>(2)?)))
        .map_err(db_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db_error)?;
    let mut links = TagLinks::default();
    for (uuid, title, _) in &tag_rows {
        links.title_of.insert(uuid.clone(), normalize_title(title.as_deref()));
        links.parent_of.insert(uuid.clone(), None);
        links.tag_to_notes.insert(uuid.clone(), HashSet::new());
    }
    for (uuid, _, content) in &tag_rows {
        for (ref_uuid, ref_type) in content_references(content) {
            if ref_type == "Note" {
                if let Some(set) = links.tag_to_notes.get_mut(uuid) {
                    set.insert(ref_uuid);
                }
            } else if ref_type == "Tag"
                && links.parent_of.contains_key(&ref_uuid)
                && &ref_uuid != uuid
                && let Some(slot) = links.parent_of.get_mut(uuid)
            {
                *slot = Some(ref_uuid);
            }
        }
    }
    let mut statement = db.prepare(
        "SELECT uuid, content FROM items WHERE content_type = 'Note' AND deleted = 0",
    )?;
    let note_rows = statement
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
        .map_err(db_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db_error)?;
    let mut live = HashSet::new();
    for (uuid, content) in &note_rows {
        if is_trashed(content) {
            continue;
        }
        live.insert(uuid.clone());
        for (ref_uuid, ref_type) in content_references(content) {
            if ref_type == "Tag"
                && let Some(set) = links.tag_to_notes.get_mut(&ref_uuid)
            {
                set.insert(uuid.clone());
            }
        }
    }
    // Tombstones: notes deleted on another device (deleted=1, content "{}")
    // are still named by the tag's own references — drop them or counts never
    // shrink.
    for set in links.tag_to_notes.values_mut() {
        set.retain(|uuid| live.contains(uuid));
    }
    Ok(links)
}

/// The full tag graph: query it once, pass it everywhere.
pub fn tag_graph(db: &CacheDb) -> Result<TagGraph, DbError> {
    let links = tag_links(db)?;
    let parent_of = resolve_parents(&links);
    Ok(TagGraph { links, parent_of })
}

/// Explicit parents (SN folders) win. Otherwise nesting is inferred from note
/// membership: a tag whose notes all also sit in another tag nests under the
/// smallest such tag (alphabetical tie-break). Equal sets fold onto the
/// alphabetically-first tag, which keeps the parent chain acyclic and makes a
/// note with overlapping tags render exactly once, under its deepest tag.
pub fn resolve_parents(links: &TagLinks) -> HashMap<String, Option<String>> {
    let tags: Vec<&String> = links.title_of.keys().collect();
    // TS's byTitle comparator: titles through titleOf, uuids as the tie-break.
    let by_title = |a: &String, b: &String| {
        let title_of = |uuid: &String| links.title_of.get(uuid).map(String::as_str).unwrap_or("");
        locale_cmp(title_of(a), title_of(b)).then_with(|| locale_cmp(a, b))
    };
    let empty: HashSet<String> = HashSet::new();
    let mut parent_of: HashMap<String, Option<String>> = HashMap::new();
    for tag in &tags {
        let explicit = links.parent_of.get(*tag).cloned().flatten();
        // check the INPUT map: parent_of (output) is half-built at this point,
        // so testing it here made explicit folders depend on SQLite row order
        if let Some(explicit) = explicit
            && links.parent_of.contains_key(&explicit)
        {
            parent_of.insert((*tag).clone(), Some(explicit));
            continue;
        }
        // borrowed, not cloned: the naive clone per (tag, other) pair made a
        // full graph build quadratic in tag count
        let mine = links.tag_to_notes.get(*tag).unwrap_or(&empty);
        if mine.is_empty() {
            // a noteless tag stays top-level rather than nesting under
            // everything that contains the empty set
            parent_of.insert((*tag).clone(), None);
            continue;
        }
        let mut best: Option<String> = None;
        for other in &tags {
            if *other == *tag {
                continue;
            }
            let theirs = links.tag_to_notes.get(*other).unwrap_or(&empty);
            if theirs.len() < mine.len() {
                continue;
            }
            let contains = mine.iter().all(|note| theirs.contains(note));
            if !contains {
                continue;
            }
            let strict = theirs.len() > mine.len();
            let folds = !strict && by_title(other, tag) == std::cmp::Ordering::Less;
            if !strict && !folds {
                continue;
            }
            let best_size = best.as_ref().map(|best| links.tag_to_notes.get(best).map(|set| set.len()).unwrap_or(0)).unwrap_or(usize::MAX);
            let should_replace = match &best {
                None => true,
                Some(best) => {
                    theirs.len() < best_size
                        || (theirs.len() == best_size && by_title(other, best) == std::cmp::Ordering::Less)
                }
            };
            if should_replace {
                best = Some((*other).clone());
            }
        }
        parent_of.insert((*tag).clone(), best);
    }
    parent_of
}

/// Depth per tag, cutting explicit-parent cycles at the first revisit.
fn tag_depths(parent_of: &HashMap<String, Option<String>>) -> HashMap<String, i64> {
    let mut depth_of: HashMap<String, i64> = HashMap::new();
    for tag in parent_of.keys().cloned().collect::<Vec<_>>() {
        depth(&mut depth_of, parent_of, &tag);
    }
    depth_of
}

fn depth(depth_of: &mut HashMap<String, i64>, parent_of: &HashMap<String, Option<String>>, tag: &str) -> i64 {
    if let Some(cached) = depth_of.get(tag) {
        return *cached;
    }
    depth_of.insert(tag.to_string(), 0);
    let parent = parent_of.get(tag).cloned().flatten();
    let result = match parent {
        Some(parent) if parent_of.contains_key(&parent) => depth(depth_of, parent_of, &parent) + 1,
        _ => 0,
    };
    depth_of.insert(tag.to_string(), result);
    result
}

/// The forest both tag renderers draw: cycle-cut depths, children lists, and
/// root detection. A tag is a root when it has no live parent (dangling links
/// included) or when its parent chain loops back through it — a parent cycle
/// renders as one chain hanging off each of its members. `cycle_root` says
/// which kind of root a tag is, so renderers can present cycles last.
pub struct TagForest {
    /// The map the forest was built from, owned so every method sees the
    /// same one (callers used to re-pass it at each call).
    pub parent_of: HashMap<String, Option<String>>,
    pub depth_of: HashMap<String, i64>,
    pub children_of: HashMap<String, Vec<String>>,
}

impl TagForest {
    pub fn is_root(&self, tag: &str) -> bool {
        let parent = match self.parent_of.get(tag) {
            Some(Some(parent)) => parent.clone(),
            _ => return true,
        };
        if !self.parent_of.contains_key(&parent) {
            return true;
        }
        let mut current = Some(parent);
        let mut seen = HashSet::new();
        while let Some(candidate) = current {
            if !self.parent_of.contains_key(&candidate) {
                break;
            }
            if candidate == tag {
                return true; // the parent chain loops through this tag
            }
            seen.insert(candidate.clone());
            current = self.parent_of.get(&candidate).cloned().flatten();
        }
        false
    }

    pub fn cycle_root(&self, tag: &str) -> bool {
        if !self.is_root(tag) {
            return false;
        }
        matches!(self.parent_of.get(tag), Some(Some(parent)) if self.parent_of.contains_key(parent))
    }
}

pub fn tag_forest(parent_of: &HashMap<String, Option<String>>) -> TagForest {
    let mut children_of: HashMap<String, Vec<String>> = HashMap::new();
    for (tag, parent) in parent_of {
        let Some(parent) = parent else { continue };
        if !parent_of.contains_key(parent) {
            continue;
        }
        children_of.entry(parent.clone()).or_default().push(tag.clone());
    }
    let depth_of = tag_depths(parent_of);
    TagForest { parent_of: parent_of.clone(), depth_of, children_of }
}

/// Read-only view of tags: title, resolved parent tag, and note count.
pub fn list_tags(db: &CacheDb) -> Result<Vec<ListedTag>, DbError> {
    Ok(tags_of(&tag_graph(db)?))
}

fn tags_of(graph: &TagGraph) -> Vec<ListedTag> {
    let mut tags: Vec<ListedTag> = graph
        .links
        .title_of
        .iter()
        .map(|(uuid, title)| ListedTag {
            uuid: uuid.clone(),
            title: title.clone(),
            parent: graph.parent_of.get(uuid).cloned().flatten(),
            notes: graph.links.tag_to_notes.get(uuid).map(|set| set.len()).unwrap_or(0),
        })
        .collect();
    tags.sort_by(|a, b| locale_cmp(&a.title, &b.title).then_with(|| locale_cmp(&a.uuid, &b.uuid)));
    tags
}

/// Note uuids under a tag or folder: the subtree's membership, so
/// `list --tag <folder>` finds notes that sit in its child tags.
pub fn tagged_note_uuids(graph: &TagGraph, tag_uuid: &str) -> HashSet<String> {
    let mut subtree: HashSet<String> = HashSet::from([tag_uuid.to_string()]);
    let mut grew = true;
    while grew {
        grew = false;
        for (tag, parent) in &graph.parent_of {
            if let Some(parent) = parent
                && subtree.contains(parent)
                && !subtree.contains(tag)
            {
                subtree.insert(tag.clone());
                grew = true;
            }
        }
    }
    let mut uuids = HashSet::new();
    for tag in &subtree {
        if let Some(notes) = graph.links.tag_to_notes.get(tag) {
            uuids.extend(notes.iter().cloned());
        }
    }
    uuids
}

pub fn resolve_tag(graph: &TagGraph, query: &str) -> Result<ListedTag, UserError> {
    let tags = tags_of(graph);
    resolve_by_prefix(&tags, query, "tag", |tag| (tag.uuid.clone(), tag.title.clone()))
}

pub struct NoteBody {
    pub title: String,
    pub body: String,
}

pub fn note_body(row: &ItemRow) -> NoteBody {
    let (content_type, content) = (&row.1, &row.5);
    let title = row.4.clone().unwrap_or_else(|| "(untitled)".into());
    let parsed: Value = match serde_json::from_str(content) {
        Ok(parsed) => parsed,
        Err(_) => return NoteBody { title, body: content.clone() },
    };
    if !parsed.is_object() {
        return NoteBody { title, body: content.clone() };
    }
    if HIDDEN_TYPES.contains(&content_type.as_str()) {
        let mut redacted = serde_json::Map::new();
        if let Some(object) = parsed.as_object() {
            for (key, value) in object {
                redacted.insert(
                    key.clone(),
                    if REDACTED_FIELDS.contains(&key.as_str()) { Value::String("[redacted]".into()) } else { value.clone() },
                );
            }
        }
        return NoteBody {
            title: if title == "(untitled)" { content_type.clone() } else { title },
            body: serde_json::to_string_pretty(&Value::Object(redacted)).expect("object serializes"),
        };
    }
    if let Some(text) = parsed.get("text").and_then(Value::as_str) {
        return NoteBody { title, body: text.to_string() };
    }
    NoteBody { title, body: serde_json::to_string_pretty(&parsed).expect("value serializes") }
}

/// Render a user-typed id inside a hint so it pastes back into a shell
/// unchanged.
pub fn shellish(text: &str) -> String {
    let shellish_safe = !text.is_empty()
        && text.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | ':' | '/' | '-'));
    if shellish_safe {
        text.to_string()
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

/// The palette the inventory draws with. The ANSI palette mirrors
/// picocolors' indexed gray (bright black) so the terminal's theme-aware
/// palette picks contrast; a pipe, a dumb terminal, or NO_COLOR gets the
/// plain palette and loses nothing but dimness.
pub trait InventoryColor {
    fn bold(&self, text: &str) -> String;
    fn gray(&self, text: &str) -> String;
    fn italic(&self, text: &str) -> String;
}

/// The no-op palette: monochrome, for tests and unstyled callers.
pub struct PlainInventoryColor;

impl InventoryColor for PlainInventoryColor {
    fn bold(&self, text: &str) -> String {
        text.to_string()
    }
    fn gray(&self, text: &str) -> String {
        text.to_string()
    }
    fn italic(&self, text: &str) -> String {
        text.to_string()
    }
}

/// picocolors-compatible ANSI palette (90/39 for gray, 3/23 italic, 1/22 bold).
pub struct AnsiInventoryColor;

impl InventoryColor for AnsiInventoryColor {
    fn bold(&self, text: &str) -> String {
        format!("\x1b[1m{text}\x1b[0m")
    }
    fn gray(&self, text: &str) -> String {
        format!("\x1b[90m{text}\x1b[0m")
    }
    fn italic(&self, text: &str) -> String {
        format!("\x1b[3m{text}\x1b[0m")
    }
}

/// Title with its ─ separator — the top of every show layout.
pub fn note_header(title: &str, color: &dyn InventoryColor) -> String {
    format!(
        "{}\n{}",
        color.bold(title),
        color.gray(&"─".repeat(title.chars().count().min(40)))
    )
}

/// The pasteable hint that names the two-argument copy form with a real key.
/// Plain text, like every other hint in the flow — only annotation dims.
fn copy_hint(query: &str, first_key: &str) -> String {
    format!("copy a value:  sns copy {} {}", shellish(query), first_key)
}

/// Drop CSI escape sequences from note-derived text the inventory wraps in
/// its own styling — a comment carrying codes could otherwise reset or
/// restyle our line. Also done before masking so it sees what the codes were
/// hiding.
fn strip_sgr(text: &str) -> String {
    static SGR: std::sync::OnceLock<StdRegex> = std::sync::OnceLock::new();
    let pattern = SGR.get_or_init(|| StdRegex::new(r"\x1b\[[0-9;:?]*[A-Za-z]").expect("static pattern"));
    pattern.replace_all(text, "").into_owned()
}

/// Mask `key=value` fragments in free text the inventory renders verbatim.
/// The parser rejects these lines (a commented-out `# OLD_KEY=…`, a mention
/// mid-sentence), so a value written that way would otherwise reach stdout —
/// the one thing this view promises never happens. Only display: parsing
/// itself is untouched.
pub fn redact_assignments(text: &str) -> String {
    static FRAGMENT: std::sync::OnceLock<StdRegex> = std::sync::OnceLock::new();
    let pattern = FRAGMENT.get_or_init(|| {
        StdRegex::new(r"(?m)(^|[ \t])([A-Za-z0-9_.-]+)[ \t]*=[ \t]*\S+").expect("static pattern")
    });
    pattern.replace_all(text, "${1}${2}=[redacted]").into_owned()
}

/// The `sns show` inventory for a note with settings: its title, the prose
/// the parser skipped, then the setting keys — each drawn as its note line
/// with the value withheld (`KEY=[redacted]`, or `KEY=  (empty)` when the
/// value is empty) plus the trailing `#` comment when the note has one.
/// Descriptive text reads first, and the actionable keys sit last, directly
/// above — on a terminal only — the hint naming the copy form with a real
/// key. Keys, prose, and the hint stay plain text; comments and value
/// markers dim via `color`, with the key names popping by contrast. Pure so
/// tests can pin the layout.
pub fn render_note_inventory(input: RenderInventoryInput<'_>) -> String {
    let lines_top = note_header(input.title, input.color);
    let prose = redact_assignments(input.prose);
    let prose = trim_trailing_newlines(&prose);
    let mut lines = vec![lines_top];
    if !prose.trim().is_empty() {
        lines.push(prose);
        lines.push(String::new());
    }
    for (key, value) in input.settings.iter() {
        let label = if value.is_empty() {
            format!("{key}=  {}", input.color.gray("(empty)"))
        } else {
            format!("{key}={}", input.color.gray("[redacted]"))
        };
        match input.comments.get(key) {
            None => lines.push(label),
            Some(comment) => lines.push(format!(
                "{label}  {}",
                input.color.italic(&input.color.gray(&strip_sgr(&redact_assignments(comment))))
            )),
        }
    }
    if input.terminal && !input.settings.is_empty() {
        let first_key = input.settings.keys().next().expect("settings non-empty");
        lines.push(String::new());
        lines.push(copy_hint(input.query, first_key));
    }
    lines.join("\n")
}

fn trim_trailing_newlines(text: &str) -> String {
    let trimmed_len = text
        .char_indices()
        .rev()
        .find(|(_, ch)| *ch != '\n')
        .map(|(byte, ch)| byte + ch.len_utf8())
        .unwrap_or(0);
    text[..trimmed_len].to_string()
}

pub struct RenderInventoryInput<'a> {
    pub title: &'a str,
    pub settings: &'a Settings,
    pub comments: &'a Settings,
    pub prose: &'a str,
    pub query: &'a str,
    pub terminal: bool,
    pub color: &'a dyn InventoryColor,
}

/// What `sns copy` should do for a resolved row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyPlan {
    Value { key: String, value: String },
    Body { body: String },
    Keys { keys: Vec<String> },
}

/// `sns copy <id> [key]`: an exact, case-sensitive key copies that parsed
/// value; no key on a settings note copies nothing (the caller lists the
/// keys); a note without settings still copies its body. A key that does not
/// exist — including a case mismatch — copies nothing and names the keys.
pub fn plan_copy(row: &ItemRow, key: Option<&str>) -> Result<CopyPlan, UserError> {
    let settings = note_settings(&row.1, &row.5);
    if settings.is_empty() {
        if key.is_some() {
            let title = row.4.clone().unwrap_or_else(|| "(untitled)".into());
            return Err(UserError(format!(
                "{} has no KEY=VALUE settings\nits whole body copies with: sns copy <id>",
                json_string(&title)
            )));
        }
        return Ok(CopyPlan::Body { body: note_body(row).body });
    }
    let Some(key) = key else {
        return Ok(CopyPlan::Keys { keys: settings.keys().cloned().collect() });
    };
    match settings.get(key) {
        Some(value) => Ok(CopyPlan::Value { key: key.to_string(), value: value.clone() }),
        None => {
            let title = row.4.clone().unwrap_or_else(|| "(untitled)".into());
            Err(UserError(format!(
                "no setting {} in {} (match is exact, case-sensitive)\nits keys: {}",
                json_string(key),
                json_string(&title),
                settings.keys().cloned().collect::<Vec<_>>().join(", ")
            )))
        }
    }
}

/// The `sns copy <id>` output on a settings note: the form, then the key names.
pub fn render_copy_keys(query: &str, keys: &[String]) -> String {
    let mut lines = vec![copy_hint(query, keys.first().expect("at least one key"))];
    lines.extend(keys.iter().map(|key| format!("  {key}")));
    lines.join("\n")
}

pub fn format_when(ms: i64) -> String {
    if ms == 0 {
        return String::new();
    }
    let timestamp = match jiff::Timestamp::from_millisecond(ms) {
        Ok(timestamp) => timestamp,
        Err(_) => return String::new(),
    };
    timestamp
        .to_zoned(jiff::tz::TimeZone::system())
        .strftime("%Y-%m-%d %H:%M")
        .to_string()
}

const UNTAGGED: &str = "(untagged)";

/// Hierarchical list. Tags render as a forest — explicit SN folders win,
/// otherwise containment is inferred (see `resolve_parents`) — and every
/// listed note is placed exactly once, under its deepest tag. Rows carry the
/// note's env-style setting count. Header counts come from the notes
/// argument (subtree totals), so limit, tag, and env filtering never show a
/// count for rows that are not listed. Tags with nothing under them are left
/// out (sns tags still shows them); untagged notes land in (untagged) last.
pub fn render_tag_groups(graph: &TagGraph, notes: &[ListedNote]) -> String {
    let links = &graph.links;
    let parent_of = &graph.parent_of;
    let forest = tag_forest(parent_of);
    let by_title = |a: &str, b: &str| locale_cmp(a, b);
    let mut children_of = forest.children_of.clone();
    for kids in children_of.values_mut() {
        kids.sort_by(|a, b| by_title(links.title_of.get(a).map(String::as_str).unwrap_or(""), links.title_of.get(b).map(String::as_str).unwrap_or("")));
    }

    // Each note's home is its deepest tag; ties go to the alphabetically first.
    let mut placed: HashMap<String, Vec<&ListedNote>> = HashMap::new();
    let mut untagged: Vec<&ListedNote> = Vec::new();
    for note in notes {
        let mut home: Option<&String> = None;
        for (tag, set) in &links.tag_to_notes {
            if !set.contains(&note.uuid) {
                continue;
            }
            let home_depth = home.map(|home| forest.depth_of.get(home).copied().unwrap_or(0)).unwrap_or(0);
            let tag_depth = forest.depth_of.get(tag).copied().unwrap_or(0);
            let better = match home {
                None => true,
                Some(_) if tag_depth > home_depth => true,
                Some(home) if tag_depth == home_depth && by_title(tag, home) == std::cmp::Ordering::Less => true,
                _ => false,
            };
            if better {
                home = Some(tag);
            }
        }
        match home {
            None => untagged.push(note),
            Some(home) => placed.entry(home.clone()).or_default().push(note),
        }
    }

    // Header counts are subtree totals over the listed notes only.
    let mut count_of: HashMap<String, usize> = HashMap::new();
    for tag in links.title_of.keys() {
        measure(&children_of, &placed, &mut count_of, tag);
    }

    let flatten = |text: &str| whitespace_collapse(text);
    let width_title = notes.iter().map(|note| flatten(&note.title).chars().count()).max().unwrap_or(0).max(5);
    let width_when = notes.iter().map(|note| format_when(note.updated_at).chars().count()).max().unwrap_or(0).max(16);
    let width_settings = notes.iter().map(|note| note.settings.to_string().len()).max().unwrap_or(0).max(1);
    let row_line = |note: &ListedNote, _depth: usize| {
        let fields = [
            pad_end(&flatten(&note.title), width_title),
            pad_end(&format_when(note.updated_at), width_when),
            format!("{:>width$}", note.settings, width = width_settings),
            note.uuid.clone(),
        ];
        let joined = fields.join("  ");
        joined.trim_end().to_string()
    };
    let indent = |depth: usize| "  ".repeat(depth);
    let row_indented = |note: &ListedNote, depth: usize| format!("{}{}", indent(depth + 1), row_line(note, depth));

    // A block is [header, rows…, child blocks…]; None when nothing shows
    // under it.
    struct BlockContext<'a> {
        links: &'a TagLinks,
        children_of: &'a HashMap<String, Vec<String>>,
        placed: &'a HashMap<String, Vec<&'a ListedNote>>,
        count_of: &'a HashMap<String, usize>,
    }

    let mut emitted: HashSet<String> = HashSet::new();
    fn block(
        tag: &str,
        depth: usize,
        context: &BlockContext<'_>,
        emitted: &mut HashSet<String>,
        row_indented: &dyn Fn(&ListedNote, usize) -> String,
    ) -> Option<Vec<String>> {
        let BlockContext { links, children_of, placed, count_of } = context;
        if emitted.contains(tag) {
            return None;
        }
        emitted.insert(tag.to_string());
        let mut rows: Vec<String> = placed
            .get(tag)
            .map(|notes| {
                let mut sorted: Vec<&&ListedNote> = notes.iter().collect();
                sorted.sort_by(|a, b| b.updated_at.cmp(&a.updated_at).then_with(|| locale_cmp(&a.uuid, &b.uuid)));
                sorted.into_iter().map(|note| row_indented(note, depth)).collect()
            })
            .unwrap_or_default();
        let mut kids: Vec<String> = Vec::new();
        if let Some(children) = children_of.get(tag) {
            for child in children {
                if let Some(child_block) = block(child, depth + 1, context, emitted, row_indented) {
                    kids.extend(child_block);
                }
            }
        }
        if rows.is_empty() && kids.is_empty() {
            return None;
        }
        let count = count_of.get(tag).copied().unwrap_or(0);
        let mut out = vec![format!("{}{} ({})", "  ".repeat(depth), links.title_of.get(tag).map(String::as_str).unwrap_or(tag), count)];
        out.append(&mut rows);
        out.append(&mut kids);
        Some(out)
    }

    let mut out: Vec<String> = Vec::new();
    let mut roots: Vec<&String> = links.title_of.keys().collect();
    roots.sort_by(|a, b| by_title(a, b));
    for tag in roots {
        if !forest.is_root(tag) {
            continue;
        }
        let context = BlockContext { links, children_of: &children_of, placed: &placed, count_of: &count_of };
        let Some(top) = block(tag, 0, &context, &mut emitted, &row_indented) else {
            continue;
        };
        if !out.is_empty() {
            out.push(String::new());
        }
        out.extend(top);
    }
    if !untagged.is_empty() {
        if !out.is_empty() {
            out.push(String::new());
        }
        out.push(format!("{UNTAGGED} ({})", untagged.len()));
        let mut sorted: Vec<&&ListedNote> = untagged.iter().collect();
        sorted.sort_by(|a, b| b.updated_at.cmp(&a.updated_at).then_with(|| locale_cmp(&a.uuid, &b.uuid)));
        for note in sorted {
            out.push(row_line(note, 0));
        }
    }
    out.join("\n")
}

fn measure(
    children_of: &HashMap<String, Vec<String>>,
    placed: &HashMap<String, Vec<&ListedNote>>,
    count_of: &mut HashMap<String, usize>,
    tag: &str,
) -> usize {
    let children = children_of.get(tag).map(Vec::as_slice).unwrap_or(&[]);
    let total = placed.get(tag).map(|rows| rows.len()).unwrap_or(0)
        + children.iter().map(|child| measure(children_of, placed, count_of, child)).sum::<usize>();
    count_of.insert(tag.to_string(), total);
    total
}

pub(crate) fn pad_end(text: &str, width: usize) -> String {
    let len = text.chars().count();
    if len >= width {
        text.to_string()
    } else {
        format!("{text}{}", " ".repeat(width - len))
    }
}
