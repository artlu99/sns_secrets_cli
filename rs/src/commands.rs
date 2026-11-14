//! The command layer, ported from `src/commands/*.ts`: login, logout, sync,
//! list, search, show, copy, tags, browse, and doctor. Interactive selects
//! are numbered prompts (no @clack); every user-facing summary string is
//! ported verbatim.

use std::collections::{HashMap, HashSet};
use std::io::{IsTerminal as _, Write as _};

use crate::clipboard::copy_to_clipboard;
use crate::db::{open_database, open_database_or_replace, remove_cache_files, CacheDb, ItemRow};
use crate::env::scrubbed_env_names;
use crate::errors::UserError;
use crate::http::ReqwestFetch;
use crate::keychain;
use crate::kdf::derive_root_key;
use crate::lock::acquire_sync_lock;
use crate::notes::{
    tag_forest,
    format_when, list_notes, note_body, note_scan, plan_copy, render_copy_keys,
    render_note_inventory, render_tag_groups, resolve_note, resolve_tag, search_notes, tag_graph,
    tagged_note_uuids, CopyPlan, ListOptions, ListedNote, ListedTag, PROSE_TYPES,
};
use crate::pager::{page_if_tall, PageOptions};
use crate::paths::{
    config_dir, db_path, ensure_config_dir, env_path, read_plain_config, session_path,
    unexpected_config_files, write_plain_config,
};
use crate::prompt::{prompt_line, prompt_secret};
use crate::session_file::{delete_session, load_session, save_session, session_key_names};
use crate::sn_api::{random_db_key, with_access, ApiClient, SessionSecrets};
use crate::sync_engine::{run_sync, SyncOptions, SyncReport};

// ---------------------------------------------------------------------------
// shared helpers

pub fn api_client(api_url: &str) -> Result<ApiClient, UserError> {
    let fetch = ReqwestFetch::new().map_err(UserError::from)?;
    Ok(ApiClient::new(api_url, Box::new(fetch)))
}

fn intro(message: &str) {
    if message.is_empty() {
        println!("sns");
    } else {
        println!("sns {message}");
    }
}

fn outro(message: &str) {
    println!("{message}");
}

fn numbered_select(message: &str, options: &[String]) -> Result<usize, UserError> {
    println!("{message}");
    for (index, option) in options.iter().enumerate() {
        println!("  {}) {option}", index + 1);
    }
    print!("choose 1-{}: ", options.len());
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        eprintln!("cancelled");
        std::process::exit(0);
    }
    let picked: Option<usize> = line
        .trim()
        .parse::<usize>()
        .ok()
        .filter(|number| (1..=options.len()).contains(number))
        .map(|number| number - 1);
    picked.ok_or_else(|| UserError("pick a number from the list".into()))
}

/// Open the decrypted cache, the way every reading command starts.
pub fn open_cache() -> Result<CacheDb, UserError> {
    let Some(secrets) = load_session()? else {
        return Err(UserError("not logged in — run sns login".into()));
    };
    if !db_path().exists() {
        return Err(UserError("no cache yet — run sns sync".into()));
    }
    open_database(&db_path(), &secrets.db_key).map_err(UserError::from)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// doctor

pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub skip: bool,
    pub detail: String,
}

fn check_line(check: &Check) -> String {
    let label = if check.skip {
        "SKIP"
    } else if check.ok {
        "ok  "
    } else {
        "FAIL"
    };
    format!("{label}  {:12} {}", check.name, check.detail)
}

pub fn doctor_checks() -> Vec<Check> {
    let mut checks = Vec::new();
    checks.push(Check {
        name: "runtime",
        ok: true,
        skip: false,
        detail: format!("sns {} (rust rewrite)", env!("CARGO_PKG_VERSION")),
    });

    let config_result: Result<(), String> = {
        ensure_config_dir();
        std::fs::read_to_string(env_path()).map(|_| ()).map_err(|error| error.to_string())
    };
    checks.push(match config_result {
        Ok(()) => Check {
            name: "config",
            ok: true,
            skip: false,
            detail: config_dir().display().to_string(),
        },
        Err(_) => Check {
            name: "config",
            ok: false,
            skip: false,
            detail: "config directory or .env is not readable".into(),
        },
    });

    let keychain = keychain::secret_service_available();
    if !keychain {
        checks.push(Check {
            name: "keychain",
            ok: true,
            skip: true,
            detail: "no secret service on this machine — the session key stays in .env.keys".into(),
        });
    } else if !session_path().exists() {
        checks.push(Check {
            name: "keychain",
            ok: true,
            skip: true,
            detail: "secret service is available; nothing stored yet".into(),
        });
    } else {
        checks.push(match keychain::keychain_get() {
            Some(_) => Check {
                name: "keychain",
                ok: true,
                skip: false,
                detail: "session key retrieved".into(),
            },
            None => Check {
                name: "keychain",
                ok: false,
                skip: false,
                detail: "session exists but the keychain has no session key".into(),
            },
        });
    }

    if !session_path().exists() {
        checks.push(Check {
            name: "session",
            ok: true,
            skip: true,
            detail: "not logged in".into(),
        });
    } else {
        let session_check: Result<String, String> = {
            let names = session_key_names();
            if let Some(unexpected) = crate::session_file::first_unexpected(&names) {
                Err(format!("unexpected session key {unexpected}"))
            } else {
                match load_session().map_err(|error| error.to_string()) {
                    Ok(Some(secrets)) => {
                        let _ = secrets;
                        Ok(format!(
                            "decrypts ({})",
                            names.iter().filter(|name| !name.starts_with("DOTENV_PUBLIC")).cloned().collect::<Vec<_>>().join(", ")
                        ))
                    }
                    Ok(None) => Err("session file has no fields".to_string()),
                    Err(error) => Err(error),
                }
            }
        };
        checks.push(match session_check {
            Ok(detail) => Check {
                name: "session",
                ok: true,
                skip: false,
                detail,
            },
            Err(message) => Check {
                name: "session",
                ok: false,
                skip: false,
                detail: message,
            },
        });
    }

    if !db_path().exists() {
        checks.push(Check {
            name: "cache",
            ok: true,
            skip: true,
            detail: "no cache.db yet".into(),
        });
    } else {
        let cache_check: Result<String, String> = match load_session().map_err(|error| error.to_string()) {
            Ok(Some(secrets)) => {
                let db = open_database(&db_path(), &secrets.db_key).map_err(|error| error.to_string());
                match db {
                    Ok(db) => {
                        let tables = db.sqlite_master_count().map_err(|error| error.to_string());
                        match tables {
                            Ok(tables) => {
                                db.close();
                                Ok(format!("opened ({tables} sqlite_master rows)"))
                            }
                            Err(error) => {
                                let _ = db;
                                Err(error)
                            }
                        }
                    }
                    Err(error) => Err(error),
                }
            }
            Ok(None) => Err("cache.db exists but there is no session key — the next sns login replaces it, or run sns logout --delete-cache".to_string()),
            Err(error) => Err(error),
        };
        checks.push(match cache_check {
            Ok(detail) => Check {
                name: "cache",
                ok: true,
                skip: false,
                detail,
            },
            Err(message) => Check {
                name: "cache",
                ok: false,
                skip: false,
                detail: message,
            },
        });
    }

    // Probe a real child process with sentinel secret variables under the
    // scrubbed map — the child must see neither.
    {
        let mut probe: HashMap<String, String> = std::env::vars().collect();
        probe.insert("SN_DB_KEY".into(), "scrub-sentinel".into());
        probe.insert("DOTENV_PRIVATE_KEY_SESSION".into(), "scrub-sentinel".into());
        let probe = crate::env::scrubbed_env_with(&probe);
        let child = std::process::Command::new("sh")
            .args(["-c", r#"printf %s "$SN_DB_KEY$DOTENV_PRIVATE_KEY_SESSION""#])
            .env_clear()
            .envs(probe)
            .output();
        checks.push(match child {
            Ok(output) if output.status.success() && output.stdout.is_empty() => Check {
                name: "scrub",
                ok: true,
                skip: false,
                detail: "child environment has no secret variables".into(),
            },
            Ok(output) => Check {
                name: "scrub",
                ok: false,
                skip: false,
                detail: format!(
                    "child probe exited {}{}",
                    output.status.code().unwrap_or(-1),
                    if output.stdout.is_empty() { "" } else { " and saw secret variables" }
                ),
            },
            Err(error) => Check {
                name: "scrub",
                ok: false,
                skip: false,
                detail: error.to_string(),
            },
        });
    }

    let password_var = "SN_PASSWORD";
    let launched = scrubbed_env_names();
    if launched.iter().any(|name| name == password_var) {
        checks.push(Check {
            name: "password",
            ok: false,
            skip: false,
            detail: format!("{password_var} was set at launch and was scrubbed — sns never reads a password from the environment"),
        });
    } else {
        checks.push(Check {
            name: "password",
            ok: true,
            skip: false,
            detail: format!("{password_var} was not in the launch environment"),
        });
    }
    checks.push(if launched.is_empty() {
        Check {
            name: "env",
            ok: true,
            skip: false,
            detail: "no secret-named variables at launch".into(),
        }
    } else {
        Check {
            name: "env",
            ok: false,
            skip: false,
            detail: format!("secret-named variables scrubbed at launch: {}", launched.join(", ")),
        }
    });

    if db_path().exists() {
        let header = std::fs::read(db_path())
            .map(|bytes| bytes[..16.min(bytes.len())].to_vec())
            .unwrap_or_default();
        let plaintext = header.starts_with(b"SQLite format 3");
        checks.push(if plaintext {
            Check {
                name: "at-rest",
                ok: false,
                skip: false,
                detail: "cache.db is a plaintext SQLite file".into(),
            }
        } else {
            Check {
                name: "at-rest",
                ok: true,
                skip: false,
                detail: "cache.db is not a plaintext SQLite file".into(),
            }
        });
    } else {
        checks.push(Check {
            name: "at-rest",
            ok: true,
            skip: true,
            detail: "no cache.db yet".into(),
        });
    }

    let extra = unexpected_config_files();
    checks.push(if extra.is_empty() {
        Check {
            name: "files",
            ok: true,
            skip: false,
            detail: "config dir has no unexpected files".into(),
        }
    } else {
        Check {
            name: "files",
            ok: false,
            skip: false,
            detail: format!("unexpected files: {}", extra.join(", ")),
        }
    });

    checks
}

pub fn doctor_command() -> i32 {
    let checks = doctor_checks();
    for check in &checks {
        println!("{}", check_line(check));
    }
    if checks.iter().any(|check| !check.ok && !check.skip) {
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// login / logout / sync

pub fn login_command() -> Result<(), UserError> {
    intro("login");
    let plain = read_plain_config();
    let mut email = plain.email.clone();
    if email.is_empty() {
        email = prompt_line("Email", None)?;
    }
    if !email.contains('@') {
        return Err(UserError("email looks wrong".into()));
    }
    write_plain_config(Some(&email), Some(&plain.api_url));

    let password = prompt_secret("Account password")?;
    let existing: Option<SessionSecrets> = if session_path().exists() {
        // `sns login` is the recovery path for a broken session — it must not
        // fail on the very state it exists to fix.
        match load_session() {
            Ok(secrets) => secrets,
            Err(error) => {
                eprintln!("the existing session is unreadable and will be replaced ({error})");
                None
            }
        }
    } else {
        None
    };
    if let Some(existing) = &existing
        && !existing.account_email.is_empty()
        && existing.account_email != email
    {
        return Err(UserError(format!(
            "this session belongs to {} — run sns logout before logging in as {email}",
            existing.account_email
        )));
    }
    let db_key = existing
        .as_ref()
        .map(|secrets| secrets.db_key.clone())
        .unwrap_or_else(random_db_key);
    let api = api_client(&plain.api_url)?;
    let (mut secrets, master_key) = api.login(
        &email,
        &password,
        &mut || prompt_secret("Two-factor code").map_err(|error| crate::sn_api::ApiClientError::User(error.to_string())),
        &db_key,
    )?;
    secrets.account_email = email.clone();
    let stored = save_session(&secrets)?;
    let synced = match pull_notes(&secrets, &api, &email, Some(master_key)) {
        Ok(synced) => synced,
        Err(error) => {
            return Err(UserError(format!(
                "session saved, but sync failed: {error}\nnext: sns sync"
            )));
        }
    };

    let where_line = if stored.keychain {
        "session saved. the session key is in the OS keychain"
    } else {
        "session saved. no secret service here — the session key is in .env.keys (mode 0600)"
    };
    outro(where_line);
    outro(&sync_summary(&synced.report, synced.replaced));
    Ok(())
}

pub fn logout_command(delete_cache: bool) -> Result<(), UserError> {
    intro("logout");
    let secrets: Option<SessionSecrets> = if session_path().exists() {
        // A broken session must not strand its secrets on disk: delete them
        // anyway.
        match load_session() {
            Ok(secrets) => secrets,
            Err(error) => {
                eprintln!("cannot read the session to revoke it server-side ({error})");
                None
            }
        }
    } else {
        return Err(UserError("not logged in".into()));
    };

    let plain = read_plain_config();
    let api = api_client(&plain.api_url)?;
    let mut revoked = false;
    if let Some(secrets) = &secrets {
        // Refresh first if needed, so logout works after the access token
        // expired — the common case, since access tokens are short-lived.
        let mut save = |next: &SessionSecrets| {
            save_session(next)
                .map(|_| ())
                .map_err(|error| crate::sn_api::ApiClientError::User(error.to_string()))
        };
        let mut run = |current: &SessionSecrets| api.logout(current);
        match with_access(secrets, &mut save, &api, now_ms().max(0) as u64, &mut run) {
            Ok(()) => revoked = true,
            Err(error) => eprintln!("server revoke failed ({error}); local secrets will still be deleted"),
        }
    }

    // Hold the sync lock: deleting cache.db under a running sync would send
    // its writes into a deleted inode while it reports success.
    let release = acquire_sync_lock(30_000)?;
    delete_session();
    if delete_cache {
        remove_cache_files(&db_path());
    }
    drop(release);

    let cache_note = if delete_cache {
        " The encrypted cache was removed with the database key."
    } else {
        " The encrypted cache stays; the next sync replaces it because its key is gone."
    };
    outro(&if revoked {
        format!("session revoked and local secrets deleted.{cache_note}")
    } else {
        format!("local secrets deleted; the server session may still be valid until it expires.{cache_note}")
    });
    Ok(())
}

pub struct PullOutcome {
    pub report: SyncReport,
    pub replaced: bool,
}

pub fn pull_notes(
    secrets: &SessionSecrets,
    api: &ApiClient,
    email: &str,
    master_key: Option<String>,
) -> Result<PullOutcome, UserError> {
    let release = acquire_sync_lock(30_000)?;
    let opened = open_database_or_replace(&db_path(), &secrets.db_key).map_err(UserError::from)?;
    println!("pulling notes");
    let outcome: Result<SyncReport, crate::sn_api::ApiClientError> = {
        let mut save = |next: &SessionSecrets| {
            save_session(next)
                .map(|_| ())
                .map_err(|error| crate::sn_api::ApiClientError::User(error.to_string()))
        };
        let email = email.to_string();
        let mut run = |current: &SessionSecrets| {
            let current = current.clone();
            let mut fetch_page = |sync_token: Option<&str>, cursor_token: Option<&str>| {
                api.sync_page(&current, sync_token, cursor_token)
            };
            let mut ensure_master_key = || {
                println!("item keys are not in the cache yet");
                let password = prompt_secret("Account password (used once to unwrap item keys)")
                    .map_err(|error| crate::sync_engine::SyncError::User(error.to_string()))?;
                let params = api
                    .key_params(&email, &mut || {
                        prompt_secret("Two-factor code").map_err(|error| crate::sn_api::ApiClientError::User(error.to_string()))
                    })
                    .map_err(crate::sync_engine::SyncError::Fetch)?;
                let root = derive_root_key(&password, &params)
                    .map_err(|error| crate::sync_engine::SyncError::User(error.to_string()))?;
                println!("pulling notes");
                Ok(root.master_key_hex())
            };
            run_sync(
                SyncOptions {
                    db: &opened.0,
                    master_key: master_key.clone(),
                    now_ms: now_ms(),
                },
                &mut fetch_page,
                &mut ensure_master_key,
            )
            .map_err(|error| match error {
                // keep the Api variant so with_access still sees 401/498
                crate::sync_engine::SyncError::Fetch(client_error) => client_error,
                other => crate::sn_api::ApiClientError::User(other.to_string()),
            })
        };
        with_access(secrets, &mut save, api, now_ms().max(0) as u64, &mut run)
    };
    let outcome = match outcome {
        Ok(report) => {
            println!("sync finished");
            report
        }
        Err(error) => {
            println!("sync failed");
            opened.0.close();
            drop(release);
            return Err(UserError::from(error));
        }
    };
    opened.0.close();
    drop(release);
    Ok(PullOutcome { report: outcome, replaced: opened.1 })
}

pub fn sync_summary(report: &SyncReport, replaced: bool) -> String {
    let cache = if replaced {
        "previous cache.db could not be opened with the current key and was removed\n"
    } else {
        ""
    };
    format!(
        "{cache}upserted {}, skipped {}, conflicts {}, pages {}\nnext: sns list",
        report.upserted, report.skipped, report.conflicts, report.pages
    )
}

pub fn sync_command() -> Result<(), UserError> {
    intro("sync");
    let Some(secrets) = load_session()? else {
        return Err(UserError("not logged in — run sns login".into()));
    };
    let plain = read_plain_config();
    if plain.email.is_empty() {
        return Err(UserError("SN_EMAIL is empty — run sns login".into()));
    }
    let api = api_client(&plain.api_url)?;
    let outcome = pull_notes(&secrets, &api, &plain.email, None)?;
    outro(&sync_summary(&outcome.report, outcome.replaced));
    Ok(())
}

// ---------------------------------------------------------------------------
// reading commands


pub fn list_command(kind: Option<&str>, tag: Option<&str>, limit: usize, all: bool) -> Result<(), UserError> {
    let db = open_cache()?;
    // one graph for resolution, filtering, and rendering
    let graph = tag_graph(&db).map_err(UserError::from)?;
    let resolved_tag = match tag {
        Some(tag) => Some(resolve_tag(&graph, tag)?),
        None => None,
    };
    let tag_uuids = resolved_tag.as_ref().map(|tag| tagged_note_uuids(&graph, &tag.uuid));
    // the default view is the secrets view: only notes whose prose carries
    // env-style settings; --all and explicit non-prose type selectors escape it
    let env = !all && (kind.is_none() || kind.is_some_and(|kind| PROSE_TYPES.contains(&kind)));
    let notes = list_notes(
        &db,
        ListOptions { kind, limit, all, tag_uuids: tag_uuids.as_ref(), env, regex: false },
    )?;
    if notes.is_empty() {
        let bare = tag.is_none() && kind.is_none();
        let where_clause = match (tag, kind) {
            (Some(tag), _) => format!("under tag {}", json_string(tag)),
            (None, Some(kind)) => format!("of type {kind}"),
            _ => "in the cache".to_string(),
        };
        let label = if env { "no notes with env-style settings" } else { "no notes" };
        let hint = if env {
            " — see everything with sns list --all"
        } else if bare {
            " — run sns sync"
        } else {
            ""
        };
        println!("{label} {where_clause}{hint}");
        return Ok(());
    }
    let table = render_tag_groups(&graph, &notes);
    // one terminal-only hint that <id> accepts a title or a uuid, prefix is
    // enough; omitted when piped so a script reading the table gets a table.
    // page_if_tall counts the hint lines, so a table that fits with its hint
    // still prints unpaged.
    let hint = if std::io::stdout().is_terminal() {
        "\n\na title or a uuid, a prefix is enough:  sns show <id>"
    } else {
        ""
    };
    page_if_tall(&format!("{table}{hint}"), &PageOptions { warn: true, no_pager: false })
}

pub fn search_command(query: &str, regex: bool, limit: usize, all: bool) -> Result<(), UserError> {
    if query.trim().is_empty() {
        return Err(UserError("search query is empty".into()));
    }
    let db = open_cache()?;
    let hits = search_notes(
        &db,
        query,
        ListOptions { regex, limit, all, tag_uuids: None, env: false, kind: None },
    )?;
    if hits.is_empty() {
        println!("no matches");
        return Ok(());
    }
    let lines: Vec<String> = hits
        .iter()
        .map(|hit| {
            format!(
                "{}  {}  {}\n  {}",
                hit.note.uuid,
                format_when(hit.note.updated_at),
                hit.note.title,
                hit.snippet
            )
        })
        .collect();
    println!("{}", lines.join("\n"));
    Ok(())
}

pub fn show_command(id: &str, no_pager: bool) -> Result<(), UserError> {
    let db = open_cache()?;
    let row = resolve_note(&db, id, false)?;
    let text = inventory_text(&row, id);
    page_if_tall(&text, &PageOptions { no_pager, warn: false })
}

/// The one rendering `sns` offers for a note: title, prose, keys — never a
/// value. There is no raw view: the full note belongs to Standard Notes' own
/// apps.
pub fn inventory_text(row: &ItemRow, query: &str) -> String {
    let body = note_body(row);
    let scan = note_scan(&row.1, &row.5);
    let terminal = std::io::stdout().is_terminal();
    let color: &dyn crate::notes::InventoryColor = if terminal {
        &crate::notes::AnsiInventoryColor
    } else {
        &crate::notes::PlainInventoryColor
    };
    render_note_inventory(crate::notes::RenderInventoryInput {
        title: &body.title,
        settings: &scan.settings,
        comments: &scan.comments,
        prose: &scan.prose,
        query,
        terminal,
        color,
    })
}

/// Execute a copy plan: on a settings note with no key, nothing leaves the
/// cache — the keys name the values and the two-argument form; a matched key
/// copies just that value; a note without settings still copies its body.
pub fn run_copy_plan(query: &str, plan: CopyPlan) -> Result<(), UserError> {
    match plan {
        CopyPlan::Keys { keys } => {
            println!("{}", render_copy_keys(query, &keys));
            Ok(())
        }
        CopyPlan::Value { key, value } => {
            println!("{}", copy_to_clipboard(&value, Some(&key))?);
            Ok(())
        }
        CopyPlan::Body { body } => {
            println!("{}", copy_to_clipboard(&body, None)?);
            Ok(())
        }
    }
}

pub fn copy_command(query: &str, key: Option<&str>) -> Result<(), UserError> {
    let db = open_cache()?;
    let row = resolve_note(&db, query, false)?;
    run_copy_plan(query, plan_copy(&row, key)?)
}

pub fn tags_command() -> Result<(), UserError> {
    let db = open_cache()?;
    let tags: Vec<ListedTag> = crate::notes::list_tags(&db).map_err(UserError::from)?;
    if tags.is_empty() {
        println!("no tags in the cache — run sns sync");
        return Ok(());
    }
    let tree = crate::commands::render_tag_tree(&tags);
    page_if_tall(&tree, &PageOptions { warn: true, no_pager: false })
}

pub fn browse_command() -> Result<(), UserError> {
    intro("");
    let db = open_cache()?;
    loop {
        let query = prompt_line("Filter", Some("title, or empty for recent"))?;
        let notes: Vec<ListedNote> = if query.is_empty() {
            list_notes(&db, ListOptions { limit: 20, ..Default::default() }).map_err(UserError::from)?
        } else {
            let hits = search_notes(
                &db,
                &query,
                ListOptions { limit: 20, kind: None, all: false, tag_uuids: None, env: false, regex: false },
            )?;
            hits.into_iter().map(|hit| hit.note).collect()
        };
        if notes.is_empty() {
            eprintln!("no matches");
            continue;
        }
        let mut options: Vec<String> = notes.iter().map(|note| note.title.clone()).collect();
        options.push("Quit".to_string());
        let picked = numbered_select("Note", &options)?;
        if picked == options.len() - 1 {
            break;
        }
        let selected = notes[picked].uuid.clone();
        let selected_title = notes[picked].title.clone();
        let actions = ["View".to_string(), "Copy".to_string(), "Back".to_string(), "Quit".to_string()];
        let action = numbered_select(&selected_title, &actions)?;
        match actions[action].as_str() {
            "quit" => break,
            "back" => continue,
            "view" => {
                let row = resolve_note(&db, &selected, false)?;
                // View draws the same masked inventory `sns show` does — there
                // is no full-text view here either; the note itself lives in
                // Standard Notes.
                page_if_tall(&inventory_text(&row, &selected_title), &PageOptions { no_pager: false, warn: false })?;
            }
            _ => {
                let row = resolve_note(&db, &selected, false)?;
                // the same plan as `sns copy`: on a settings note the picker
                // copies one chosen value, never the whole body
                match plan_copy(&row, None)? {
                    CopyPlan::Keys { keys } => {
                        let mut key_options = keys.clone();
                        key_options.push("Back".to_string());
                        let picked = numbered_select("Copy which key", &key_options)?;
                        if picked < keys.len() {
                            run_copy_plan(&selected_title, plan_copy(&row, Some(&keys[picked]))?)?;
                        }
                    }
                    plan => run_copy_plan(&selected_title, plan)?,
                }
            }
        }
    }
    outro("done");
    Ok(())
}





fn json_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serialization is infallible")
}


fn count_label(notes: usize) -> String {
    match notes {
        0 => "(empty)".to_string(),
        1 => "(1 note)".to_string(),
        notes => format!("({notes} notes)"),
    }
}

fn pad(text: &str, width: usize) -> String {
    let len = text.chars().count();
    if len >= width {
        text.to_string()
    } else {
        format!("{text}{}", " ".repeat(width - len))
    }
}

/// The `sns tags` view: parents, children, cycles — the same forest as
/// `sns list`, drawn as an aligned two-column tree.
pub fn render_tag_tree(tags: &[ListedTag]) -> String {
    let by_uuid: std::collections::HashMap<&str, &ListedTag> =
        tags.iter().map(|tag| (tag.uuid.as_str(), tag)).collect();
    let mut parent_of: HashMap<String, Option<String>> = HashMap::new();
    for tag in tags {
        let parent = tag
            .parent
            .as_ref()
            .filter(|parent| by_uuid.contains_key(parent.as_str()))
            .cloned();
        parent_of.insert(tag.uuid.clone(), parent);
    }
    let forest = tag_forest(&parent_of);
    let mut children_of = forest.children_of.clone();
    for kids in children_of.values_mut() {
        kids.sort_by(|a, b| {
            let title_of = |uuid: &str| {
                by_uuid
                    .get(uuid)
                    .map(|tag| tag.title.as_str())
                    .unwrap_or("")
            };
            crate::notes::locale_cmp(title_of(a), title_of(b))
                .then_with(|| crate::notes::locale_cmp(a, b))
        });
    }

    let mut rows: Vec<(String, String)> = Vec::new();
    let mut emitted: HashSet<String> = HashSet::new();
    fn emit(
        tag: &str,
        depth: usize,
        by_uuid: &std::collections::HashMap<&str, &ListedTag>,
        children_of: &HashMap<String, Vec<String>>,
        rows: &mut Vec<(String, String)>,
        emitted: &mut HashSet<String>,
    ) {
        // the guard cuts parent cycles: the second way around stops the walk
        if emitted.contains(tag) {
            return;
        }
        emitted.insert(tag.to_string());
        let entry = by_uuid.get(tag).expect("emitted tags exist in the map");
        rows.push((format!("{}{}", "  ".repeat(depth), entry.title), count_label(entry.notes)));
        for child in children_of.get(tag).cloned().unwrap_or_default() {
            emit(&child, depth + 1, by_uuid, children_of, rows, emitted);
        }
    }
    for tag in tags {
        if emitted.contains(&tag.uuid)
            || !forest.is_root(&parent_of, &tag.uuid)
            || forest.cycle_root(&parent_of, &tag.uuid)
        {
            continue;
        }
        emit(&tag.uuid, 0, &by_uuid, &children_of, &mut rows, &mut emitted);
    }
    for tag in tags {
        if emitted.contains(&tag.uuid) || !forest.cycle_root(&parent_of, &tag.uuid) {
            continue;
        }
        emit(&tag.uuid, 0, &by_uuid, &children_of, &mut rows, &mut emitted);
    }
    for tag in tags {
        if !emitted.contains(&tag.uuid) {
            rows.push((tag.title.clone(), count_label(tag.notes)));
        }
    }

    let width = rows.iter().map(|(label, _)| label.chars().count()).max().unwrap_or(0);
    rows
        .iter()
        .map(|(label, count)| format!("{}  {}", pad(label, width), count))
        .collect::<Vec<_>>()
        .join("\n")
}
