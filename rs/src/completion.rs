//! Port of `src/completion.ts` — bash/zsh scripts and argv completer for
//! `show`/`copy` note ids and `copy` setting keys. Candidates are only
//! offered when the resolver accepts them, and the shell scripts quote what
//! they insert — a note titled "staging api" completes to one shell word
//! that `sns show staging api` resolves.

use crate::db::{open_database, CacheDb};
use crate::errors::UserError;
use crate::notes::{note_settings, resolve_note, visible_note_rows};
use crate::paths::db_path;
use crate::session_file::load_session;

pub const COMPLETION_SHELLS: &[&str] = &["bash", "zsh"];

/// Keep in sync with the clap `Commands` enum in main.rs — a test there pins
/// the two together. `help` is clap's own.
pub const SUBCOMMANDS: &[&str] = &[
    "doctor",
    "login",
    "logout",
    "purge",
    "sync",
    "tags",
    "list",
    "search",
    "show",
    "copy",
    "sink",
    "completion",
    "help",
];

/// Upper bound on note candidates: shells get sluggish with huge match lists.
const MAX_CANDIDATES: usize = 100;

#[derive(Clone, Copy, PartialEq, Eq)]
enum StageKind {
    Subcommands,
    Shells,
    NoteIds,
    Keys,
    LogoutFlag,
    None,
}

struct Stage {
    kind: StageKind,
    partial: String,
    note_query: String,
}

/// Which completion stage the cursor is in. Argument slots count only
/// non-flag words, so `sns show --no-pager <TAB>` still fills the note slot;
/// a `-` word being typed gets no candidates (flag names are not offered).
fn stage_for(words: &[String], cword: usize) -> Stage {
    let index = cword.min(words.len());
    let partial = words.get(index).map(String::as_str).unwrap_or("").to_string();
    let args: Vec<&str> = words.iter().skip(1).map(String::as_str).collect();

    if index <= 1 {
        let head = if index == 1 {
            args.first().copied().unwrap_or("")
        } else {
            words.first().map(String::as_str).unwrap_or("")
        };
        return Stage {
            kind: StageKind::Subcommands,
            partial: head.to_string(),
            note_query: String::new(),
        };
    }
    if partial.starts_with('-') {
        return Stage {
            kind: StageKind::None,
            partial,
            note_query: String::new(),
        };
    }

    let mut slot = 0usize;
    let mut current: Option<usize> = None;
    for (offset, arg) in args.iter().enumerate().skip(1) {
        let is_current = offset == index - 1;
        if arg.starts_with('-') {
            if is_current {
                break;
            }
            continue;
        }
        if is_current {
            current = Some(slot);
            break;
        }
        slot += 1;
    }
    let current = match current {
        Some(found) => found,
        None if index > args.len() => slot, // completing a brand-new word
        None => {
            return Stage {
                kind: StageKind::None,
                partial,
                note_query: String::new(),
            }
        }
    };

    let command = args.first().copied().unwrap_or("");
    let kind = match (command, current) {
        ("completion", 0) => StageKind::Shells,
        ("show", 0) | ("copy", 0) | ("sink", 0) => StageKind::NoteIds,
        ("copy", 1) | ("sink", 1) => StageKind::Keys,
        ("logout", 0) => StageKind::LogoutFlag,
        _ => StageKind::None,
    };
    Stage {
        kind,
        partial,
        note_query: args.get(1).copied().unwrap_or("").to_string(),
    }
}

/// Pure completer — pass `Some(db)` for note/key candidates.
pub fn complete_argv(words: &[String], cword: usize, db: Option<&CacheDb>) -> Vec<String> {
    complete_stage(&stage_for(words, cword), db)
}

fn complete_stage(stage: &Stage, db: Option<&CacheDb>) -> Vec<String> {
    match stage.kind {
        StageKind::Subcommands => filter_prefix(SUBCOMMANDS, &stage.partial),
        StageKind::Shells => filter_prefix(COMPLETION_SHELLS, &stage.partial),
        StageKind::NoteIds => filter_prefix_loose(note_id_candidates(db), &stage.partial),
        StageKind::Keys => filter_prefix_owned(key_candidates(db, &stage.note_query), &stage.partial),
        StageKind::LogoutFlag => filter_prefix(&["--delete-cache"], &stage.partial),
        StageKind::None => Vec::new(),
    }
}

pub fn complete_with_cache(words: &[String], cword: usize) -> Vec<String> {
    let stage = stage_for(words, cword);
    // Constant stages answer without touching the session or the cache at all.
    let db = if matches!(stage.kind, StageKind::NoteIds | StageKind::Keys) {
        try_open_cache()
    } else {
        None
    };
    complete_stage(&stage, db.as_ref())
}

pub fn completion_script(shell: &str) -> Result<String, UserError> {
    match shell {
        "bash" => Ok(bash_script().into()),
        "zsh" => Ok(zsh_script().into()),
        other => Err(UserError(format!(
            "unknown shell {other:?} — use bash or zsh"
        ))),
    }
}

/// Candidates are printed one per line and rendered by readline/zle, so any
/// control character (C0, DEL, C1) would corrupt the line protocol or smuggle
/// terminal escapes into the completion display — every CSI/OSC sequence
/// needs ESC or the lone-C1 CSI introducer, both in this class. Such
/// titles/keys are simply not offered (the note's uuid prefix still is);
/// they are never rewritten, so an offered candidate always resolves exactly
/// as typed. (Port of the TS completion CONTROL_CHARS filter.)
fn has_control_chars(value: &str) -> bool {
    value.chars().any(|c| matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}'))
}

fn note_id_candidates(db: Option<&CacheDb>) -> Vec<String> {
    let Some(db) = db else {
        return Vec::new();
    };
    let rows = match visible_note_rows(db, &["Note"]) {
        Ok(rows) => rows,
        Err(_) => return Vec::new(),
    };
    let titles: Vec<String> = rows
        .iter()
        .map(|row| row.4.clone().unwrap_or_default().trim().to_lowercase())
        .collect();
    let uuids: Vec<String> = rows.iter().map(|row| row.0.to_lowercase()).collect();
    // Offer only candidates the resolver accepts — same trim/case rules as
    // resolve_by_prefix — so TAB never completes a word the command rejects
    // as ambiguous ("API Keys" when "API Keys Old" exists) or unmatchable.
    let resolves = |candidate: &str| -> bool {
        let probe = candidate.to_lowercase();
        let looks_like_uuid_prefix =
            candidate.len() >= 8 && candidate.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
        if looks_like_uuid_prefix {
            let by_uuid = uuids.iter().filter(|uuid| uuid.starts_with(&probe)).count();
            if by_uuid == 1 {
                return true;
            }
            if by_uuid > 1 {
                return false;
            }
        }
        titles.iter().filter(|title| title.starts_with(&probe)).count() == 1
    };

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for row in &rows {
        let title = row.4.clone().unwrap_or_default().trim().to_string();
        if !title.is_empty() && !has_control_chars(&title) && !seen.contains(&title) && resolves(&title) {
            seen.insert(title.clone());
            out.push(title);
        }
        let short: String = row.0.chars().take(8).collect();
        if !seen.contains(&short) && resolves(&short) {
            seen.insert(short.clone());
            out.push(short);
        }
        if out.len() >= MAX_CANDIDATES {
            break;
        }
    }
    out
}

fn key_candidates(db: Option<&CacheDb>, note_query: &str) -> Vec<String> {
    let Some(db) = db else {
        return Vec::new();
    };
    if note_query.is_empty() {
        return Vec::new();
    }
    let Ok(row) = resolve_note(db, note_query, false) else {
        return Vec::new();
    };
    note_settings(&row.1, &row.5)
        .keys()
        .filter(|key| !has_control_chars(key))
        .cloned()
        .collect()
}

fn filter_prefix(candidates: &[&str], partial: &str) -> Vec<String> {
    candidates
        .iter()
        .filter(|candidate| partial.is_empty() || candidate.starts_with(partial))
        .map(|candidate| (*candidate).to_string())
        .collect()
}

/// The resolver matches titles and uuid prefixes case-insensitively, so a
/// typed "sta" must still complete to "Staging". Setting keys stay
/// case-sensitive: plan_copy matches them exactly.
fn filter_prefix_loose(candidates: Vec<String>, partial: &str) -> Vec<String> {
    if partial.is_empty() {
        return candidates;
    }
    let needle = partial.to_lowercase();
    candidates
        .into_iter()
        .filter(|candidate| candidate.to_lowercase().starts_with(&needle))
        .collect()
}

fn filter_prefix_owned(candidates: Vec<String>, partial: &str) -> Vec<String> {
    candidates
        .into_iter()
        .filter(|candidate| partial.is_empty() || candidate.starts_with(partial))
        .collect()
}

fn try_open_cache() -> Option<CacheDb> {
    if !db_path().exists() {
        return None;
    }
    let secrets = load_session().ok()??;
    open_database(&db_path(), &secrets.db_key).ok()
}

fn bash_script() -> &'static str {
    r#"# sns bash completion — eval "$(sns completion bash)"
_sns() {
  local cword=${COMP_CWORD}
  local -a words=("${COMP_WORDS[@]}")
  local out line
  out=$(sns __complete --cword="$cword" -- "${words[@]}" 2>/dev/null) || return
  COMPREPLY=()
  # %q quotes each candidate, so a title with spaces or metacharacters is
  # inserted as one shell word.
  while IFS= read -r line; do
    [[ -n "$line" ]] && COMPREPLY+=("$(printf '%q' "$line")")
  done <<<"$out"
}
complete -o nospace -F _sns sns
"#
}

fn zsh_script() -> &'static str {
    r#"# sns zsh completion — eval "$(sns completion zsh)"
_sns() {
  local -a out
  local cword=$((CURRENT - 1))
  out=("${(@f)$(sns __complete --cword="$cword" -- "${words[@]}" 2>/dev/null)}")
  # No -Q: compadd must quote metacharacters on insertion, so a title with
  # spaces or parens lands as one escaped word.
  compadd -- "${out[@]}"
}
# compdef is defined by compinit; load that first so the eval works anywhere
# in .zshrc.
if ! (( $+functions[compdef] )); then
  autoload -Uz compinit && compinit
fi
compdef _sns sns
"#
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_database, remove_cache_files, ItemRow};

    fn words(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_string()).collect()
    }

    struct TempDb(CacheDb, std::path::PathBuf);

    fn seeded_db(tag: &str) -> TempDb {
        let path = std::env::temp_dir().join(format!("sns-complete-{tag}-{}.db", std::process::id()));
        remove_cache_files(&path);
        let db = open_database(&path, &"ab".repeat(32)).expect("opens");
        let rows: [ItemRow; 2] = [
            (
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
                "Note".into(),
                2,
                0,
                Some("Staging".into()),
                serde_json::json!({
                    "title": "Staging",
                    "text": "deploy notes\nAPI_KEY=secret\nDB_HOST=db.example\n"
                })
                .to_string(),
            ),
            (
                "11111111-2222-3333-4444-555555555555".into(),
                "Note".into(),
                1,
                0,
                Some("Personal".into()),
                serde_json::json!({ "title": "Personal", "text": "just prose" }).to_string(),
            ),
        ];
        db.upsert_items(&rows).expect("seed");
        TempDb(db, path)
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            remove_cache_files(&self.1);
        }
    }

    #[test]
    fn subcommand_completion_filters_by_prefix() {
        assert_eq!(complete_argv(&words(&["sns", "sh"]), 1, None), vec!["show"]);
        let all = complete_argv(&words(&["sns"]), 1, None);
        assert!(all.iter().any(|s| s == "copy"));
        assert!(all.iter().any(|s| s == "completion"));
    }

    #[test]
    fn completion_shell_argument_lists_bash_and_zsh() {
        assert_eq!(
            complete_argv(&words(&["sns", "completion", ""]), 2, None),
            vec!["bash", "zsh"]
        );
        assert_eq!(
            complete_argv(&words(&["sns", "completion", "z"]), 2, None),
            vec!["zsh"]
        );
    }

    #[test]
    fn show_and_copy_complete_note_titles_and_short_uuids() {
        let temp = seeded_db("ids");
        let show = complete_argv(&words(&["sns", "show", ""]), 2, Some(&temp.0));
        assert!(show.iter().any(|s| s == "Staging"));
        assert!(show.iter().any(|s| s == "Personal"));
        assert!(show.iter().any(|s| s == "aaaaaaaa"));
        assert!(show.iter().any(|s| s == "11111111"));
        assert_eq!(
            complete_argv(&words(&["sns", "copy", "Sta"]), 2, Some(&temp.0)),
            vec!["Staging"]
        );
    }

    #[test]
    fn copy_second_argument_completes_setting_keys() {
        let temp = seeded_db("keys");
        assert_eq!(
            complete_argv(&words(&["sns", "copy", "Staging", ""]), 3, Some(&temp.0)),
            vec!["API_KEY", "DB_HOST"]
        );
        assert_eq!(
            complete_argv(&words(&["sns", "copy", "Staging", "DB"]), 3, Some(&temp.0)),
            vec!["DB_HOST"]
        );
        assert!(complete_argv(&words(&["sns", "copy", "nope", ""]), 3, Some(&temp.0)).is_empty());
    }

    #[test]
    fn note_completion_is_case_insensitive_like_the_resolver() {
        let temp = seeded_db("case");
        assert_eq!(
            complete_argv(&words(&["sns", "copy", "sta"]), 2, Some(&temp.0)),
            vec!["Staging"]
        );
    }

    #[test]
    fn control_character_titles_are_never_offered_uuids_still_are() {
        let path = std::env::temp_dir().join(format!("sns-complete-controls-{}.db", std::process::id()));
        remove_cache_files(&path);
        let db = open_database(&path, &"ab".repeat(32)).expect("opens");
        let esc_title = "\u{1b}[31mesc\u{1b}[0m";
        db.upsert_items(&[
            (
                "99999999-8888-7777-6666-555555555555".into(),
                "Note".into(),
                3,
                0,
                Some(esc_title.into()),
                serde_json::json!({ "title": esc_title, "text": "prose" }).to_string(),
            ),
            (
                "cccccccc-dddd-eeee-ffff-000000000000".into(),
                "Note".into(),
                4,
                0,
                Some("multi\nline".into()),
                serde_json::json!({ "title": "multi\nline", "text": "prose" }).to_string(),
            ),
        ])
        .expect("seed");
        let temp = TempDb(db, path);

        let candidates = complete_argv(&words(&["sns", "show", ""]), 2, Some(&temp.0));
        for candidate in &candidates {
            assert!(
                !candidate.chars().any(|c| matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}')),
                "control bytes in candidate {candidate:?}"
            );
        }
        assert!(!candidates.contains(&esc_title.to_string()));
        assert!(!candidates.contains(&"multi".to_string()));
        // the poisoned notes stay reachable by their uuid prefix
        assert!(candidates.iter().any(|s| s == "99999999"));
        assert!(candidates.iter().any(|s| s == "cccccccc"));
    }

    #[test]
    fn a_title_that_is_another_titles_prefix_is_never_offered() {
        let temp = seeded_db("prefixes");
        let extra: [ItemRow; 2] = [
            (
                "99999999-8888-7777-6666-555555555555".into(),
                "Note".into(),
                3,
                0,
                Some("API Keys".into()),
                serde_json::json!({ "title": "API Keys", "text": "prose" }).to_string(),
            ),
            (
                "44444444-3333-2222-1111-000000000000".into(),
                "Note".into(),
                4,
                0,
                Some("API Keys Old".into()),
                serde_json::json!({ "title": "API Keys Old", "text": "prose" }).to_string(),
            ),
        ];
        temp.0.upsert_items(&extra).expect("seed");
        let candidates = complete_argv(&words(&["sns", "show", ""]), 2, Some(&temp.0));
        assert!(candidates.iter().any(|s| s == "API Keys Old"), "{candidates:?}");
        assert!(!candidates.iter().any(|s| s == "API Keys"), "{candidates:?}");
    }

    #[test]
    fn flags_do_not_shift_the_note_arguments_position() {
        let temp = seeded_db("flags");
        assert_eq!(
            complete_argv(&words(&["sns", "show", "--no-pager", "Sta"]), 3, Some(&temp.0)),
            vec!["Staging"]
        );
        assert!(complete_argv(&words(&["sns", "show", "--no-pager", ""]), 3, Some(&temp.0))
            .iter()
            .any(|s| s == "Staging"));
        assert!(complete_argv(&words(&["sns", "show", "--"]), 2, Some(&temp.0)).is_empty());
    }

    #[test]
    fn completion_scripts_mention_complete_hook() {
        let bash = completion_script("bash").unwrap();
        assert!(bash.contains("sns __complete"));
        assert!(bash.contains("complete -o nospace -F _sns sns"));
        assert!(bash.contains("printf '%q'"));
        let zsh = completion_script("zsh").unwrap();
        assert!(zsh.contains("sns __complete"));
        assert!(zsh.contains("compdef _sns sns"));
        assert!(!zsh.contains("compadd -Q"));
    }
}
