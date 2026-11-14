//! Port of `src/note-env.ts` — parse `KEY=VALUE` settings out of the prose of
//! a note.
//!
//! An assignment is recognized only at the start of a line (leading spaces
//! and tabs allowed): `=` is the only separator, with optional spaces/tabs
//! around it. Keys match `[A-Za-z0-9_.-]+` and are kept verbatim —
//! case-sensitive, so `Token` and `TOKEN` are distinct entries. Exact
//! duplicates: last occurrence wins, first-seen order. Nothing is ever
//! expanded (`$HOME`, `${FOO}` stay literal) and non-assignment lines are
//! skipped without complaint.
//!
//! Values run to end of line unless quoted. All three quote styles span
//! lines with real line breaks preserved; only double quotes process the
//! `\n` escape into a newline, and no backslash sequence protects a closing
//! quote. In an unquoted value a whitespace-preceded `#` starts a comment; a
//! bare `#` is literal. After a closing quote a `#` tail is a comment too;
//! anything else there is ignored. An unclosed quote discards the assignment
//! and parsing resumes on the next line.
//!
//! `scan_note` runs the same walk and additionally returns each assignment's
//! trailing comment (comments never enter values, so they never reach the
//! clipboard) and the skipped lines as the note's prose, for views that show
//! keys without values.

use indexmap::IndexMap;

/// Result entries are keyed by first appearance, with last assignment winning.
pub type Settings = IndexMap<String, String>;

pub fn parse_note_settings(text: &str) -> Settings {
    scan_note(text, false).settings
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteScan {
    /// Parsed settings, keyed by first appearance, last assignment winning.
    pub settings: Settings,
    /// Trailing `# …` comments, keyed like the settings and stripped from
    /// every value. Present only when the winning assignment carried one: a
    /// duplicate key whose last occurrence has no comment keeps no stale
    /// comment.
    pub comments: Settings,
    /// The lines the parser skipped, verbatim and in order — the note's
    /// prose. Continuation lines of a multi-line quoted value are part of
    /// that value and never appear here, and neither does a line whose
    /// assignment never closed its quote (a half-written secret stays out of
    /// the description).
    pub prose: String,
}

/// One walk that yields the keys, their comments, and — unless `with_prose`
/// is false — the skipped lines, so the key inventory can never disagree
/// with the copy lookup.
pub fn scan_note(text: &str, with_prose: bool) -> NoteScan {
    let bytes = text.as_bytes();
    let mut settings = Settings::new();
    let mut comments = Settings::new();
    let mut prose = if with_prose { Some(String::new()) } else { None };
    let mut i = 0usize;
    while i < bytes.len() {
        // On success try_assignment returns the start of the next line; when
        // the line is prose or its quote never closes it returns None, and
        // resuming at the next line is the permissive fallback either way.
        if let Some(next) = try_assignment(text, i, &mut settings, &mut comments) {
            i = next;
            continue;
        }
        let line_end = line_end_after(bytes, i);
        // try_assignment returned None on a line that does start an
        // assignment only when its quote never closed — that line is not
        // prose either.
        if let Some(prose_buffer) = prose.as_mut()
            && !assignment_starts_at(bytes, i)
        {
            prose_buffer.push_str(&text[i..line_end]);
        }
        i = line_end;
    }
    NoteScan { settings, comments, prose: prose.unwrap_or_default() }
}

/// Whether a line begins `key =` (blanks, optional export, key charset).
fn assignment_starts_at(bytes: &[u8], start: usize) -> bool {
    let mut i = start;
    while is_blank(byte_at(bytes, i)) {
        i += 1;
    }
    if is_export_token(bytes, i) {
        i += "export".len();
    }
    while is_blank(byte_at(bytes, i)) {
        i += 1;
    }
    let key_start = i;
    while is_key_char(byte_at(bytes, i)) {
        i += 1;
    }
    if i == key_start {
        return false;
    }
    while is_blank(byte_at(bytes, i)) {
        i += 1;
    }
    byte_at(bytes, i) == Some(b'=')
}

/// Spaces and tabs only — a newline ends the key and `=` must be on the same
/// line.
fn is_blank(byte: Option<u8>) -> bool {
    byte == Some(b' ') || byte == Some(b'\t')
}

/// `export` as a whole token followed by whitespace; `exports = 5` still keys
/// on `exports`.
fn is_export_token(bytes: &[u8], i: usize) -> bool {
    bytes[i..].starts_with(b"export") && is_blank(bytes.get(i + "export".len()).copied())
}

fn is_key_char(byte: Option<u8>) -> bool {
    byte.is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn byte_at(bytes: &[u8], i: usize) -> Option<u8> {
    bytes.get(i).copied()
}

/// Parse one assignment starting at a line boundary. On success returns the
/// start of the next line (the rest of the assignment's last line is
/// ignored). Returns None when the line is prose or the quote is unclosed.
fn try_assignment(
    text: &str,
    start: usize,
    settings: &mut Settings,
    comments: &mut Settings,
) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut i = start;
    while is_blank(byte_at(bytes, i)) {
        i += 1;
    }
    if is_export_token(bytes, i) {
        i += "export".len();
    }
    while is_blank(byte_at(bytes, i)) {
        i += 1;
    }
    let key_start = i;
    while is_key_char(byte_at(bytes, i)) {
        i += 1;
    }
    if i == key_start {
        return None;
    }
    let key = text[key_start..i].to_string();
    while is_blank(byte_at(bytes, i)) {
        i += 1;
    }
    if byte_at(bytes, i) != Some(b'=') {
        return None;
    }
    i += 1;
    while is_blank(byte_at(bytes, i)) {
        i += 1;
    }
    let quote = byte_at(bytes, i);
    let parsed = match quote {
        Some(quote @ (b'"' | b'\'' | b'`')) => read_quoted(text, i, quote)?,
        _ => read_unquoted(text, i),
    };
    settings.insert(key.clone(), parsed.value);
    // the winning assignment's comment (or absence of one) wins with it
    match parsed.comment {
        None => {
            comments.shift_remove(&key);
        }
        Some(comment) => {
            comments.insert(key, comment);
        }
    }
    Some(line_end_after(bytes, parsed.end))
}

/// Index past the next newline (or end of text), so scanning resumes at a
/// line boundary.
fn line_end_after(bytes: &[u8], i: usize) -> usize {
    match bytes[i..].iter().position(|byte| *byte == b'\n') {
        Some(offset) => i + offset + 1,
        None => bytes.len(),
    }
}

struct Assignment {
    value: String,
    comment: Option<String>,
    end: usize,
}

/// The leftmost whitespace-preceded (or line-starting) `#` — JS's `(^|\s)#`
/// on a line without newlines — as an index into the line.
fn comment_match_index(line: &str) -> Option<usize> {
    let mut previous_was_whitespace = true; // the `^` alternative
    for (index, ch) in line.char_indices() {
        if ch == '#' && previous_was_whitespace {
            return Some(index);
        }
        previous_was_whitespace = ch.is_whitespace();
    }
    None
}

/// The `# …` tail of a line, trimmed; None when the line carries no comment.
fn comment_on(line: &str) -> Option<String> {
    comment_match_index(line).map(|index| line[index..].trim().to_string())
}

/// Unquoted value: rest of the line, comment-truncated, whitespace-trimmed.
fn read_unquoted(text: &str, start: usize) -> Assignment {
    let bytes = text.as_bytes();
    let end = line_end_at(bytes, start);
    let line = &text[start..end];
    let value_end = comment_match_index(line).unwrap_or(line.len());
    Assignment {
        value: line[..value_end].trim().to_string(),
        comment: comment_on(line),
        end,
    }
}

fn line_end_at(bytes: &[u8], start: usize) -> usize {
    match bytes[start..].iter().position(|byte| *byte == b'\n') {
        Some(offset) => start + offset,
        None => bytes.len(),
    }
}

/// Quoted value: real line breaks preserved; `\n` unescaped in double quotes
/// only; the first matching quote closes (no backslash protects it). Returns
/// None when the quote never closes before the end of the text. A `#` tail on
/// the same line after the closing quote is the assignment's comment.
fn read_quoted(text: &str, start: usize, quote: u8) -> Option<Assignment> {
    let bytes = text.as_bytes();
    let close = bytes[start + 1..]
        .iter()
        .position(|byte| *byte == quote)
        .map(|offset| start + 1 + offset)?;
    let raw = &text[start + 1..close];
    let value = if quote == b'"' { raw.replace("\\n", "\n") } else { raw.to_string() };
    let tail_end = line_end_at(bytes, close + 1);
    let tail = &text[close + 1..tail_end];
    Some(Assignment { value, comment: comment_on(tail), end: close + 1 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use indexmap::indexmap;

    fn settings_of(note: &str) -> Vec<(String, String)> {
        parse_note_settings(note).into_iter().collect()
    }

    #[test]
    fn extracts_settings_and_ignores_the_prose_around_them() {
        let note = [
            "Notes on my API setup.",
            "",
            "DB_HOST=localhost",
            "The retry policy lives in docs/retry.md.",
            "API_KEY=abc123",
            "Ask Alice about rate limits.",
        ]
        .join("\n");
        assert_eq!(
            settings_of(&note),
            vec![("DB_HOST".into(), "localhost".into()), ("API_KEY".into(), "abc123".into())]
        );
    }

    #[test]
    fn keys_are_case_sensitive_and_kept_verbatim() {
        let settings = parse_note_settings("Token=a\nTOKEN=b");
        assert_eq!(settings.keys().collect::<Vec<_>>(), vec!["Token", "TOKEN"]);
        assert_eq!(settings.get("Token").map(String::as_str), Some("a"));
        assert_eq!(settings.get("TOKEN").map(String::as_str), Some("b"));
    }

    #[test]
    fn key_charset_is_letters_digits_underscore_dot_dash() {
        let settings = parse_note_settings("A_1=x\nkey-with-dashes=y\ndotted.key=z");
        assert_eq!(settings.get("A_1").map(String::as_str), Some("x"));
        assert_eq!(settings.get("key-with-dashes").map(String::as_str), Some("y"));
        assert_eq!(settings.get("dotted.key").map(String::as_str), Some("z"));
    }

    #[test]
    fn no_variable_expansion() {
        let settings = parse_note_settings("FOO=$HOME\nBAR=${FOO}\nPRICE=$19.99");
        assert_eq!(settings.get("FOO").map(String::as_str), Some("$HOME"));
        assert_eq!(settings.get("BAR").map(String::as_str), Some("${FOO}"));
        assert_eq!(settings.get("PRICE").map(String::as_str), Some("$19.99"));
    }

    #[test]
    fn all_three_quote_styles_keep_real_line_breaks() {
        let settings = parse_note_settings("D=\"first\nsecond\"");
        assert_eq!(settings.get("D").map(String::as_str), Some("first\nsecond"));
        let settings = parse_note_settings("S='keep \\n literal\nsecond'");
        assert_eq!(settings.get("S").map(String::as_str), Some("keep \\n literal\nsecond"));
        let settings = parse_note_settings("B=`raw\ntext`");
        assert_eq!(settings.get("B").map(String::as_str), Some("raw\ntext"));
    }

    #[test]
    fn backslash_n_escapes_become_newlines_only_inside_double_quotes() {
        let settings = parse_note_settings("A=\"l1\\nl2\"");
        assert_eq!(settings.get("A").map(String::as_str), Some("l1\nl2"));
        let settings = parse_note_settings("A='l1\\nl2'");
        assert_eq!(settings.get("A").map(String::as_str), Some("l1\\nl2"));
        let settings = parse_note_settings("A=`l1\\nl2`");
        assert_eq!(settings.get("A").map(String::as_str), Some("l1\\nl2"));
    }

    #[test]
    fn anything_after_a_closing_quote_on_the_same_line_is_ignored() {
        let settings = parse_note_settings("A=\"x\" B=y");
        assert_eq!(settings.keys().collect::<Vec<_>>(), vec!["A"]);
        assert_eq!(settings.get("A").map(String::as_str), Some("x"));
    }

    #[test]
    fn comment_rules_for_unquoted_and_quoted_values() {
        let settings = parse_note_settings("plain=value  # note");
        assert_eq!(settings.get("plain").map(String::as_str), Some("value"));
        let settings = parse_note_settings("plain=# note");
        assert_eq!(settings.get("plain").map(String::as_str), Some(""));
        let settings = parse_note_settings("plain=v#1");
        assert_eq!(settings.get("plain").map(String::as_str), Some("v#1"));
        let settings = parse_note_settings("plain=\"a # b\"");
        assert_eq!(settings.get("plain").map(String::as_str), Some("a # b"));
        let settings = parse_note_settings("plain=\"a\" # note");
        assert_eq!(settings.get("plain").map(String::as_str), Some("a"));
    }

    #[test]
    fn scan_keeps_each_assignments_comment_keyed_like_the_settings() {
        let scan = scan_note(
            "user=pass  # shared account\nplain=# starts with hash\nTOKEN=\"a # b\"  # rotated\nquiet=\"x\" B=y\n",
            false,
        );
        assert_eq!(scan.comments.get("user").map(String::as_str), Some("# shared account"));
        assert_eq!(scan.comments.get("plain").map(String::as_str), Some("# starts with hash"));
        assert_eq!(scan.comments.get("TOKEN").map(String::as_str), Some("# rotated"));
        // after a closing quote, a non-# tail is not a comment
        assert!(!scan.comments.contains_key("quiet"));
        // and the comment text never lands in a value
        assert_eq!(scan.settings.get("user").map(String::as_str), Some("pass"));
    }

    #[test]
    fn a_duplicate_keys_last_occurrence_decides_the_comment_too() {
        let scan = scan_note("A=1 # first\nA=2\nB=1\nB=2 # second\n", false);
        assert_eq!(scan.settings.get("A").map(String::as_str), Some("2"));
        assert!(!scan.comments.contains_key("A"));
        assert_eq!(scan.settings.get("B").map(String::as_str), Some("2"));
        assert_eq!(scan.comments.get("B").map(String::as_str), Some("# second"));
    }

    #[test]
    fn exact_duplicates_last_wins_first_seen_order() {
        let settings = parse_note_settings("A=1\nB=2\nA=3");
        assert_eq!(settings.keys().collect::<Vec<_>>(), vec!["A", "B"]);
        assert_eq!(settings.get("A").map(String::as_str), Some("3"));
    }

    #[test]
    fn an_unclosed_quote_ignores_that_assignment_and_parsing_continues() {
        let settings = parse_note_settings("A=\"oops\nB=still-here");
        assert!(!settings.contains_key("A"));
        assert_eq!(settings.get("B").map(String::as_str), Some("still-here"));
    }

    #[test]
    fn export_is_skipped_only_before_a_valid_assignment() {
        let settings = parse_note_settings("export DB_HOST=localhost");
        assert_eq!(settings.get("DB_HOST").map(String::as_str), Some("localhost"));
        assert_eq!(parse_note_settings("export is a shell builtin").len(), 0);
        let settings = parse_note_settings("exports = 5");
        assert_eq!(settings.get("exports").map(String::as_str), Some("5"));
    }

    #[test]
    fn spaces_and_tabs_around_the_equals_sign_are_allowed() {
        let settings = parse_note_settings("Title = With Spaces\n\tINDENTED=yes");
        assert_eq!(settings.get("Title").map(String::as_str), Some("With Spaces"));
        assert_eq!(settings.get("INDENTED").map(String::as_str), Some("yes"));
    }

    #[test]
    fn unquoted_values_are_trimmed_and_keep_internal_spacing() {
        let settings = parse_note_settings("KEY=  spaced  out  ");
        assert_eq!(settings.get("KEY").map(String::as_str), Some("spaced  out"));
        let settings = parse_note_settings("KEY=");
        assert_eq!(settings.get("KEY").map(String::as_str), Some(""));
    }

    #[test]
    fn equals_is_the_only_separator_colons_are_prose() {
        assert_eq!(parse_note_settings("Title: something").len(), 0);
        assert_eq!(parse_note_settings("ratio 1:2 = fine").len(), 0);
        let settings = parse_note_settings("ratio=1:2");
        assert_eq!(settings.get("ratio").map(String::as_str), Some("1:2"));
    }

    #[test]
    fn a_url_on_its_own_line_is_prose_a_querystring_after_equals_is_a_value() {
        assert_eq!(parse_note_settings("see https://example.com/a?b=c").len(), 0);
        let settings = parse_note_settings("url=https://example.com/a?b=c");
        assert_eq!(settings.get("url").map(String::as_str), Some("https://example.com/a?b=c"));
    }

    #[test]
    fn parsing_resumes_on_the_line_after_a_multi_line_value() {
        let settings = parse_note_settings("A=\"x\ny\"\nB=z");
        assert_eq!(settings.get("A").map(String::as_str), Some("x\ny"));
        assert_eq!(settings.get("B").map(String::as_str), Some("z"));
    }

    #[test]
    fn crlf_notes_parse_the_same_as_lf_notes() {
        let settings = parse_note_settings("A=one\r\nB=\"two\"\r\n");
        assert_eq!(settings.get("A").map(String::as_str), Some("one"));
        assert_eq!(settings.get("B").map(String::as_str), Some("two"));
    }

    #[test]
    fn an_empty_note_and_pure_prose_yield_an_empty_map() {
        assert_eq!(parse_note_settings("").len(), 0);
        assert_eq!(parse_note_settings("Just a paragraph.\n\nAnother one.").len(), 0);
    }

    #[test]
    fn a_realistic_mixed_note_parses_to_its_settings() {
        let note = [
            "# deploy credentials",
            "",
            "These are the secrets for the staging deploy. Rotate quarterly.",
            "",
            "```",
            "export STAGING_URL=https://staging.example.test",
            "STAGING_TOKEN=\"s3cr3t\\nwith-newline\"",
            "```",
            "",
            "DEPLOY_USER=deploy  # shared account",
            "NOTE = this key has spaces around the equals sign",
            "",
            "Talk to Alice before rotating.",
        ]
        .join("\n");
        let settings = parse_note_settings(&note);
        assert_eq!(settings.get("STAGING_URL").map(String::as_str), Some("https://staging.example.test"));
        assert_eq!(settings.get("STAGING_TOKEN").map(String::as_str), Some("s3cr3t\nwith-newline"));
        assert_eq!(settings.get("DEPLOY_USER").map(String::as_str), Some("deploy"));
        assert_eq!(settings.get("NOTE").map(String::as_str), Some("this key has spaces around the equals sign"));
        assert_eq!(settings.len(), 4);
    }

    #[test]
    fn scan_splits_the_keys_from_the_prose_lines_it_skipped() {
        let scan = scan_note("Notes up top.\nDB_HOST=localhost\nmore prose\nAPI_KEY=abc\n", true);
        assert_eq!(scan.settings.keys().collect::<Vec<_>>(), vec!["DB_HOST", "API_KEY"]);
        assert_eq!(scan.prose, "Notes up top.\nmore prose\n");
    }

    #[test]
    fn scan_keeps_quoted_continuation_lines_out_of_the_prose() {
        let scan = scan_note("CERT=\"-----BEGIN\nMIIE\n-----END-----\"\nafter prose", true);
        assert_eq!(
            scan.settings.get("CERT").map(String::as_str),
            Some("-----BEGIN\nMIIE\n-----END-----")
        );
        assert_eq!(scan.prose, "after prose");
    }

    #[test]
    fn scan_hides_an_unclosed_quote_line_but_still_parses_the_next_one() {
        let scan = scan_note("A=\"oops\nB=still-here", true);
        assert!(!scan.settings.contains_key("A"));
        assert_eq!(scan.settings.get("B").map(String::as_str), Some("still-here"));
        // the half-written secret does not reappear as a paragraph
        assert_eq!(scan.prose, "");
    }

    #[test]
    fn prose_only_and_settings_only_notes() {
        let prose_only = scan_note("Just a paragraph.\n\nAnother one.", true);
        assert_eq!(prose_only.settings.len(), 0);
        assert_eq!(prose_only.prose, "Just a paragraph.\n\nAnother one.");
        let settings_only = scan_note("A=1\nB=2", true);
        assert_eq!(settings_only.prose, "");
        assert_eq!(settings_only.settings.keys().collect::<Vec<_>>(), vec!["A", "B"]);
        assert_eq!(
            scan_note("", false),
            NoteScan { settings: indexmap! {}, comments: indexmap! {}, prose: String::new() }
        );
    }
}
