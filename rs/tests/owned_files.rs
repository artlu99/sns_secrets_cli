//! The ownership predicates behind purge/delete amnesia and the uuid
//! sanitizer for the display sinks (unit-level twins of the cases in
//! src/orphan-sweep.test.ts; the purge sweep itself is pinned in
//! commands.rs's purge_tests).

use sns::notes::sanitize_uuid;
use sns::paths::{is_owned_config_file_name, is_owned_session_file_name};

#[test]
fn owned_file_predicates_cover_exact_names_and_orphan_temps() {
    for owned in [
        ".env.session",
        ".env.keys",
        ".env.session.GhK1a2",
        ".env.keys.tmp-123-abc",
        "cache.db",
        "cache.db-journal",
        "sync.lock",
        "clipboard-clear-at",
        ".env",
    ] {
        assert!(is_owned_config_file_name(owned), "{owned} should be owned");
    }
    assert!(is_owned_session_file_name(".env.session.19048"));
    assert!(is_owned_session_file_name(".env.keys.tmp-99-zz1"));
    for foreign in [
        ".env.session.bak.old",
        "operator-notes.txt",
        ".envrc",
        "cache.db.backup",
        "other.env.keys.x",
        "x.env.keys.tmp-1-a",
        ".env.keys.tmp-x-1a",
    ] {
        assert!(!is_owned_config_file_name(foreign), "{foreign} should not be owned");
    }
}

#[test]
fn sanitize_uuid_strips_the_whitespace_sanitize_text_keeps_for_prose() {
    assert_eq!(sanitize_uuid("\u{1b}]0;pwned\u{7}ab\u{1b}[31mcd\u{1b}[0m"), "abcd");
    assert_eq!(sanitize_uuid("12\n34\t56"), "123456");
    assert_eq!(
        sanitize_uuid("aaaaaaaa-1111-2222-3333-444444444444"),
        "aaaaaaaa-1111-2222-3333-444444444444"
    );
}
