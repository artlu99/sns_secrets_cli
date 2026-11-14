//! Port of `src/notes.test.ts` — the reading layer against real cache files,
//! plus the command-layer renderers the suite pins (tag tree, inventory).

use sns::commands::{inventory_text, render_tag_tree};
use sns::db::{open_database, remove_cache_files, ItemRow};
use sns::errors::UserError;
use sns::notes::{InventoryColor,
    list_notes, list_tags, note_settings, plan_copy, render_copy_keys, render_note_inventory,
    render_tag_groups, resolve_note, resolve_tag, search_notes, tag_graph, tagged_note_uuids,
    CopyPlan, ListOptions,
};

fn row(uuid: &str, content_type: &str, updated_at: i64, deleted: i64, title: Option<&str>, content: String) -> ItemRow {
    (uuid.to_string(), content_type.to_string(), updated_at, deleted, title.map(str::to_string), content)
}

fn note(uuid: &str, updated_at: i64, title: &str, content: String) -> ItemRow {
    row(uuid, "Note", updated_at, 0, Some(title), content)
}

fn json(value: serde_json::Value) -> String {
    value.to_string()
}

struct TempDb(sns::db::CacheDb, std::path::PathBuf);

fn temp_db(tag: &str) -> TempDb {
    let path = std::env::temp_dir().join(format!("sns-notes-{tag}-{}.db", std::process::id()));
    remove_cache_files(&path);
    let db = open_database(&path, &"ab".repeat(32)).expect("opens");
    TempDb(db, path)
}

impl Drop for TempDb {
    fn drop(&mut self) {
        self.0.close();
        remove_cache_files(&self.1);
    }
}

fn list(db: &sns::db::CacheDb, limit: usize) -> Vec<sns::notes::ListedNote> {
    list_notes(db, ListOptions { limit, ..plain() }).expect("list")
}

fn plain() -> ListOptions<'static> {
    ListOptions { kind: None, limit: 10, all: false, tag_uuids: None, env: false, regex: false }
}

#[test]
fn list_hides_trashed_notes_and_non_note_types() {
    let temp = temp_db("trash");
    temp.0.upsert_items(
        &[
            note("11111111-1111-1111-1111-111111111111", 2_000, "Kept", json(serde_json::json!({ "title": "Kept", "text": "stay", "trashed": false, "protected": true }))),
            note("22222222-2222-2222-2222-222222222222", 1_000, "Gone", json(serde_json::json!({ "title": "Gone", "text": "bin", "trashed": true }))),
            note("44444444-4444-4444-4444-444444444444", 1_500, "Open", json(serde_json::json!({ "title": "Open", "text": "plain" }))),
            row("33333333-3333-3333-3333-333333333333", "SN|UserPreferences", 3_000, 0, Some("Prefs"), "{}".into()),
        ],
    )
    .expect("seed");
    let notes = list(&temp.0, 10);
    let titles: Vec<&str> = notes.iter().map(|note| note.title.as_str()).collect();
    assert_eq!(titles, vec!["Kept", "Open"]);
    let table = render_tag_groups(&tag_graph(&temp.0).expect("graph"), &notes);
    assert!(table.contains("(untagged) (2)"));
    let lines: Vec<&str> = table.split('\n').collect();
    let kept = lines.iter().position(|line| line.contains("Kept")).expect("Kept line");
    let open = lines.iter().position(|line| line.contains("Open")).expect("Open line");
    assert!(kept < open);
    assert!(!table.contains("Gone"));
    assert!(!table.contains("Prefs"));
}

#[test]
fn a_cached_row_that_is_not_json_does_not_kill_the_listing() {
    let temp = temp_db("broken");
    temp.0.upsert_items(
        &[
            note("aaaaaaaa-1111-1111-1111-111111111111", 2_000, "Broken", "not-json{{{".into()),
            note("aaaaaaaa-2222-2222-2222-222222222222", 1_000, "Good", json(serde_json::json!({ "title": "Good", "text": "fine" }))),
        ],
    )
    .expect("seed");
    let notes = list(&temp.0, 10);
    let titles: Vec<&str> = notes.iter().map(|note| note.title.as_str()).collect();
    assert_eq!(titles, vec!["Broken", "Good"]);
    let hits = search_notes(&temp.0, "fine", ListOptions { regex: false, ..plain() }).expect("search");
    let titles: Vec<&str> = hits.iter().map(|hit| hit.note.title.as_str()).collect();
    assert_eq!(titles, vec!["Good"]);
}

#[test]
fn all_includes_key_bearing_rows_the_default_hides_them() {
    let temp = temp_db("all");
    temp.0.upsert_items(
        &[
            note("bbbbbbbb-1111-1111-1111-111111111111", 2_000, "Note", json(serde_json::json!({ "title": "Note", "text": "hello" }))),
            row("bbbbbbbb-2222-2222-2222-222222222222", "SN|ItemsKey", 1_000, 0, None, json(serde_json::json!({ "itemsKey": "synthetic-key-not-real", "version": "004" }))),
            row("bbbbbbbb-3333-3333-3333-333333333333", "Tag", 500, 0, Some("prod"), json(serde_json::json!({ "title": "prod", "references": [] }))),
        ],
    )
    .expect("seed");
    let base = list(&temp.0, 10);
    let kinds: Vec<&str> = base.iter().map(|note| note.content_type.as_str()).collect();
    assert_eq!(kinds, vec!["Note"]);
    let all = list_notes(&temp.0, ListOptions { all: true, ..plain() }).expect("list all");
    let kinds: Vec<&str> = all.iter().map(|note| note.content_type.as_str()).collect();
    assert_eq!(kinds, vec!["Note", "SN|ItemsKey"], "--all adds key-bearing items, never tag rows");
    assert_eq!(all[1].title, "SN|ItemsKey");
    let search_all = search_notes(&temp.0, "synthetic-key", ListOptions { all: true, ..plain() }).expect("search");
    let kinds: Vec<&str> = search_all.iter().map(|hit| hit.note.content_type.as_str()).collect();
    assert_eq!(kinds, vec!["SN|ItemsKey"]);
    let search_base = search_notes(&temp.0, "synthetic-key", plain()).expect("search");
    assert!(search_base.is_empty());
    let search_tag = search_notes(&temp.0, "prod", ListOptions { all: true, ..plain() }).expect("search");
    assert!(search_tag.is_empty());
    // an explicit --type still reaches tags (debugging escape hatch)
    let typed = list_notes(&temp.0, ListOptions { kind: Some("Tag"), ..plain() }).expect("list typed");
    let titles: Vec<&str> = typed.iter().map(|row| row.title.as_str()).collect();
    assert_eq!(titles, vec!["prod"]);
}

#[test]
fn the_env_view_lists_only_notes_with_settings_and_per_note_counts() {
    let temp = temp_db("env");
    let creds = "eeeeeeee-1111-1111-1111-111111111111";
    let cert = "eeeeeeee-2222-2222-2222-222222222222";
    temp.0.upsert_items(
        &[
            note(
                creds,
                3_000,
                "Creds",
                json(serde_json::json!({
                    "title": "Creds",
                    "text": "staging secrets\n\nexport API_KEY=abc\nURL=https://x.test\nTOKEN="
                })),
            ),
            note(cert, 2_500, "Cert", json(serde_json::json!({ "title": "Cert", "text": "CERT=\"-----BEGIN\nMIIE\n-----END-----\"" }))),
            note("eeeeeeee-3333-3333-3333-333333333333", 2_000, "Journal", json(serde_json::json!({ "title": "Journal", "text": "thoughts, and 1+1=2 inline" }))),
            note("eeeeeeee-4444-4444-4444-444444444444", 1_500, "TrashedCreds", json(serde_json::json!({ "title": "TrashedCreds", "text": "OLD=1", "trashed": true }))),
        ],
    )
    .expect("seed");
    let env = list_notes(&temp.0, ListOptions { env: true, ..plain() }).expect("env list");
    let titles: Vec<&str> = env.iter().map(|note| note.title.as_str()).collect();
    assert_eq!(titles, vec!["Creds", "Cert"]);
    // export prefix, plain, and empty values all count; a multi-line quoted value counts once
    let counts: Vec<usize> = env.iter().map(|note| note.settings).collect();
    assert_eq!(counts, vec![3, 1]);
    // the default view and search still see prose-only notes
    let all = list(&temp.0, 10);
    let titles: Vec<&str> = all.iter().map(|note| note.title.as_str()).collect();
    assert_eq!(titles, vec!["Creds", "Cert", "Journal"]);
    let hits = search_notes(&temp.0, "thoughts", plain()).expect("search");
    let titles: Vec<&str> = hits.iter().map(|hit| hit.note.title.as_str()).collect();
    assert_eq!(titles, vec!["Journal"]);
    // count column sits between the timestamp and the uuid
    let table = render_tag_groups(&tag_graph(&temp.0).expect("graph"), &env);
    let creds_line = table.split('\n').find(|line| line.contains("Creds")).expect("Creds row");
    assert!(creds_line.ends_with(&format!(" 3  {creds}")));
    let cert_line = table.split('\n').find(|line| line.contains("Cert")).expect("Cert row");
    assert!(cert_line.ends_with(&format!(" 1  {cert}")));
    assert!(table.contains("(untagged) (2)"));
}

#[test]
fn tags_union_both_link_sides_and_tolerate_broken_rows() {
    let temp = temp_db("tags");
    let note_a = "cccccccc-1111-1111-1111-111111111111";
    let note_b = "cccccccc-2222-2222-2222-222222222222";
    let prod = "cccccccc-aaaa-1111-1111-111111111111";
    let eu = "cccccccc-aaaa-2222-2222-222222222222";
    temp.0.upsert_items(
        &[
            note(note_a, 4_000, "Alpha", json(serde_json::json!({ "title": "Alpha", "text": "a", "references": [{ "uuid": prod, "content_type": "Tag" }] }))),
            note(note_b, 3_000, "Beta", json(serde_json::json!({ "title": "Beta", "text": "b", "references": [{ "uuid": prod, "content_type": "Tag" }] }))),
            row(prod, "Tag", 2_000, 0, Some("prod"), json(serde_json::json!({ "title": "prod", "references": [{ "uuid": note_b, "content_type": "Note" }] }))),
            row(eu, "Tag", 1_000, 0, Some("eu"), json(serde_json::json!({ "title": "eu", "references": [{ "uuid": note_a, "content_type": "Note" }, { "uuid": prod, "content_type": "Tag" }] }))),
            row(
                "cccccccc-aaaa-3333-3333-333333333333",
                "Tag",
                900,
                0,
                Some("orphan"),
                json(serde_json::json!({ "title": "orphan", "references": [{ "uuid": "cccccccc-aaaa-9999-9999-999999999999", "content_type": "Tag" }] })),
            ),
            row("cccccccc-aaaa-4444-4444-444444444444", "Tag", 800, 0, Some("broken"), "not-json{{{".into()),
            row("cccccccc-aaaa-5555-5555-555555555555", "Tag", 700, 1, Some("deleted"), "{}".into()),
        ],
    )
    .expect("seed");
    let tags = list_tags(&temp.0).expect("tags");
    let titles: Vec<&str> = tags.iter().map(|tag| tag.title.as_str()).collect();
    assert_eq!(titles, vec!["broken", "eu", "orphan", "prod"]);
    let by_title = |name: &str| tags.iter().find(|tag| tag.title == name).expect("tag present");
    assert_eq!(by_title("prod").notes, 2, "Alpha + Beta");
    assert_eq!(by_title("eu").parent.as_deref(), Some(prod), "explicit parent (folder) wins over inference");
    assert_eq!(by_title("eu").notes, 1, "Alpha");
    assert_eq!(by_title("orphan").notes, 0);
    assert_eq!(by_title("broken").notes, 0);

    let graph = tag_graph(&temp.0).expect("graph");
    let eu_uuids = tagged_note_uuids(&graph, eu);
    assert!(eu_uuids.contains(note_a));
    assert!(!eu_uuids.contains(note_b));
    assert_eq!(tagged_note_uuids(&graph, "cccccccc-aaaa-dddd-dddd-dddddddddddd").len(), 0);

    assert_eq!(resolve_tag(&graph, prod).expect("resolves").title, "prod");
    assert_eq!(resolve_tag(&graph, "eu").expect("resolves").title, "eu");
    // all four tags share the "cccccccc-aaaa" uuid prefix -> ambiguous
    let error = resolve_tag(&graph, "cccccccc-aaaa").expect_err("ambiguous refuses");
    assert!(error.to_string().contains("matches 4 tags"), "got: {error}");
    assert!(resolve_tag(&graph, "zzz").expect_err("no match").to_string().contains("no tag matches"));

    let under_eu = list_notes(&temp.0, ListOptions { tag_uuids: Some(&eu_uuids), ..plain() }).expect("list");
    let titles: Vec<&str> = under_eu.iter().map(|row| row.title.as_str()).collect();
    assert_eq!(titles, vec!["Alpha"]);
    let prod_uuids = tagged_note_uuids(&graph, prod);
    let under_prod = list_notes(&temp.0, ListOptions { tag_uuids: Some(&prod_uuids), ..plain() }).expect("list");
    let titles: Vec<&str> = under_prod.iter().map(|row| row.title.as_str()).collect();
    assert_eq!(titles, vec!["Alpha", "Beta"]);

    // hierarchical list: Alpha lives once, under eu (its deepest tag), nested
    // in prod; noteless tags do not render at all
    let listed = list(&temp.0, 10);
    let table = render_tag_groups(&graph, &listed);
    let lines: Vec<&str> = table.split('\n').collect();
    assert_eq!(lines[0], "prod (2)");
    assert!(lines[1].contains("Beta"));
    assert_eq!(lines[2], "  eu (1)");
    assert!(lines[3].contains("Alpha"));
    assert_eq!(table.matches("Alpha").count(), 1, "exactly once");
    assert!(!table.contains("orphan"));
    assert!(!table.contains("broken"));
}

#[test]
fn render_tag_tree_nests_children_and_aligns_counts() {
    let tags = vec![
        sns::notes::ListedTag { uuid: "prod".into(), title: "prod".into(), parent: None, notes: 2 },
        sns::notes::ListedTag { uuid: "eu".into(), title: "eu".into(), parent: Some("prod".into()), notes: 1 },
        sns::notes::ListedTag { uuid: "apac".into(), title: "apac".into(), parent: Some("prod".into()), notes: 0 },
        sns::notes::ListedTag { uuid: "misc".into(), title: "misc".into(), parent: None, notes: 5 },
        sns::notes::ListedTag { uuid: "loop-a".into(), title: "loop-a".into(), parent: Some("loop-b".into()), notes: 0 },
        sns::notes::ListedTag { uuid: "loop-b".into(), title: "loop-b".into(), parent: Some("loop-a".into()), notes: 0 },
    ];
    let tree = render_tag_tree(&tags);
    let lines: Vec<&str> = tree.split('\n').collect();
    assert_eq!(lines[0], "prod      (2 notes)");
    // children are sorted alphabetically, not by input order
    assert_eq!(lines[1], "  apac    (empty)");
    assert_eq!(lines[2], "  eu      (1 note)");
    assert_eq!(lines[3], "misc      (5 notes)");
    // parent cycles hang off their cycle root as one chain, after the clean tree
    assert!(lines.contains(&"loop-a    (empty)"));
    assert!(lines.contains(&"  loop-b  (empty)"));
}

#[test]
fn list_infers_the_hierarchy_from_note_membership_and_renders_each_note_once() {
    let temp = temp_db("hierarchy");
    let tag_row = |suffix: &str, title: &str, refs: &[&str]| {
        row(
            &format!("dddddddd-aaaa-{suffix}"),
            "Tag",
            1_000,
            0,
            Some(title),
            json(serde_json::json!({
                "title": title,
                "references": refs.iter().map(|r| serde_json::json!({ "uuid": format!("dddddddd-bbbb-{r}"), "content_type": "Note" })).collect::<Vec<_>>()
            })),
        )
    };
    let note_row = |suffix: &str, title: &str, updated: i64, tags: &[&str]| {
        row(
            &format!("dddddddd-bbbb-{suffix}"),
            "Note",
            updated,
            0,
            Some(title),
            json(serde_json::json!({
                "title": title,
                "text": title,
                "references": tags.iter().map(|t| serde_json::json!({ "uuid": format!("dddddddd-aaaa-{t}"), "content_type": "Tag" })).collect::<Vec<_>>()
            })),
        )
    };
    let (n1, n2, n3, n4, n5, n6, n7) = ("1111", "2222", "3333", "4444", "5555", "6666", "7777");
    temp.0.upsert_items(
        &[
            // {1,2,3} ⊂ infra, {4,5,6} ⊂ infra, apps = social = {7}
            tag_row("ta", "data", &[n1, n2, n3]),
            tag_row("tb", "compute", &[n4, n5, n6]),
            tag_row("tc", "apps", &[n7]),
            tag_row("td", "social", &[n7]),
            tag_row("te", "infra", &[n1, n2, n3, n4, n5, n6]),
            note_row(n1, "one", 7_000, &["data", "infra"]),
            note_row(n2, "two", 6_000, &["data", "infra"]),
            note_row(n3, "three", 5_000, &["data", "infra"]),
            note_row(n4, "four", 4_000, &["compute", "infra"]),
            note_row(n5, "five", 3_000, &["compute", "infra"]),
            note_row(n6, "six", 2_000, &["compute", "infra"]),
            note_row(n7, "seven", 1_000, &["apps", "social"]),
        ],
    )
    .expect("seed");
    // inference is visible in sns tags too
    let tags = list_tags(&temp.0).expect("tags");
    let by_title = |name: &str| tags.iter().find(|tag| tag.title == name).expect("tag");
    assert_eq!(by_title("data").parent.as_deref(), Some(by_title("infra").uuid.as_str()));
    assert_eq!(by_title("compute").parent.as_deref(), Some(by_title("infra").uuid.as_str()));
    assert_eq!(by_title("social").parent.as_deref(), Some(by_title("apps").uuid.as_str()));
    assert_eq!(by_title("infra").parent, None);

    let table = render_tag_groups(&tag_graph(&temp.0).expect("graph"), &list(&temp.0, 10));
    let lines: Vec<&str> = table.split('\n').collect();
    // headers: alphabetical at each level, counts are full tag membership
    assert_eq!(lines[0], "apps (1)");
    assert_eq!(lines[1], "  social (1)");
    assert!(lines[2].contains("dddddddd-bbbb-7777"));
    assert_eq!(lines[3], "");
    assert_eq!(lines[4], "infra (6)");
    assert_eq!(lines[5], "  compute (3)");
    assert!(lines[6].contains("dddddddd-bbbb-4444"), "newest first inside each group");
    assert!(lines[7].contains("dddddddd-bbbb-5555"));
    assert!(lines[8].contains("dddddddd-bbbb-6666"));
    assert_eq!(lines[9], "  data (3)");
    assert!(lines[10].contains("dddddddd-bbbb-1111"));
    assert!(lines[11].contains("dddddddd-bbbb-2222"));
    assert!(lines[12].contains("dddddddd-bbbb-3333"));
    // exactly once across the whole tree
    let uuids: Vec<&str> = table.match_indices("dddddddd-bbbb").map(|(index, _)| &table[index..index + 16]).collect();
    let distinct: std::collections::HashSet<_> = uuids.iter().collect();
    assert_eq!(distinct.len(), 7);
    assert_eq!(uuids.len(), 7);
}

#[test]
fn an_explicit_folder_wins_over_the_inferred_parent_untagged_notes_render_last() {
    let temp = temp_db("explicit");
    let big = "eeeeeeee-1111-1111-1111-111111111111";
    let small = "eeeeeeee-2222-2222-2222-222222222222";
    let tagged = "eeeeeeee-3333-3333-3333-333333333333";
    temp.0.upsert_items(
        &[
            // explicit parent of `tagged`, but holds no notes itself
            row(big, "Tag", 1_000, 0, Some("big"), json(serde_json::json!({ "title": "big", "references": [] }))),
            // would win inference (equal note set, alphabetically first), but has
            // no explicit link — `tagged` must stay under big
            row(small, "Tag", 900, 0, Some("small"), json(serde_json::json!({ "title": "small", "references": [] }))),
            row(tagged, "Tag", 800, 0, Some("leaf"), json(serde_json::json!({ "title": "leaf", "references": [{ "uuid": big, "content_type": "Tag" }] }))),
            note(
                "eeeeeeee-4444-4444-4444-444444444444",
                5_000,
                "child",
                json(serde_json::json!({ "title": "child", "text": "x", "references": [{ "uuid": tagged, "content_type": "Tag" }, { "uuid": small, "content_type": "Tag" }] })),
            ),
            note("eeeeeeee-5555-5555-5555-555555555555", 4_000, "loose", json(serde_json::json!({ "title": "loose", "text": "y" }))),
        ],
    )
    .expect("seed");
    let tags = list_tags(&temp.0).expect("tags");
    assert_eq!(tags.iter().find(|tag| tag.title == "leaf").expect("leaf").parent.as_deref(), Some(big));

    let table = render_tag_groups(&tag_graph(&temp.0).expect("graph"), &list(&temp.0, 10));
    let lines: Vec<&str> = table.split('\n').collect();
    // counts are subtree totals over the listed notes: big has none directly,
    // but its child chain lists one
    assert_eq!(lines[0], "big (1)");
    assert_eq!(lines[1], "  leaf (1)");
    // `small` holds the note too, but its set equals leaf's, so it folds under
    // leaf (alphabetical) — the note still renders exactly once, in the chain
    assert_eq!(lines[2], "    small (1)");
    assert!(lines[3].contains("eeeeeeee-4444-4444-4444-444444444444"));
    assert_eq!(lines[4], "");
    assert_eq!(lines[5], "(untagged) (1)");
    assert!(lines[6].contains("eeeeeeee-5555-5555-5555-555555555555"));
    assert_eq!(table.matches("eeeeeeee-4444").count(), 1);
}

#[test]
fn explicit_folder_nesting_does_not_depend_on_tag_row_order() {
    let temp = temp_db("folder-order");
    let parent = "ffff0000-1111-1111-1111-111111111111";
    let child = "ffff0000-2222-2222-2222-222222222222";
    temp.0.upsert_items(
        &[
            // synced first: when the child is processed, the parent is not yet in
            // the resolved map — the explicit link must survive anyway
            row(child, "Tag", 1_000, 0, Some("child"), json(serde_json::json!({ "title": "child", "references": [{ "uuid": parent, "content_type": "Tag" }] }))),
            row(parent, "Tag", 2_000, 0, Some("zulu"), json(serde_json::json!({ "title": "zulu", "references": [] }))),
        ],
    )
    .expect("seed");
    let tags = list_tags(&temp.0).expect("tags");
    assert_eq!(tags.iter().find(|tag| tag.title == "child").expect("child").parent.as_deref(), Some(parent));
}

#[test]
fn hard_deleted_and_trashed_notes_stop_counting_toward_tags() {
    let temp = temp_db("phantom");
    let work = "ffff1000-1111-1111-1111-111111111111";
    let dead = "ffff1000-2222-2222-2222-222222222222";
    let trashed = "ffff1000-3333-3333-3333-333333333333";
    let live = "ffff1000-4444-4444-4444-444444444444";
    temp.0.upsert_items(
        &[
            // the tag's references still name a note deleted on another device
            row(
                work,
                "Tag",
                1_000,
                0,
                Some("work"),
                json(serde_json::json!({ "title": "work", "references": [
                    { "uuid": dead, "content_type": "Note" },
                    { "uuid": trashed, "content_type": "Note" },
                    { "uuid": live, "content_type": "Note" }
                ] })),
            ),
            row(dead, "Note", 900, 1, None, "{}".into()),
            note(trashed, 800, "Trashed", json(serde_json::json!({ "title": "Trashed", "trashed": true }))),
            note(live, 700, "Live", json(serde_json::json!({ "title": "Live", "text": "x" }))),
        ],
    )
    .expect("seed");
    let tags = list_tags(&temp.0).expect("tags");
    assert_eq!(tags.iter().find(|tag| tag.title == "work").expect("work").notes, 1);
    let graph = tag_graph(&temp.0).expect("graph");
    let uuids = tagged_note_uuids(&graph, work);
    assert!(uuids.contains(live));
    assert!(!uuids.contains(dead));
    assert!(!uuids.contains(trashed));
}

#[test]
fn list_tag_on_a_folder_reaches_notes_under_its_child_tags() {
    let temp = temp_db("subtree");
    let folder = "ffff2000-1111-1111-1111-111111111111";
    let leaf = "ffff2000-2222-2222-2222-222222222222";
    let note_uuid = "ffff2000-3333-3333-3333-333333333333";
    temp.0.upsert_items(
        &[
            row(folder, "Tag", 2_000, 0, Some("big"), json(serde_json::json!({ "title": "big", "references": [] }))),
            row(leaf, "Tag", 1_000, 0, Some("leaf"), json(serde_json::json!({ "title": "leaf", "references": [{ "uuid": folder, "content_type": "Tag" }, { "uuid": note_uuid, "content_type": "Note" }] }))),
            note(note_uuid, 3_000, "child", json(serde_json::json!({ "title": "child", "text": "x", "references": [{ "uuid": leaf, "content_type": "Tag" }] }))),
        ],
    )
    .expect("seed");
    // the list renders the note under big -> leaf; --tag big must find it too
    let graph = tag_graph(&temp.0).expect("graph");
    let uuids = tagged_note_uuids(&graph, folder);
    assert!(uuids.contains(note_uuid));
    let notes = list_notes(&temp.0, ListOptions { tag_uuids: Some(&uuids), ..plain() }).expect("list");
    let titles: Vec<&str> = notes.iter().map(|row| row.title.as_str()).collect();
    assert_eq!(titles, vec!["child"]);
}

#[test]
fn header_counts_reflect_the_listed_notes_not_the_whole_cache() {
    let temp = temp_db("counts");
    let prod = "ffff3000-1111-1111-1111-111111111111";
    let note_a = "ffff3000-2222-2222-2222-222222222222";
    let note_b = "ffff3000-3333-3333-3333-333333333333";
    temp.0.upsert_items(
        &[
            row(prod, "Tag", 1_000, 0, Some("prod"), json(serde_json::json!({ "title": "prod", "references": [{ "uuid": note_a, "content_type": "Note" }, { "uuid": note_b, "content_type": "Note" }] }))),
            note(note_a, 4_000, "Alpha", json(serde_json::json!({ "title": "Alpha", "references": [{ "uuid": prod, "content_type": "Tag" }] }))),
            note(note_b, 3_000, "Beta", json(serde_json::json!({ "title": "Beta", "references": [{ "uuid": prod, "content_type": "Tag" }] }))),
        ],
    )
    .expect("seed");
    // --limit cut Beta out: the header must not claim it
    let table = render_tag_groups(&tag_graph(&temp.0).expect("graph"), &list_notes(&temp.0, ListOptions { limit: 1, ..plain() }).expect("list"));
    assert_eq!(table.split('\n').next(), Some("prod (1)"));
    assert!(!table.contains("Beta"));
}

#[test]
fn tag_titles_are_whitespace_normalized_for_rendering_and_matching() {
    let temp = temp_db("title");
    let messy = "ffff4000-1111-1111-1111-111111111111";
    let note_uuid = "ffff4000-2222-2222-2222-222222222222";
    temp.0.upsert_items(
        &[
            row(messy, "Tag", 1_000, 0, Some("a\nb"), json(serde_json::json!({ "title": "a\nb", "references": [{ "uuid": note_uuid, "content_type": "Note" }] }))),
            note(note_uuid, 2_000, "child", json(serde_json::json!({ "title": "child", "references": [{ "uuid": messy, "content_type": "Tag" }] }))),
        ],
    )
    .expect("seed");
    let table = render_tag_groups(&tag_graph(&temp.0).expect("graph"), &list(&temp.0, 10));
    assert_eq!(table.split('\n').next(), Some("a b (1)"));
    assert!(!table.contains("a\nb"));
    // resolution matches the normalized title too
    assert_eq!(resolve_tag(&tag_graph(&temp.0).expect("graph"), "a b").expect("resolves").uuid, messy);
}

#[test]
fn render_note_inventory_lists_keys_marks_empties_and_hints_the_copy_form() {
    use sns::note_env::Settings;
    use sns::notes::{PlainInventoryColor, RenderInventoryInput};
    let settings: Settings = Settings::from_iter([
        ("DB_HOST".to_string(), "x".to_string()),
        ("TOKEN".to_string(), String::new()),
        ("API_KEY".to_string(), "y".to_string()),
    ]);
    let comments: Settings = Settings::from_iter([
        ("DB_HOST".to_string(), "# primary host".to_string()),
        ("TOKEN".to_string(), "# rotate quarterly".to_string()),
    ]);
    let text = render_note_inventory(RenderInventoryInput {
        title: "staging api",
        settings: &settings,
        comments: &comments,
        prose: "Notes on the staging API.\nAsk Alice before rotating.\n",
        query: "staging",
        terminal: true,
        color: &PlainInventoryColor,
    });
    let lines: Vec<&str> = text.split('\n').collect();
    assert_eq!(lines[0], "staging api");
    assert_eq!(lines[1], "───────────");
    // prose reads first, right under the title
    assert_eq!(lines[2..5], ["Notes on the staging API.", "Ask Alice before rotating.", ""]);
    // keys sit below the prose in first-seen order, drawn as their note lines
    // with values withheld, empties marked, comments beside their key
    assert_eq!(lines[5..8], ["DB_HOST=[redacted]  # primary host", "TOKEN=  (empty)  # rotate quarterly", "API_KEY=[redacted]"]);
    // the hint names one real key so the next command is pasteable
    assert!(text.ends_with("copy a value:  sns copy staging DB_HOST"));
    // a query with a space is quoted so the hint pastes back correctly
    let quoted = render_note_inventory(RenderInventoryInput {
        title: "t",
        settings: &settings,
        comments: &comments,
        prose: "",
        query: "prod db",
        terminal: true,
        color: &PlainInventoryColor,
    });
    assert!(quoted.contains("sns copy 'prod db' DB_HOST"));
    // blank-line-only prose adds no block, and a pipe gets no hint
    let bare = render_note_inventory(RenderInventoryInput {
        title: "t",
        settings: &settings,
        comments: &Settings::new(),
        prose: "\n\n",
        query: "t",
        terminal: false,
        color: &PlainInventoryColor,
    });
    assert_eq!(bare.split('\n').collect::<Vec<_>>(), vec!["t", "─", "DB_HOST=[redacted]", "TOKEN=  (empty)", "API_KEY=[redacted]"]);
}

struct AnsiColor;

impl sns::notes::InventoryColor for AnsiColor {
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

#[test]
fn render_note_inventory_draws_annotation_with_the_palette_and_strips_note_supplied_codes() {
    use sns::note_env::Settings;
    use sns::notes::{RenderInventoryInput, AnsiInventoryColor};
    let color = AnsiColor;
    let settings: Settings = Settings::from_iter([
        ("DB_HOST".to_string(), "x".to_string()),
        ("TOKEN".to_string(), String::new()),
    ]);
    let comments: Settings = Settings::from_iter([
        ("DB_HOST".to_string(), "# primary host".to_string()),
        ("TOKEN".to_string(), "# OLD_TOKEN=\x1b[31mhunter2\x1b[0m until Friday".to_string()),
    ]);
    let text = render_note_inventory(RenderInventoryInput {
        title: "staging api",
        settings: &settings,
        comments: &comments,
        prose: "",
        query: "staging",
        terminal: true,
        color: &AnsiInventoryColor,
    });
    assert!(text.contains(&color.bold("staging api")));
    assert!(text.contains(&format!("DB_HOST={}  {}", color.gray("[redacted]"), color.italic(&color.gray("# primary host")))));
    assert!(text.contains("TOKEN=  \x1b[90m(empty)\x1b[0m"));
    // the note's own SGR is stripped before masking runs, so the code-hidden
    // value is still caught — and none of their codes survive into our output
    assert!(text.contains("OLD_TOKEN=[redacted] until Friday"));
    assert!(!text.contains("\x1b[31m"));
    assert!(!text.contains("hunter2"));
    // the hint stays plain text, consistent with hints elsewhere in the flow
    assert!(text.contains("copy a value:  sns copy staging DB_HOST"));
    assert!(!text.contains("\x1b[90mcopy a value:"));
}

#[test]
fn render_note_inventory_masks_assignment_shaped_fragments_the_parser_rejected() {
    use sns::note_env::Settings;
    use sns::notes::{RenderInventoryInput, PlainInventoryColor};
    // a commented-out line and a mid-sentence mention carry values the parser
    // never parsed — the inventory still must not print them
    let settings: Settings = Settings::from_iter([("TOKEN".to_string(), "new".to_string())]);
    let comments: Settings = Settings::from_iter([("TOKEN".to_string(), "# OLD_TOKEN=hunter2 until Friday".to_string())]);
    let text = render_note_inventory(RenderInventoryInput {
        title: "t",
        settings: &settings,
        comments: &comments,
        prose: "# DB_PASS=hunter2 (rotated)\nset KEY = abc midway through the note\nplain prose stays",
        query: "t",
        terminal: false,
        color: &PlainInventoryColor,
    });
    assert!(text.contains("TOKEN=[redacted]  # OLD_TOKEN=[redacted] until Friday"));
    assert!(text.contains("# DB_PASS=[redacted] (rotated)"));
    assert!(text.contains("set KEY=[redacted] midway through the note"));
    assert!(text.contains("plain prose stays"));
    assert!(!text.contains("hunter2"));
    assert!(!text.contains(" abc"));
    // trailing base64 padding (`=` with nothing after it) and prose without an
    // assignment shape are left alone
    let settings: Settings = Settings::from_iter([("A".to_string(), "1".to_string())]);
    let harmless = render_note_inventory(RenderInventoryInput {
        title: "t",
        settings: &settings,
        comments: &Settings::new(),
        prose: "ends with base64 cGFzc3dvcmQ=\nno equals here",
        query: "t",
        terminal: false,
        color: &PlainInventoryColor,
    });
    assert!(harmless.contains("ends with base64 cGFzc3dvcmQ="));
    assert!(harmless.contains("no equals here"));
}

#[test]
fn render_copy_keys_shows_the_form_first_then_the_key_names() {
    assert_eq!(
        render_copy_keys("staging", &["API_KEY".into(), "API_URL".into(), "TOKEN".into()]),
        ["copy a value:  sns copy staging API_KEY", "  API_KEY", "  API_URL", "  TOKEN"].join("\n")
    );
}

#[test]
fn plan_copy_picks_the_value_the_key_list_or_the_body() {
    let temp = temp_db("copyplan");
    temp.0.upsert_items(
        &[
            note(
                "cccccc00-0000-0000-0000-000000000001",
                2_000,
                "Creds",
                json(serde_json::json!({ "title": "Creds", "text": "staging secrets\nexport API_KEY=abc\nURL=https://x.test\nTOKEN=" })),
            ),
            note("cccccc00-0000-0000-0000-000000000002", 1_000, "Journal", json(serde_json::json!({ "title": "Journal", "text": "thoughts" }))),
        ],
    )
    .expect("seed");
    let creds = resolve_note(&temp.0, "Creds", false).expect("resolves");
    // an exact key copies its parsed value
    assert_eq!(plan_copy(&creds, Some("API_KEY")).expect("copies"), CopyPlan::Value { key: "API_KEY".into(), value: "abc".into() });
    // an empty value is still a value
    assert_eq!(plan_copy(&creds, Some("TOKEN")).expect("copies"), CopyPlan::Value { key: "TOKEN".into(), value: String::new() });
    // no key on a settings note copies nothing and lists the keys
    assert_eq!(
        plan_copy(&creds, None).expect("lists"),
        CopyPlan::Keys { keys: vec!["API_KEY".into(), "URL".into(), "TOKEN".into()] }
    );
    // matching is exact and case-sensitive: neither API nor api_key selects API_KEY
    let error = plan_copy(&creds, Some("API")).expect_err("refuses");
    assert!(error.to_string().contains("no setting \"API\" in \"Creds\""), "got: {error}");
    let error = plan_copy(&creds, Some("api_key")).expect_err("refuses");
    assert!(error.to_string().contains("no setting \"api_key\" in \"Creds\""));
    assert!(error.to_string().contains("its keys: API_KEY, URL, TOKEN"));
    // a note without settings still copies its body
    let journal = resolve_note(&temp.0, "Journal", false).expect("resolves");
    assert_eq!(plan_copy(&journal, None).expect("copies"), CopyPlan::Body { body: "thoughts".into() });
    // a key on a note without settings is an error, not a silent body copy
    assert!(plan_copy(&journal, Some("KEY")).expect_err("refuses").to_string().contains("has no KEY=VALUE settings"));
}

#[test]
fn search_matches_full_content_but_the_snippet_never_carries_a_value() {
    let temp = temp_db("snippet");
    temp.0.upsert_items(
        &[note(
            "dddddddd-1111-1111-1111-111111111111",
            2_000,
            "Staging",
            json(serde_json::json!({
                "title": "Staging",
                "text": "ask Alice first\nAPI_KEY=sk-live-999\nTOKEN=\"hunter two hidden\"\nBROKEN=\"oops-no-close\nstaging notes here"
            })),
        )],
    )
    .expect("seed");
    // a hit on the value itself still matches, and shows the masked line
    let by_value = search_notes(&temp.0, "sk-live-999", plain()).expect("search");
    assert_eq!(by_value.len(), 1);
    assert!(by_value[0].snippet.contains("API_KEY=[redacted]"));
    assert!(!by_value[0].snippet.contains("sk-live-999"));
    // a quoted value loses its continuation words to the line-level mask
    let by_tail = search_notes(&temp.0, "hidden", plain()).expect("search");
    assert_eq!(by_tail.len(), 1);
    assert!(!by_tail[0].snippet.contains("hunter two"));
    assert!(by_tail[0].snippet.contains("TOKEN=[redacted]"));
    // an unclosed quote — a half-written secret — masks the same way
    let by_broken = search_notes(&temp.0, "oops-no-close", plain()).expect("search");
    assert_eq!(by_broken.len(), 1);
    assert!(!by_broken[0].snippet.contains("oops-no-close"));
    assert!(by_broken[0].snippet.contains("BROKEN=[redacted]"));
    // prose keeps matching and showing as before
    let by_prose = search_notes(&temp.0, "staging notes", plain()).expect("search");
    assert_eq!(by_prose.len(), 1);
    assert!(by_prose[0].snippet.contains("staging notes here"));
}

#[test]
fn inventory_text_renders_a_keyless_note_as_masked_prose_the_only_view_there_is() {
    let temp = temp_db("inventory");
    temp.0.upsert_items(
        &[note(
            "eeeeeeee-1111-1111-1111-111111111111",
            2_000,
            "Journal",
            json(serde_json::json!({
                "title": "Journal",
                "text": "thoughts about staging\nthe old line was TOKEN=hunter2\nand DONE=yes, mostly"
            })),
        )],
    )
    .expect("seed");
    let row = resolve_note(&temp.0, "Journal", false).expect("resolves");
    let text = inventory_text(&row, "Journal");
    // the whole body shows as prose — rejected fragments masked, no hint
    assert!(text.contains("thoughts about staging"));
    assert!(text.contains("the old line was TOKEN=[redacted]"));
    assert!(text.contains("and DONE=[redacted] mostly"));
    assert!(!text.contains("hunter2"));
    assert!(!text.contains("copy a value"));
}

#[test]
fn note_settings_counts_remain_available_per_row() {
    let settings = note_settings("Note", &json(serde_json::json!({ "text": "A=1\nB=2" })));
    assert_eq!(settings.len(), 2);
    let none = note_settings("SN|ItemsKey", &json(serde_json::json!({ "itemsKey": "x" })));
    assert_eq!(none.len(), 0);
    let _ = UserError("type reference keeps the import honest".into());
}
