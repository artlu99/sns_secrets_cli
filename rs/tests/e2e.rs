//! End-to-end smoke test: craft a logged-in config state, then drive the
//! compiled binary through doctor, list, show, copy, tags, and the version
//! flag — the full user surface, offline, against real files.

use std::process::Command;

use sns::db::{open_database, remove_cache_files, ItemRow};
use sns::paths::{config_dir, db_path, env_path, session_path};
use sns::session_file::save_session;

fn run_cli(args: &[&str], config_dir: &str) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_sns"))
        .args(args)
        .env("SNS_CONFIG_DIR", config_dir)
        .output()
        .expect("binary spawns");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn the_binary_drives_a_crafted_session_end_to_end() {
    // SAFETY: this integration test owns the SNS_CONFIG_DIR value for its
    // duration; no other test in this file reads the environment.
    unsafe {
        std::env::set_var("SNS_CONFIG_DIR", "");
    }
    let dir = std::env::temp_dir().join(format!("sns-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("config dir creates");
    unsafe {
        std::env::set_var("SNS_CONFIG_DIR", &dir);
    }

    // The db key is fixed for this test; the session is crafted with the
    // same key so the cache opens.
    let db_key = "cd".repeat(32);
    let secrets = sns::sn_api::SessionSecrets {
        account_email: "e2e@example.test".into(),
        refresh_token: "refresh-token".into(),
        access_token: "access-token".into(),
        access_expiration_ms: 1_800_000_000_000,
        refresh_expiration_ms: 1_900_000_000_000,
        access_cookie: "access_token=a".into(),
        refresh_cookie: "refresh_token=r".into(),
        db_key: db_key.clone(),
    };
    let stored = save_session(&secrets).expect("session saves");
    // No secret service in the test environment: file custody.
    assert!(!stored.keychain);
    assert!(session_path().exists());
    assert!(sns::paths::keys_path().exists());
    std::fs::write(env_path(), "SN_EMAIL=e2e@example.test\nSN_API_URL=https://api.standardnotes.com\n")
        .expect("plain config writes");

    // The doctor passes on this state before any cache exists.
    let (code, stdout, stderr) = run_cli(&["doctor"], &dir.display().to_string());
    assert_eq!(code, 0, "doctor exit: {stderr}");
    assert!(stdout.contains("ok    config"), "stdout:\n{stdout}");
    assert!(stdout.contains("ok    session") && stdout.contains("decrypts"), "stdout:\n{stdout}");
    assert!(stdout.contains("SKIP  cache"), "stdout:\n{stdout}");
    assert!(stdout.contains("ok    at-rest") || stdout.contains("SKIP  at-rest"));

    // `sns --version` matches the package version.
    let (code, stdout, _) = run_cli(&["--version"], &dir.display().to_string());
    assert_eq!(code, 0);
    assert_eq!(stdout.trim(), "sns 0.2.0");

    // list without a cache names the next step instead of crashing.
    let (code, _stdout, stderr) = run_cli(&["list"], &dir.display().to_string());
    assert_eq!(code, 1);
    assert!(stderr.contains("no cache yet — run sns sync"), "stderr: {stderr}");

    // A seeded cache flows through list, show, copy (keys), and tags.
    let items: Vec<ItemRow> = vec![(
        "11111111-1111-4111-8111-111111111111".to_string(),
        "Note".to_string(),
        1_700_000_000_000_i64,
        0_i64,
        Some("Staging".to_string()),
        serde_json::json!({ "title": "Staging", "text": "deploy notes\nexport API_KEY=abc\nURL=https://x.test" }).to_string(),
    )];
    // open + upsert through the crate, exactly as sync would.
    let db = open_database(&db_path(), &db_key).expect("cache opens");
    db.upsert_items(&items).expect("seeds");
    db.close();

    let (code, stdout, _) = run_cli(&["list"], &dir.display().to_string());
    assert_eq!(code, 0, "list runs");
    assert!(stdout.contains("Staging"), "stdout:\n{stdout}");
    assert!(stdout.contains("(untagged) (1)"), "stdout:\n{stdout}");

    let (code, stdout, _) = run_cli(&["show", "Staging"], &dir.display().to_string());
    assert_eq!(code, 0);
    assert!(stdout.contains("Staging") && stdout.contains("deploy notes"), "stdout:\n{stdout}");
    assert!(stdout.contains("API_KEY=[redacted]"), "values never reach the inventory\n{stdout}");
    assert!(!stdout.contains("abc"), "the parsed value never prints\n{stdout}");

    let (code, stdout, _) = run_cli(&["copy", "Staging"], &dir.display().to_string());
    assert_eq!(code, 0);
    assert!(stdout.contains("copy a value:  sns copy Staging API_KEY"), "stdout:\n{stdout}");

    let (code, stdout, _) = run_cli(&["tags"], &dir.display().to_string());
    assert_eq!(code, 0);
    assert!(stdout.contains("no tags in the cache"), "stdout:\n{stdout}");

    // A wrong-key cache is replaced by logout --delete-cache's contract, and
    // logout removes the secrets.
    let (code, stdout, _) = run_cli(&["logout"], &dir.display().to_string());
    assert_eq!(code, 0, "logout runs");
    assert!(stdout.contains("local secrets deleted"), "stdout:\n{stdout}");
    assert!(!session_path().exists());
    assert!(!sns::paths::keys_path().exists());

    // And the cache still opens with the key only this test knows — logout
    // without --delete-cache leaves it in place.
    let db = open_database(&db_path(), &db_key).expect("cache survives logout");
    remove_cache_files(&db_path());
    drop(db);
    let _ = config_dir(); // touch the module so the import stays honest
}
