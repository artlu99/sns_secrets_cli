//! Port of `src/keychain.ts` — the OS secret service via the same CLI tools
//! the TS implementation shells out to (`security` on macOS,
//! `secret-tool` on Linux), run with the scrubbed environment.

use std::process::Stdio;

use crate::env::{scrubbed_command, which};

const SERVICE: &str = "sn_secrets_cli";
const ACCOUNT: &str = "dotenvkey";

struct RunResult {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(command: &str, args: &[&str], stdin: Option<&str>) -> Result<RunResult, String> {
    let mut child = scrubbed_command(command)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    use std::io::Write as _;
    if let Some(input) = stdin
        && let Some(mut handle) = child.stdin.take()
    {
        let _ = handle.write_all(input.as_bytes());
    }
    let output = child.wait_with_output().map_err(|error| error.to_string())?;
    Ok(RunResult {
        code: output.status.code().unwrap_or(1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

fn platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    }
}

fn probe_result(stderr: &str, code: i32) -> bool {
    if code == 0 {
        return true;
    }
    let connectivity = [
        "could not connect",
        "cannot autolaunch",
        "secret service",
        "org.freedesktop.secrets",
        "no such file or directory",
    ];
    if connectivity.iter().any(|needle| stderr.to_lowercase().contains(needle)) {
        return false;
    }
    code == 1
}

use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

static TEST_DISABLE: AtomicBool = AtomicBool::new(false);

/// Test escape hatch — the port of the TS `SNS_DISABLE_KEYCHAIN` guard.
/// `security add-generic-password -U` is an upsert, so a test calling
/// save_session or purge would clobber the developer's real keychain entry
/// on macOS. An atomic instead of the env var because edition 2024 marks
/// `set_var` unsafe in multi-threaded test binaries.
pub fn disable_for_tests() {
    TEST_DISABLE.store(true, AtomicOrdering::Relaxed);
}

/// The OS secret service answered. A missing item still counts as available.
pub fn secret_service_available() -> bool {
    if TEST_DISABLE.load(AtomicOrdering::Relaxed) {
        return false;
    }
    match platform() {
        "darwin" => which("security"),
        "linux" => {
            if !which("secret-tool") {
                return false;
            }
            match run("secret-tool", &["lookup", "service", SERVICE, "account", "__sns_probe__"], None) {
                Ok(result) => probe_result(&result.stderr, result.code),
                Err(_) => false,
            }
        }
        _ => false,
    }
}

fn strip_trailing_newline(text: &str) -> String {
    text.strip_suffix('\n').unwrap_or(text).to_string()
}

pub fn keychain_get() -> Option<String> {
    // No availability probe here: a missing tool or a dead service fails the
    // lookup below, which maps to None either way — the probe (a DBus round
    // trip) would only add a second spawn to every cache-touching command.
    let result = match platform() {
        "darwin" => run("security", &["find-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w"], None).ok()?,
        _ => run("secret-tool", &["lookup", "service", SERVICE, "account", ACCOUNT], None).ok()?,
    };
    if result.code != 0 {
        return None;
    }
    Some(strip_trailing_newline(&result.stdout))
}

pub fn keychain_put(secret: &str) -> bool {
    if !secret_service_available() {
        return false;
    }
    match platform() {
        "darwin" => run(
            "security",
            &["add-generic-password", "-U", "-s", SERVICE, "-a", ACCOUNT, "-w", secret],
            None,
        )
        .map(|result| result.code == 0)
        .unwrap_or(false),
        _ => run(
            "secret-tool",
            &["store", &format!("--label={SERVICE} dotenvx key"), "service", SERVICE, "account", ACCOUNT],
            Some(secret),
        )
        .map(|result| result.code == 0)
        .unwrap_or(false),
    }
}

/// Outcome of a keychain removal (mirrors src/keychain.ts KeychainDeleteResult).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeychainDeleteResult {
    /// The delete tool exited 0.
    Deleted,
    /// The tool failed or could not be spawned: the item may be absent (macOS
    /// reports missing items as failure) or may still exist — callers warn.
    Unconfirmed,
    /// No secret service answered: the item's state is unknown, probably present.
    Unavailable,
}

/// Best-effort removal that never panics and never no-ops silently (the Rust
/// side has always been infallible; the return value now says what happened).
pub fn keychain_delete() -> KeychainDeleteResult {
    if !secret_service_available() {
        return KeychainDeleteResult::Unavailable;
    }
    let result = match platform() {
        "darwin" => run("security", &["delete-generic-password", "-s", SERVICE, "-a", ACCOUNT], None),
        _ => run("secret-tool", &["clear", "service", SERVICE, "account", ACCOUNT], None),
    };
    match result {
        Ok(output) if output.code == 0 => KeychainDeleteResult::Deleted,
        Ok(_) => KeychainDeleteResult::Unconfirmed,
        Err(_) => KeychainDeleteResult::Unconfirmed,
    }
}

/// The one warning every keychain-removal path owes the operator when the
/// item's deletion could not be confirmed (mirrors src/keychain.ts
/// warnIfKeychainItemSurvived). `file_custody` — true when `.env.keys`
/// existed at deletion time — silences the Unavailable case: on a machine
/// whose secret service never answers, custody was necessarily the file and
/// no keychain item can exist to warn about.
pub fn warn_if_keychain_item_survived(result: KeychainDeleteResult, file_custody: bool) {
    match result {
        KeychainDeleteResult::Deleted => {}
        KeychainDeleteResult::Unavailable if file_custody => {}
        KeychainDeleteResult::Unavailable => eprintln!(
            "the keychain item could not be confirmed deleted (no secret service answered) — if present, remove it with: secret-tool clear service {SERVICE} account {ACCOUNT}"
        ),
        KeychainDeleteResult::Unconfirmed => eprintln!(
            "the keychain item could not be confirmed deleted (the delete command failed) — if present, remove it with: secret-tool clear service {SERVICE} account {ACCOUNT}"
        ),
    }
}
