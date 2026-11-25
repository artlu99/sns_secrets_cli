//! Custody transport for the session private key: one OS secret-service slot
//! (`service=sn_secrets_cli`, `account=dotenvkey`), reached through the same
//! CLI tools on every platform — `secret-tool` on Linux, the `security` CLI
//! on macOS — run with the scrubbed environment. The direction that matters:
//! writes hand the tool the secret over stdin (`secret-tool`'s stdin, or
//! `security -i`, the tool's stdin command mode), so no argument list ever
//! carries it; reads take it from the tool's stdout, the only retrieval
//! transport those tools offer — the same crossing the TypeScript CLI makes,
//! and inside the same-user boundary that could run the lookup itself.

const SERVICE: &str = "sn_secrets_cli";
const ACCOUNT: &str = "dotenvkey";

use std::process::Stdio;

use crate::env::{scrubbed_command, which};

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

/// True when the keychain must never be touched: the in-process test flag,
/// or the TS-parity `SNS_DISABLE_KEYCHAIN=1` environment variable. The env
/// var is what covers spawned processes (the e2e binary runs under it) —
/// the atomic cannot cross a process boundary; reading an env var is safe
/// where setting one is not, which is why the flag exists at all.
fn disabled() -> bool {
    TEST_DISABLE.load(AtomicOrdering::Relaxed)
        || std::env::var("SNS_DISABLE_KEYCHAIN").is_ok_and(|value| value == "1")
}

/// Test escape hatch — the port of the TS `SNS_DISABLE_KEYCHAIN` guard.
/// Storing the key is an upsert, so a test calling save_session or purge
/// would clobber the developer's real keychain entry on every platform.
/// An atomic instead of the env var because edition 2024 marks `set_var`
/// unsafe in multi-threaded test binaries.
pub fn disable_for_tests() {
    TEST_DISABLE.store(true, AtomicOrdering::Relaxed);
}

/// The OS secret service answered. A missing item still counts as available.
pub fn secret_service_available() -> bool {
    if disabled() {
        return false;
    }
    if cfg!(target_os = "macos") {
        // TS parity: on macOS the only question is whether the `security`
        // tool is on PATH — the login keychain is part of every macOS user
        // session, and there is no daemon probe to make.
        which("security")
    } else {
        linux_service_answered()
    }
}

fn linux_service_answered() -> bool {
    if !which("secret-tool") {
        return false;
    }
    match run("secret-tool", &["lookup", "service", SERVICE, "account", "__sns_probe__"], None) {
        Ok(result) => probe_result(&result.stderr, result.code),
        Err(_) => false,
    }
}

fn strip_trailing_newline(text: &str) -> String {
    text.strip_suffix('\n').unwrap_or(text).to_string()
}

pub fn keychain_get() -> Option<String> {
    // The disable guard is checked here directly: unlike put/delete this read
    // never calls secret_service_available (no probe — a missing tool or a
    // dead service fails the lookup below and maps to None either way, and
    // the probe would only add a second spawn to every cache-touching
    // command), so without this check a test on a machine with a live secret
    // service would read the developer's real session key.
    if disabled() {
        return None;
    }
    if cfg!(target_os = "macos") {
        // Same transport as the TypeScript CLI: the key comes back on the
        // tool's stdout (its only retrieval form), one trailing newline off.
        let result = run(
            "security",
            &["find-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w"],
            None,
        )
        .ok()?;
        if result.code != 0 {
            return None;
        }
        return Some(strip_trailing_newline(&result.stdout));
    }
    let result = run("secret-tool", &["lookup", "service", SERVICE, "account", ACCOUNT], None).ok()?;
    if result.code != 0 {
        return None;
    }
    Some(strip_trailing_newline(&result.stdout))
}

pub fn keychain_put(secret: &str) -> bool {
    if !secret_service_available() {
        return false;
    }
    if cfg!(target_os = "macos") {
        // The key must not sit in an argument list: `security -i` is the
        // tool's documented interactive mode — it reads commands from stdin
        // (the prompt appears only on a tty; exit status is the status of
        // the last command) — so the secret transits one anonymous pipe
        // instead of argv, where every same-user process could read it.
        // The line is argv-tokenized by the tool's own quoting rules;
        // SERVICE/ACCOUNT and the 64-hex key need no quoting, and -v must
        // never be added (verbose echoes every argument, including the -w
        // value, to stderr). `add-generic-password -U` upserts, so items
        // the other binary or the dotenvx CLI wrote are replaced in place.
        return run(
            "security",
            &["-i"],
            Some(&format!("add-generic-password -U -s {SERVICE} -a {ACCOUNT} -w {secret}\n")),
        )
        .map(|result| result.code == 0)
        .unwrap_or(false);
    }
    run(
        "secret-tool",
        &["store", &format!("--label={SERVICE} dotenvx key"), "service", SERVICE, "account", ACCOUNT],
        Some(secret),
    )
    .map(|result| result.code == 0)
    .unwrap_or(false)
}

/// Outcome of a keychain removal (mirrors src/keychain.ts KeychainDeleteResult).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeychainDeleteResult {
    /// The delete tool exited 0.
    Deleted,
    /// The delete failed or could not be attempted: on macOS a missing item
    /// also lands here (the security tool reports missing items as failure)
    /// — callers warn either way, on both binaries.
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
    if cfg!(target_os = "macos") {
        let result = run("security", &["delete-generic-password", "-s", SERVICE, "-a", ACCOUNT], None);
        return match result {
            Ok(output) if output.code == 0 => KeychainDeleteResult::Deleted,
            _ => KeychainDeleteResult::Unconfirmed,
        };
    }
    let result = run("secret-tool", &["clear", "service", SERVICE, "account", ACCOUNT], None);
    match result {
        Ok(output) if output.code == 0 => KeychainDeleteResult::Deleted,
        _ => KeychainDeleteResult::Unconfirmed,
    }
}

/// The one warning every keychain-removal path owes the operator when the
/// item's deletion could not be confirmed (mirrors src/keychain.ts
/// warnIfKeychainItemSurvived). `file_custody` — true when `.env.keys`
/// existed at deletion time — silences the Unavailable case: on a machine
/// whose secret service never answers, custody was necessarily the file and
/// no keychain item can exist to warn about.
pub fn warn_if_keychain_item_survived(result: KeychainDeleteResult, file_custody: bool) {
    let tool = if cfg!(target_os = "macos") {
        format!("security delete-generic-password -s {SERVICE} -a {ACCOUNT}")
    } else {
        format!("secret-tool clear service {SERVICE} account {ACCOUNT}")
    };
    match result {
        KeychainDeleteResult::Deleted => {}
        KeychainDeleteResult::Unavailable if file_custody => {}
        KeychainDeleteResult::Unavailable => eprintln!(
            "the keychain item could not be confirmed deleted (no secret service answered) — if present, remove it with: {tool}"
        ),
        KeychainDeleteResult::Unconfirmed => eprintln!(
            "the keychain item could not be confirmed deleted (the delete command failed) — if present, remove it with: {tool}"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_disable_guard_keeps_every_keychain_read_off_the_real_secret_service() {
        disable_for_tests();
        // On a machine with a live secret service these must come back
        // empty — the guard short-circuits before any spawn, so a test can
        // never trial-decrypt against the developer's real session key.
        // On machines without a service the same assertions hold vacuously;
        // the invariant is pinned either way.
        assert_eq!(keychain_get(), None);
        assert!(!secret_service_available());
        assert_eq!(keychain_delete(), KeychainDeleteResult::Unavailable);
        assert!(!keychain_put("never-stored-anywhere"));
    }
}
