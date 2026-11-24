//! Custody transport for the session private key: one OS secret-service slot
//! (`service=sn_secrets_cli`, `account=dotenvkey`). Linux speaks to the
//! secret service through `secret-tool` — label arguments only, the secret
//! itself rides stdin. macOS speaks SecItem in-process through
//! security-framework: no subprocess, so no argv and no child stdio ever
//! carry the key. (The TypeScript CLI keeps the `security` tool on macOS,
//! driving writes through the tool's stdin command mode; this crate does not
//! spawn it anywhere.)

const SERVICE: &str = "sn_secrets_cli";
const ACCOUNT: &str = "dotenvkey";

#[cfg(target_os = "macos")]
mod mac_keychain {
    use security_framework::passwords;
    use security_framework_sys::base::errSecItemNotFound;

    use super::{ACCOUNT, KeychainDeleteResult, SERVICE};

    /// The stored scalar, straight out of SecItem — no CLI trailing newline
    /// to strip, no stdout involved.
    pub(super) fn get() -> Option<String> {
        match passwords::get_generic_password(SERVICE, ACCOUNT) {
            Ok(bytes) => Some(String::from_utf8_lossy(&bytes).into_owned()),
            Err(_) => None,
        }
    }

    /// SecItemAdd, which upserts: on errSecDuplicateItem only the value data
    /// is updated — the same semantics as `security add-generic-password -U`,
    /// against the same class+service+account query, so items the CLI tools
    /// wrote are replaced in place and items this writes are readable by them.
    pub(super) fn put(secret: &str) -> bool {
        passwords::set_generic_password(SERVICE, ACCOUNT, secret.as_bytes()).is_ok()
    }

    /// A missing item counts as deleted: nothing to remove is the outcome
    /// every caller wants, and SecItemNotFound is that, not a failure.
    pub(super) fn delete() -> KeychainDeleteResult {
        match passwords::delete_generic_password(SERVICE, ACCOUNT) {
            Ok(()) => KeychainDeleteResult::Deleted,
            Err(error) if error.code() == errSecItemNotFound => KeychainDeleteResult::Deleted,
            Err(_) => KeychainDeleteResult::Unconfirmed,
        }
    }
}

#[cfg(not(target_os = "macos"))]
use std::process::Stdio;

#[cfg(not(target_os = "macos"))]
use crate::env::{scrubbed_command, which};

#[cfg(not(target_os = "macos"))]
struct RunResult {
    code: i32,
    stdout: String,
    stderr: String,
}

#[cfg(not(target_os = "macos"))]
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

#[cfg(not(target_os = "macos"))]
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
    #[cfg(target_os = "macos")]
    {
        // SecItem is linked into this binary; the login keychain is part of
        // every macOS user session, and there is no daemon probe to make.
        return true;
    }
    #[cfg(not(target_os = "macos"))]
    {
        linux_service_answered()
    }
}

#[cfg(not(target_os = "macos"))]
fn linux_service_answered() -> bool {
    if !which("secret-tool") {
        return false;
    }
    match run("secret-tool", &["lookup", "service", SERVICE, "account", "__sns_probe__"], None) {
        Ok(result) => probe_result(&result.stderr, result.code),
        Err(_) => false,
    }
}

#[cfg(not(target_os = "macos"))]
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
    #[cfg(target_os = "macos")]
    {
        return mac_keychain::get();
    }
    #[cfg(not(target_os = "macos"))]
    {
        let result = run("secret-tool", &["lookup", "service", SERVICE, "account", ACCOUNT], None).ok()?;
        if result.code != 0 {
            return None;
        }
        Some(strip_trailing_newline(&result.stdout))
    }
}

pub fn keychain_put(secret: &str) -> bool {
    if !secret_service_available() {
        return false;
    }
    #[cfg(target_os = "macos")]
    {
        return mac_keychain::put(secret);
    }
    #[cfg(not(target_os = "macos"))]
    {
        run(
            "secret-tool",
            &["store", &format!("--label={SERVICE} dotenvx key"), "service", SERVICE, "account", ACCOUNT],
            Some(secret),
        )
        .map(|result| result.code == 0)
        .unwrap_or(false)
    }
}

/// Outcome of a keychain removal (mirrors src/keychain.ts KeychainDeleteResult).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeychainDeleteResult {
    /// The delete tool exited 0 (in-process SecItem on macOS: the item is
    /// gone, and a missing item counts here too — deleting nothing succeeded).
    Deleted,
    /// The delete failed or could not be attempted: on the TypeScript CLI's
    /// macOS route a missing item also lands here (the security tool reports
    /// missing items as failure) — callers warn either way.
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
    #[cfg(target_os = "macos")]
    {
        return mac_keychain::delete();
    }
    #[cfg(not(target_os = "macos"))]
    {
        let result = run("secret-tool", &["clear", "service", SERVICE, "account", ACCOUNT], None);
        match result {
            Ok(output) if output.code == 0 => KeychainDeleteResult::Deleted,
            Ok(_) => KeychainDeleteResult::Unconfirmed,
            Err(_) => KeychainDeleteResult::Unconfirmed,
        }
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
