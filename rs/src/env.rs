//! Port of `src/env.ts` — the launch-environment scrubber. Secret-named
//! variables are dropped from the process environment at startup and their
//! names recorded so `sns doctor` can report them; child processes spawn
//! with the scrubbed map.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::errors::UserError;

const PUBLIC_SN_ENV: [&str; 2] = ["SN_EMAIL", "SN_API_URL"];

/// True when a process environment name carries credential material.
pub fn is_secret_env_name(name: &str) -> bool {
    if name == "DOTENV_KEY" || name.starts_with("DOTENV_PRIVATE_KEY") {
        return true;
    }
    if name == "SNS_SESSION_PRIVATE_KEY" {
        return true;
    }
    name.starts_with("SN_") && !PUBLIC_SN_ENV.contains(&name)
}

/// A child process starts with secret-named variables removed, plus every
/// `SNS_` knob — pager, clipboard, and keychain children never need this
/// program's own settings, and a reserved namespace must not leak even its
/// non-secret values. (The launch scrub keeps the knobs: this process reads
/// them itself.)
fn is_child_env_secret(name: &str) -> bool {
    is_secret_env_name(name) || name.starts_with("SNS_")
}

pub fn scrubbed_env() -> HashMap<String, String> {
    std::env::vars().filter(|(key, _)| !is_child_env_secret(key)).collect()
}

/// A child-process `Command` with the scrubbed environment pre-applied. The
/// `env_clear()` + `envs(scrubbed_env())` pairing is the security property
/// doctor's scrub check probes; this keeps new spawn sites from half-copying
/// it (`envs(scrubbed_env())` alone still leaks the launch env).
pub fn scrubbed_command(bin: &str) -> std::process::Command {
    let mut command = std::process::Command::new(bin);
    command.env_clear().envs(scrubbed_env());
    command
}

/// `Bun.which` — a PATH walk with one stat per candidate, true only when the
/// entry is a regular file with an exec bit (unix).
pub fn which(bin: &str) -> bool {
    std::env::var("PATH").unwrap_or_default().split(':').any(|dir| {
        let candidate = std::path::Path::new(dir).join(bin);
        std::fs::metadata(&candidate)
            .map(|meta| {
                use std::os::unix::fs::PermissionsExt;
                meta.is_file() && meta.permissions().mode() & 0o111 != 0
            })
            .unwrap_or(false)
    })
}

/// `scrubbedEnv(base)` for probes that need a doctored copy of the current
/// environment.
pub fn scrubbed_env_with(base: &HashMap<String, String>) -> HashMap<String, String> {
    base.iter().filter(|(key, _)| !is_child_env_secret(key)).map(|(key, value)| (key.clone(), value.clone())).collect()
}

static SCRUBBED_NAMES: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Secret-named variables the launch environment carried, recorded by
/// `scrub_process_env`. Names only — the values are gone for good.
pub fn scrubbed_env_names() -> Vec<String> {
    SCRUBBED_NAMES.lock().expect("scrubbed names lock").clone()
}

/// Drop secret-named variables bun or a parent shell may have loaded.
pub fn scrub_process_env() {
    // Safe here by contract: this runs once at startup, before any thread
    // that could concurrently read the environment exists.
    for (key, _) in std::env::vars() {
        if is_secret_env_name(&key) {
            // SAFETY: single-threaded startup, no other env readers yet.
            unsafe {
                std::env::remove_var(&key);
            }
            let mut names = SCRUBBED_NAMES.lock().expect("scrubbed names lock");
            if !names.contains(&key) {
                names.push(key);
            }
        }
    }
}

/// Tests only: forget recorded names so a suite starts from a clean state.
pub fn clear_scrubbed_env_names() {
    SCRUBBED_NAMES.lock().expect("scrubbed names lock").clear();
}

/// Plain .env values are written unquoted (`SN_EMAIL=${email}`), so a control
/// character would forge additional lines in a file the operator reads and
/// edits. Reject rather than escape: a value that needs dotenvx quoting has
/// no business in the two keys sns owns. (Port of the TS
/// `assertPlainEnvValue`.)
pub fn assert_plain_env_value(name: &str, value: &str) -> Result<(), UserError> {
    if value.chars().any(|ch| ch <= '\u{1f}' || ch == '\u{7f}') {
        return Err(UserError(format!("{name} contains a control character — refusing to write it to .env")));
    }
    Ok(())
}

fn is_loopback_host(parsed: &url::Url) -> bool {
    // WHATWG parity with the TS check: the literal names only, brackets
    // stripped, case-folded — not the whole loopback ranges.
    let Some(host) = parsed.host_str() else { return false };
    let name = host.trim_start_matches('[').trim_end_matches(']').to_lowercase();
    name == "localhost" || name == "127.0.0.1" || name == "::1"
}

/// The API URL carries the refresh token and every sync across the network:
/// refuse plaintext HTTP to a non-loopback host at config load. Loopback is
/// allowed (local development against a local server never leaves the
/// machine), and `SNS_ALLOW_INSECURE_API=1` is the operator's explicit
/// escape hatch for a self-hosted plaintext endpoint. (Port of the TS
/// `assertApiUrl` — the plain .env is shared between the binaries, so the
/// gate must protect both.)
pub fn assert_api_url(url: &str) -> Result<(), UserError> {
    let escape_hatch = std::env::var("SNS_ALLOW_INSECURE_API").as_deref() == Ok("1");
    assert_api_url_with_hatch(url, escape_hatch)
}

/// The gate with the escape hatch injected, so tests exercise the whole
/// matrix without mutating the process environment (tests in a binary run
/// in parallel threads).
fn assert_api_url_with_hatch(url: &str, escape_hatch: bool) -> Result<(), UserError> {
    if url.is_empty() {
        return Ok(());
    }
    let parsed = url::Url::parse(url).map_err(|_| UserError(format!("SN_API_URL is not a valid URL ({url})")))?;
    if parsed.scheme() == "https" {
        return Ok(());
    }
    if parsed.scheme() != "http" {
        return Err(UserError(format!(
            "SN_API_URL must use https or http (got {})",
            parsed.scheme()
        )));
    }
    if escape_hatch {
        return Ok(());
    }
    if is_loopback_host(&parsed) {
        return Ok(());
    }
    Err(UserError(
        "SN_API_URL is http on a non-loopback host — the refresh token would cross the network in plaintext; use https, a loopback host, or set SNS_ALLOW_INSECURE_API=1 to accept the risk".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_names_are_recognized_wherever_they_appear() {
        for name in [
            "SN_DB_KEY",
            "SN_REFRESH_TOKEN",
            "SN_ACCESS_COOKIE",
            "SN_PASSWORD",
            "DOTENV_KEY",
            "DOTENV_PRIVATE_KEY_SESSION",
            "SNS_SESSION_PRIVATE_KEY",
        ] {
            assert!(is_secret_env_name(name), "{name} is a secret name");
        }
        // the two public names, and everything unrelated, are not secrets
        for name in ["SN_EMAIL", "SN_API_URL", "PATH", "HOME", "LANG"] {
            assert!(!is_secret_env_name(name), "{name} is not a secret name");
        }
    }

    /// The child map drops the whole reserved `SNS_` namespace — the session
    /// private key included — even though the launch scrub must keep the
    /// knobs (`SNS_CONFIG_DIR` is read by this process, never handed on).
    #[test]
    fn the_child_environment_drops_the_whole_sns_namespace() {
        let mut base: HashMap<String, String> = HashMap::new();
        base.insert("PATH".into(), "/usr/bin".into());
        base.insert("SN_EMAIL".into(), "me@example.test".into());
        base.insert("SNS_CONFIG_DIR".into(), "/tmp/somewhere".into());
        base.insert("SNS_SESSION_PRIVATE_KEY".into(), "64-hex-not-real".into());
        base.insert("SN_DB_KEY".into(), "64-hex-not-real".into());
        base.insert("DOTENV_PRIVATE_KEY_SESSION".into(), "dotenvx-key".into());
        let scrubbed = scrubbed_env_with(&base);
        // sorted: HashMap order is randomized per process
        let mut keys: Vec<&str> = scrubbed.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["PATH", "SN_EMAIL"]);
    }

    #[test]
    fn plain_env_values_reject_control_characters() {
        assert_plain_env_value("SN_EMAIL", "me@example.com").expect("plain value accepted");
        let error = assert_plain_env_value("SN_DB_KEY", "owned\nSN_DB_KEY=owned").expect_err("newline refused");
        assert!(error.0.contains("control character"), "got: {}", error.0);
        let error = assert_plain_env_value("SN_EMAIL", "tab\tstays?").expect_err("tab refused");
        assert!(error.0.contains("control character"), "got: {}", error.0);
    }

    /// The https gate, end to end: https always allowed, loopback http
    /// allowed, plaintext remote refused naming the escape hatch, the
    /// escape hatch accepted, other schemes and garbage refused.
    #[test]
    fn the_api_url_gate_enforces_https_unless_loopback_or_the_escape_hatch() {
        assert_api_url_with_hatch("https://api.standardnotes.com", false).expect("https allowed");
        assert_api_url_with_hatch("http://localhost:3000", false).expect("localhost allowed");
        assert_api_url_with_hatch("http://127.0.0.1:8080", false).expect("ipv4 loopback allowed");
        assert_api_url_with_hatch("http://[::1]:8080", false).expect("ipv6 loopback allowed");
        let error = assert_api_url_with_hatch("http://api.standardnotes.com", false).expect_err("plaintext refused");
        assert!(error.0.contains("plaintext"), "got: {}", error.0);
        assert!(error.0.contains("SNS_ALLOW_INSECURE_API"), "got: {}", error.0);
        let error = assert_api_url_with_hatch("ftp://api.standardnotes.com", false).expect_err("ftp refused");
        assert!(error.0.contains("https or http"), "got: {}", error.0);
        let error = assert_api_url_with_hatch("not a url", false).expect_err("garbage refused");
        assert!(error.0.contains("not a valid URL"), "got: {}", error.0);
        assert_api_url_with_hatch("http://api.standardnotes.com", true).expect("escape hatch accepted");
    }
}
