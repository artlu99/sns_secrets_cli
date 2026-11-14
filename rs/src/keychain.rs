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
    } else if cfg!(windows) {
        "windows"
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

/// The OS secret service answered. A missing item still counts as available.
pub fn secret_service_available() -> bool {
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

pub fn keychain_delete() {
    if !secret_service_available() {
        return;
    }
    let _ = match platform() {
        "darwin" => run("security", &["delete-generic-password", "-s", SERVICE, "-a", ACCOUNT], None),
        _ => run("secret-tool", &["clear", "service", SERVICE, "account", ACCOUNT], None),
    };
}
