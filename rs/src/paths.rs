//! Port of `src/paths.ts` — the config directory and its file layout.

use std::path::{Path, PathBuf};

pub const DEFAULT_API_URL: &str = "https://api.standardnotes.com";

/// The per-process override used by tests; real invocations read the
/// environment once in `config_dir`.
static CONFIG_OVERRIDE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Tests use this so concurrent cases do not share SNS_CONFIG_DIR.
pub fn with_config_dir<T>(dir: &str, run: impl FnOnce() -> T) -> T {
    let mut guard = CONFIG_OVERRIDE.lock().expect("config override lock");
    let previous = guard.take();
    *guard = Some(dir.to_string());
    drop(guard);
    let result = run();
    let mut guard = CONFIG_OVERRIDE.lock().expect("config override lock");
    *guard = previous;
    result
}

pub fn config_dir() -> PathBuf {
    let guard = CONFIG_OVERRIDE.lock().expect("config override lock");
    if let Some(overridden) = guard.as_ref() {
        return PathBuf::from(overridden);
    }
    drop(guard);
    let override_value = std::env::var("SNS_CONFIG_DIR").unwrap_or_default();
    if !override_value.trim().is_empty() {
        return PathBuf::from(override_value);
    }
    home_dir().join(".config").join("sn_secrets_cli")
}

fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

pub fn env_path() -> PathBuf {
    config_dir().join(".env")
}

pub fn session_path() -> PathBuf {
    config_dir().join(".env.session")
}

pub fn keys_path() -> PathBuf {
    config_dir().join(".env.keys")
}

pub fn db_path() -> PathBuf {
    config_dir().join("cache.db")
}

pub fn lock_path() -> PathBuf {
    config_dir().join("sync.lock")
}

pub fn clipboard_marker_path() -> PathBuf {
    config_dir().join("clipboard-clear-at")
}

pub fn ensure_config_dir() -> PathBuf {
    let dir = config_dir();
    std::fs::create_dir_all(&dir).expect("config directory creates");
    set_mode_700(&dir);
    if !env_path().exists() {
        std::fs::write(env_path(), format!("SN_EMAIL=\nSN_API_URL={DEFAULT_API_URL}\n")).expect("env template writes");
        set_mode_600(&env_path());
    }
    set_mode_600(&env_path());
    dir
}

#[cfg(unix)]
fn set_mode_700(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}

/// Mode 0600 for secrets-bearing files in the config dir (`.env`,
/// `.env.session`, `.env.keys`).
#[cfg(unix)]
pub(crate) fn set_mode_600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn set_mode_700(_path: &Path) {}
#[cfg(not(unix))]
fn set_mode_600(_path: &Path) {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlainConfig {
    pub email: String,
    pub api_url: String,
}

fn parse_env_file(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.split('\n') {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some(eq) = trimmed.find('=') else { continue };
        if eq == 0 {
            continue;
        }
        let key = trimmed[..eq].trim().to_string();
        let mut value = trimmed[eq + 1..].trim().to_string();
        if (value.starts_with('"') && value.ends_with('"') && value.len() >= 2)
            || (value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2)
        {
            value = value[1..value.len() - 1].to_string();
        }
        out.push((key, value));
    }
    out
}

fn env_value(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

pub fn read_plain_config() -> PlainConfig {
    ensure_config_dir();
    let parsed = parse_env_file(&std::fs::read_to_string(env_path()).unwrap_or_default());
    let lookup = |name: &str| parsed.iter().find(|(key, _)| key == name).map(|(_, value)| value.clone());
    // `||`, not `??`: the template .env writes an empty SN_EMAIL=, and a value
    // set in the environment must win over that placeholder.
    let email = lookup("SN_EMAIL").filter(|value| !value.is_empty()).or_else(|| env_value("SN_EMAIL")).unwrap_or_default();
    let api_url = lookup("SN_API_URL")
        .filter(|value| !value.is_empty())
        .or_else(|| env_value("SN_API_URL"))
        .unwrap_or_else(|| DEFAULT_API_URL.to_string());
    PlainConfig { email, api_url: api_url.trim_end_matches('/').to_string() }
}

pub fn write_plain_config(email: Option<&str>, api_url: Option<&str>) {
    ensure_config_dir();
    let current = read_plain_config();
    let email = email.unwrap_or(&current.email);
    let api_url = api_url.unwrap_or(&current.api_url);
    std::fs::write(env_path(), format!("SN_EMAIL={email}\nSN_API_URL={api_url}\n")).expect("plain config writes");
    set_mode_600(&env_path());
}

const ALLOWED_CONFIG_FILES: [&str; 9] = [
    ".env",
    ".env.session",
    ".env.keys",
    "cache.db",
    "cache.db-journal",
    "cache.db-wal",
    "cache.db-shm",
    "sync.lock",
    "clipboard-clear-at",
];

pub fn unexpected_config_files() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(config_dir()) else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| !ALLOWED_CONFIG_FILES.contains(&name.as_str()))
        .collect()
}
