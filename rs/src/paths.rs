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

fn set_mode_700(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}

/// Mode 0600 for secrets-bearing files in the config dir (`.env`,
/// `.env.session`, `.env.keys`).
pub(crate) fn set_mode_600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

/// Write a secrets-bearing file crash-safe: a temp file is created O_EXCL|
/// O_NOFOLLOW at 0600, fully written and mode-asserted, then atomically
/// renamed over the destination — a crash never leaves a half-written
/// secret, and a planted symlink at the destination is replaced, never
/// written through. (Port of the TS `writePrivateFileSync`.)
pub(crate) fn write_secret_file(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let suffix = random_suffix();
    let tmp = PathBuf::from(format!("{}.tmp-{}-{suffix}", path.display(), std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)?;
    let outcome = file
        .write_all(contents.as_bytes())
        .and_then(|()| {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
        });
    drop(file);
    match outcome {
        Ok(()) => rename_or_cleanup(&tmp, path),
        Err(error) => {
            let _ = std::fs::remove_file(&tmp);
            Err(error)
        }
    }
}

fn rename_or_cleanup(tmp: &Path, path: &Path) -> std::io::Result<()> {
    match std::fs::rename(tmp, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = std::fs::remove_file(tmp);
            Err(error)
        }
    }
}

fn random_suffix() -> String {
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).expect("system rng");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

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
    // Operators keep hand-added lines: every rewrite carries them through
    // instead of truncating the file to the two keys this program owns.
    // (Port of the TS writePlainConfig preservation.)
    const OWNED: [&str; 2] = ["SN_EMAIL", "SN_API_URL"];
    let mut preserved: Vec<String> = Vec::new();
    if let Ok(text) = std::fs::read_to_string(env_path()) {
        for line in text.split('\n') {
            let trimmed = line.trim_start();
            let owned = OWNED
                .iter()
                .any(|key| trimmed.starts_with(key) && trimmed[key.len()..].trim_start().starts_with('='));
            if !owned {
                preserved.push(line.to_string());
            }
        }
    }
    let mut out = format!("SN_EMAIL={email}\nSN_API_URL={api_url}\n");
    let tail = preserved.join("\n");
    let tail = tail.trim_end_matches('\n');
    if !tail.is_empty() {
        out.push_str(tail);
        out.push('\n');
    }
    std::fs::write(env_path(), out).expect("plain config writes");
    set_mode_600(&env_path());
}

/// Every file sns creates in the config directory. `sns purge` deletes
/// exactly these; anything else is left in place and named (the same set
/// doctor's unexpected-files check flags).
pub const KNOWN_CONFIG_FILES: [&str; 9] = [
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
        .filter(|name| !KNOWN_CONFIG_FILES.contains(&name.as_str()))
        .collect()
}
