//! Port of `src/paths.ts` — the config directory and its file layout.

use std::path::{Path, PathBuf};

use crate::env::{assert_api_url, assert_plain_env_value};
use crate::errors::UserError;

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

/// Serialize every test that resolves paths through the config override.
/// with_config_dir guards only the set/restore of the override, not the
/// closure: two modules' closures running concurrently would re-point the
/// global override under each other and resolve into each other's
/// directories. Every config-dir test takes this one process-wide lock for
/// its whole closure (the per-module mutexes this replaces did not
/// serialize across modules).
#[cfg(test)]
pub(crate) fn lock_config_for_tests() -> std::sync::MutexGuard<'static, ()> {
    static CONFIG_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    CONFIG_TEST_LOCK.lock().expect("config test lock")
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

/// Create the config directory (and the `.env` template) or explain the
/// failure — a missing parent, a read-only HOME, or a full disk must reach
/// the terminal as a message, not a panic.
pub fn ensure_config_dir() -> Result<PathBuf, UserError> {
    let dir = config_dir();
    std::fs::create_dir_all(&dir).map_err(|error| {
        UserError(format!(
            "could not create the config directory at {} — check that its parent is writable and the disk is not full ({error})",
            dir.display()
        ))
    })?;
    set_mode_700(&dir);
    if !env_path().exists() {
        write_secret_file(&env_path(), &format!("SN_EMAIL=\nSN_API_URL={DEFAULT_API_URL}\n")).map_err(|error| {
            UserError(format!(
                "could not write the .env template at {} — check that the directory is writable and the disk is not full ({error})",
                env_path().display()
            ))
        })?;
    }
    set_mode_600(&env_path());
    Ok(dir)
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
/// O_NOFOLLOW at 0600, fully written and mode-asserted, fsync-ed, then
/// atomically renamed over the destination, and the parent directory is
/// fsync-ed so the rename itself survives a power cut — a crash or power
/// loss never leaves a half-written secret, and a planted symlink at the
/// destination is replaced, never written through. (Port of the TS
/// `writePrivateFileSync`, hardened with the durability the TS code lacks.)
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
        })
        // sync_all, not sync_data: the mode change rides the same flush.
        .and_then(|()| file.sync_all());
    drop(file);
    match outcome {
        Ok(()) => rename_and_sync_dir(&tmp, path),
        Err(error) => {
            let _ = std::fs::remove_file(&tmp);
            Err(error)
        }
    }
}

fn rename_and_sync_dir(tmp: &Path, path: &Path) -> std::io::Result<()> {
    match std::fs::rename(tmp, path) {
        Ok(()) => {
            // The rename landed and the file itself is already fsynced, so
            // the write succeeded. A directory-entry fsync failure (some
            // FUSE/network mounts return EINVAL) only costs durability of
            // the rename, not the write — reporting it would make every
            // caller treat an on-disk file as a failure ("Err means nothing
            // was written"), so it stays best-effort.
            let _ = sync_parent_dir(path);
            Ok(())
        }
        Err(error) => {
            let _ = std::fs::remove_file(tmp);
            Err(error)
        }
    }
}

/// fsync the directory holding `path` — the rename is only as durable as the
/// directory entry carrying it. Best-effort: callers never see its errors.
fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::File::open(parent)?.sync_all()
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

pub fn read_plain_config() -> Result<PlainConfig, UserError> {
    ensure_config_dir()?;
    let parsed = parse_env_file(&std::fs::read_to_string(env_path()).unwrap_or_default());
    let lookup = |name: &str| parsed.iter().find(|(key, _)| key == name).map(|(_, value)| value.clone());
    // `||`, not `??`: the template .env writes an empty SN_EMAIL=, and a value
    // set in the environment must win over that placeholder.
    let email = lookup("SN_EMAIL").filter(|value| !value.is_empty()).or_else(|| env_value("SN_EMAIL")).unwrap_or_default();
    let api_url = lookup("SN_API_URL")
        .filter(|value| !value.is_empty())
        .or_else(|| env_value("SN_API_URL"))
        .unwrap_or_else(|| DEFAULT_API_URL.to_string());
    let normalized = api_url.trim_end_matches('/').to_string();
    // Config load is the gate every network command passes through: no
    // plaintext HTTP to a remote host. (Callers that must survive a broken
    // config — logout — catch this and fall back to the default host.)
    assert_api_url(&normalized)?;
    Ok(PlainConfig { email, api_url: normalized })
}

pub fn write_plain_config(email: Option<&str>, api_url: Option<&str>) -> Result<(), UserError> {
    ensure_config_dir()?;
    let current = read_plain_config()?;
    let email = email.unwrap_or(&current.email);
    let api_url = api_url.unwrap_or(&current.api_url);
    // The file is written unquoted; a control character here would forge
    // lines in the operator's .env. The URL gate applies at write time too,
    // so a plaintext remote never lands in the file in the first place (the
    // SNS_ALLOW_INSECURE_API escape hatch still applies, via assert_api_url).
    assert_plain_env_value("SN_EMAIL", email)?;
    assert_plain_env_value("SN_API_URL", api_url)?;
    assert_api_url(api_url)?;
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
    // The crash-safe path, not a direct write: a torn .env would lose the
    // operator lines every rewrite promises to carry through.
    write_secret_file(&env_path(), &out).map_err(|error| {
        UserError(format!(
            "could not write .env at {} — check that the directory is writable and the disk is not full ({error})",
            env_path().display()
        ))
    })?;
    set_mode_600(&env_path());
    Ok(())
}

/// The exact-name core of what sns creates in the config directory. purge and
/// delete_session own the crash-orphan temp spellings on top of these
/// (is_owned_session_file_name / is_owned_config_file_name); doctor's
/// unexpected-files check uses the same ownership test, so an orphan temp
/// reads as sns's own leftover, not a foreign file.
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

/// Sns-owned spellings of the session/keys files, including the crash-orphan
/// temps: write_secret_file stages `<path>.tmp-<pid>-<suffix>` and a crash
/// mid-write leaves the temp on disk — the `.env.keys` one carries the
/// plaintext session scalar. The suffix is one hash segment or one
/// `tmp-<pid>-<rand>`, so an operator's own `.env.session.bak.old` is NOT
/// claimed (mirrors src/paths.ts isOwnedSessionFileName).
pub fn is_owned_session_file_name(name: &str) -> bool {
    if name == ".env.session" || name == ".env.keys" {
        return true;
    }
    let Some(rest) = name
        .strip_prefix(".env.session.")
        .or_else(|| name.strip_prefix(".env.keys."))
    else {
        return false;
    };
    let suffix = match rest.strip_prefix("tmp-") {
        Some(after) => match after.split_once('-') {
            Some((pid, rand)) if !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()) => {
                if rand.is_empty() {
                    return false;
                }
                rand
            }
            _ => return false,
        },
        None => rest,
    };
    !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// purge's ownership test: the exact KNOWN_CONFIG_FILES names plus the orphan temps.
pub fn is_owned_config_file_name(name: &str) -> bool {
    KNOWN_CONFIG_FILES.contains(&name) || is_owned_session_file_name(name)
}

pub fn unexpected_config_files() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(config_dir()) else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| !is_owned_config_file_name(name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A regular file sitting where the config directory should go makes
    /// every create fail with ENOTDIR — for root and non-root alike, so the
    /// unwritable-HOME shape is deterministic in tests. Every config-dir
    /// entry point must answer a UserError, never a panic.
    fn blocked_dir(tag: &str) -> String {
        let dir = std::env::temp_dir().join(format!("sns-paths-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp root creates");
        let blocker = dir.join("blocker");
        std::fs::write(&blocker, b"").expect("blocker file writes");
        blocker.join("sn_secrets_cli").display().to_string()
    }

    #[test]
    fn a_broken_config_dir_is_a_user_error_not_a_panic() {
        let dir = blocked_dir("ensure");
        let _serial = lock_config_for_tests();
        with_config_dir(&dir, || {
            let error = ensure_config_dir().expect_err("creation fails with a message");
            assert!(error.0.contains(&dir), "message names the path: {}", error.0);
            assert!(error.0.contains("could not create the config directory"), "got: {}", error.0);
            // the read path carries the same failure instead of a panic
            assert!(read_plain_config().is_err());
        });
    }

    #[test]
    fn write_plain_config_reports_a_broken_config_dir_instead_of_panicking() {
        let dir = blocked_dir("write");
        let _serial = lock_config_for_tests();
        with_config_dir(&dir, || {
            let error = write_plain_config(Some("a@b.c"), None).expect_err("write fails with a message");
            assert!(error.0.contains("writable"), "message is actionable: {}", error.0);
        });
    }

    /// The https gate rides config load in both binaries (the plain .env is
    /// shared): a plaintext remote refused, a loopback host allowed.
    #[test]
    fn read_plain_config_enforces_the_api_url_gate() {
        let dir = std::env::temp_dir().join(format!("sns-paths-gate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp root creates");
        let _serial = lock_config_for_tests();
        with_config_dir(&dir.display().to_string(), || {
            std::fs::write(env_path(), "SN_EMAIL=a@b.c\nSN_API_URL=http://api.example.com\n").expect(".env writes");
            let error = read_plain_config().expect_err("plaintext remote refused");
            assert!(error.0.contains("plaintext"), "got: {}", error.0);
            std::fs::write(env_path(), "SN_EMAIL=a@b.c\nSN_API_URL=http://localhost:3000\n").expect(".env writes");
            assert_eq!(read_plain_config().expect("loopback allowed").api_url, "http://localhost:3000");
        });
        let _ = std::fs::remove_dir_all(&dir);
    }
}
