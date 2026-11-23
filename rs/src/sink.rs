//! Port of `src/commands/sink.ts` — `sns sink <id> <key> <path>`: the
//! sanctioned value-exit to a file for agent handoff. The file is 0600 from
//! the instant it exists; the value is never echoed; stdout is never a
//! destination; deleting the file is the reader's obligation.

use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use crate::commands::open_cache;
use crate::errors::UserError;
use crate::notes::{plan_copy, resolve_note, CopyPlan};

pub fn sink_command(id: &str, key: &str, path: &str, force: bool) -> Result<(), UserError> {
    let db = open_cache()?;
    let row = resolve_note(&db, id, false)?;
    let plan = plan_copy(&row, Some(key))?;
    let CopyPlan::Value { key, value } = plan else {
        // Unreachable with a required key — plan_copy throws for every other
        // outcome — but the union stays narrowed for the compiler.
        return Err(UserError("sink needs one KEY=VALUE setting — `sns copy <id>` lists a note's keys".into()));
    };
    if let Some(warning) = disk_backed_warning(path) {
        eprintln!("warning: {warning}");
    }
    write_handoff_file(&value, Path::new(path), force)?;
    println!("wrote {key} ({} bytes) → {path} (0600)", value.len());
    Ok(())
}

fn write_handoff_file(value: &str, path: &Path, force: bool) -> Result<(), UserError> {
    // lstat catches a symlink target with a clear message (the O_EXCL create
    // would surface it as EEXIST), and O_NOFOLLOW backs the --force reopen
    // where O_EXCL is absent. lstat-to-open is same-user-race territory,
    // outside the threat model.
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return Err(UserError(format!("{} is a symlink — refusing to write through it", path.display())));
    }
    create_parents_0700(path)?;
    let flags = libc::O_WRONLY | libc::O_CREAT | if force { libc::O_TRUNC } else { libc::O_EXCL } | libc::O_NOFOLLOW;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(force)
        .mode(0o600)
        .custom_flags(flags)
        .open(path)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::AlreadyExists => {
                UserError(format!("{} already exists — pass --force to overwrite", path.display()))
            }
            _ => UserError(error.to_string()),
        })?;
    let outcome = write_and_verify(&file, value, path);
    drop(file);
    // Any failure inside the write removes the partial file.
    match outcome {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = std::fs::remove_file(path);
            Err(error)
        }
    }
}

fn write_and_verify(file: &std::fs::File, value: &str, path: &Path) -> Result<(), UserError> {
    let mut file = file;
    // umask-proof: the mode at creation is masked by the umask, so assert it
    // explicitly before the first byte lands.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|error| UserError(error.to_string()))?;
    file.write_all(value.as_bytes()).map_err(|error| UserError(error.to_string()))?;
    // The handoff value is one-shot and irreplaceable (a fresh sink refuses
    // existing targets): the fd closes only after the bytes are on the device.
    file.sync_all().map_err(|error| UserError(error.to_string()))?;
    let meta = file.metadata().map_err(|error| UserError(error.to_string()))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(UserError(format!(
            "{} is not 0600 after the write (mode 0{:o}) — removing it",
            path.display(),
            mode
        )));
    }
    // write(2) may return a short count without erroring — never report a
    // secret as fully written when it is not on the disk.
    if meta.len() != value.len() as u64 {
        return Err(UserError(format!(
            "{} is truncated after the write ({} of {} bytes) — removing it",
            path.display(),
            meta.len(),
            value.len()
        )));
    }
    Ok(())
}

fn create_parents_0700(path: &Path) -> Result<(), UserError> {
    use std::os::unix::fs::DirBuilderExt as _;
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() || parent.exists() {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(parent)
        .map_err(|error| UserError(error.to_string()))?;
    // DirBuilder's mode is umask-masked; 0700 has no group/other bits to
    // strip, but assert it anyway.
    let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    Ok(())
}

/// One-line warning when the destination's filesystem is not tmpfs; none
/// when undetectable. statfs needs an existing path, so this walks up to the
/// nearest existing ancestor — the first sink into a brand-new handoff dir
/// is exactly the case the warning exists for. Linux only (the field the
/// warning reads, f_type, carries nothing usable on macOS).
#[cfg(target_os = "linux")]
fn disk_backed_warning(path: &str) -> Option<String> {
    let start = Path::new(path).parent()?;
    let mut dir: PathBuf = if start.as_os_str().is_empty() { PathBuf::from(".") } else { start.to_path_buf() };
    for _ in 0..8 {
        match statfs_type(&dir) {
            Ok(TMPFS_MAGIC) => return None,
            Ok(_) => {
                return Some(format!(
                    "{path} is on disk-backed storage — a handoff dir under $XDG_RUNTIME_DIR or /dev/shm leaves no disk remnants"
                ));
            }
            Err(_) => match dir.parent() {
                Some(parent) if parent != dir => dir = parent.to_path_buf(),
                _ => return None,
            },
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn disk_backed_warning(_path: &str) -> Option<String> {
    None
}

#[cfg(target_os = "linux")]
const TMPFS_MAGIC: i64 = 0x01021994;

/// The filesystem type id of the directory's mount, or an error when the
/// path is gone. FFI like lock.rs's flock: the wrapper owns the struct and
/// the raw pointer never escapes. f_type is c_long on glibc but u64 on
/// musl — widened to i64 so both targets compile; the values involved are
/// small positive constants.
#[cfg(target_os = "linux")]
fn statfs_type(dir: &Path) -> std::io::Result<i64> {
    let c_path = std::ffi::CString::new(dir.as_os_str().to_str().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path is not valid unicode")
    })?)?;
    let mut stats: libc::statfs = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::statfs(c_path.as_ptr(), &mut stats) };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(stats.f_type as i64)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::sn_api::SessionSecrets;

    /// Synthetic cache under a temp config dir, mirroring the TS tests: a
    /// saved session plus one settings note seeded into the cache at the
    /// config paths, so `open_cache` resolves. Serialized: the global
    /// config override has one slot, and concurrent tests would otherwise
    /// resolve into each other's config dirs (WrongKey crossfire).
    fn with_sink_cache(run: impl FnOnce(&Path)) {
        static CONFIG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _serial = CONFIG_LOCK.lock().expect("test config lock");
        let dir = std::env::temp_dir().join(format!(
            "sns-rs-sink-{}-{}",
            std::process::id(),
            random_suffix("sink")
        ));
        std::fs::create_dir_all(&dir).unwrap();
        crate::keychain::disable_for_tests();
        crate::paths::with_config_dir(dir.to_str().unwrap(), || {
            crate::paths::ensure_config_dir().expect("config dir creates");
            let secrets = SessionSecrets {
                account_email: "me@example.com".into(),
                refresh_token: "refresh-1".into(),
                access_token: "access-1".into(),
                access_expiration_ms: 1_700_000_000_000,
                refresh_expiration_ms: 1_800_000_000_000,
                access_cookie: String::new(),
                refresh_cookie: String::new(),
                db_key: "ab".repeat(32),
            };
            crate::session_file::save_session(&secrets).unwrap();
            let db = crate::db::open_database(&crate::paths::db_path(), &secrets.db_key).unwrap();
            let rows = [(
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
                "Note".into(),
                2,
                0,
                Some("Release tokens".into()),
                r#"{"title":"Release tokens","text":"GITHUB_TOKEN=ghs_secret123\nFORGEJO_TOKEN=fj_secret456\n"}"#.to_string(),
            )];
            db.upsert_items(&rows).unwrap();
            db.close();
            run(&dir);
        });
        std::fs::remove_dir_all(&dir).ok();
    }

    fn random_suffix(tag: &str) -> String {
        let mut bytes = [0u8; 4];
        getrandom::fill(&mut bytes).expect("system rng");
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        format!("{tag}-{hex}")
    }

    #[test]
    fn writes_exact_value_at_0600_with_0700_parents() {
        with_sink_cache(|dir| {
            let path = dir.join("handoff").join("github-token");
            sink_command("Release tokens", "GITHUB_TOKEN", path.to_str().unwrap(), false).unwrap();
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "ghs_secret123");
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(
                path.parent().unwrap().metadata().unwrap().permissions().mode() & 0o777,
                0o700
            );
        });
    }

    #[test]
    fn refuses_existing_without_force_and_overwrites_0600_with_force() {
        with_sink_cache(|dir| {
            let path = dir.join("tok");
            std::fs::write(&path, "stale-value").unwrap();
            let error = sink_command("Release tokens", "GITHUB_TOKEN", path.to_str().unwrap(), false).unwrap_err();
            assert!(error.0.contains("already exists"), "{error:?}");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "stale-value");

            sink_command("Release tokens", "GITHUB_TOKEN", path.to_str().unwrap(), true).unwrap();
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "ghs_secret123");
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        });
    }

    #[test]
    fn refuses_to_write_through_a_symlink() {
        with_sink_cache(|dir| {
            let target = dir.join("real-target");
            std::fs::write(&target, "untouched").unwrap();
            let link = dir.join("tok-link");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let error = sink_command("Release tokens", "GITHUB_TOKEN", link.to_str().unwrap(), false).unwrap_err();
            assert!(error.0.contains("symlink"), "{error:?}");
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched");
            assert!(link.exists());
        });
    }

    #[test]
    fn a_wrong_key_names_the_keys_and_writes_nothing() {
        with_sink_cache(|dir| {
            let path = dir.join("tok");
            let error = sink_command("Release tokens", "GITHUB_TOK", path.to_str().unwrap(), false).unwrap_err();
            assert!(error.0.contains("GITHUB_TOKEN"), "{error:?}");
            assert!(!path.exists());
        });
    }

    #[test]
    fn the_disk_backed_warning_verdict_matches_the_existing_ancestor() {
        with_sink_cache(|dir| {
            let missing = dir.join("new").join("deep").join("tok");
            let existing = dir.join("tok");
            assert_eq!(
                disk_backed_warning(missing.to_str().unwrap()),
                disk_backed_warning(existing.to_str().unwrap())
            );
        });
    }
}
