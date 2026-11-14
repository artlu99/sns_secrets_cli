//! Port of `src/lock.ts` — the exclusive sync lock: O_EXCL create, stale
//! takeover after 30 minutes (dead holder, recycled pid, or own leaked lock),
//! and a release that only deletes the file when it still holds our token.

use std::path::Path;
use std::time::{Duration, SystemTime};

use crate::errors::UserError;
use crate::paths::lock_path;
use crate::time::now_ms;

const STALE_MS: u64 = 30 * 60 * 1000;

/// Tokens of locks this process created; one leaked by a crashed run can be
/// reclaimed after STALE_MS.
fn ours() -> &'static std::sync::Mutex<std::collections::HashSet<String>> {
    static OURS: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    &OURS
}

fn lock_contents(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

fn pid_alive(pid: i32) -> bool {
    if !(0..=i32::MAX).contains(&pid) || pid <= 0 {
        return false;
    }
    // kill(pid, 0): signal 0 checks liveness without delivering anything.
    #[cfg(unix)]
    unsafe {
        libc::kill(pid, 0) == 0
    }
    #[cfg(not(unix))]
    false
}

fn mtime_ms(path: &Path) -> Option<u64> {
    std::fs::metadata(path).ok().and_then(|meta| meta.modified().ok()).and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok()).map(|duration| duration.as_millis() as u64)
}

/// Linux only: a recycled pid belonging to an unrelated process must not
/// wedge the lock.
fn looks_like_sns(pid: i32) -> bool {
    let cmdline = match std::fs::read_to_string(format!("/proc/{pid}/cmdline")) {
        Ok(text) => text,
        // no /proc (macOS) or the process just exited — assume it is a real holder
        Err(_) => return true,
    };
    cmdline.contains("sns") || cmdline.contains("bun")
}

fn age_stale(path: &Path) -> bool {
    match mtime_ms(path) {
        Some(mtime) => now_ms().saturating_sub(mtime as i64) > STALE_MS as i64,
        None => false,
    }
}

/// The trimmed content of a lock this process judges stale — dead holder,
/// recycled pid, or our own leaked lock that aged out — so the takeover can
/// verify the file still holds that content before unlinking it. None when
/// the lock is live. Empty content (a crash between the O_EXCL create and
/// the token write) is stale.
fn judged_stale(path: &Path) -> Option<String> {
    let content = lock_contents(path);
    let trimmed = content.trim().to_string();
    let mut parts = trimmed.split(' ');
    let pid_text = parts.next().unwrap_or("");
    let token = parts.next();
    let Ok(pid) = pid_text.parse::<i32>() else { return Some(trimmed) };
    if pid <= 0 {
        return Some(trimmed);
    }
    if !pid_alive(pid) {
        return Some(trimmed);
    }
    if let Some(token) = token
        && ours().lock().expect("lock-token registry").contains(token)
    {
        // our own leaked lock: stale only once it aged out
        return age_stale(path).then_some(trimmed);
    }
    if !looks_like_sns(pid) {
        return Some(trimmed);
    }
    age_stale(path).then_some(trimmed)
}

/// Exclusive sync lock. A second sync waits, then fails with a clear
/// message. The returned closure releases the lock.
pub fn acquire_sync_lock(wait_ms: u64) -> Result<impl FnOnce(), UserError> {
    acquire_sync_lock_at(lock_path(), wait_ms)
}

/// The lock mechanics over an explicit (owned) path, so tests exercise real
/// files without the global config-dir override.
fn acquire_sync_lock_at(path: std::path::PathBuf, wait_ms: u64) -> Result<impl FnOnce(), UserError> {
    let started = SystemTime::now();
    loop {
        let token = format!("{}-{}", std::process::id(), now_ms());
        let lock_file = std::fs::OpenOptions::new().create_new(true).write(true).open(&path);
        let file = match lock_file {
            Ok(file) => Some(file),
            Err(error) => {
                if error.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(UserError(error.to_string()));
                }
                // Unlink only when the content is still the lock we judged
                // stale — never a fresh lock a racing waiter just created.
                if let Some(judged) = judged_stale(&path)
                    && lock_contents(&path).trim() == judged
                    && std::fs::remove_file(&path).is_ok()
                {
                    continue; // took the stale lock over; retry the create at once
                }
                None
            }
        };
        let Some(mut file) = file else {
            // Every failed attempt (a live holder, or a stale lock another
            // waiter keeps re-creating) waits, then fails cleanly — nothing
            // on this path may spin without a timeout.
            if now_ms().saturating_sub(ms_since(started) as i64) >= wait_ms as i64 {
                return Err(UserError(
                    "another sns sync is still running — wait for it to finish, then retry".into(),
                ));
            }
            std::thread::sleep(Duration::from_millis(200));
            continue;
        };
        use std::io::Write as _;
        let _ = write!(file, "{} {}", std::process::id(), token);
        ours().lock().expect("lock-token registry").insert(token.clone());
        let path_for_release = path.clone();
        let token_for_release = token.clone();
        return Ok(move || {
            let mut tokens = ours().lock().expect("lock-token registry");
            tokens.remove(&token_for_release);
            // Delete only if the file still holds OUR token — never a
            // successor's lock.
            if lock_contents(&path_for_release).trim() == format!("{} {token_for_release}", std::process::id()) {
                let _ = std::fs::remove_file(&path_for_release);
            }
        });
    }
}

fn ms_since(started: SystemTime) -> u64 {
    started.elapsed().map(|elapsed| elapsed.as_millis() as u64).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_lock(tag: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("sns-lock-test-{}-{tag}.lock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn empty_and_dead_holder_locks_are_taken_over_at_once() {
        let path = temp_lock("stale");
        // a crash between the O_EXCL create and the token write leaves
        // 0 bytes — the lock must be taken over, never spun on
        std::fs::write(&path, "").expect("empty lock written");
        let release = acquire_sync_lock_at(path.clone(), 1_000).expect("empty lock is taken over");
        release();
        assert!(!path.exists(), "release removes the lock");
        // a dead holder's lock is stale without waiting STALE_MS
        std::fs::write(&path, "2147483000 dead-token").expect("dead lock written");
        let release = acquire_sync_lock_at(path.clone(), 1_000).expect("dead holder's lock is taken over");
        release();
        assert!(!path.exists());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_live_foreign_lock_waits_then_fails_cleanly() {
        let path = temp_lock("live");
        // our own pid, a token this process never registered: live
        std::fs::write(&path, format!("{} foreign-holder", std::process::id())).expect("live lock written");
        let error = match acquire_sync_lock_at(path.clone(), 300) {
            Ok(_) => panic!("a live foreign lock is not taken over"),
            Err(error) => error,
        };
        assert!(error.0.contains("another sns sync is still running"), "got: {error}");
        assert!(path.exists(), "the live holder's lock is untouched");
        let _ = std::fs::remove_file(&path);
    }
}
