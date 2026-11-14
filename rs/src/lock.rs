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

/// Stale when the holder is dead, when the pid was recycled by a non-sns
/// process, or when it is our own leaked lock that aged out. A lock held by a
/// live foreign sns process is only taken over after STALE_MS.
fn lock_is_stale(path: &Path) -> bool {
    let content = lock_contents(path).trim().to_string();
    let mut parts = content.split(' ');
    let pid_text = parts.next().unwrap_or("");
    let token = parts.next();
    let Ok(pid) = pid_text.parse::<i32>() else { return true };
    if pid <= 0 {
        return true;
    }
    if !pid_alive(pid) {
        return true;
    }
    if let Some(token) = token
        && ours().lock().expect("lock-token registry").contains(token)
    {
        return match mtime_ms(path) {
            Some(mtime) => now_ms().saturating_sub(mtime as i64) > STALE_MS as i64,
            None => false,
        };
    }
    if !looks_like_sns(pid) {
        return true;
    }
    age_stale(path)
}

/// Exclusive sync lock. A second sync waits, then fails with a clear
/// message. The returned closure releases the lock.
pub fn acquire_sync_lock(wait_ms: u64) -> Result<impl FnOnce(), UserError> {
    let path = lock_path();
    let started = SystemTime::now();
    loop {
        let token = format!("{}-{}", std::process::id(), now_ms());
        let lock_file = std::fs::OpenOptions::new().create_new(true).write(true).open(&path);
        let mut file = match lock_file {
            Ok(file) => file,
            Err(error) => {
                if error.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(UserError(error.to_string()));
                }
                if path.exists() && lock_is_stale(&path) {
                    // Unlink only when the content is still what we judged
                    // stale — never a fresh lock a racing waiter just created.
                    let judged = lock_contents(&path);
                    if !judged.is_empty() && lock_contents(&path) == judged {
                        let _ = std::fs::remove_file(&path);
                    }
                    continue;
                }
                if now_ms().saturating_sub(ms_since(started) as i64) >= wait_ms as i64 {
                    return Err(UserError(
                        "another sns sync is still running — wait for it to finish, then retry".into(),
                    ));
                }
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
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
