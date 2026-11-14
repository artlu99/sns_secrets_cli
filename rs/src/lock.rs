//! Port of `src/lock.ts` (the flock revision) — the exclusive sync lock.
//!
//! Mutual exclusion is `flock(2)` on a sentinel file: the kernel drops the
//! lock when the holder's process exits, so a crash cannot stick and there
//! is nothing to take over. The file's bytes are not a protocol — nothing
//! reads or writes them; the file exists so there is something to flock.
//! A waiter polls every 200 ms and fails cleanly after `wait_ms`.
//!
//! Platforms without `flock` fall back to an exclusive-create sentinel:
//! exclusion works, a crashed holder's file must be deleted by hand, and
//! the timeout error says so.

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
#[cfg(unix)]
use std::os::unix::io::AsRawFd as _;
use std::time::{Duration, SystemTime};

use crate::errors::UserError;
use crate::paths::lock_path;

/// Exclusive sync lock. A second sync waits, then fails with a clear
/// message. The returned closure releases the lock.
pub fn acquire_sync_lock(wait_ms: u64) -> Result<impl FnOnce(), UserError> {
    acquire_sync_lock_at(lock_path(), wait_ms)
}

/// The lock mechanics over an explicit (owned) path, so tests exercise real
/// files without the global config-dir override.
#[cfg(unix)]
fn acquire_sync_lock_at(path: std::path::PathBuf, wait_ms: u64) -> Result<impl FnOnce(), UserError> {
    // Mode 0600 applies at creation only. The sentinel carries no bytes and
    // no secrets — it exists so the kernel has something to flock, so
    // truncating whatever bytes an older scheme left is fine.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| UserError(error.to_string()))?;
    let fd = file.as_raw_fd();
    let started = SystemTime::now();
    loop {
        // SAFETY: flock on a descriptor we own; 0 means the lock is held.
        if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(move || {
                // SAFETY: unlocking the descriptor we locked above.
                unsafe { libc::flock(fd, libc::LOCK_UN) };
                // The descriptor closes here; even if this unlock raced a
                // takeover that cannot exist, the kernel lock dies with it.
                drop(file);
            });
        }
        let error = std::io::Error::last_os_error();
        match error.kind() {
            // A live holder (EAGAIN/EWOULDBLOCK) or a signal mid-call: wait.
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => {}
            _ => return Err(UserError(format!("could not lock sync ({error})"))),
        }
        if ms_since(started) >= wait_ms {
            return Err(UserError(
                "another sns sync is still running — wait for it to finish, then retry".into(),
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Exclusive-create fallback where `flock` does not exist: exclusion works,
/// a crashed holder's sentinel must be deleted by hand.
#[cfg(not(unix))]
fn acquire_sync_lock_at(path: std::path::PathBuf, wait_ms: u64) -> Result<impl FnOnce(), UserError> {
    let started = SystemTime::now();
    loop {
        match std::fs::OpenOptions::new().create_new(true).write(true).open(&path) {
            Ok(file) => {
                let path_for_release = path.clone();
                return Ok(move || {
                    // Only the creator reaches here, so deleting its own
                    // sentinel can never remove someone else's.
                    drop(file);
                    let _ = std::fs::remove_file(&path_for_release);
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if ms_since(started) >= wait_ms {
                    return Err(UserError(
                        "another sns sync is still running — wait for it to finish, then retry (if no sync is running, delete the stale sync.lock)".into(),
                    ));
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(error) => return Err(UserError(error.to_string())),
        }
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
    fn a_live_holder_excludes_until_release() {
        let path = temp_lock("flock");
        let release = acquire_sync_lock_at(path.clone(), 1_000).expect("first holder acquires");
        // flock treats two descriptors of the same process as independent
        // holders, so this contends exactly as a second process would.
        let error = match acquire_sync_lock_at(path.clone(), 300) {
            Ok(_) => panic!("the lock excludes a second holder"),
            Err(error) => error,
        };
        assert!(error.0.contains("another sns sync is still running"), "got: {error}");
        release();
        let release = acquire_sync_lock_at(path.clone(), 1_000).expect("re-acquires after release");
        release();
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn a_leftover_sentinel_file_never_blocks_a_fresh_acquire() {
        let path = temp_lock("sentinel");
        // A crash between the file's creation and anything else leaves a
        // 0-byte sentinel: the kernel never held a lock on it, so acquiring
        // is unconditional. Bytes from the older content-protocol scheme are
        // equally irrelevant — they are not read.
        std::fs::write(&path, "").expect("empty sentinel written");
        let release = acquire_sync_lock_at(path.clone(), 1_000).expect("a leftover sentinel does not wedge");
        release();
        std::fs::write(&path, "2147483000 dead-token").expect("old-scheme content written");
        let release = acquire_sync_lock_at(path.clone(), 1_000).expect("content is not a protocol");
        release();
        let _ = std::fs::remove_file(&path);
    }
}
