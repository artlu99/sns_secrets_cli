//! Port of `src/clipboard.ts` — OSC 52 clipboard copy with the tmux escape
//! wrapper, a detached 30-second clearer, helper-tool fallbacks, and the
//! stale-clipboard sweep.

use std::io::{IsTerminal as _, Write as _};
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
use std::process::Stdio;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

use crate::env::{scrubbed_command, which};
use crate::errors::UserError;
use crate::paths::{clipboard_marker_path, ensure_config_dir};
use crate::time::now_ms;

const MAX_BYTES: usize = 60_000;

fn tmux_active() -> bool {
    std::env::var("TMUX").is_ok()
}

pub fn osc52(text: &str, tmux: bool) -> String {
    let payload = BASE64.encode(text.as_bytes());
    let sequence = format!("\x1b]52;c;{payload}\x07");
    if !tmux {
        return sequence;
    }
    format!("\x1bPtmux;{}\x1b\\", sequence.replace('\x1b', "\x1b\x1b"))
}

pub fn clear_sequence(tmux: bool) -> String {
    let sequence = "\x1b]52;c;\x07";
    if !tmux {
        return sequence.to_string();
    }
    format!("\x1bPtmux;{}\x1b\\", sequence.replace('\x1b', "\x1b\x1b"))
}

fn stdout_is_tty() -> bool {
    std::io::stdout().is_terminal()
}

pub fn write_osc(sequence: &str) -> bool {
    match std::fs::OpenOptions::new().write(true).open("/dev/tty") {
        Ok(mut tty) => tty.write_all(sequence.as_bytes()).is_ok(),
        Err(_) => {
            if stdout_is_tty() {
                let mut out = std::io::stdout();
                out.write_all(sequence.as_bytes()).is_ok()
            } else {
                false
            }
        }
    }
}

/// A detached (setsid) sleeper cannot open /dev/tty itself (ENXIO) — that
/// silently swallowed every clear, so the tty fd is opened here and handed
/// to the child as fd 3, which the sleeper writes to with `>&3`.
#[cfg(unix)]
fn arm_clear(sequence: &str) {
    use std::os::unix::io::AsRawFd;
    ensure_config_dir();
    let marker = format!("{}", now_ms() + 30_000);
    let _ = std::fs::write(clipboard_marker_path(), marker);
    let tty = std::fs::OpenOptions::new().write(true).open("/dev/tty");
    let Ok(tty_file) = tty else {
        // no tty now; the marker lets a later command clear instead
        return;
    };
    let tty_fd = tty_file.as_raw_fd();
    let mut command = scrubbed_command("sh");
    command
        .args(["-c", "sleep 30; printf %s \"$1\" >&3 || true", "sns-clear", sequence])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    // SAFETY: the closure runs between fork and exec, in the child process
    // only, dup2-ing the tty over fd 3 — the detached sleeper's whole job.
    unsafe {
        command.pre_exec(move || {
            libc::dup2(tty_fd, 3);
            Ok(())
        });
    }
    let spawn_result = command.spawn();
    // Detached like the TS `unref()`: the sleeper lives 30s on its own.
    let _ = spawn_result;
    // tty_file closes here, after the fd was duplicated into the child
}

#[cfg(not(unix))]
fn arm_clear(_sequence: &str) {
    // No unix tty fd to hand a sleeper on Windows; the marker lets a later
    // command clear instead.
    ensure_config_dir();
    let marker = format!("{}", now_ms() + 30_000);
    let _ = std::fs::write(clipboard_marker_path(), marker);
}

fn copy_via_tool(text: &str) -> bool {
    let tools: [(&str, &[&str]); 4] = [
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard"]),
        ("pbcopy", &[]),
        ("clip.exe", &[]),
    ];
    for (bin, args) in tools {
        if !which(bin) {
            continue;
        }
        let mut child = match scrubbed_command(bin)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            // A helper that fails to spawn (no DISPLAY) is a failed attempt.
            Err(_) => continue,
        };
        use std::io::Write as _;
        let drained = match child.stdin.take() {
            Some(mut handle) => handle.write_all(text.as_bytes()).is_ok(),
            None => false,
        };
        let ok = match child.wait() {
            Ok(status) => status.success(),
            Err(_) => false,
        };
        // A helper that exits instantly (no DISPLAY, failed clip.exe) closes
        // the pipe before the write drains; that is a failed attempt, not a
        // crash.
        if drained && ok {
            return true;
        }
    }
    false
}

pub fn copy_to_clipboard(text: &str, subject: Option<&str>) -> Result<String, UserError> {
    let bytes = text.len();
    if bytes > MAX_BYTES {
        return Err(UserError(format!(
            "{} is {bytes} bytes, over the {MAX_BYTES} byte clipboard cap",
            subject.unwrap_or("note")
        )));
    }
    let wrote = write_osc(&osc52(text, tmux_active()));
    if !wrote && !copy_via_tool(text) {
        return Err(UserError(
            "no clipboard path: OSC 52 needs a terminal, and wl-copy/xclip/pbcopy were not found".into(),
        ));
    }
    arm_clear(&clear_sequence(tmux_active()));
    // a subject names the copied setting; the body copy stays anonymous
    Ok(match subject {
        Some(subject) => format!("copied {subject} ({bytes} bytes, clears in 30s)"),
        None => format!("Copied {bytes} bytes (clears in 30s)"),
    })
}

/// Next command clears a clipboard whose sleeper may have died.
pub fn maybe_clear_stale_clipboard() {
    let path = clipboard_marker_path();
    if !path.exists() {
        return;
    }
    let Ok(text) = std::fs::read_to_string(&path) else { return };
    let Ok(at) = text.parse::<i64>() else { return };
    if now_ms() < at {
        return;
    }
    let _ = write_osc(&clear_sequence(tmux_active()));
    let _ = std::fs::remove_file(&path);
}
