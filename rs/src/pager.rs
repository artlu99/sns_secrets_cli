//! Port of `src/pager.ts` — stdout writes that treat a closed pipe as done,
//! `less -R` paging, and the page-only-when-taller-than-the-screen rule.

use std::io::{IsTerminal as _, Write as _};

use crate::env::{scrubbed_command, which};
use crate::errors::UserError;

/// stdout write that treats a closed pipe as done, not as a crash: piping
/// `sns show --no-pager | head -1` closes the pipe early by design.
pub fn write_stdout(body: &str) {
    let mut out = std::io::stdout();
    if out.write_all(body.as_bytes()).is_err() {
        // EPIPE or a closed stdout is done, not a crash.
    }
    let _ = out.flush();
}

#[derive(Debug, Default)]
pub struct PageOptions {
    pub no_pager: bool,
    /// False for output that provably carries no values (the show inventory)
    /// — the warning is about plaintext secrets, not titles.
    pub warn: bool,
}

pub fn page(text: &str, options: &PageOptions) -> Result<(), UserError> {
    let body = if text.ends_with('\n') { text.to_string() } else { format!("{text}\n") };
    let interactive = std::io::stdout().is_terminal() && !options.no_pager && which("less");
    if !interactive {
        // warn: false for output that provably carries no values (the show
        // inventory) — the warning is about plaintext secrets, not titles.
        if options.warn {
            let why = if options.no_pager {
                "printing plaintext to stdout; a redirect or the scrollback keeps a copy"
            } else {
                "printing plaintext to stdout; the scrollback keeps a copy"
            };
            eprintln!("{why}");
        }
        write_stdout(&body);
        return Ok(());
    }
    let mut child = scrubbed_command("less")
        .arg("-R")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|_| UserError("could not start less".into()))?;
    // less quitting before the body is drained (the user pressed q) closes
    // the pipe mid-write; that is a normal exit, not an error.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(body.as_bytes());
    }
    match child.wait() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(UserError(format!("less exited {}", status.code().map(|code| code.to_string()).unwrap_or_else(|| "abnormally".into())))),
        Err(error) => Err(UserError(error.to_string())),
    }
}

/// The list/show/tags rule in one place: page only when the output is taller
/// than the screen. The row count covers everything passed in — hints
/// included — so the decision always matches what actually prints. A pty can
/// report 0 rows: unknown, not tiny, so the screen falls back to 24.
pub fn page_if_tall(text: &str, options: &PageOptions) -> Result<(), UserError> {
    let rows = text.split('\n').count();
    let screen = terminal_rows().unwrap_or(24);
    if std::io::stdout().is_terminal() && !options.no_pager && rows > screen.saturating_sub(1) {
        return page(text, options);
    }
    let body = if text.ends_with('\n') { text.to_string() } else { format!("{text}\n") };
    write_stdout(&body);
    Ok(())
}

fn terminal_rows() -> Option<usize> {
    terminal_size::terminal_size().map(|(_width, height)| height.0 as usize)
}
