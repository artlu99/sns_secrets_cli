//! Port of `src/commands/prompt.ts` — the interactive prompts the CLI
//! needs. @clack's select picker lives in the browse command; cancel-on-EOF
//! mirrors `unwrap(cancel(...))` exiting with `cancelled`.

use std::io::Write as _;

use crate::errors::UserError;

fn read_line() -> Option<String> {
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(0) => None, // EOF: Ctrl-D is a cancel
        Ok(_) => Some(line),
        Err(_) => None,
    }
}

fn cancelled() -> ! {
    eprintln!("cancelled");
    std::process::exit(0);
}

pub fn prompt_secret(message: &str) -> Result<String, UserError> {
    print!("{message}: ");
    let _ = std::io::stdout().flush();
    let value = rpassword::prompt_password("").map_err(|error| UserError(error.to_string()))?;
    let value = value.trim_end_matches(['\n', '\r']).to_string();
    if value.trim().is_empty() {
        return Err(UserError("empty input".into()));
    }
    Ok(value)
}

/// Prompt for a line. When `default` is set it is shown in brackets and used
/// if the user presses Enter on an empty line (login's email escape hatch).
/// When only a placeholder hint is needed and empty input must stay empty
/// (browse filter), pass `default: None` and put the hint in `message`.
pub fn prompt_line(message: &str, default: Option<&str>) -> Result<String, UserError> {
    match default {
        Some(default) => print!("{message} [{default}]: "),
        None => print!("{message}: "),
    }
    let _ = std::io::stdout().flush();
    let Some(line) = read_line() else { cancelled() };
    let trimmed = line.trim().to_string();
    if trimmed.is_empty()
        && let Some(default) = default
    {
        return Ok(default.to_string());
    }
    Ok(trimmed)
}

/// Yes/no confirm. Default answer is used on empty Enter. Any y-prefixed
/// answer counts as yes — @clack's confirm commits on the first `y`
/// keystroke, so "yeah" must not mean no here.
pub fn prompt_confirm(message: &str, default: bool) -> Result<bool, UserError> {
    let hint = if default { "Y/n" } else { "y/N" };
    print!("{message} [{hint}]: ");
    let _ = std::io::stdout().flush();
    let Some(line) = read_line() else { cancelled() };
    let trimmed = line.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return Ok(default);
    }
    Ok(trimmed.starts_with('y'))
}
