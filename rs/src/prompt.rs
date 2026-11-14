//! Port of `src/commands/prompt.ts` — the two interactive prompts the CLI
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

pub fn prompt_line(message: &str, placeholder: Option<&str>) -> Result<String, UserError> {
    match placeholder {
        Some(placeholder) => print!("{message} [{placeholder}]: "),
        None => print!("{message}: "),
    }
    let _ = std::io::stdout().flush();
    let Some(line) = read_line() else { cancelled() };
    Ok(line.trim().to_string())
}
