//! Port of `src/env.ts` — the launch-environment scrubber. Secret-named
//! variables are dropped from the process environment at startup and their
//! names recorded so `sns doctor` can report them; child processes spawn
//! with the scrubbed map.

use std::collections::HashMap;
use std::sync::Mutex;

const PUBLIC_SN_ENV: [&str; 2] = ["SN_EMAIL", "SN_API_URL"];

/// True when a process environment name carries credential material.
pub fn is_secret_env_name(name: &str) -> bool {
    if name == "DOTENV_KEY" || name.starts_with("DOTENV_PRIVATE_KEY") {
        return true;
    }
    name.starts_with("SN_") && !PUBLIC_SN_ENV.contains(&name)
}

pub fn scrubbed_env() -> HashMap<String, String> {
    std::env::vars().filter(|(key, _)| !is_secret_env_name(key)).collect()
}

/// A child-process `Command` with the scrubbed environment pre-applied. The
/// `env_clear()` + `envs(scrubbed_env())` pairing is the security property
/// doctor's scrub check probes; this keeps new spawn sites from half-copying
/// it (`envs(scrubbed_env())` alone still leaks the launch env).
pub fn scrubbed_command(bin: &str) -> std::process::Command {
    let mut command = std::process::Command::new(bin);
    command.env_clear().envs(scrubbed_env());
    command
}

/// `Bun.which` — a PATH walk with one stat per candidate, true only when the
/// entry is a regular file with an exec bit (unix).
pub fn which(bin: &str) -> bool {
    std::env::var("PATH").unwrap_or_default().split(':').any(|dir| {
        let candidate = std::path::Path::new(dir).join(bin);
        std::fs::metadata(&candidate)
            .map(|meta| {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    meta.is_file() && meta.permissions().mode() & 0o111 != 0
                }
                #[cfg(not(unix))]
                meta.is_file()
            })
            .unwrap_or(false)
    })
}

/// `scrubbedEnv(base)` for probes that need a doctored copy of the current
/// environment.
pub fn scrubbed_env_with(base: &HashMap<String, String>) -> HashMap<String, String> {
    base.iter().filter(|(key, _)| !is_secret_env_name(key)).map(|(key, value)| (key.clone(), value.clone())).collect()
}

static SCRUBBED_NAMES: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Secret-named variables the launch environment carried, recorded by
/// `scrub_process_env`. Names only — the values are gone for good.
pub fn scrubbed_env_names() -> Vec<String> {
    SCRUBBED_NAMES.lock().expect("scrubbed names lock").clone()
}

/// Drop secret-named variables bun or a parent shell may have loaded.
pub fn scrub_process_env() {
    // Safe here by contract: this runs once at startup, before any thread
    // that could concurrently read the environment exists.
    for (key, _) in std::env::vars() {
        if is_secret_env_name(&key) {
            // SAFETY: single-threaded startup, no other env readers yet.
            unsafe {
                std::env::remove_var(&key);
            }
            let mut names = SCRUBBED_NAMES.lock().expect("scrubbed names lock");
            if !names.contains(&key) {
                names.push(key);
            }
        }
    }
}

/// Tests only: forget recorded names so a suite starts from a clean state.
pub fn clear_scrubbed_env_names() {
    SCRUBBED_NAMES.lock().expect("scrubbed names lock").clear();
}
