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
