//! Millisecond wall-clock helpers shared across modules (`Date.now()` in
//! the TS).

/// Unix wall-clock in milliseconds. Pre-epoch clocks read as 0, never
/// negative — callers compare against parsed file contents of the same kind.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}
