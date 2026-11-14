//! Port of `src/session-file.ts` over the native session crypto
//! (`session.rs`): save, load, and delete the encrypted session file, with
//! the private key held in the OS keychain when one exists and in
//! `.env.keys` (mode 0600) otherwise. Field names match the TS layout so
//! the rest of the app reads the same names; the encryption format is the
//! native `enc1:` one (no dotenvx compatibility, by decision).

use std::collections::HashMap;
use std::path::Path;

use crate::errors::UserError;
use crate::keychain;
use crate::paths::{keys_path, session_path};
use crate::session::{
    decrypt_value, encrypt_value, generate_keypair, parse_session_file, render_session_file,
    SessionPrivateKey, SessionPublicKey,
};
use crate::sn_api::SessionSecrets;

const PRIVATE_KEY_FIELD: &str = "SNS_SESSION_PRIVATE_KEY";

fn set_mode_600(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn read_private_key_file() -> Option<String> {
    let text = std::fs::read_to_string(keys_path()).ok()?;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix(&format!("{PRIVATE_KEY_FIELD}=")) {
            return Some(value.trim().to_string());
        }
    }
    None
}

fn write_private_key_file(key: &str) {
    crate::paths::ensure_config_dir();
    std::fs::write(keys_path(), format!("# sns session private key\n{PRIVATE_KEY_FIELD}={key}\n")).expect("keys file writes");
    set_mode_600(&keys_path());
}

fn pairs(secrets: &SessionSecrets) -> Vec<(&'static str, String)> {
    vec![
        ("SN_ACCOUNT_EMAIL", secrets.account_email.clone()),
        ("SN_REFRESH_TOKEN", secrets.refresh_token.clone()),
        ("SN_ACCESS_TOKEN", secrets.access_token.clone()),
        ("SN_ACCESS_EXPIRATION", secrets.access_expiration_ms.to_string()),
        ("SN_REFRESH_EXPIRATION", secrets.refresh_expiration_ms.to_string()),
        ("SN_ACCESS_COOKIE", secrets.access_cookie.clone()),
        ("SN_REFRESH_COOKIE", secrets.refresh_cookie.clone()),
        ("SN_DB_KEY", secrets.db_key.clone()),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SaveOutcome {
    /// True when the session private key went into the OS keychain instead
    /// of `.env.keys`.
    pub keychain: bool,
}

/// Save the session: reuse the existing session keypair when its private key
/// is recoverable (keychain or `.env.keys`), generate a fresh one otherwise,
/// encrypt every field, and settle the private key's custody.
pub fn save_session(secrets: &SessionSecrets) -> Result<SaveOutcome, UserError> {
    if !(secrets.db_key.len() == 64 && secrets.db_key.chars().all(|c| c.is_ascii_hexdigit())) {
        return Err(UserError("refusing to store a database key that is not 64 hex characters".into()));
    }
    crate::paths::ensure_config_dir();
    let keychain_key = keychain::keychain_get();
    let existing = keychain_key.clone().or_else(read_private_key_file);
    let (private, public) = match existing {
        Some(hex) => {
            let private = SessionPrivateKey::from_hex(&hex)
                .map_err(|_| UserError("the stored session key is not a valid P-256 scalar — run sns logout".into()))?;
            let public = private.public_key();
            (private, public)
        }
        None => generate_keypair(),
    };

    let fields: Vec<(&'static str, String)> = pairs(secrets)
        .into_iter()
        .map(|(name, value)| {
            let record = encrypt_value(&value, &public, name)
                .map_err(|error| UserError(format!("could not encrypt {name}: {error}")))?;
            Ok((name, record))
        })
        .collect::<Result<Vec<_>, UserError>>()?;
    let file = render_session_file(&public, &fields);
    std::fs::write(session_path(), file).map_err(|error| UserError(error.to_string()))?;
    set_mode_600(&session_path());

    // Custody: the OS keychain wins; .env.keys (mode 0600) is the fallback.
    let keychain = keychain::keychain_put(&private.to_hex());
    if keychain {
        let _ = std::fs::remove_file(keys_path());
    } else {
        write_private_key_file(&private.to_hex());
    }
    Ok(SaveOutcome { keychain })
}

/// Names as they appear in the session file (`sessionKeyNames`).
pub fn session_key_names() -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(session_path()) else {
        return Vec::new();
    };
    parse_session_file(&text).map(|parsed| parsed.fields.iter().map(|(name, _)| name.clone()).collect()).unwrap_or_default()
}

/// `assertSessionKeyNames` — the first name outside the session contract,
/// ignoring the dotenvx public-key prefix a hand-edited file may still carry.
pub fn first_unexpected(names: &[String]) -> Option<String> {
    names
        .iter()
        .find(|name| !name.starts_with("DOTENV_PUBLIC_KEY") && !crate::session::SESSION_VALUE_KEYS.contains(&name.as_str()))
        .cloned()
}

/// Load and decrypt the session. None when no session file exists.
pub fn load_session() -> Result<Option<SessionSecrets>, UserError> {
    if !session_path().exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(session_path()).map_err(|error| UserError(error.to_string()))?;
    let parsed = parse_session_file(&text).map_err(|error| UserError(error.to_string()))?;
    let public_base64 = parsed
        .public_key_base64
        .ok_or_else(|| UserError("session file is missing its public key — run sns login".into()))?;
    let _validated = SessionPublicKey::from_base64(&public_base64)
        .map_err(|_| UserError("session file carries an invalid public key — run sns login".into()))?;
    let names: Vec<String> = parsed.fields.iter().map(|(name, _)| name.clone()).collect();
    if let Some(unexpected) = first_unexpected(&names) {
        return Err(UserError(format!("session file contains an unexpected key ({unexpected})")));
    }
    let private_hex = keychain::keychain_get()
        .or_else(read_private_key_file)
        .ok_or_else(|| UserError("session file is encrypted but the session key is missing — run sns login".into()))?;
    let private = SessionPrivateKey::from_hex(&private_hex)
        .map_err(|_| UserError("the stored session key is not valid — run sns logout".into()))?;

    let mut values: HashMap<String, String> = HashMap::new();
    for (name, record) in &parsed.fields {
        let decrypted = decrypt_value(record, &private, name).map_err(|_| {
            UserError("could not decrypt .env.session — the session key does not match".into())
        })?;
        values.insert(name.clone(), decrypted.as_str().to_string());
    }
    let field = |name: &str| values.get(name).cloned().unwrap_or_default();
    let refresh_token = field("SN_REFRESH_TOKEN");
    let db_key = field("SN_DB_KEY");
    if refresh_token.is_empty() || db_key.is_empty() {
        return Err(UserError("session file is missing the refresh token or database key — run sns login".into()));
    }
    Ok(Some(SessionSecrets {
        account_email: field("SN_ACCOUNT_EMAIL"),
        refresh_token,
        access_token: field("SN_ACCESS_TOKEN"),
        access_expiration_ms: field("SN_ACCESS_EXPIRATION").parse().unwrap_or(0),
        refresh_expiration_ms: field("SN_REFRESH_EXPIRATION").parse().unwrap_or(0),
        access_cookie: field("SN_ACCESS_COOKIE"),
        refresh_cookie: field("SN_REFRESH_COOKIE"),
        db_key,
    }))
}

/// Delete the session file, the keys file, and the keychain entry.
pub fn delete_session() {
    let _ = std::fs::remove_file(session_path());
    let _ = std::fs::remove_file(keys_path());
    keychain::keychain_delete();
}
