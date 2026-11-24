//! Port of `src/session-file.ts` over the native session crypto
//! (`session.rs`): save, load, and delete the encrypted session file, with
//! the private key held in the OS keychain when one exists and in
//! `.env.keys` (mode 0600) otherwise. The bytes on disk are the dotenvx
//! session wire format, implemented natively (maintainer decision B — no
//! dotenvx subprocess, no per-machine Node dependency): the TypeScript
//! CLI, this binary, and the dotenvx CLI all read and write the same file,
//! pinned byte-for-byte by `tests/fixtures/session-vectors.json`. The
//! legacy `enc1:` format (written by sns <= 0.5.0) is read only for the
//! one-shot migration — [`load_session`] falls back to it and re-saves the
//! file in the dotenvx format under the sync lock. Field names match the
//! TS layout so the rest of the app reads the same names.

use std::collections::HashMap;

use crate::db::is_64_hex;
use crate::errors::UserError;
use crate::keychain;
use crate::paths::{keys_path, session_path, set_mode_600, write_secret_file};
use crate::session::{
    decrypt_value, encrypt_value, generate_keypair, parse_session_file, render_session_file,
    LegacySessionPrivateKey, ParsedSession, SessionPrivateKey,
};
use crate::sn_api::SessionSecrets;

/// The dotenvx custody line in `.env.keys` (`src/session-file.ts`
/// readPrivateKeyFile / writePrivateKeyFile).
const PRIVATE_KEY_FIELD: &str = "DOTENV_PRIVATE_KEY_SESSION";
/// The legacy enc1 custody line. Kept deliberately: until migration
/// replaces `.env.keys`, the line is a live credential the loader must
/// still find.
const LEGACY_PRIVATE_KEY_FIELD: &str = "SNS_SESSION_PRIVATE_KEY";

/// One value out of an `.env.keys`-style line, with the TS reader grammar
/// (`src/session-file.ts` readPrivateKeyFile): `FIELD=` then either a
/// `"..."` or `'...'` quoted form (non-empty, no interior quote of that
/// kind, only whitespace to end of line) or an unquoted `[^\s#]+` run
/// (only whitespace to end of line). Malformed lines yield None, exactly
/// where the TS regex fails to match.
fn key_line_value(line: &str, field: &str) -> Option<String> {
    let rest = line.strip_prefix(field)?.strip_prefix('=')?;
    for quote in ['"', '\''] {
        if let Some(after) = rest.strip_prefix(quote) {
            let close = after.rfind(quote)?;
            let value = &after[..close];
            let tail = &after[close + 1..];
            if value.is_empty() || value.contains(quote) || !tail.bytes().all(|b| b.is_ascii_whitespace()) {
                return None;
            }
            return Some(value.to_string());
        }
    }
    let cut = rest
        .find(|c: char| c == '#' || c.is_whitespace())
        .unwrap_or(rest.len());
    let value = &rest[..cut];
    if value.is_empty() || !rest[cut..].bytes().all(|b| b.is_ascii_whitespace()) {
        return None;
    }
    Some(value.to_string())
}

/// The dotenvx private key from `.env.keys` — the DOTENV line ONLY. The
/// legacy SNS line is not a custody source for the dotenvx format (TS
/// parity: the TS reader never saw it either).
fn read_private_key_file() -> Option<String> {
    let text = std::fs::read_to_string(keys_path()).ok()?;
    for line in text.lines() {
        if let Some(value) = key_line_value(line, PRIVATE_KEY_FIELD) {
            return Some(value);
        }
    }
    None
}

/// The legacy enc1 private key from its `SNS_SESSION_PRIVATE_KEY` line,
/// trimmed (legacy files are unquoted). Only the migration reads this.
fn read_legacy_key_line() -> Option<String> {
    let text = std::fs::read_to_string(keys_path()).ok()?;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix(&format!("{LEGACY_PRIVATE_KEY_FIELD}=")) {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// write_secret_file + 0600, with the operator-facing write failure message
/// every secrets-bearing config write shares.
fn write_config_secret(path: &std::path::Path, contents: &str, label: &str) -> Result<(), UserError> {
    write_secret_file(path, contents).map_err(|error| {
        UserError(format!(
            "could not write {label} at {} — check that the directory is writable and the disk is not full ({error})",
            path.display()
        ))
    })?;
    set_mode_600(path);
    Ok(())
}

/// The TS custody file text, byte-for-byte (`src/session-file.ts`
/// writePrivateKeyFile): one header line, one unquoted value line. This
/// REPLACES the whole `.env.keys` — any stale legacy SNS line dies here,
/// which is correct: the line dropped is always the key of a file that no
/// longer exists.
fn write_private_key_file(key: &str) -> Result<(), UserError> {
    crate::paths::ensure_config_dir()?;
    write_config_secret(
        &keys_path(),
        &format!("# dotenvx private key for .env.session\n{PRIVATE_KEY_FIELD}={key}\n"),
        ".env.keys",
    )
}

/// The session fields as name/value pairs, in the canonical
/// SESSION_VALUE_KEYS order — built by iterating that constant so this
/// order and the migration's cannot drift apart.
fn pairs_from_values(values: &HashMap<String, String>) -> Vec<(&'static str, String)> {
    crate::session::SESSION_VALUE_KEYS
        .iter()
        .map(|name| (*name, values.get(*name).cloned().unwrap_or_default()))
        .collect()
}

fn pairs(secrets: &SessionSecrets) -> Vec<(&'static str, String)> {
    let mut values: HashMap<String, String> = HashMap::new();
    values.insert("SN_ACCOUNT_EMAIL".into(), secrets.account_email.clone());
    values.insert("SN_REFRESH_TOKEN".into(), secrets.refresh_token.clone());
    values.insert("SN_ACCESS_TOKEN".into(), secrets.access_token.clone());
    values.insert("SN_ACCESS_EXPIRATION".into(), secrets.access_expiration_ms.to_string());
    values.insert("SN_REFRESH_EXPIRATION".into(), secrets.refresh_expiration_ms.to_string());
    values.insert("SN_ACCESS_COOKIE".into(), secrets.access_cookie.clone());
    values.insert("SN_REFRESH_COOKIE".into(), secrets.refresh_cookie.clone());
    values.insert("SN_DB_KEY".into(), secrets.db_key.clone());
    pairs_from_values(&values)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SaveOutcome {
    /// True when the session private key went into the OS keychain instead
    /// of `.env.keys`.
    pub keychain: bool,
}

/// Trial-decrypt the session file with a candidate private key
/// (`src/session-file.ts` keyDecryptsSession): true only when every
/// `encrypted:` record in the file decrypts under this key. save_session
/// refuses to write over a session no available key opens (dotenvx would
/// re-encrypt every new value to the file's orphaned public key and report
/// success), and doctor uses it to say whether the keychain key actually
/// matches the session.
///
/// Deliberate divergence from TS, fail-closed: TS only checks that the
/// eight SESSION_VALUE_KEYS values are no longer `encrypted:` strings, so a
/// foreign junk ciphertext under another name would not block it; here ANY
/// undecryptable `encrypted:` record fails the attempt — writing over a
/// partially unreadable file is exactly what the guard exists to prevent.
/// On success no value can still start with `encrypted:`, so TS's leftover
/// sweep collapses into "the attempt succeeded". No stderr interception is
/// needed either: the TS hack silences dotenvx's
/// `[WRONG/INVALID_PRIVATE_KEY]` console noise and its key-prefix echoes,
/// and native Rust crypto prints nothing.
pub fn key_decrypts_session(candidate_hex: &str) -> bool {
    if !session_path().exists() {
        return false;
    }
    let Ok(text) = std::fs::read_to_string(session_path()) else {
        return false;
    };
    let Ok(parsed) = parse_session_file(&text) else {
        return false;
    };
    try_decrypt_dotenvx(&parsed, candidate_hex).is_some()
}

/// The per-field dotenvx attempt shared by the trial-decrypt and the load:
/// validate the scalar, then decrypt every `encrypted:` record; values
/// without a record prefix pass through, mirroring dotenvx parse; an
/// `enc1:` value fails the attempt — it is not a dotenvx record, and
/// silently carrying it through would surface garbage. None on any
/// failure: wrong key, tampered record, and malformed base64 all look the
/// same, by construction of GCM.
fn try_decrypt_dotenvx(parsed: &ParsedSession, key_hex: &str) -> Option<HashMap<String, String>> {
    let private = SessionPrivateKey::from_hex(key_hex).ok()?;
    let mut values = HashMap::new();
    for (name, value) in &parsed.fields {
        if value.starts_with(crate::session::RECORD_PREFIX) {
            let decrypted = decrypt_value(value, &private, name).ok()?;
            values.insert(name.clone(), decrypted.as_str().to_string());
        } else if value.starts_with(crate::session::LEGACY_RECORD_PREFIX) {
            return None;
        } else {
            values.insert(name.clone(), value.clone());
        }
    }
    Some(values)
}

/// Bare substring test for the dotenvx public-key marker, mirroring the TS
/// regex exactly — a commented-out hit false-positives in TS too; parity
/// over cleverness. A hit means a dotenvx-format writer produced this file,
/// so the save brick-guard applies.
fn session_has_dotenvx_public_key() -> bool {
    std::fs::read_to_string(session_path())
        .map(|text| text.contains(&format!("{}=", crate::session::PUBLIC_KEY_FIELD)))
        .unwrap_or(false)
}

/// The TS 0-size cleanup (src/session-file.ts): drop a 0-byte .env.session
/// before the custody decisions. Rust's own writer cannot produce one —
/// write_secret_file is temp+rename, so a crash never leaves a 0-size
/// target — but the TS CLI pre-creates the empty target before dotenvx's
/// first rename, and the two binaries share this directory: a TS
/// crash-orphan must not wedge the bootstrap path here. Removal errors are
/// ignored; the write below surfaces real failures. (The Rust analogue of
/// TS's ensureSessionFilePrivate O_EXCL/fchmod dance is write_secret_file
/// itself: 0600 from creation, O_NOFOLLOW, symlink replacement.)
fn remove_empty_session_file() {
    if let Ok(meta) = std::fs::metadata(session_path())
        && meta.is_file()
        && meta.len() == 0
    {
        let _ = std::fs::remove_file(session_path());
    }
}

/// Custody settle, shared by save and migration: the OS keychain wins
/// (`keychain_put` is an upsert); when no secret service accepts the entry,
/// `.env.keys` (mode 0600) holds the key instead. On the file path the
/// write REPLACES the whole `.env.keys` — a stale legacy SNS line dies
/// here, which is correct: the key just written is the key of the session
/// file just written.
fn settle_custody(key_hex: &str) -> Result<bool, UserError> {
    if keychain::keychain_put(key_hex) {
        let _ = std::fs::remove_file(keys_path());
        Ok(true)
    } else {
        write_private_key_file(key_hex)?;
        Ok(false)
    }
}

/// Save the session over the dotenvx wire format. The keypair is reused
/// when its private key is recoverable (keychain, then the
/// `DOTENV_PRIVATE_KEY_SESSION` line in `.env.keys`), a fresh one is
/// generated otherwise, every field is encrypted to it, and the private
/// key's custody is settled.
///
/// The brick-guard refuses to write over a session no available key opens —
/// dotenvx (and this writer) encrypt to whatever public key the file
/// carries and would report success even when nothing can ever decrypt the
/// result; a stale keychain item (or a lost key) would silently brick the
/// session while the custody message claims the opposite. An enc1 file
/// meets none of that: it carries no dotenvx marker, so the guard is
/// skipped, and a legacy scalar still in the keychain is reused as a
/// secp256k1 scalar (valid range with probability 1-2^-128) — the file is
/// overwritten in the dotenvx format to that same hex, consistent and
/// openable. On a file-custody machine without a DOTENV line a fresh
/// keypair replaces the legacy one; both shapes stay openable. This only
/// happens on the login-replaces-unreadable-session path; normal reads
/// migrate first (load_session). No special case, on purpose.
///
/// There is no Rust analogue of the TS bootstrap dance (writePrivateKeyFile
/// only when a session exists, CI=true, the DOTENV_PRIVATE_KEY_SESSION env
/// injection, dotenvx's refusal to overwrite .env.keys during bootstrap):
/// this writer renders the file natively and settles custody itself.
pub fn save_session(secrets: &SessionSecrets) -> Result<SaveOutcome, UserError> {
    if !is_64_hex(&secrets.db_key) {
        return Err(UserError("refusing to store a database key that is not 64 hex characters".into()));
    }
    crate::paths::ensure_config_dir()?;
    remove_empty_session_file();
    let keychain_key = keychain::keychain_get();
    let file_key = read_private_key_file();
    // A session no available private key opens must not be written over.
    // `sns logout` deletes the unreadable file; the next login bootstraps
    // fresh (the TS-verbatim operator instruction, backticks included).
    if session_has_dotenvx_public_key() {
        let opens = keychain_key.as_deref().map(key_decrypts_session).unwrap_or(false)
            || file_key.as_deref().map(key_decrypts_session).unwrap_or(false);
        if !opens {
            return Err(UserError(
                ".env.session is encrypted to a dotenvx key sns cannot find — run `sns logout` to delete it, then `sns login` again".into(),
            ));
        }
    }
    let (private, public) = match keychain_key.clone().or_else(|| file_key.clone()) {
        Some(hex) => {
            // When the file carries the marker, the guard above already
            // proved this hex opens the session, so from_hex cannot fail
            // there; the map_err is for the no-file / no-marker paths.
            let private = SessionPrivateKey::from_hex(&hex).map_err(|_| {
                UserError("the stored session key is not a valid secp256k1 scalar — run sns logout".into())
            })?;
            let public = private.public_key();
            (private, public)
        }
        None => generate_keypair(),
    };

    let fields: Vec<(&'static str, String)> = pairs(secrets)
        .into_iter()
        .map(|(name, value)| {
            let record = encrypt_value(&value, &public, name)
                .map_err(|_| UserError(format!("could not encrypt {name}")))?;
            Ok((name, record))
        })
        .collect::<Result<Vec<_>, UserError>>()?;
    let file = render_session_file(&public, &fields);
    write_config_secret(&session_path(), &file, "the session file")?;

    let keychain = settle_custody(&private.to_hex())?;
    Ok(SaveOutcome { keychain })
}

/// Names as they appear in the session file (`sessionKeyNames`).
pub fn session_key_names() -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(session_path()) else {
        return Vec::new();
    };
    parse_session_file(&text).map(|parsed| parsed.fields.iter().map(|(name, _)| name.clone()).collect()).unwrap_or_default()
}

/// `with_access`'s save hook: refreshed session secrets reach the same
/// encrypted file (and keychain custody) as a login. One named policy shared
/// by every caller, typed for the API layer.
pub fn persist(next: &SessionSecrets) -> Result<(), crate::sn_api::ApiClientError> {
    save_session(next)
        .map(|_| ())
        .map_err(|error| crate::sn_api::ApiClientError::User(error.to_string()))
}

/// `assertSessionKeyNames` — the first name outside the session contract,
/// ignoring the dotenvx public-key prefix a hand-edited file may still carry.
pub fn first_unexpected(names: &[String]) -> Option<String> {
    names
        .iter()
        .find(|name| !name.starts_with("DOTENV_PUBLIC_KEY") && !crate::session::SESSION_VALUE_KEYS.contains(&name.as_str()))
        .cloned()
}

/// The legacy enc1 attempt: validate the candidate as a P-256 scalar, then
/// decrypt every `enc1:` record with the field name as associated data
/// (legacy records ARE name-bound); values without a record prefix pass
/// through. None on any failure.
fn try_decrypt_enc1(parsed: &ParsedSession, key_hex: &str) -> Option<HashMap<String, String>> {
    let private = LegacySessionPrivateKey::from_hex(key_hex).ok()?;
    let mut values = HashMap::new();
    for (name, value) in &parsed.fields {
        if value.starts_with(crate::session::LEGACY_RECORD_PREFIX) {
            let decrypted = private.decrypt_value(value, name).ok()?;
            values.insert(name.clone(), decrypted.as_str().to_string());
        } else {
            values.insert(name.clone(), value.clone());
        }
    }
    Some(values)
}

/// The shared tail of both load attempts: the missing-token check, then the
/// SessionSecrets. TS's leftover-ciphertext sweep (src/session-file.ts
/// loadSession) has no separate Rust shape — the attempt that produced
/// `values` returned Some only when every `encrypted:` record decrypted.
fn finish_loaded_session(values: HashMap<String, String>) -> Result<Option<SessionSecrets>, UserError> {
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

/// Load and decrypt the session. None when no session file exists.
///
/// dotenvx first, legacy enc1 second. Detection is by marker: a
/// `DOTENV_PUBLIC_KEY_SESSION` header or `encrypted:` records means the
/// dotenvx format; an `SNS_SESSION_PUBLIC_KEY` header or `enc1:` records
/// means legacy enc1. Plaintext files (no markers) pass through, mirroring
/// dotenvx parse — the missing-token check then fires exactly as TS. Mixed
/// files try dotenvx, then enc1, and fail closed when neither opens, where
/// TS's dotenvx parse would silently pass garbled values through.
///
/// Custody candidates: the keychain, the `.env.keys` DOTENV line, and (for
/// the legacy attempt) the SNS line, in that order, deduplicated. A
/// deliberate divergence from TS: a legacy-only file with ONLY the SNS line
/// present does not hit the missing-custody error, because that state is
/// the migration entry point. A legacy-only file whose keychain scalar is
/// the old P-256 key simply fails the dotenvx attempt (the scalar parses as
/// secp256k1 with probability 1-2^-128 and then decrypts nothing) and is
/// opened by the enc1 attempt — never an error path, never special-cased.
pub fn load_session() -> Result<Option<SessionSecrets>, UserError> {
    if !session_path().exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(session_path()).map_err(|error| UserError(error.to_string()))?;
    let parsed = parse_session_file(&text).map_err(|error| UserError(error.to_string()))?;
    let names: Vec<String> = parsed.fields.iter().map(|(name, _)| name.clone()).collect();
    if let Some(unexpected) = first_unexpected(&names) {
        return Err(UserError(format!("session file contains an unexpected key ({unexpected})")));
    }

    let has_dotenvx = parsed.public_key_base64.is_some()
        || parsed.fields.iter().any(|(_, value)| value.starts_with(crate::session::RECORD_PREFIX));
    let has_legacy = parsed.legacy_public_key_base64.is_some()
        || parsed.fields.iter().any(|(_, value)| value.starts_with(crate::session::LEGACY_RECORD_PREFIX));
    let legacy_only = has_legacy && !has_dotenvx;

    let keychain_key = keychain::keychain_get();
    let dotenv_line = read_private_key_file();
    let legacy_line = read_legacy_key_line();
    let dotenv_custody = keychain_key.is_some() || dotenv_line.is_some();
    if (!legacy_only && !dotenv_custody) || (legacy_only && !dotenv_custody && legacy_line.is_none()) {
        return Err(UserError(
            "session file is encrypted but the dotenvx private key is missing — run sns login".into(),
        ));
    }

    // Attempt 1 — dotenvx, keychain then the DOTENV line (the TS
    // readPrivateKey order).
    let mut tried: Vec<&str> = Vec::new();
    for candidate in keychain_key.as_deref().into_iter().chain(dotenv_line.as_deref()) {
        if tried.contains(&candidate) {
            continue;
        }
        tried.push(candidate);
        if let Some(values) = try_decrypt_dotenvx(&parsed, candidate) {
            return finish_loaded_session(values);
        }
    }
    if !has_legacy {
        return Err(UserError(
            "could not decrypt .env.session — the dotenvx key does not match".into(),
        ));
    }

    // Attempt 2 — legacy enc1; the DOTENV line is tried last because it
    // matters at crash-window C2 (a staged new key while the file still
    // says enc1 is recovered from the SNS line instead).
    let mut tried_legacy: Vec<&str> = Vec::new();
    for candidate in keychain_key
        .as_deref()
        .into_iter()
        .chain(legacy_line.as_deref())
        .chain(dotenv_line.as_deref())
    {
        if tried_legacy.contains(&candidate) {
            continue;
        }
        tried_legacy.push(candidate);
        if let Some(values) = try_decrypt_enc1(&parsed, candidate) {
            run_migration(&values);
            return finish_loaded_session(values);
        }
    }
    // One error shape for "no key opens this session": post-migration the
    // only format is dotenvx, and the operator instruction (logout + login)
    // is identical — a legacy-specific message would dead-end now that enc1
    // encryption is gone.
    Err(UserError(
        "could not decrypt .env.session — the dotenvx key does not match".into(),
    ))
}

/// One-shot legacy enc1 -> dotenvx migration. Runs only after a successful
/// enc1 decrypt, under the sync lock (run_migration). The step order IS the
/// crash-safety argument:
///
/// A. generate a fresh secp256k1 keypair;
/// B. STAGE the new key to `.env.keys` — with the old SNS line carried over
///    if, and only if, it was already on disk (a keychain secret is never
///    copied to a file; that would undo what keychain custody is for) —
///    BEFORE touching the session file;
/// C. FLIP the session file: re-encrypt all eight values to the new public
///    key in the dotenvx format;
/// D. settle custody: the keychain put is an upsert, so the old P-256
///    scalar in the shared slot (service sn_secrets_cli, account dotenvkey)
///    is overwritten in place; on success the staged `.env.keys` is
///    removed, on failure it is replaced with the clean two-line file (the
///    old key is dead once the file flipped).
///
/// Crash windows:
/// - before B: unchanged enc1 state; a later command retries. Safe.
/// - C1 after B, before C (staged keys file, session still enc1):
///   keychain-custody machines still hold the OLD key — the dotenvx attempt
///   fails and the enc1 attempt recovers via the keychain; file-custody
///   machines recover the old SNS line from the staged file. Safe.
/// - C2 after C, before D (file flipped to the new key, custody not settled):
///   the staged DOTENV line recovers the new key. This is the window that
///   would brick under any custody-first order (the keychain overwritten
///   while the file is still enc1) and under any flip-first order without
///   staging (the file flipped while the new key exists nowhere).
///   Stage-before-flip is what closes it.
/// - C3 after D's keychain put, before the removal: the keychain opens; the
///   two-line file is inert. Safe.
/// - C4 after settle: fully migrated.
///
/// Double-migration race: two processes that both detect enc1 and decrypt
/// the SAME plaintext are serialized by the sync lock around B-D; the
/// second runs a FULL migration (fresh keypair, stage, flip, settle) rather
/// than a delta. Each migration is a complete state transition whose stage
/// carries the very key its flip encrypts to, so every interleaving
/// converges to one self-consistent key. Cross-binary (a concurrent TS
/// save): TS's protectPrivateKey puts whatever hex is in .env.keys —
/// exactly the key the flip encrypted to — so those interleavings converge
/// too. Worst case is one redundant extra migration and a superseded
/// plaintext, never a brick.
fn migrate_to_dotenvx(values: &HashMap<String, String>) -> Result<(), UserError> {
    let (private, public) = generate_keypair();
    // Step B — stage the new key before the flip.
    let mut staged = format!("# dotenvx private key for .env.session\n{PRIVATE_KEY_FIELD}={}\n", private.to_hex());
    if let Some(old) = read_legacy_key_line() {
        staged.push_str(&format!("{LEGACY_PRIVATE_KEY_FIELD}={old}\n"));
    }
    crate::paths::ensure_config_dir()?;
    write_config_secret(&keys_path(), &staged, ".env.keys")?;
    // Step C — flip the session file to the new public key.
    let mut fields = Vec::new();
    for (name, value) in pairs_from_values(values) {
        let record = encrypt_value(&value, &public, name)
            .map_err(|_| UserError(format!("could not encrypt {name}")))?;
        fields.push((name, record));
    }
    let file = render_session_file(&public, &fields);
    write_config_secret(&session_path(), &file, "the session file")?;
    // Step D — settle custody (keychain upsert over the old scalar, or the
    // clean file on a no-service machine).
    settle_custody(&private.to_hex())?;
    Ok(())
}

/// The sync lock around the migration. No load_session call site runs under
/// the lock today (logout and sync acquire it AFTER their load_session
/// calls), so this cannot self-deadlock. On lock timeout the migration is
/// skipped with a note and the read proceeds — a read command stuck behind
/// a long sync still works, and the migration retries on the next command.
fn run_migration(values: &HashMap<String, String>) {
    let result = match crate::lock::acquire_sync_lock(30_000) {
        Ok(release) => {
            let result = migrate_to_dotenvx(values);
            release();
            result
        }
        Err(error) => Err(error),
    };
    // Custody-relevant event (keychain slot contents change, .env.keys is
    // rewritten or removed): one line on stderr, stdout stays
    // machine-readable — logout/purge warnings set the precedent. A failed
    // migration is never fatal to the load: the plaintext is already in
    // hand, every crash state above is recoverable, and a later command
    // retries.
    match result {
        Ok(()) => eprintln!("migrated the legacy enc1 session file to the dotenvx format"),
        Err(error) => eprintln!(
            "note: the legacy session file was left in place — migration will retry on the next command ({error})"
        ),
    }
}

/// Delete the session file, the keys file, and the keychain entry.
pub fn delete_session() {
    // Captured before the sweep (mirrors src/session-file.ts deleteSession):
    // a keys file present at delete time means custody was the file, which
    // silences the unavailable-service keychain warning.
    let file_custody = keys_path().exists();
    // Exact names plus the crash-orphan temps: write_secret_file stages
    // `.env.keys.tmp-<pid>-<suffix>` carrying the plaintext session scalar,
    // and a SIGKILL mid-write leaves it behind — logout's amnesia promise
    // covers it too. Regular files and symlinks (a planted link at
    // .env.session is removed itself, never followed); a same-named
    // directory is left for the operator.
    if let Ok(entries) = std::fs::read_dir(crate::paths::config_dir()) {
        for entry in entries.flatten() {
            let removable = entry
                .file_type()
                .map(|t| t.is_file() || t.is_symlink())
                .unwrap_or(false)
                && crate::paths::is_owned_session_file_name(&entry.file_name().to_string_lossy());
            if removable {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    let result = keychain::keychain_delete();
    keychain::warn_if_keychain_item_survived(result, file_custody);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::collections::BTreeMap;

    // Every test here runs with keychain::disable_for_tests() (file custody;
    // keychain_put and secret_service_available become no-ops, so the real
    // keychain is never touched) inside with_config_dir over a fresh /tmp
    // dir. Caveat shared with the purge tests: keychain_get bypasses the
    // disable flag, which is fine on this box — secret-tool is absent, so
    // the lookup deterministically returns None.

    // Serialized: the global config override has one slot, and concurrent
    // tests would otherwise resolve into each other's config dirs. The lock
    // is the crate-wide config test lock — per-module mutexes do not
    // serialize across modules.
    fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
        crate::paths::lock_config_for_tests()
    }

    fn fresh_dir(tag: &str) -> String {
        let mut bytes = [0u8; 4];
        getrandom::fill(&mut bytes).expect("system rng");
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("sns-rs-session-{}-{hex}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp config dir creates");
        dir.display().to_string()
    }

    fn test_secrets() -> SessionSecrets {
        SessionSecrets {
            account_email: "mig-test@example.test".into(),
            refresh_token: "refresh-token".into(),
            access_token: "access-token".into(),
            access_expiration_ms: 1_800_000_000_000,
            refresh_expiration_ms: 1_900_000_000_000,
            access_cookie: "access_token=a".into(),
            refresh_cookie: "refresh_token=r".into(),
            db_key: "ab".repeat(32),
        }
    }

    // -- Golden vectors (file cases) ----------------------------------------

    const VECTORS_JSON: &str = include_str!("../tests/fixtures/session-vectors.json");

    #[derive(Deserialize)]
    struct Vectors {
        #[serde(rename = "fileCases")]
        file_cases: Vec<FileCase>,
    }

    #[derive(Deserialize)]
    struct FileCase {
        name: String,
        #[serde(rename = "publicKeyHex")]
        public_key_hex: String,
        secrets: BTreeMap<String, String>,
        #[serde(rename = "sessionFile")]
        session_file: String,
        #[serde(rename = "keysFile")]
        keys_file: String,
    }

    // -- Legacy enc1 fixture (captured from the enc1-era code) --------------

    const LEGACY_SESSION: &str = include_str!("../tests/fixtures/legacy-enc1/.env.session");
    const LEGACY_KEYS: &str = include_str!("../tests/fixtures/legacy-enc1/.env.keys");

    fn legacy_key_line() -> String {
        LEGACY_KEYS
            .lines()
            .find_map(|line| line.strip_prefix("SNS_SESSION_PRIVATE_KEY="))
            .expect("fixture carries the SNS custody line")
            .to_string()
    }

    #[test]
    fn key_decrypts_session_true_for_the_matching_key() {
        crate::keychain::disable_for_tests();
        let _serial = serial_guard();
        let dir = fresh_dir("kds-true");
        crate::paths::with_config_dir(&dir, || {
            save_session(&test_secrets()).expect("session saves");
            let stored = read_private_key_file().expect("dotenvx key lands in .env.keys");
            assert!(key_decrypts_session(&stored), "the custody key opens the session");
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn key_decrypts_session_false_for_a_wrong_key() {
        crate::keychain::disable_for_tests();
        let _serial = serial_guard();
        let dir = fresh_dir("kds-wrong");
        crate::paths::with_config_dir(&dir, || {
            save_session(&test_secrets()).expect("session saves");
            let wrong = generate_keypair().0.to_hex();
            assert!(!key_decrypts_session(&wrong), "an unrelated scalar opens nothing");
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn key_decrypts_session_false_without_a_session_file() {
        crate::keychain::disable_for_tests();
        let _serial = serial_guard();
        let dir = fresh_dir("kds-absent");
        crate::paths::with_config_dir(&dir, || {
            assert!(!key_decrypts_session(&"cd".repeat(32)), "no session file, no trial");
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn key_decrypts_session_false_for_a_garbage_scalar() {
        crate::keychain::disable_for_tests();
        let _serial = serial_guard();
        let dir = fresh_dir("kds-garbage");
        crate::paths::with_config_dir(&dir, || {
            save_session(&test_secrets()).expect("session saves");
            assert!(!key_decrypts_session("zz"), "not hex");
            assert!(!key_decrypts_session(""), "empty");
            assert!(!key_decrypts_session(&"ab".repeat(31)), "63 hex is not a scalar");
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_session_refuses_to_write_over_an_orphaned_public_key() {
        crate::keychain::disable_for_tests();
        let _serial = serial_guard();
        let dir = fresh_dir("brick");
        crate::paths::with_config_dir(&dir, || {
            // A session encrypted to a key nothing on this machine holds.
            let public = generate_keypair().1;
            let fields: Vec<(&'static str, String)> = crate::session::SESSION_VALUE_KEYS
                .iter()
                .map(|name| (*name, "encrypted:junk".to_string()))
                .collect();
            let orphan = render_session_file(&public, &fields);
            std::fs::write(session_path(), &orphan).expect("orphan session written");

            let error = save_session(&test_secrets()).expect_err("the brick-guard refuses");
            assert!(
                error.0.contains("encrypted to a dotenvx key sns cannot find"),
                "got: {error}"
            );
            assert_eq!(
                std::fs::read_to_string(session_path()).expect("orphan still reads"),
                orphan,
                "the refused save leaves the file byte-identical"
            );
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_session_reuses_a_key_that_opens_the_session() {
        crate::keychain::disable_for_tests();
        let _serial = serial_guard();
        let dir = fresh_dir("reuse");
        crate::paths::with_config_dir(&dir, || {
            save_session(&test_secrets()).expect("first save");
            let first = parse_session_file(&std::fs::read_to_string(session_path()).expect("reads"))
                .expect("parses")
                .public_key_base64
                .expect("header present");
            save_session(&test_secrets()).expect("second save");
            let second = parse_session_file(&std::fs::read_to_string(session_path()).expect("reads"))
                .expect("parses")
                .public_key_base64
                .expect("header present");
            assert_eq!(first, second, "the key that opens the session is reused");
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_session_bootstraps_a_fresh_keypair_without_a_session_file() {
        crate::keychain::disable_for_tests();
        let _serial = serial_guard();
        let dir = fresh_dir("bootstrap");
        crate::paths::with_config_dir(&dir, || {
            save_session(&test_secrets()).expect("bootstrap save");
            let text = std::fs::read_to_string(session_path()).expect("session written");
            let parsed = parse_session_file(&text).expect("parses");
            assert!(parsed.public_key_base64.is_some(), "dotenvx header present");

            // Exact TS custody-file bytes: header line, one unquoted line.
            let keys = std::fs::read_to_string(keys_path()).expect("keys file written");
            let (header, rest) = keys.split_once('\n').expect("header terminated");
            assert_eq!(header, "# dotenvx private key for .env.session");
            let (key_line, tail) = rest.split_once('\n').expect("key line terminated");
            assert_eq!(tail, "", "file ends with a single trailing newline");
            let scalar = key_line
                .strip_prefix("DOTENV_PRIVATE_KEY_SESSION=")
                .expect("field name");
            assert_eq!(scalar.len(), 64, "64 hex characters");
            assert!(hex::decode(scalar).is_ok(), "scalar is hex");

            let loaded = load_session().expect("loads").expect("some session");
            assert_eq!(pairs(&loaded), pairs(&test_secrets()), "all 8 values round trip");
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_session_removes_a_crash_orphaned_empty_session_file() {
        crate::keychain::disable_for_tests();
        let _serial = serial_guard();
        let dir = fresh_dir("empty-orphan");
        crate::paths::with_config_dir(&dir, || {
            std::fs::write(session_path(), "").expect("0-byte orphan written");
            assert_eq!(std::fs::metadata(session_path()).expect("orphan exists").len(), 0);
            save_session(&test_secrets()).expect("the orphan does not wedge the save");
            let text = std::fs::read_to_string(session_path()).expect("session written");
            assert!(!text.is_empty(), "the real session replaced the orphan");
            assert!(parse_session_file(&text).expect("parses").public_key_base64.is_some());
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_dotenvx_session_from_the_golden_vectors_loads() {
        crate::keychain::disable_for_tests();
        let _serial = serial_guard();
        let dir = fresh_dir("golden");
        crate::paths::with_config_dir(&dir, || {
            let vectors: Vectors = serde_json::from_str(VECTORS_JSON).expect("golden vectors parse");
            let case = vectors
                .file_cases
                .iter()
                .find(|case| case.name == "canonical-fresh-session")
                .expect("fresh-session file case exists");
            std::fs::write(session_path(), &case.session_file).expect("golden session written");
            std::fs::write(keys_path(), &case.keys_file).expect("golden keys written");

            let loaded = load_session().expect("loads").expect("some session");
            for (name, value) in pairs(&loaded) {
                assert_eq!(
                    case.secrets.get(name).map(String::as_str),
                    Some(value.as_str()),
                    "{name} matches the library's plaintext"
                );
            }
            let parsed = parse_session_file(&std::fs::read_to_string(session_path()).expect("reads"))
                .expect("parses");
            assert_eq!(
                parsed.public_key_base64.as_deref(),
                Some(case.public_key_hex.as_str()),
                "the header carries the fixture public key"
            );
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_orphaned_public_key_session_fails_load_with_the_parity_message() {
        crate::keychain::disable_for_tests();
        let _serial = serial_guard();
        let dir = fresh_dir("orphan-load");
        crate::paths::with_config_dir(&dir, || {
            let vectors: Vectors = serde_json::from_str(VECTORS_JSON).expect("golden vectors parse");
            let case = vectors
                .file_cases
                .iter()
                .find(|case| case.name == "canonical-fresh-session")
                .expect("fresh-session file case exists");
            std::fs::write(session_path(), &case.session_file).expect("golden session written");
            // Valid scalar, wrong key: the exact TS mismatch message.
            std::fs::write(
                keys_path(),
                format!("# dotenvx private key for .env.session\nDOTENV_PRIVATE_KEY_SESSION={}\n", "ee".repeat(32)),
            )
            .expect("unrelated keys written");

            let error = load_session().expect_err("a session no key opens is an error");
            assert_eq!(
                error.0,
                "could not decrypt .env.session — the dotenvx key does not match"
            );
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_session_with_a_garbage_key_and_no_session_is_an_error() {
        crate::keychain::disable_for_tests();
        let _serial = serial_guard();
        let dir = fresh_dir("garbage-save");
        crate::paths::with_config_dir(&dir, || {
            std::fs::write(keys_path(), "DOTENV_PRIVATE_KEY_SESSION=zz\n").expect("garbage keys written");
            let error = save_session(&test_secrets()).expect_err("a garbage scalar refuses to save");
            assert!(error.0.contains("not a valid secp256k1 scalar"), "got: {error}");
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_session_migrates_the_legacy_enc1_fixture() {
        crate::keychain::disable_for_tests();
        let _serial = serial_guard();
        let dir = fresh_dir("migrate");
        crate::paths::with_config_dir(&dir, || {
            crate::paths::ensure_config_dir().expect("config dir creates");
            std::fs::write(session_path(), LEGACY_SESSION).expect("legacy session seeded");
            std::fs::write(keys_path(), LEGACY_KEYS).expect("legacy keys seeded");

            let loaded = load_session().expect("migration load succeeds").expect("some session");
            assert!(is_64_hex(&loaded.db_key), "db key is 64 hex");
            assert!(!loaded.refresh_token.is_empty(), "refresh token present");

            let session = std::fs::read_to_string(session_path()).expect("session reads");
            assert!(session.contains("DOTENV_PUBLIC_KEY_SESSION="), "migrated header present");
            assert!(!session.contains("enc1:"), "no legacy records remain");
            let keys = std::fs::read_to_string(keys_path()).expect("keys reads");
            assert!(keys.contains("DOTENV_PRIVATE_KEY_SESSION="), "dotenvx custody present");
            assert!(!keys.contains("SNS_SESSION_PRIVATE_KEY="), "legacy custody line gone");

            let again = load_session().expect("second load").expect("some session");
            assert_eq!(pairs(&again), pairs(&loaded), "stable — no re-migration");
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn migration_recovers_from_a_staged_keys_file_crash() {
        crate::keychain::disable_for_tests();
        let _serial = serial_guard();
        let dir = fresh_dir("crash-windows");
        crate::paths::with_config_dir(&dir, || {
            crate::paths::ensure_config_dir().expect("config dir creates");

            // C1: the staged keys file exists, the session file is still enc1.
            std::fs::write(session_path(), LEGACY_SESSION).expect("legacy session seeded");
            let staged = format!(
                "# dotenvx private key for .env.session\nDOTENV_PRIVATE_KEY_SESSION={}\nSNS_SESSION_PRIVATE_KEY={}\n",
                generate_keypair().0.to_hex(),
                legacy_key_line()
            );
            std::fs::write(keys_path(), staged).expect("staged keys written");
            let c1 = load_session().expect("C1 recovers via the enc1 attempt").expect("some session");
            assert_eq!(c1.db_key, "ab".repeat(32), "the legacy plaintext came through");

            // C2: the session file is already flipped to a fresh key K and
            // .env.keys holds only K — the dotenvx attempt recovers it.
            let (private, public) = generate_keypair();
            let fields: Vec<(&'static str, String)> = pairs(&test_secrets())
                .into_iter()
                .map(|(name, value)| {
                    let record = encrypt_value(&value, &public, name).expect("field encrypts");
                    (name, record)
                })
                .collect();
            std::fs::write(session_path(), render_session_file(&public, &fields))
                .expect("flipped session written");
            std::fs::write(
                keys_path(),
                format!("# dotenvx private key for .env.session\nDOTENV_PRIVATE_KEY_SESSION={}\n", private.to_hex()),
            )
            .expect("staged new key written");
            let c2 = load_session().expect("C2 recovers via the dotenvx attempt").expect("some session");
            assert_eq!(pairs(&c2), pairs(&test_secrets()), "the staged key opens the flipped file");
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn migration_failure_leaves_the_legacy_file_in_place() {
        crate::keychain::disable_for_tests();
        let _serial = serial_guard();
        let dir = fresh_dir("migrate-fail");
        crate::paths::with_config_dir(&dir, || {
            crate::paths::ensure_config_dir().expect("config dir creates");
            std::fs::write(session_path(), LEGACY_SESSION).expect("legacy session seeded");
            std::fs::write(
                keys_path(),
                format!("# dotenvx private key for .env.session\nDOTENV_PRIVATE_KEY_SESSION={}\n", "ee".repeat(32)),
            )
            .expect("unrelated custody written");

            let error = load_session().expect_err("no key opens the fixture");
            assert_eq!(
                error.0,
                "could not decrypt .env.session — the dotenvx key does not match"
            );
            let session = std::fs::read_to_string(session_path()).expect("session reads");
            assert!(session.contains("enc1:"), "legacy records untouched");
            assert!(!session.contains("DOTENV_PUBLIC_KEY_SESSION="), "no header written");
        });
        let _ = std::fs::remove_dir_all(&dir);
    }
}
