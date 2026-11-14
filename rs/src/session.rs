//! Native session-file crypto — replaces dotenvx with the same security bar.
//!
//! Format (no compatibility with dotenvx; field names stay app-compatible):
//!
//! ```text
//! SNS_SESSION_PUBLIC_KEY=<base64 33-byte compressed P-256 point>
//! SN_ACCOUNT_EMAIL=enc1:<base64 record>
//! ...
//! ```
//!
//! Each record is `enc1:` + base64 of `ephemeral_public(33) || nonce(12) ||
//! ciphertext || tag(16)` — an ECIES-style encryption of the value for the
//! session public key: ECDH P-256 (ephemeral-static), HKDF-SHA256 with the
//! ephemeral public key as salt and `sns/session/v1` as info, AES-256-GCM
//! with the field name as associated data (values cannot be swapped between
//! fields). This is dotenvx's bar (verified from its source: prime256v1
//! ECDH + HKDF-SHA256 + AES-256-GCM) with the field binding added.
//!
//! The private half is a 32-byte hex scalar in `.env.keys` (or the OS
//! keychain, where one exists). Wrong key and tampering are the same error,
//! by construction of GCM.

use aes_gcm::aead::array::Array;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use hkdf::Hkdf;
use p256::ecdh::SharedSecret;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{PublicKey, SecretKey};
use sha2::Sha256;
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Eq)]
pub enum SessionError {
    NotARecord,
    MalformedRecord,
    InvalidPublicKey,
    InvalidPrivateKey,
    KeyMismatch,
    Crypto(String),
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotARecord => write!(f, "not an enc1 session record"),
            Self::MalformedRecord => write!(f, "session record is malformed"),
            Self::InvalidPublicKey => write!(f, "session public key is invalid"),
            Self::InvalidPrivateKey => write!(f, "session private key is invalid"),
            Self::KeyMismatch => {
                write!(f, "could not decrypt — the session key does not match or the record was modified")
            }
            Self::Crypto(detail) => write!(f, "session crypto failed: {detail}"),
        }
    }
}

impl std::error::Error for SessionError {}

/// Every secret name a session file may carry (`env.ts`'s SESSION_VALUE_KEYS).
pub const SESSION_VALUE_KEYS: [&str; 8] = [
    "SN_ACCOUNT_EMAIL",
    "SN_REFRESH_TOKEN",
    "SN_ACCESS_TOKEN",
    "SN_ACCESS_EXPIRATION",
    "SN_REFRESH_EXPIRATION",
    "SN_ACCESS_COOKIE",
    "SN_REFRESH_COOKIE",
    "SN_DB_KEY",
];

/// The header line carrying the recipient public key.
pub const PUBLIC_KEY_FIELD: &str = "SNS_SESSION_PUBLIC_KEY";
const RECORD_PREFIX: &str = "enc1:";
const HKDF_INFO: &[u8] = b"sns/session/v1";
const EPHEMERAL_PUBLIC_BYTES: usize = 33;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const RECORD_OVERHEAD: usize = EPHEMERAL_PUBLIC_BYTES + NONCE_BYTES + TAG_BYTES;

pub struct SessionPrivateKey(Zeroizing<[u8; 32]>);

impl SessionPrivateKey {
    pub fn from_hex(hex_str: &str) -> Result<Self, SessionError> {
        let raw = hex::decode(hex_str).map_err(|_| SessionError::InvalidPrivateKey)?;
        let bytes: [u8; 32] = raw.try_into().map_err(|_| SessionError::InvalidPrivateKey)?;
        // Reject scalars outside [1, n-1]: a zero or over-order key from a
        // corrupted .env.keys would panic at first use otherwise.
        SecretKey::from_slice(&bytes).map_err(|_| SessionError::InvalidPrivateKey)?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(*self.0)
    }

    /// Compressed SEC1 public point, the form stored in the session file.
    pub fn public_key(&self) -> SessionPublicKey {
        let secret = SecretKey::from_slice(&self.0[..]).expect("validated at construction");
        let point = secret.public_key().to_sec1_point(true);
        SessionPublicKey(point.as_bytes().try_into().expect("compressed point is 33 bytes"))
    }

    pub fn secret_key(&self) -> SecretKey {
        SecretKey::from_slice(&self.0[..]).expect("validated at construction")
    }
}

impl core::fmt::Debug for SessionPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SessionPrivateKey([redacted])")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SessionPublicKey([u8; 33]);

impl SessionPublicKey {
    pub fn from_base64(encoded: &str) -> Result<Self, SessionError> {
        let raw = BASE64.decode(encoded).map_err(|_| SessionError::InvalidPublicKey)?;
        let bytes: [u8; 33] = raw.try_into().map_err(|_| SessionError::InvalidPublicKey)?;
        // Reject points that are not on the curve, not just the length.
        PublicKey::from_sec1_bytes(&bytes).map_err(|_| SessionError::InvalidPublicKey)?;
        Ok(Self(bytes))
    }

    pub fn to_base64(&self) -> String {
        BASE64.encode(self.0)
    }
}

impl core::fmt::Debug for SessionPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SessionPublicKey").field(&self.to_base64()).finish()
    }
}

/// A fresh session keypair — generated once per `login`.
pub fn generate_keypair() -> (SessionPrivateKey, SessionPublicKey) {
    let private = random_secret();
    let public = private.public_key();
    (private, public)
}

/// The `.env.keys` custodian never sees a SecretKey type — just 64 hex chars.
fn random_secret() -> SessionPrivateKey {
    loop {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("system rng");
        if SecretKey::from_slice(&bytes).is_ok() {
            return SessionPrivateKey(Zeroizing::new(bytes));
        }
    }
}

fn shared_secret(private: &SessionPrivateKey, peer: &[u8; 33]) -> Result<SharedSecret, SessionError> {
    let peer_public = PublicKey::from_sec1_bytes(peer).map_err(|_| SessionError::MalformedRecord)?;
    Ok(p256::ecdh::diffie_hellman(private.secret_key().to_nonzero_scalar(), peer_public.as_affine()))
}

fn session_key(shared: &SharedSecret, ephemeral_public: &[u8; 33]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(ephemeral_public), shared.raw_secret_bytes());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, &mut *okm).expect("32 bytes is a valid HKDF output length");
    okm
}

/// Encrypt one field. The field name is authenticated — records cannot be
/// swapped between names.
pub fn encrypt_value(plaintext: &str, recipient: &SessionPublicKey, field: &str) -> Result<String, SessionError> {
    let ephemeral = random_secret();
    let mut nonce = [0u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|error| SessionError::Crypto(error.to_string()))?;
    encrypt_value_with_ephemeral(plaintext, recipient, field, &ephemeral, &nonce)
}

fn encrypt_value_with_ephemeral(
    plaintext: &str,
    recipient: &SessionPublicKey,
    field: &str,
    ephemeral: &SessionPrivateKey,
    nonce: &[u8; NONCE_BYTES],
) -> Result<String, SessionError> {
    let ephemeral_public = ephemeral.public_key();
    let shared = shared_secret(ephemeral, &recipient.0)?;
    let key = session_key(&shared, &ephemeral_public.0);

    let ciphertext = Aes256Gcm::new(&Array::from(*key))
        .encrypt(&Array::from(*nonce), Payload { msg: plaintext.as_bytes(), aad: field.as_bytes() })
        .map_err(|_| SessionError::Crypto("encrypt failed".into()))?;

    let mut record = Vec::with_capacity(RECORD_OVERHEAD + plaintext.len());
    record.extend_from_slice(&ephemeral_public.0);
    record.extend_from_slice(nonce);
    record.extend_from_slice(&ciphertext);
    Ok(format!("{RECORD_PREFIX}{}", BASE64.encode(record)))
}

/// Decrypt one field. Wrong key and tampered records are the same error —
/// GCM cannot tell them apart, so neither do we.
pub fn decrypt_value(record: &str, private: &SessionPrivateKey, field: &str) -> Result<Zeroizing<String>, SessionError> {
    let encoded = record.strip_prefix(RECORD_PREFIX).ok_or(SessionError::NotARecord)?;
    let raw = BASE64.decode(encoded).map_err(|_| SessionError::MalformedRecord)?;
    if raw.len() < RECORD_OVERHEAD {
        return Err(SessionError::MalformedRecord);
    }
    let (ephemeral_public, rest) = raw.split_at(EPHEMERAL_PUBLIC_BYTES);
    let ephemeral_public: [u8; 33] = ephemeral_public.try_into().expect("split at 33");
    let (nonce, ciphertext) = rest.split_at(NONCE_BYTES);

    let shared = shared_secret(private, &ephemeral_public)?;
    let key = session_key(&shared, &ephemeral_public);
    let nonce: [u8; NONCE_BYTES] = nonce.try_into().expect("split at 12");
    let plaintext = Aes256Gcm::new(&Array::from(*key))
        .decrypt(&Array::from(nonce), Payload { msg: ciphertext, aad: field.as_bytes() })
        .map_err(|_| SessionError::KeyMismatch)?;
    Ok(Zeroizing::new(String::from_utf8(plaintext).map_err(|_| SessionError::Crypto("decrypted value is not utf-8".into()))?))
}

/// Render a session file: the public-key header, then one `KEY=record` line
/// per field, in the given order.
pub fn render_session_file(public_key: &SessionPublicKey, fields: &[(&str, String)]) -> String {
    let mut out = format!("{PUBLIC_KEY_FIELD}={}\n", public_key.to_base64());
    for (name, record) in fields {
        out.push_str(&format!("{name}={record}\n"));
    }
    out
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParsedSession {
    pub public_key_base64: Option<String>,
    pub fields: Vec<(String, String)>,
}

/// Parse a session file. Comment and blank lines are ignored; the public-key
/// header is lifted out, everything else stays a name/value pair. Duplicate
/// keys resolve last-wins, matching the dotenvx parser this replaces.
pub fn parse_session_file(text: &str) -> Result<ParsedSession, SessionError> {
    let mut parsed = ParsedSession { public_key_base64: None, fields: Vec::new() };
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (name, value) = trimmed.split_once('=').ok_or(SessionError::MalformedRecord)?;
        if name == PUBLIC_KEY_FIELD {
            parsed.public_key_base64 = Some(value.to_string());
        } else if let Some(existing) = parsed.fields.iter_mut().find(|(key, _)| key == name) {
            existing.1 = value.to_string();
        } else {
            parsed.fields.push((name.to_string(), value.to_string()));
        }
    }
    Ok(parsed)
}

/// Names outside the session contract (`env.ts`'s assertSessionKeyNames).
pub fn unexpected_keys(names: &[&str]) -> Vec<String> {
    names
        .iter()
        .filter(|name| !SESSION_VALUE_KEYS.contains(name))
        .map(|name| (*name).to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Independent known-answer vector: computed with node:crypto in Bun
    /// (createECDH prime256v1 + hkdfSync + aes-256-gcm), NOT by this module.
    /// Pins the whole composition — ECDH, salt choice, HKDF info, nonce
    /// placement, AAD binding, field order in the record.
    const KAT_RECIPIENT_HEX: &str = concat!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    const KAT_EPHEMERAL_HEX: &str = concat!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    const KAT_PUBLIC_B64: &str = "AjgBTGA8idqXEkJjIO5TqUx5Xdo7kLtbB5Guj120hrfb";
    const KAT_RECORD: &str = "enc1:AnYKBshY3BflxTbegR9xB7+iTU/uOdZK/ZFY7rqrPPJbAAECAwQFBgcICQoLHNs2JZe7dVwNHAHp5tHFvWAafUco0u5V/O7FGoP2MLDu9vuK7hWzBQoz3Se/ZSh49FNvcreAkNrMjl/q9odCaTcTDEPk0fXKOGEvFTNqwuc=";

    #[test]
    fn matches_the_independent_node_crypto_vector() {
        let recipient = SessionPrivateKey::from_hex(KAT_RECIPIENT_HEX).expect("recipient key");
        assert_eq!(recipient.public_key().to_base64(), KAT_PUBLIC_B64, "compressed point encoding matches");

        let ephemeral = SessionPrivateKey::from_hex(KAT_EPHEMERAL_HEX).expect("ephemeral key");
        let nonce = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let plaintext = Zeroizing::new("ab".repeat(32));
        let record = encrypt_value_with_ephemeral(&plaintext, &recipient.public_key(), "SN_DB_KEY", &ephemeral, &nonce)
            .expect("kat encryption succeeds");
        assert_eq!(record, KAT_RECORD);
        assert_eq!(decrypt_value(KAT_RECORD, &recipient, "SN_DB_KEY").expect("kat decrypts"), plaintext);
    }

    #[test]
    fn wrong_field_name_or_key_or_bytes_all_fail_closed() {
        let recipient = SessionPrivateKey::from_hex(KAT_RECIPIENT_HEX).expect("recipient key");
        let other = generate_keypair().0;
        assert_eq!(
            decrypt_value(KAT_RECORD, &recipient, "SN_REFRESH_TOKEN").expect_err("field swap refuses"),
            SessionError::KeyMismatch
        );
        assert_eq!(
            decrypt_value(KAT_RECORD, &other, "SN_DB_KEY").expect_err("wrong key refuses"),
            SessionError::KeyMismatch
        );
        let mut tampered = KAT_RECORD.to_string();
        tampered.replace_range(70..71, if tampered.as_bytes()[70] == b'A' { "B" } else { "A" });
        assert_eq!(decrypt_value(&tampered, &recipient, "SN_DB_KEY").expect_err("tamper refuses"), SessionError::KeyMismatch);
        assert_eq!(decrypt_value("junk", &recipient, "SN_DB_KEY"), Err(SessionError::NotARecord));
    }

    #[test]
    fn a_login_shaped_file_round_trips_end_to_end() {
        let (private, public) = generate_keypair();
        let values = [
            ("SN_ACCOUNT_EMAIL", "release-test@example.com"),
            ("SN_REFRESH_TOKEN", "token-🦀-with-unicode"),
            ("SN_ACCESS_TOKEN", "access"),
            ("SN_ACCESS_EXPIRATION", "1700000000000"),
            ("SN_REFRESH_EXPIRATION", "1799999999999"),
            ("SN_ACCESS_COOKIE", "cookie-a"),
            ("SN_REFRESH_COOKIE", "cookie-b"),
            ("SN_DB_KEY", &"ab".repeat(32)),
        ];
        let fields: Vec<(&str, String)> = values
            .iter()
            .map(|(name, value)| (*name, encrypt_value(value, &public, name).expect("field encrypts")))
            .collect();
        let file = render_session_file(&public, &fields);

        let parsed = parse_session_file(&file).expect("parses");
        assert_eq!(parsed.public_key_base64.as_deref(), Some(public.to_base64().as_str()));
        let names: Vec<&str> = parsed.fields.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(unexpected_keys(&names), Vec::<String>::new());
        assert_eq!(parsed.fields.len(), SESSION_VALUE_KEYS.len());

        for (name, value) in values {
            let record = parsed.fields.iter().find(|(field, _)| field == name).expect("field present").1.as_str();
            assert_eq!(decrypt_value(record, &private, name).expect("field decrypts").as_str(), value);
        }
    }

    #[test]
    fn records_are_never_reusable_between_fields_and_runs() {
        let (private, public) = generate_keypair();
        let a = encrypt_value("alpha", &public, "SN_DB_KEY").expect("encrypts");
        let b = encrypt_value("beta", &public, "SN_REFRESH_TOKEN").expect("encrypts");
        assert_ne!(a, b, "different fields and values never produce equal records");
        assert_ne!(a, encrypt_value("alpha", &public, "SN_DB_KEY").expect("encrypts again"), "randomized encryption");

        // Swap the ciphertexts: the field name in the AAD must reject both.
        let parsed = parse_session_file(&render_session_file(&public, &[("SN_DB_KEY", a), ("SN_REFRESH_TOKEN", b.clone())])).expect("parses");
        let swapped = vec![
            ("SN_DB_KEY".to_string(), b.clone()),
            ("SN_REFRESH_TOKEN".to_string(), parsed.fields[0].1.clone()),
        ];
        for (name, record) in &swapped {
            assert_eq!(decrypt_value(record, &private, name), Err(SessionError::KeyMismatch));
        }
    }

    #[test]
    fn public_keys_are_validated_on_decode() {
        let (_, public) = generate_keypair();
        assert_eq!(SessionPublicKey::from_base64(&public.to_base64()).expect("round trips"), public);
        assert!(SessionPublicKey::from_base64(&BASE64.encode([0u8; 33])).is_err(), "identity point is not on the curve");
        assert!(SessionPublicKey::from_base64("junk").is_err());
    }

    #[test]
    fn private_key_debug_never_leaks_and_hex_round_trips() {
        let (private, _) = generate_keypair();
        let debug = format!("{private:?}");
        assert_eq!(debug, "SessionPrivateKey([redacted])");
        assert!(!debug.contains(&private.to_hex()));
        assert_eq!(SessionPrivateKey::from_hex(&private.to_hex()).expect("hex round trips").to_hex(), private.to_hex());
        assert!(SessionPrivateKey::from_hex("abcd").is_err());
    }

    #[test]
    fn parse_ignores_comments_and_reports_malformed_lines() {
        let (private, public) = generate_keypair();
        let record = encrypt_value("x", &public, "SN_ACCESS_TOKEN").expect("encrypts");
        let file = format!("# a comment\n\n{PUBLIC_KEY_FIELD}={}\nSN_ACCESS_TOKEN={record}\n", public.to_base64());
        let parsed = parse_session_file(&file).expect("parses");
        assert_eq!(parsed.fields.len(), 1);
        assert_eq!(decrypt_value(&parsed.fields[0].1, &private, "SN_ACCESS_TOKEN").expect("decrypts").as_str(), "x");
        assert_eq!(parse_session_file("no equals sign"), Err(SessionError::MalformedRecord));
    }
}
