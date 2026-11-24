//! Session-file crypto in the dotenvx wire format — one `.env.session`
//! readable and writable by the TypeScript CLI, this binary, and the dotenvx
//! CLI alike (maintainer decision B: the format is implemented natively, no
//! dotenvx subprocess or per-machine Node dependency).
//!
//! Wire format, pinned byte-for-byte against @dotenvx/dotenvx 2.38.2 /
//! @dotenvx/primitives 3.3.1 (executable oracle: `scripts/session-spec-
//! reference.ts`; golden vectors: `rs/tests/fixtures/session-vectors.json`):
//!
//! ```text
//! #/-------------------[DOTENV_PUBLIC_KEY]--------------------/
//! DOTENV_PUBLIC_KEY_SESSION="<66-char compressed secp256k1 public key, hex>"
//!
//! # .env.session
//! SN_ACCOUNT_EMAIL="encrypted:<base64 record>"
//! ...
//! ```
//!
//! Each record is `encrypted:` + standard padded base64 of
//! `ephemeral_public(65, uncompressed) || iv(16) || auth_tag(16) ||
//! ciphertext`. The scheme is ECIES over secp256k1: the ephemeral key is an
//! uncompressed 65-byte public point; the ECDH shared point enters the key
//! derivation uncompressed (65 bytes) while the peer key feeds the scalar
//! multiplication compressed; the shared key is HKDF-SHA256 with a
//! 32-zero-byte salt and empty info; and AES-256-GCM runs with a 16-byte IV
//! and NO associated data, tag stored between the IV and the ciphertext.
//!
//! The absence of associated data is load-bearing for compatibility: a record
//! is not bound to its field name and decrypts identically under any name
//! (disclosed in SECURITY.md).
//!
//! The private half is a 32-byte hex secp256k1 scalar in `.env.keys`
//! (`DOTENV_PRIVATE_KEY_SESSION`) or the OS keychain (shared slot with the TS
//! CLI). Wrong key and tampering are the same error, by construction of GCM.

use aes_gcm::aead::array::Array;
use aes_gcm::aead::{Aead, KeyInit, consts::U16};
use aes_gcm::aes::Aes256;
use aes_gcm::AesGcm;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use hkdf::Hkdf;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::{ProjectivePoint, PublicKey, SecretKey};
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
            Self::NotARecord => write!(f, "not an encrypted session record"),
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

/// The public-key line in `.env.session` (`keynames(".env.session")`-derived).
pub const PUBLIC_KEY_FIELD: &str = "DOTENV_PUBLIC_KEY_SESSION";
/// The record prefix framing every encrypted value.
pub const RECORD_PREFIX: &str = "encrypted:";

/// Exact bytes of the `DOTENV_PUBLIC_KEY` banner dotenvx prepends above the
/// public-key line (pinned from @dotenvx/dotenvx's `prependPublicKey` helper;
/// asserted against the golden file vectors in tests).
pub const PUBLIC_KEY_BANNER: &str = "#/-------------------[DOTENV_PUBLIC_KEY]--------------------/\n#/            public-key encryption for .env files          /\n#/       [how it works](https://dotenvx.com/encryption)     /\n#/----------------------------------------------------------/\n";

const EPHEMERAL_PUBLIC_BYTES: usize = 65;
const IV_BYTES: usize = 16;
const TAG_BYTES: usize = 16;
const RECORD_OVERHEAD: usize = EPHEMERAL_PUBLIC_BYTES + IV_BYTES + TAG_BYTES;

/// AES-256-GCM with the dotenvx 16-byte nonce (`symmetricNonceLength = 16`).
type Gcm16 = AesGcm<Aes256, U16>;

#[derive(PartialEq, Eq)]
pub struct SessionPrivateKey(Zeroizing<[u8; 32]>);

impl SessionPrivateKey {
    pub fn from_hex(hex_str: &str) -> Result<Self, SessionError> {
        let raw = hex::decode(hex_str).map_err(|_| SessionError::InvalidPrivateKey)?;
        let bytes: [u8; 32] = raw.try_into().map_err(|_| SessionError::InvalidPrivateKey)?;
        // Reject scalars outside [1, n-1]: a zero or over-order key from a
        // corrupted .env.keys would fail at first use otherwise.
        SecretKey::from_slice(&bytes).map_err(|_| SessionError::InvalidPrivateKey)?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(*self.0)
    }

    /// Compressed SEC1 public point (the dotenvx public-key serialization),
    /// the form stored in the session file's `DOTENV_PUBLIC_KEY_SESSION`.
    pub fn public_key(&self) -> SessionPublicKey {
        let secret = SecretKey::from_slice(&self.0[..]).expect("validated at construction");
        let point = secret.public_key().to_sec1_point(true);
        SessionPublicKey(point.as_bytes().try_into().expect("compressed point is 33 bytes"))
    }
}

impl core::fmt::Debug for SessionPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SessionPrivateKey([redacted])")
    }
}

/// A session public key, held in its compressed 33-byte SEC1 form (the
/// dotenvx 66-char hex serialization).
#[derive(Clone, PartialEq, Eq)]
pub struct SessionPublicKey([u8; 33]);

impl SessionPublicKey {
    /// Parse the dotenvx public-key serialization: 66-char compressed hex, or
    /// 130-char uncompressed hex for parity with the library's accepted
    /// receiver encodings. The point must be on secp256k1.
    pub fn from_hex(hex_str: &str) -> Result<Self, SessionError> {
        let raw = hex::decode(hex_str).map_err(|_| SessionError::InvalidPublicKey)?;
        let point = PublicKey::from_sec1_bytes(&raw).map_err(|_| SessionError::InvalidPublicKey)?;
        Ok(Self(point.to_sec1_point(true).as_bytes().try_into().expect("compressed point is 33 bytes")))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl core::fmt::Debug for SessionPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SessionPublicKey").field(&self.to_hex()).finish()
    }
}

/// A fresh session keypair — generated once per `login`. The public key is
/// the compressed serialization, exactly what `DOTENV_PUBLIC_KEY_SESSION`
/// carries.
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

/// Encrypt one field value into an `encrypted:` record. The `field` argument
/// is accepted for call-site stability and IGNORED: the dotenvx wire format
/// carries no associated data, so the field name is not authenticated.
pub fn encrypt_value(plaintext: &str, recipient: &SessionPublicKey, field: &str) -> Result<String, SessionError> {
    let _ = field;
    let ephemeral = random_secret();
    let mut iv = [0u8; IV_BYTES];
    getrandom::fill(&mut iv).map_err(|error| SessionError::Crypto(error.to_string()))?;
    encrypt_value_with_ephemeral(plaintext, recipient, &ephemeral, &iv)
}

/// Deterministic core of [`encrypt_value`] — the golden-vector tests drive
/// this directly with the fixtures' fixed ephemeral scalars and IVs.
fn encrypt_value_with_ephemeral(
    plaintext: &str,
    recipient: &SessionPublicKey,
    ephemeral: &SessionPrivateKey,
    iv: &[u8; IV_BYTES],
) -> Result<String, SessionError> {
    let ephemeral_key = SecretKey::from_slice(&ephemeral.0[..]).map_err(|_| SessionError::InvalidPrivateKey)?;
    let ephemeral_public = ephemeral_key.public_key().to_sec1_point(false);
    let peer_public = PublicKey::from_sec1_bytes(&recipient.0).map_err(|_| SessionError::InvalidPublicKey)?;

    // S = d_e × receiver, serialized UNCOMPRESSED (65 bytes) — the noble
    // `getSharedSecret(secret, pub, false)` output. The scalar-mult input is
    // the peer key in compressed form; both curves' crates parse either.
    let shared_point = (ProjectivePoint::from(peer_public) * ephemeral_key.to_nonzero_scalar().as_ref()).to_affine();

    let mut ikm = Zeroizing::new([0u8; 130]);
    ikm[..EPHEMERAL_PUBLIC_BYTES].copy_from_slice(ephemeral_public.as_bytes());
    ikm[EPHEMERAL_PUBLIC_BYTES..].copy_from_slice(shared_point.to_sec1_point(false).as_bytes());
    let key = shared_key(&ikm);

    // aes-gcm appends the tag: ct||tag. The wire record stores the tag
    // BETWEEN the iv and the ciphertext (dotenvx symEncrypt: iv||tag||ct).
    let tagged = Gcm16::new(&Array::from(*key))
        .encrypt(&Array::from(*iv), plaintext.as_bytes())
        .map_err(|_| SessionError::Crypto("encrypt failed".into()))?;
    let body = tagged.len() - TAG_BYTES;

    let mut record = Vec::with_capacity(RECORD_OVERHEAD + plaintext.len());
    record.extend_from_slice(ephemeral_public.as_bytes());
    record.extend_from_slice(iv);
    record.extend_from_slice(&tagged[body..]);
    record.extend_from_slice(&tagged[..body]);
    Ok(format!("{RECORD_PREFIX}{}", BASE64.encode(record)))
}

/// HKDF-SHA256 over `ikm = ephemeral_public(65) || shared_point(65)`, with
/// dotenvx's exact parameters: salt = 32 zero bytes, info = empty, L = 32.
fn shared_key(ikm: &Zeroizing<[u8; 130]>) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), ikm.as_slice());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(&[], &mut *okm).expect("32 bytes is a valid HKDF output length");
    okm
}

/// Decrypt one `encrypted:` value. Wrong key and tampered records are the
/// same error — GCM cannot tell them apart, so neither do we, and a wrong-key
/// decrypt never returns garbage. The `field` argument is accepted for
/// call-site stability and IGNORED: this format binds no associated data, so
/// a record decrypts identically under any field name (the structural fact
/// SECURITY.md discloses; see also the pinned test asserting it).
pub fn decrypt_value(value: &str, private: &SessionPrivateKey, field: &str) -> Result<Zeroizing<String>, SessionError> {
    let _ = field;
    let encoded = value.strip_prefix(RECORD_PREFIX).ok_or(SessionError::NotARecord)?;
    let raw = BASE64.decode(encoded).map_err(|_| SessionError::MalformedRecord)?;
    if raw.len() < RECORD_OVERHEAD {
        return Err(SessionError::MalformedRecord);
    }
    let ephemeral_public = &raw[..EPHEMERAL_PUBLIC_BYTES];
    let iv: [u8; IV_BYTES] = raw[EPHEMERAL_PUBLIC_BYTES..EPHEMERAL_PUBLIC_BYTES + IV_BYTES]
        .try_into()
        .expect("split at fixed bounds");
    let tag = &raw[EPHEMERAL_PUBLIC_BYTES + IV_BYTES..RECORD_OVERHEAD];
    let ciphertext = &raw[RECORD_OVERHEAD..];

    let ephemeral_point =
        PublicKey::from_sec1_bytes(ephemeral_public).map_err(|_| SessionError::MalformedRecord)?;
    let key = SecretKey::from_slice(&private.0[..]).map_err(|_| SessionError::InvalidPrivateKey)?;
    let shared_point = (ProjectivePoint::from(ephemeral_point) * key.to_nonzero_scalar().as_ref()).to_affine();

    let mut ikm = Zeroizing::new([0u8; 130]);
    ikm[..EPHEMERAL_PUBLIC_BYTES].copy_from_slice(ephemeral_public);
    ikm[EPHEMERAL_PUBLIC_BYTES..].copy_from_slice(shared_point.to_sec1_point(false).as_bytes());
    let aes_key = shared_key(&ikm);

    let mut tagged = Vec::with_capacity(ciphertext.len() + TAG_BYTES);
    tagged.extend_from_slice(ciphertext);
    tagged.extend_from_slice(tag);
    let plaintext = Gcm16::new(&Array::from(*aes_key))
        .decrypt(&Array::from(iv), tagged.as_slice())
        .map_err(|_| SessionError::KeyMismatch)?;
    Ok(Zeroizing::new(
        String::from_utf8(plaintext).map_err(|_| SessionError::Crypto("decrypted value is not utf-8".into()))?,
    ))
}

/// Render a session file exactly the way dotenvx's fresh-session layout looks:
/// the `DOTENV_PUBLIC_KEY` banner, the quoted public-key line, the
/// `# .env.session` marker, then one double-quoted `KEY="record"` line per
/// field, in the given order, LF endings, trailing newline. Values arrive
/// already framed (`encrypted:…`), so the renderer is format-neutral; the
/// base64 alphabet never contains quotes, so no escaping is ever needed.
pub fn render_session_file(public_key: &SessionPublicKey, fields: &[(&str, String)]) -> String {
    let mut out = String::new();
    out.push_str(PUBLIC_KEY_BANNER);
    out.push_str(&format!("{PUBLIC_KEY_FIELD}=\"{}\"\n", public_key.to_hex()));
    out.push_str("\n# .env.session\n");
    for (name, record) in fields {
        out.push_str(&format!("{name}=\"{record}\"\n"));
    }
    out
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParsedSession {
    /// The armored public key from the file's `DOTENV_PUBLIC_KEY_SESSION`
    /// line (bare hex — quotes stripped by the parser).
    pub public_key_base64: Option<String>,
    pub fields: Vec<(String, String)>,
}

/// Parse a session file with the dotenvx reader contract: CRLF normalized to
/// LF; blank lines and whole-line `#` comments (including the banner) skip;
/// an optional `export ` prefix; the public-key lines lifted out; values
/// single-, double- or backtick-quoted (double quotes expand `\n`, `\r`,
/// `\t` but leave `\"` literal, matching dotenvx) or unquoted up to an inline
/// `#` comment, then trimmed. Duplicate keys resolve last-wins. The parser is
/// format-neutral: it never looks at value content.
pub fn parse_session_file(text: &str) -> Result<ParsedSession, SessionError> {
    let mut parsed = ParsedSession {
        public_key_base64: None,
        fields: Vec::new(),
    };
    for line in text.replace("\r\n", "\n").lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let body = match trimmed.strip_prefix("export") {
            Some(rest) if rest.starts_with(char::is_whitespace) => rest.trim_start(),
            _ => trimmed,
        };
        let Some((name, raw_value)) = body.split_once('=') else {
            return Err(SessionError::MalformedRecord);
        };
        let name = name.trim();
        if name.is_empty() {
            return Err(SessionError::MalformedRecord);
        }
        let value = parse_value(raw_value)?;
        if name == PUBLIC_KEY_FIELD {
            parsed.public_key_base64 = Some(value);
        } else if let Some(existing) = parsed.fields.iter_mut().find(|(key, _)| key == name) {
            existing.1 = value;
        } else {
            parsed.fields.push((name.to_string(), value));
        }
    }
    Ok(parsed)
}

/// One value as dotenvx reads it: quoted forms with their escape rules, or
/// unquoted text cut at the first `#` and trimmed.
fn parse_value(raw: &str) -> Result<String, SessionError> {
    let raw = raw.trim_start();
    if let Some(open) = raw.strip_prefix('"').or_else(|| raw.strip_prefix('\'')).or_else(|| raw.strip_prefix('`')) {
        let quote = raw.as_bytes()[0];
        let mut out = String::new();
        let mut closed = false;
        let mut chars = open.chars();
        while let Some(c) = chars.next() {
            if c as u8 == quote {
                closed = true;
                break;
            }
            if quote == b'"' && c == '\\' {
                match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    // dotenvx does NOT unescape \" — it stays literal.
                    Some(other) => {
                        out.push('\\');
                        out.push(other);
                    }
                    None => return Err(SessionError::MalformedRecord),
                }
            } else {
                out.push(c);
            }
        }
        if !closed {
            return Err(SessionError::MalformedRecord);
        }
        return Ok(out);
    }
    let unquoted = match raw.split_once('#') {
        Some((head, _)) => head.trim_end(),
        None => raw.trim_end(),
    };
    Ok(unquoted.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::collections::BTreeMap;

    // -- Golden vectors -----------------------------------------------------
    // Generated from the pinned @dotenvx/dotenvx 2.38.2 / @dotenvx/primitives
    // 3.3.1 library by scripts/session-spec-reference.ts and byte-validated
    // there (1122 checks). Every assertion below is against the library's
    // own bytes, not our reimplementation of them.

    const VECTORS_JSON: &str = include_str!("../tests/fixtures/session-vectors.json");

    #[derive(Deserialize)]
    struct Vectors {
        #[serde(rename = "recordCases")]
        record_cases: Vec<RecordCase>,
        #[serde(rename = "fileCases")]
        file_cases: Vec<FileCase>,
    }

    #[derive(Deserialize)]
    struct RecordCase {
        name: String,
        #[serde(rename = "privateKeyHex")]
        private_key_hex: String,
        #[serde(rename = "publicKeyHex")]
        public_key_hex: String,
        #[serde(rename = "publicKeyEncoding")]
        public_key_encoding: String,
        #[serde(rename = "ephemeralPrivateHex")]
        ephemeral_private_hex: String,
        #[serde(rename = "ivHex")]
        iv_hex: String,
        plaintext: String,
        value: String,
        #[serde(rename = "recordHex")]
        record_hex: String,
        #[serde(rename = "negativePrivateKeyHex")]
        negative_private_key_hex: Option<String>,
        #[serde(rename = "negativeKeyMustFail")]
        negative_key_must_fail: Option<bool>,
    }

    #[derive(Deserialize)]
    struct FileCase {
        name: String,
        #[serde(rename = "privateKeyHex")]
        private_key_hex: String,
        #[serde(rename = "publicKeyHex")]
        public_key_hex: String,
        #[serde(rename = "keysFileStyle")]
        keys_file_style: String,
        secrets: BTreeMap<String, String>,
        #[serde(rename = "sessionFile")]
        session_file: String,
        #[serde(rename = "keysFile")]
        keys_file: String,
        #[serde(rename = "recordInputs")]
        record_inputs: Vec<RecordInput>,
    }

    #[derive(Deserialize)]
    struct RecordInput {
        key: String,
        #[serde(rename = "ephemeralPrivateHex")]
        ephemeral_private_hex: String,
        #[serde(rename = "ivHex")]
        iv_hex: String,
    }

    fn vectors() -> Vectors {
        serde_json::from_str(VECTORS_JSON).expect("golden vectors parse")
    }

    fn iv_of(hex_str: &str) -> [u8; IV_BYTES] {
        hex::decode(hex_str).expect("fixture iv is hex").try_into().expect("iv is 16 bytes")
    }

    /// Every record case: our reconstruction with the fixture's fixed
    /// ephemeral scalar and IV is byte-identical to the library's record,
    /// and our decrypt of the library's record returns the plaintext.
    #[test]
    fn golden_record_vectors_reconstruct_and_decrypt() {
        let vectors = vectors();
        let mut checked = 0;
        for case in &vectors.record_cases {
            let recipient = SessionPrivateKey::from_hex(&case.private_key_hex).expect("fixture key");
            let recipient_public = SessionPublicKey::from_hex(&case.public_key_hex).expect("fixture public key");
            if case.public_key_encoding == "compressed" {
                assert_eq!(recipient.public_key().to_hex(), case.public_key_hex, "{}: compressed point matches", case.name);
            } else {
                // Uncompressed receiver encoding: accepted, compressed for
                // storage, and equal to the key derived from the scalar.
                assert_eq!(
                    recipient_public.to_hex(),
                    recipient.public_key().to_hex(),
                    "{}: 130-hex receiver compresses to the scalar's point",
                    case.name
                );
            }

            let ephemeral = SessionPrivateKey::from_hex(&case.ephemeral_private_hex).expect("fixture ephemeral");
            let record = encrypt_value_with_ephemeral(&case.plaintext, &recipient_public, &ephemeral, &iv_of(&case.iv_hex))
                .unwrap_or_else(|error| panic!("{}: reconstruction encrypts: {error}", case.name));
            assert_eq!(record, case.value, "{}: reconstructed record is byte-identical", case.name);

            let raw = BASE64
                .decode(record.strip_prefix(RECORD_PREFIX).expect("our own prefix"))
                .expect("our own base64");
            assert_eq!(hex::encode(&raw), case.record_hex, "{}: record layout matches", case.name);
            assert_eq!(raw.len(), RECORD_OVERHEAD + case.plaintext.len(), "{}: 65+16+16+utf8len", case.name);

            let decrypted = decrypt_value(&case.value, &recipient, "SN_DB_KEY")
                .unwrap_or_else(|error| panic!("{}: decrypts: {error}", case.name));
            assert_eq!(decrypted.as_str(), case.plaintext, "{}: plaintext round trips", case.name);
            checked += 1;
        }
        assert_eq!(checked, 14, "every record case exercised");
    }

    /// Every case flagged `negativeKeyMustFail` carries a second key the
    /// record was NOT encrypted to: decrypting with it must fail closed.
    #[test]
    fn golden_negative_vectors_refuse_the_wrong_key() {
        let vectors = vectors();
        let mut checked = 0;
        for case in &vectors.record_cases {
            let Some(wrong_hex) = &case.negative_private_key_hex else { continue };
            assert_eq!(case.negative_key_must_fail, Some(true), "{}: flagged must-fail", case.name);
            let wrong = SessionPrivateKey::from_hex(wrong_hex).expect("fixture wrong key");
            assert_eq!(
                decrypt_value(&case.value, &wrong, "SN_DB_KEY"),
                Err(SessionError::KeyMismatch),
                "{}: wrong key refuses",
                case.name
            );
            checked += 1;
        }
        assert!(checked >= 1, "at least one negative vector exercised");
    }

    /// The canonical fresh-session file case: parsing the library-rendered
    /// file lifts the public key and decrypts every field, and re-rendering
    /// the file from reconstructed records reproduces the library's bytes
    /// exactly (banner, quotes, order, LF endings, trailing newline).
    #[test]
    fn golden_fresh_session_file_parses_decrypts_and_rerenders_byte_identical() {
        let vectors = vectors();
        let case = vectors
            .file_cases
            .iter()
            .find(|case| case.name == "canonical-fresh-session")
            .expect("fresh-session file case exists");

        let private = SessionPrivateKey::from_hex(&case.private_key_hex).expect("fixture key");
        assert_eq!(private.public_key().to_hex(), case.public_key_hex);

        let parsed = parse_session_file(&case.session_file).expect("golden file parses");
        assert_eq!(parsed.public_key_base64.as_deref(), Some(case.public_key_hex.as_str()));
        let names: Vec<&str> = parsed.fields.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names.len(), SESSION_VALUE_KEYS.len(), "all 8 canonical fields");
        for (expected, actual) in case.record_inputs.iter().zip(names.iter()) {
            assert_eq!(&expected.key, *actual, "canonical field order");
        }
        assert!(
            names.iter().all(|name| SESSION_VALUE_KEYS.contains(name)),
            "every session field is inside the contract"
        );

        for (name, value) in &parsed.fields {
            let decrypted =
                decrypt_value(value, &private, name).unwrap_or_else(|error| panic!("{name} decrypts: {error}"));
            assert_eq!(&decrypted.as_str().to_string(), case.secrets.get(name).expect("secret in fixture"), "{name}");
        }

        let reconstructed_fields: Vec<(&str, String)> = case
            .record_inputs
            .iter()
            .map(|input| {
                let ephemeral = SessionPrivateKey::from_hex(&input.ephemeral_private_hex).expect("fixture ephemeral");
                let plaintext = case.secrets.get(&input.key).expect("secret in fixture");
                let record = encrypt_value_with_ephemeral(
                    plaintext,
                    &private.public_key(),
                    &ephemeral,
                    &iv_of(&input.iv_hex),
                )
                .expect("reconstruction encrypts");
                (input.key.as_str(), record)
            })
            .collect();
        let rendered = render_session_file(&private.public_key(), &reconstructed_fields);
        assert_eq!(rendered, case.session_file, "re-rendered file is byte-identical to the library's");
    }

    /// The TS-style `.env.keys` custody file is pinned as an exact byte
    /// string; the dotenvx bootstrap variant is pinned structurally (its
    /// banner carries a unicode rune and hand-transcription is risky — the
    /// fixture stays the byte authority for it).
    #[test]
    fn keys_file_custody_formats_are_pinned() {
        for case in vectors().file_cases {
            match case.keys_file_style.as_str() {
                "sns" => {
                    let expected =
                        format!("# dotenvx private key for .env.session\nDOTENV_PRIVATE_KEY_SESSION={}\n", case.private_key_hex);
                    assert_eq!(case.keys_file, expected);
                }
                "dotenvx" => {
                    assert!(case.keys_file.starts_with("#/------------------!DOTENV_PRIVATE_KEYS!"));
                    assert!(case.keys_file.contains("DO NOT commit to source control"));
                    assert!(case.keys_file.contains("dotenvx armor up"));
                    assert!(
                        case.keys_file.ends_with(&format!("\n# .env.session\nDOTENV_PRIVATE_KEY_SESSION={}\n", case.private_key_hex)),
                        "unquoted key line, file ends with a newline"
                    );
                }
                other => panic!("unknown keys file style {other}"),
            }
        }
    }

    /// The bootstrap-over-existing file case: an unquoted pre-existing line
    /// (`OLD_VAR=1`) and a comment survive the parse alongside the encrypted
    /// fields, and the encrypted field still decrypts.
    #[test]
    fn golden_bootstrap_file_parses_with_unquoted_lines() {
        let vectors = vectors();
        let case = vectors
            .file_cases
            .iter()
            .find(|case| case.name == "dotenvx-bootstrap-over-existing")
            .expect("bootstrap file case exists");
        let private = SessionPrivateKey::from_hex(&case.private_key_hex).expect("fixture key");
        let parsed = parse_session_file(&case.session_file).expect("bootstrap file parses");
        assert_eq!(parsed.public_key_base64.as_deref(), Some(case.public_key_hex.as_str()));
        let old = parsed.fields.iter().find(|(name, _)| name == "OLD_VAR").expect("OLD_VAR kept");
        assert_eq!(old.1, "1", "unquoted value passes through");
        let email = parsed.fields.iter().find(|(name, _)| name == "SN_ACCOUNT_EMAIL").expect("email kept");
        assert_eq!(
            decrypt_value(&email.1, &private, "SN_ACCOUNT_EMAIL").expect("decrypts").as_str(),
            case.secrets.get("SN_ACCOUNT_EMAIL").expect("fixture secret")
        );
    }

    // -- Roundtrip properties -----------------------------------------------

    /// A login-shaped session with fresh keys round trips through render and
    /// parse, field by field.
    #[test]
    fn a_login_shaped_file_round_trips_end_to_end() {
        let (private, public) = generate_keypair();
        let values = [
            ("SN_ACCOUNT_EMAIL", "release-test@example.com"),
            ("SN_REFRESH_TOKEN", "token-🦀-with-unicode"),
            ("SN_ACCESS_TOKEN", "access"),
            ("SN_ACCESS_EXPIRATION", "1700000000000"),
            ("SN_REFRESH_EXPIRATION", "1799999999999"),
            ("SN_ACCESS_COOKIE", "cookie-a; Path=/api; HttpOnly"),
            ("SN_REFRESH_COOKIE", "cookie-b"),
            ("SN_DB_KEY", &"ab".repeat(32)),
        ];
        let fields: Vec<(&str, String)> = values
            .iter()
            .map(|(name, value)| (*name, encrypt_value(value, &public, name).expect("field encrypts")))
            .collect();
        let file = render_session_file(&public, &fields);

        let parsed = parse_session_file(&file).expect("parses");
        assert_eq!(parsed.public_key_base64.as_deref(), Some(public.to_hex().as_str()));
        let names: Vec<String> = parsed.fields.iter().map(|(name, _)| name.clone()).collect();
        assert_eq!(crate::session_file::first_unexpected(&names), None, "every field inside the contract");
        assert_eq!(parsed.fields.len(), SESSION_VALUE_KEYS.len());

        for (name, value) in values {
            let record = parsed.fields.iter().find(|(field, _)| field == name).expect("field present").1.as_str();
            assert_eq!(decrypt_value(record, &private, name).expect("field decrypts").as_str(), value);
        }
    }

    /// Randomized encryption: same plaintext never repeats a record, and the
    /// record length is exactly overhead + plaintext bytes.
    #[test]
    fn records_are_randomized_and_sized_exactly() {
        let (private, public) = generate_keypair();
        let first = encrypt_value("alpha", &public, "SN_DB_KEY").expect("encrypts");
        let second = encrypt_value("alpha", &public, "SN_DB_KEY").expect("encrypts again");
        assert_ne!(first, second, "fresh randomness every encryption");

        let raw = BASE64.decode(first.strip_prefix(RECORD_PREFIX).expect("prefix")).expect("base64");
        assert_eq!(raw.len(), RECORD_OVERHEAD + "alpha".len());
        assert_eq!(&raw[..1], b"\x04", "ephemeral public key is uncompressed");
        assert_eq!(decrypt_value(&first, &private, "SN_DB_KEY").expect("decrypts").as_str(), "alpha");
        assert_eq!(decrypt_value(&second, &private, "SN_DB_KEY").expect("decrypts").as_str(), "alpha");
    }

    // -- Failure behavior ---------------------------------------------------

    #[test]
    fn wrong_key_and_tampering_fail_closed() {
        let (private, public) = generate_keypair();
        let other = generate_keypair().0;
        let record = encrypt_value("alpha", &public, "SN_DB_KEY").expect("encrypts");

        assert_eq!(decrypt_value(&record, &other, "SN_DB_KEY"), Err(SessionError::KeyMismatch), "wrong key");
        assert_eq!(decrypt_value("junk", &private, "SN_DB_KEY"), Err(SessionError::NotARecord), "not a record");

        // Flip one byte of the auth tag.
        let mut raw = BASE64.decode(record.strip_prefix(RECORD_PREFIX).expect("prefix")).expect("base64");
        raw[EPHEMERAL_PUBLIC_BYTES + IV_BYTES] ^= 0x01;
        let tampered = format!("{RECORD_PREFIX}{}", BASE64.encode(&raw));
        assert_eq!(decrypt_value(&tampered, &private, "SN_DB_KEY"), Err(SessionError::KeyMismatch));

        // Flip one byte of the iv.
        let mut raw = BASE64.decode(record.strip_prefix(RECORD_PREFIX).expect("prefix")).expect("base64");
        raw[EPHEMERAL_PUBLIC_BYTES] ^= 0x01;
        let tampered = format!("{RECORD_PREFIX}{}", BASE64.encode(&raw));
        assert_eq!(decrypt_value(&tampered, &private, "SN_DB_KEY"), Err(SessionError::KeyMismatch));

        // Truncated and oversized-junk records are malformed, not decryptable.
        raw.truncate(RECORD_OVERHEAD - 1);
        let truncated = format!("{RECORD_PREFIX}{}", BASE64.encode(&raw));
        assert_eq!(decrypt_value(&truncated, &private, "SN_DB_KEY"), Err(SessionError::MalformedRecord));
        assert_eq!(decrypt_value("encrypted:not base64!!", &private, "SN_DB_KEY"), Err(SessionError::MalformedRecord));
    }

    /// THE DISCLOSED WEAKNESS, asserted so it can never regress silently:
    /// the dotenvx wire format carries no associated data, so a record
    /// decrypts under ANY field name. SECURITY.md documents this as the
    /// accepted cost of dotenvx compatibility.
    #[test]
    fn records_are_not_bound_to_field_names_in_this_format() {
        let (private, public) = generate_keypair();
        let record = encrypt_value("top secret", &public, "SN_DB_KEY").expect("encrypts");
        assert_eq!(
            decrypt_value(&record, &private, "SN_DB_KEY").expect("own name decrypts").as_str(),
            "top secret"
        );
        let swapped = decrypt_value(&record, &private, "SN_REFRESH_TOKEN").expect("SWAPPED NAME STILL DECRYPTS");
        assert_eq!(swapped.as_str(), "top secret");
    }

    // -- Parser contract ----------------------------------------------------

    #[test]
    fn parser_accepts_the_dotenvx_reader_contract() {
        let (_, public) = generate_keypair();
        let file = format!(
            "{PUBLIC_KEY_BANNER}\
             export {PUBLIC_KEY_FIELD}=\"{hex}\"\n\
             SN_DB_KEY=\"line1\\nline2\"\n\
             SN_ACCESS_TOKEN='lit#eral'\n\
             SN_REFRESH_COOKIE=`back # tick`\n\
             SN_REFRESH_TOKEN =  unquoted value   # trailing comment\n\
             SN_ACCOUNT_EMAIL=plain\r\n\
             SN_ACCESS_EXPIRATION=\n\
             SN_ACCESS_COOKIE=\"first\"\n\
             SN_ACCESS_COOKIE=\"second\"\n",
            hex = public.to_hex()
        );
        let parsed = parse_session_file(&file).expect("parses");
        assert_eq!(parsed.public_key_base64.as_deref(), Some(public.to_hex().as_str()), "export prefix and quotes");
        assert_eq!(parsed.fields.len(), 7, "duplicate collapsed");
        let value = |name: &str| parsed.fields.iter().find(|(key, _)| key == name).expect("present").1.as_str();
        assert_eq!(value("SN_DB_KEY"), "line1\nline2", "double-quote \\n expands");
        assert_eq!(value("SN_ACCESS_TOKEN"), "lit#eral", "single quotes keep # literal");
        assert_eq!(value("SN_REFRESH_COOKIE"), "back # tick", "backtick quotes keep # literal");
        assert_eq!(value("SN_REFRESH_TOKEN"), "unquoted value", "unquoted cuts at # and trims");
        assert_eq!(value("SN_ACCOUNT_EMAIL"), "plain", "CRLF normalized");
        assert_eq!(value("SN_ACCESS_EXPIRATION"), "", "empty value");
        assert_eq!(value("SN_ACCESS_COOKIE"), "second", "duplicate keys resolve last-wins");
    }

    /// dotenvx keeps `\"` literal inside double quotes (it does NOT unescape
    /// it) — pinned so our reader never diverges from the library's.
    #[test]
    fn escaped_quote_stays_literal_backslash_quote() {
        let parsed = parse_session_file("SN_DB_KEY=\"a\\\"b\"\n").expect("parses");
        assert_eq!(parsed.fields[0].1, "a\\\"b");
    }

    #[test]
    fn parser_rejects_malformed_lines() {
        assert_eq!(parse_session_file("no equals sign"), Err(SessionError::MalformedRecord));
        assert_eq!(parse_session_file("=no name"), Err(SessionError::MalformedRecord));
        assert_eq!(parse_session_file("SN_DB_KEY=\"unterminated"), Err(SessionError::MalformedRecord));
    }

    // -- Key validation -----------------------------------------------------

    #[test]
    fn public_keys_are_validated_on_decode() {
        let (_, public) = generate_keypair();
        assert_eq!(SessionPublicKey::from_hex(&public.to_hex()).expect("hex round trips"), public);
        assert!(SessionPublicKey::from_hex(&"00".repeat(66)).is_err(), "identity point is not on the curve");
        assert!(SessionPublicKey::from_hex("junk").is_err());
        assert!(SessionPublicKey::from_hex(&"ff".repeat(66)).is_err(), "over-length hex is not a point");
        assert!(
            SessionPublicKey::from_hex(&format!("02{}", "00".repeat(32))).is_err(),
            "compressed identity refuses"
        );
    }

    #[test]
    fn private_key_debug_never_leaks_and_hex_round_trips() {
        let (private, _) = generate_keypair();
        assert_eq!(format!("{private:?}"), "SessionPrivateKey([redacted])");
        assert_eq!(SessionPrivateKey::from_hex(&private.to_hex()).expect("hex round trips").to_hex(), private.to_hex());
        assert_eq!(SessionPrivateKey::from_hex("abcd"), Err(SessionError::InvalidPrivateKey));
    }

    #[test]
    fn an_invalid_scalar_is_a_typed_error_not_a_panic() {
        // The zero scalar parses as hex but is not a valid secp256k1 key; a
        // corrupted .env.keys must produce an error, not a crash.
        assert_eq!(SessionPrivateKey::from_hex(&"00".repeat(32)), Err(SessionError::InvalidPrivateKey));
        assert_eq!(
            SessionPrivateKey::from_hex(&"ff".repeat(32)).map(|key| key.public_key().to_hex()),
            Err(SessionError::InvalidPrivateKey),
            "any scalar at or above the curve order refuses"
        );
    }
}
