//! Port of `src/sn-crypto/004.ts` — Standard Notes 004 item encryption.
//!
//! Payload shape: `004:{nonceHex}:{base64(ciphertext||tag)}:{base64(aad)}`.
//! The AEAD is XChaCha20-Poly1305-IETF over a 24-byte public nonce with the
//! base64 of the canonical JSON as authenticated data; an optional fifth
//! `:`-component carries signing metadata and is deliberately *not*
//! authenticated. Ciphertexts embed the 16-byte Poly1305 tag, exactly like
//! libsodium's `crypto_aead_xchacha20poly1305_ietf_*` output. Tests pin
//! deterministic vectors produced by the TypeScript/libsodium implementation.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Nonce, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305};
use serde::Deserialize as _;
use serde_json::Value;
use zeroize::Zeroizing;

pub const ITEMS_KEY_TYPE: &str = "SN|ItemsKey";
const NONCE_BYTES: usize = 24;
const KEY_BYTES: usize = 32;

/// Lenient `Option<bool>`: the server has sent booleans and 0/1 integers.
fn deserialize_opt_bool<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<bool>, D::Error> {
    let value = Option::<Value>::deserialize(deserializer)?;
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(flag)) => Ok(Some(flag)),
        Some(Value::Number(ref number)) => number
            .as_i64()
            .map(|as_int| Some(as_int != 0))
            .ok_or_else(|| serde::de::Error::custom("expected a boolean or an integer")),
        Some(Value::String(text)) => match text.as_str() {
            "true" => Ok(Some(true)),
            "false" => Ok(Some(false)),
            other => {
                let as_int: i64 = other
                    .parse()
                    .map_err(|_| serde::de::Error::custom("expected a boolean or an integer"))?;
                Ok(Some(as_int != 0))
            }
        },
        Some(_) => Err(serde::de::Error::custom("expected a boolean or an integer")),
    }
}

/// Lenient `Option<f64>` — timestamps arrive as integers, floats, or strings;
/// the fraction is kept so `to_unix_ms` can round like Math.round does.
fn deserialize_opt_f64<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<f64>, D::Error> {
    let value = Option::<Value>::deserialize(deserializer)?;
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(ref number)) => number
            .as_f64()
            .map(Some)
            .ok_or_else(|| serde::de::Error::custom("expected a number")),
        Some(Value::String(text)) => text
            .trim()
            .parse::<f64>()
            .map(Some)
            .map_err(|_| serde::de::Error::custom("expected a number")),
        Some(_) => Err(serde::de::Error::custom("expected a number")),
    }
}

/// The wire shape of a synced item (`src/sn-crypto/004.ts`'s `EncryptedItem`).
/// Deserialization is deliberately lenient: a strict parse would silently
/// drop live notes or tombstones from a sync page while the sync token still
/// advanced, so every server-side spelling of a field must parse.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EncryptedItem {
    pub uuid: String,
    pub content_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc_item_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items_key_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_opt_bool", skip_serializing_if = "Option::is_none")]
    pub deleted: Option<bool>,
    /// The server sends an ISO string (or a number); carried as-is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<Value>,
    #[serde(default, deserialize_with = "deserialize_opt_f64", skip_serializing_if = "Option::is_none")]
    pub updated_at_timestamp: Option<f64>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Proto004Error {
    NotA004Payload,
    InvalidNonce,
    InvalidKey,
    DecryptionFailed,
    MissingCiphertext,
    BadItemKey,
    CipherUtf8,
    Aead(String),
}

impl core::fmt::Display for Proto004Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotA004Payload => write!(f, "not a protocol 004 payload"),
            Self::InvalidNonce => write!(f, "protocol 004 nonce is invalid"),
            Self::InvalidKey => write!(f, "decryption key is invalid"),
            // One message for every post-validation failure, matching TS.
            Self::DecryptionFailed | Self::Aead(_) | Self::CipherUtf8 => write!(f, "decryption failed"),
            Self::MissingCiphertext => write!(f, "item is missing ciphertext"),
            Self::BadItemKey => write!(f, "item key did not decrypt"),
        }
    }
}

impl std::error::Error for Proto004Error {}

/// Canonical JSON: object keys sorted recursively, everything else as
/// `JSON.stringify` renders it. serde_json's map is a BTreeMap, so plain
/// serialization emits keys in sorted order; escaping matches JSON.stringify
/// for the string shapes Standard Notes puts in authenticated data (uuids,
/// versions, identifiers).
pub fn canonical_json(value: &Value) -> String {
    serde_json::to_string(value).expect("serializing a Value is infallible")
}

/// The AEAD's associated data: base64 of the canonical JSON.
pub fn aad_base64(authenticated_data: &Value) -> String {
    BASE64.encode(canonical_json(authenticated_data))
}

fn key_bytes(key_hex: &str) -> Result<Zeroizing<[u8; KEY_BYTES]>, Proto004Error> {
    let raw = hex::decode(key_hex).map_err(|_| Proto004Error::InvalidKey)?;
    let key: [u8; KEY_BYTES] = raw.try_into().map_err(|_| Proto004Error::InvalidKey)?;
    Ok(Zeroizing::new(key))
}

fn is_hex_of_len(value: &str, bytes: usize) -> bool {
    hex::decode(value).is_ok_and(|decoded| decoded.len() == bytes)
}

/// Encrypt with a fresh random nonce — the production path.
pub fn encrypt004(plaintext: &str, key_hex: &str, authenticated_data: &Value) -> Result<String, Proto004Error> {
    let mut nonce = [0u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|error| Proto004Error::Aead(error.to_string()))?;
    encrypt004_with_nonce(plaintext, key_hex, authenticated_data, &nonce)
}

/// Encrypt with a fixed nonce — deterministic output for tests and for
/// cross-implementation vectors.
pub fn encrypt004_with_nonce(
    plaintext: &str,
    key_hex: &str,
    authenticated_data: &Value,
    nonce: &[u8; NONCE_BYTES],
) -> Result<String, Proto004Error> {
    let key = key_bytes(key_hex)?;
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let aad = aad_base64(authenticated_data);
    let ciphertext = cipher
        .encrypt(&Nonce::<XChaCha20Poly1305>::from(*nonce), Payload { msg: plaintext.as_bytes(), aad: aad.as_bytes() })
        .map_err(|error| Proto004Error::Aead(error.to_string()))?;
    Ok(format!("004:{}:{}:{}", hex::encode(nonce), BASE64.encode(ciphertext), aad))
}

/// Decrypt a 004 payload. Accepts (and ignores) a fifth signing component.
pub fn decrypt004(payload: &str, key_hex: &str) -> Result<String, Proto004Error> {
    let parts: Vec<&str> = payload.split(':').collect();
    if parts.first() != Some(&"004") || parts.len() < 4 {
        return Err(Proto004Error::NotA004Payload);
    }
    let nonce_hex = parts[1];
    let cipher_b64 = parts[2];
    let aad = parts[3];
    let nonce = hex::decode(nonce_hex)
        .ok()
        .filter(|decoded| decoded.len() == NONCE_BYTES)
        .ok_or(Proto004Error::InvalidNonce)?;
    let key = key_bytes(key_hex)?;
    let ciphertext = BASE64.decode(cipher_b64).map_err(|_| Proto004Error::DecryptionFailed)?;
    let plaintext = XChaCha20Poly1305::new(&Key::from(*key))
        .decrypt(
            &Nonce::<XChaCha20Poly1305>::try_from(nonce.as_slice()).expect("nonce length validated above"),
            Payload { msg: &ciphertext, aad: aad.as_bytes() },
        )
        .map_err(|_| Proto004Error::DecryptionFailed)?;
    String::from_utf8(plaintext).map_err(|_| Proto004Error::CipherUtf8)
}

/// Decrypt one item. Items keys use the master key; everything else uses an
/// items key.
pub fn decrypt_item_content(item: &EncryptedItem, parent_key_hex: &str) -> Result<String, Proto004Error> {
    let enc_item_key = item.enc_item_key.as_deref().ok_or(Proto004Error::MissingCiphertext)?;
    let content = item.content.as_deref().ok_or(Proto004Error::MissingCiphertext)?;
    let item_key = Zeroizing::new(decrypt004(enc_item_key, parent_key_hex)?.trim().to_string());
    if !is_hex_of_len(&item_key, KEY_BYTES) {
        return Err(Proto004Error::BadItemKey);
    }
    decrypt004(content, &item_key)
}

/// Extract an items key from decrypted `SN|ItemsKey` content.
pub fn items_key_from_content(content: &str) -> Option<String> {
    let parsed: Value = serde_json::from_str(content).ok()?;
    let items_key = parsed.get("itemsKey")?.as_str()?;
    if is_hex_of_len(items_key, KEY_BYTES) {
        Some(items_key.to_lowercase())
    } else {
        None
    }
}

pub fn is_items_key(content_type: &str) -> bool {
    content_type == ITEMS_KEY_TYPE
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Deterministic vectors produced by the TypeScript/libsodium
    /// implementation (scripts run against src/sn-crypto/004.ts) — these pin
    /// canonical JSON, base64, nonce encoding, and the AEAD output together.
    const KEY_11: &str = concat!("11111111111111111111111111111111", "11111111111111111111111111111111");
    const VECTOR_HELLO: &str = "004:000102030405060708090a0b0c0d0e0f1011121314151617:83++Ho1yIWaBcKqag9gfg+zv1U8j:eyJ1IjoiMSIsInYiOiIwMDQifQ==";
    const KEY_22: &str = concat!("22222222222222222222222222222222", "22222222222222222222222222222222");
    const VECTOR_NOTE: &str = "004:18191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f:EAtoaAgkPLK9//OzV1RRS2C9fSuOUWzAr7ns4FcaL/iRrvremZxXGKK0gh8b4E5TGMoqnIxtFnE=:eyJ1Ijoibm90ZS11dWlkIiwidiI6IjAwNCJ9";
    const NOTE_JSON: &str = r#"{"title":"Pins","text":"door code 2468"}"#;

    fn fixed_nonce(byte_offset: u8) -> [u8; NONCE_BYTES] {
        let mut nonce = [0u8; NONCE_BYTES];
        for (index, byte) in nonce.iter_mut().enumerate() {
            *byte = byte_offset + index as u8;
        }
        nonce
    }

    fn random_key_hex() -> String {
        let mut key = [0u8; KEY_BYTES];
        getrandom::fill(&mut key).expect("system rng fills the key");
        hex::encode(key)
    }

    #[test]
    fn encrypt_output_byte_matches_the_typescript_implementation() {
        let payload = encrypt004_with_nonce("hello", KEY_11, &json!({ "u": "1", "v": "004" }), &fixed_nonce(0))
            .expect("encryption succeeds");
        assert_eq!(payload, VECTOR_HELLO);
        let decrypted = decrypt004(VECTOR_HELLO, KEY_11).expect("vector decrypts");
        assert_eq!(decrypted, "hello");
    }

    #[test]
    fn note_payload_byte_matches_and_round_trips() {
        let payload = encrypt004_with_nonce(
            NOTE_JSON,
            KEY_22,
            &json!({ "u": "note-uuid", "v": "004" }),
            &fixed_nonce(24),
        )
        .expect("encryption succeeds");
        assert_eq!(payload, VECTOR_NOTE);
        assert_eq!(decrypt004(VECTOR_NOTE, KEY_22).expect("vector decrypts"), NOTE_JSON);
    }

    /// The full key hierarchy from kdf.test.ts's sibling: master key wraps an
    /// items key (twice — an outer wrapping key), items key wraps the note.
    #[test]
    fn round_trips_a_note_through_an_items_key() {
        let master = random_key_hex();
        let items_key = random_key_hex();
        let wrapping_key = random_key_hex();
        let note_key = random_key_hex();
        let items_key_id = "11111111-1111-4111-8111-111111111111";
        let note_id = "22222222-2222-4222-8222-222222222222";

        let items_aad = json!({ "kp": { "identifier": "a@b.c", "version": "004" }, "u": items_key_id, "v": "004" });
        let note_aad = json!({ "u": note_id, "v": "004" });

        let items_item = EncryptedItem {
            uuid: items_key_id.into(),
            content_type: ITEMS_KEY_TYPE.into(),
            enc_item_key: Some(encrypt004(&wrapping_key, &master, &items_aad).expect("wrap key encrypts")),
            content: Some(
                encrypt004(&json!({ "itemsKey": items_key, "version": "004" }).to_string(), &wrapping_key, &items_aad)
                    .expect("items key encrypts"),
            ),
            items_key_id: None,
            deleted: None,
            updated_at: None,
            updated_at_timestamp: None,
        };
        let note_item = EncryptedItem {
            uuid: note_id.into(),
            content_type: "Note".into(),
            enc_item_key: Some(encrypt004(&note_key, &items_key, &note_aad).expect("note key encrypts")),
            content: Some(encrypt004(NOTE_JSON, &note_key, &note_aad).expect("note encrypts")),
            items_key_id: Some(items_key_id.into()),
            deleted: None,
            updated_at: None,
            updated_at_timestamp: None,
        };

        let items_plain = decrypt_item_content(&items_item, &master).expect("items key item decrypts");
        assert_eq!(items_key_from_content(&items_plain).as_deref(), Some(items_key.as_str()));
        assert_eq!(decrypt_item_content(&note_item, &items_key).expect("note decrypts"), NOTE_JSON);
        // The wrong level of key fails closed.
        assert_eq!(decrypt004(note_item.content.as_deref().expect("content"), &master), Err(Proto004Error::DecryptionFailed));
    }

    #[test]
    fn a_fifth_signing_component_is_not_part_of_the_authenticated_data() {
        let key = random_key_hex();
        let payload = encrypt004("hello", &key, &json!({ "u": "1", "v": "004" })).expect("encrypts");
        let with_signature = format!("{payload}:c2lnbmVkLW1ldGFkYXRh");
        assert_eq!(with_signature.split(':').count(), 5);
        assert_eq!(decrypt004(&with_signature, &key).expect("still decrypts"), "hello");
    }

    #[test]
    fn tampered_ciphertext_does_not_decrypt() {
        let key = random_key_hex();
        let payload = encrypt004("hello", &key, &json!({ "u": "1", "v": "004" })).expect("encrypts");
        let mut parts: Vec<String> = payload.split(':').map(str::to_string).collect();
        let cipher = parts[2].clone();
        let short = cipher.len() - 2;
        parts[2] = format!("{}aa", &cipher[..short]);
        assert_eq!(decrypt004(&parts.join(":"), &key), Err(Proto004Error::DecryptionFailed));
    }

    #[test]
    fn payload_and_parameter_validation_matches_the_typescript_messages() {
        let key = random_key_hex();
        assert_eq!(decrypt004("001:aa:bb:cc", &key), Err(Proto004Error::NotA004Payload));
        assert_eq!(decrypt004("004:aa:bb:cc", &key), Err(Proto004Error::InvalidNonce));
        assert_eq!(decrypt004("004:0011:bb:cc", &key), Err(Proto004Error::InvalidNonce));
        assert_eq!(
            decrypt004(VECTOR_HELLO, "abcd"),
            Err(Proto004Error::InvalidKey),
            "short key reports the TS message"
        );
        assert_eq!(
            decrypt004(VECTOR_HELLO, KEY_22),
            Err(Proto004Error::DecryptionFailed),
            "wrong key (KEY_22 cannot read KEY_11's payload)"
        );
    }

    #[test]
    fn canonical_json_sorts_object_keys_recursively() {
        assert_eq!(canonical_json(&json!({ "b": 1, "a": { "d": 4, "c": 3 } })), r#"{"a":{"c":3,"d":4},"b":1}"#);
        assert_eq!(canonical_json(&json!([3, 1, 2])), "[3,1,2]");
        assert_eq!(canonical_json(&Value::Null), "null");
    }

    #[test]
    fn items_key_extraction_follows_the_typescript_rules() {
        assert_eq!(items_key_from_content(r#"{"itemsKey":"ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"}"#),
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into()), "lowercases");
        assert_eq!(items_key_from_content(r#"{"itemsKey":"nope"}"#), None);
        assert_eq!(items_key_from_content(r#"{"other":1}"#), None);
        assert_eq!(items_key_from_content("not json"), None);
    }

    #[test]
    fn missing_ciphertext_is_refused_before_any_crypto() {
        let item = EncryptedItem {
            uuid: "u".into(),
            content_type: "Note".into(),
            content: Some("004:aa".into()),
            enc_item_key: None,
            items_key_id: None,
            deleted: None,
            updated_at: None,
            updated_at_timestamp: None,
        };
        assert_eq!(decrypt_item_content(&item, KEY_11), Err(Proto004Error::MissingCiphertext));
    }
}
