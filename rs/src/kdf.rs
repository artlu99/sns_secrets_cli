//! Port of `src/sn-crypto/kdf.ts` — Standard Notes 004 root key derivation.
//!
//! Salt is the first 16 bytes of SHA-256 over `identifier:pwNonce` (the TS
//! code digests, hex-encodes, and slices the first 32 hex chars). Argon2id,
//! version 0x13 — the algorithm libsodium exposes as ARGON2ID13 — then
//! derives 64 bytes: the first 32 are the account's master key, the last 32
//! the server password. Defaults (t=5, 64 MiB, p=1) and the memory-unit quirk
//! (values below 8 MiB arrive as kibibytes) come straight from the TS module.
//! The tests pin the published 004 vector from `kdf.test.ts`.

use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// Protocol 004 defaults from the Standard Notes specification.
pub const ARGON2_DEFAULTS: Argon2Defaults = Argon2Defaults {
    iterations: 5,
    memory_bytes: 67_108_864,
    parallelism: 1,
};

pub struct Argon2Defaults {
    pub iterations: u32,
    pub memory_bytes: u64,
    pub parallelism: u32,
}

#[derive(Debug, Clone)]
pub struct KdfParams {
    pub version: String,
    pub identifier: String,
    pub pw_nonce: String,
    /// Argon2 time cost. Defaults to 5 when the server omits it.
    pub iterations: Option<u32>,
    /// Memory in bytes. Values under 8 MiB are treated as kibibytes.
    pub memory: Option<u64>,
    pub parallelism: Option<u32>,
}

/// Derived credentials. The master key encrypts locally; the server password
/// authenticates. Both are zeroized when dropped.
#[derive(Debug)]
pub struct RootKey {
    pub master_key: Zeroizing<[u8; 32]>,
    pub server_password: Zeroizing<[u8; 32]>,
}

impl RootKey {
    pub fn master_key_hex(&self) -> String {
        hex::encode(self.master_key.as_slice())
    }

    pub fn server_password_hex(&self) -> String {
        hex::encode(self.server_password.as_slice())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum KdfError {
    UnsupportedVersion(String),
    MissingIdentifier,
    MissingSaltSeed,
    UnsupportedParallelism(u32),
    MemoryOutOfRange(u64),
    Argon2(String),
}

impl core::fmt::Display for KdfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => write!(f, "protocol version {version} is not supported"),
            // One sentence for either missing field, matching the TS message.
            Self::MissingIdentifier | Self::MissingSaltSeed => {
                write!(f, "key parameters are missing an identifier or salt seed")
            }
            Self::UnsupportedParallelism(p) => write!(f, "this build only supports Argon2id parallelism 1 (got {p})"),
            Self::MemoryOutOfRange(bytes) => write!(f, "argon2 memory request {bytes} bytes is out of range"),
            Self::Argon2(detail) => write!(f, "argon2 key derivation failed: {detail}"),
        }
    }
}

impl std::error::Error for KdfError {}

/// SHA-256 over `identifier:pwNonce`, first 16 bytes. Sync here where the TS
/// needed `crypto.subtle`'s promise.
pub fn salt_bytes(identifier: &str, pw_nonce: &str) -> [u8; 16] {
    let full = Sha256::digest(format!("{identifier}:{pw_nonce}").as_bytes());
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&full[..16]);
    salt
}

/// `memory ≤ 0` or absent means the 64 MiB default; a value below 8 MiB is
/// the server sending kibibytes, so it scales to bytes.
pub fn memory_bytes(memory: Option<u64>) -> u64 {
    match memory {
        None | Some(0) => ARGON2_DEFAULTS.memory_bytes,
        Some(value) if value < 8 * 1024 * 1024 => value * 1024,
        Some(value) => value,
    }
}

/// Argon2id(password, salt) → 64 bytes. First 32 are the master key, last 32
/// are the server password. The password is not retained.
pub fn derive_root_key(password: &str, params: &KdfParams) -> Result<RootKey, KdfError> {
    if params.version != "004" {
        return Err(KdfError::UnsupportedVersion(params.version.clone()));
    }
    if params.identifier.is_empty() {
        return Err(KdfError::MissingIdentifier);
    }
    if params.pw_nonce.is_empty() {
        return Err(KdfError::MissingSaltSeed);
    }
    let parallelism = params.parallelism.unwrap_or(ARGON2_DEFAULTS.parallelism);
    if parallelism != ARGON2_DEFAULTS.parallelism {
        return Err(KdfError::UnsupportedParallelism(parallelism));
    }
    let iterations = params.iterations.unwrap_or(ARGON2_DEFAULTS.iterations);
    let memory_kib = u32::try_from(memory_bytes(params.memory) / 1024)
        .map_err(|_| KdfError::MemoryOutOfRange(memory_bytes(params.memory)))?;

    // RustCrypto measures memory cost in KiB; libsodium's crypto_pwhash (and
    // the TS module) take bytes.
    let argon_params =
        Params::new(memory_kib, iterations, parallelism, Some(64)).map_err(|error| KdfError::Argon2(error.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let salt = salt_bytes(&params.identifier, &params.pw_nonce);
    let mut derived = [0u8; 64];
    argon
        .hash_password_into(password.as_bytes(), &salt, &mut derived)
        .map_err(|error| KdfError::Argon2(error.to_string()))?;

    let mut master_key = Zeroizing::new([0u8; 32]);
    let mut server_password = Zeroizing::new([0u8; 32]);
    master_key.copy_from_slice(&derived[..32]);
    server_password.copy_from_slice(&derived[32..]);
    derived.zeroize();
    Ok(RootKey { master_key, server_password })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published Standard Notes 004 vector, as asserted in kdf.test.ts.
    const VECTOR_PASSWORD: &str = "debugtest";
    const VECTOR_IDENTIFIER: &str = "sn004@lessknown.co.uk";
    const VECTOR_PW_NONCE: &str = "2c409996650e46c748856fbd6aa549f89f35be055a8f9bfacdf0c4b29b2152e9";
    const VECTOR_MASTER: &str = "2396d6ac0bc70fe45db1d2bcf3daa522603e9c6fcc88dc933ce1a3a31bbc08ed";
    const VECTOR_SERVER: &str = "a5eb9fbc767eafd6e54fd9d3646b19520e038ba2ccc9cceddf2340b37b788b47";

    #[test]
    fn root_key_matches_the_published_vector() {
        let root = derive_root_key(
            VECTOR_PASSWORD,
            &KdfParams {
                version: "004".into(),
                identifier: VECTOR_IDENTIFIER.into(),
                pw_nonce: VECTOR_PW_NONCE.into(),
                iterations: None,
                memory: None,
                parallelism: None,
            },
        )
        .expect("vector derivation succeeds");
        assert_eq!(root.master_key_hex(), VECTOR_MASTER);
        assert_eq!(root.server_password_hex(), VECTOR_SERVER);
    }

    /// Digest computed independently (Bun CryptoHasher), not by this module —
    /// guards the `identifier:nonce` joining and the 16-byte slice.
    #[test]
    fn salt_is_first_16_bytes_of_sha256_over_identifier_colon_nonce() {
        let salt = salt_bytes(VECTOR_IDENTIFIER, VECTOR_PW_NONCE);
        assert_eq!(
            hex::encode(salt),
            "7129955dbbbfb376fdcac49890ef17bc",
            "first 16 bytes of 7129955dbbbfb376fdcac49890ef17bc1b4f73dad21c480f0b28a36849a7459e"
        );
    }

    #[test]
    fn non_004_versions_are_refused() {
        let error = derive_root_key(
            VECTOR_PASSWORD,
            &KdfParams {
                version: "003".into(),
                identifier: "a@b.c".into(),
                pw_nonce: "abc".into(),
                iterations: None,
                memory: None,
                parallelism: None,
            },
        )
        .expect_err("003 must refuse");
        assert_eq!(error, KdfError::UnsupportedVersion("003".into()));
        assert!(error.to_string().contains("not supported"));
    }

    #[test]
    fn missing_identifier_or_nonce_is_refused() {
        let params = |identifier: &str, nonce: &str| KdfParams {
            version: "004".into(),
            identifier: identifier.into(),
            pw_nonce: nonce.into(),
            iterations: None,
            memory: None,
            parallelism: None,
        };
        assert_eq!(
            derive_root_key(VECTOR_PASSWORD, &params("", "abc")).expect_err("empty identifier refuses"),
            KdfError::MissingIdentifier
        );
        assert_eq!(
            derive_root_key(VECTOR_PASSWORD, &params("a@b.c", "")).expect_err("empty nonce refuses"),
            KdfError::MissingSaltSeed
        );
    }

    #[test]
    fn parallelism_above_one_is_refused() {
        let error = derive_root_key(
            VECTOR_PASSWORD,
            &KdfParams {
                version: "004".into(),
                identifier: VECTOR_IDENTIFIER.into(),
                pw_nonce: VECTOR_PW_NONCE.into(),
                iterations: None,
                memory: None,
                parallelism: Some(4),
            },
        )
        .expect_err("parallelism 4 refuses");
        assert_eq!(error, KdfError::UnsupportedParallelism(4));
    }

    #[test]
    fn memory_units_follow_the_ts_quirks() {
        assert_eq!(memory_bytes(None), 67_108_864);
        assert_eq!(memory_bytes(Some(0)), 67_108_864);
        // Below 8 MiB the value is kibibytes.
        assert_eq!(memory_bytes(Some(1024)), 1024 * 1024);
        // The 8 MiB boundary itself is already bytes.
        assert_eq!(memory_bytes(Some(8 * 1024 * 1024)), 8 * 1024 * 1024);
        assert_eq!(memory_bytes(Some((8 * 1024 * 1024) - 1)), (8 * 1024 * 1024 - 1) * 1024);
    }
}
