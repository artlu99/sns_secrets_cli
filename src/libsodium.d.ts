declare module "libsodium-wrappers-sumo" {
  interface Sodium {
    ready: Promise<void>;
    crypto_pwhash_ALG_ARGON2ID13: number;
    crypto_pwhash(
      keyLength: number,
      password: string | Uint8Array,
      salt: Uint8Array,
      opsLimit: number,
      memLimit: number,
      algorithm: number,
    ): Uint8Array;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
      message: string | Uint8Array,
      additional_data: string | Uint8Array | null,
      secret_nonce: string | Uint8Array | null,
      public_nonce: Uint8Array,
      key: Uint8Array,
    ): Uint8Array;
    crypto_aead_xchacha20poly1305_ietf_decrypt(
      secret_nonce: string | Uint8Array | null,
      ciphertext: string | Uint8Array,
      additional_data: string | Uint8Array | null,
      public_nonce: Uint8Array,
      key: Uint8Array,
    ): Uint8Array;
    from_hex(input: string): Uint8Array;
    to_hex(input: Uint8Array | string): string;
    randombytes_buf(length: number): Uint8Array;
    memzero(bytes: Uint8Array): void;
  }

  const sodium: Sodium;
  export default sodium;
}
