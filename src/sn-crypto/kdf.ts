import { getSodium, sodiumReady } from "./sodium.ts";

/** Protocol 004 defaults from the Standard Notes specification. */
export const ARGON2_DEFAULTS = {
  iterations: 5,
  memoryBytes: 67_108_864,
  parallelism: 1,
} as const;

export type KdfParams = {
  version: string;
  identifier: string;
  pwNonce: string;
  /** Argon2 time cost. Defaults to 5 when the server omits it. */
  iterations?: number;
  /** Memory in bytes. Values under 8 MiB are treated as kibibytes. */
  memory?: number;
  parallelism?: number;
};

export type RootKey = {
  masterKey: string;
  serverPassword: string;
};

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function saltBytes(identifier: string, pwNonce: string): Promise<Uint8Array> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${identifier}:${pwNonce}`)),
  );
  const saltHex = toHex(digest).slice(0, 32);
  const sodium = getSodium();
  await sodiumReady();
  return sodium.from_hex(saltHex);
}

function memoryBytes(memory: number | undefined): number {
  if (memory === undefined || memory <= 0) return ARGON2_DEFAULTS.memoryBytes;
  if (memory < 8 * 1024 * 1024) return memory * 1024;
  return memory;
}

/**
 * Argon2id(password, salt) → 64 bytes. First 32 are the master key, last 32
 * are the server password. The password is not retained.
 */
export async function deriveRootKey(password: string, params: KdfParams): Promise<RootKey> {
  if (params.version !== "004") {
    throw new Error(`protocol version ${params.version} is not supported`);
  }
  if (params.identifier === "" || params.pwNonce === "") {
    throw new Error("key parameters are missing an identifier or salt seed");
  }
  const parallelism = params.parallelism ?? ARGON2_DEFAULTS.parallelism;
  if (parallelism !== 1) {
    throw new Error("this build only supports Argon2id parallelism 1");
  }
  await sodiumReady();
  const sodium = getSodium();
  const salt = await saltBytes(params.identifier, params.pwNonce);
  const derived = sodium.crypto_pwhash(
    64,
    password,
    salt,
    params.iterations ?? ARGON2_DEFAULTS.iterations,
    memoryBytes(params.memory),
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
  const hex = sodium.to_hex(derived);
  sodium.memzero(derived);
  return { masterKey: hex.slice(0, 64), serverPassword: hex.slice(64) };
}
