import { chmodSync, existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { parse, set } from "@dotenvx/dotenvx";
import { UserError } from "./errors.ts";
import { SESSION_VALUE_KEYS, assertSessionKeyNames, type SessionValueKey } from "./env.ts";
import { keychainDelete, keychainGet, keychainPut, secretServiceAvailable } from "./keychain.ts";
import { ensureConfigDir, keysPath, sessionPath } from "./paths.ts";

process.env.DOTENV_CONFIG_QUIET ??= "true";

const SET_OPTIONS = {
  encrypt: true,
  noArmor: true,
  noNative: true,
  no1Password: true,
  noBitwarden: true,
} as const;

export type SessionSecrets = {
  /** Non-secret label of the account this session belongs to; guards cache reuse across accounts. */
  accountEmail: string;
  refreshToken: string;
  accessToken: string;
  accessExpirationMs: number;
  refreshExpirationMs: number;
  accessCookie: string;
  refreshCookie: string;
  dbKey: string;
};

function sessionOptions(): { path: string; envKeysFile: string } & typeof SET_OPTIONS {
  return { path: sessionPath(), envKeysFile: keysPath(), ...SET_OPTIONS };
}

export function readPrivateKeyFile(): string | null {
  if (!existsSync(keysPath())) return null;
  const text = readFileSync(keysPath(), "utf8");
  const match = text.match(/^DOTENV_PRIVATE_KEY_SESSION=(?:"([^"]+)"|'([^']+)'|([^\s#]+))\s*$/m);
  return match?.[1] ?? match?.[2] ?? match?.[3] ?? null;
}

export async function readPrivateKey(): Promise<string | null> {
  const fromKeychain = await keychainGet();
  if (fromKeychain) return fromKeychain;
  return readPrivateKeyFile();
}

function writePrivateKeyFile(key: string): void {
  ensureConfigDir();
  writeFileSync(keysPath(), `# dotenvx private key for .env.session\nDOTENV_PRIVATE_KEY_SESSION=${key}\n`, {
    mode: 0o600,
  });
  chmodSync(keysPath(), 0o600);
}

/** Move the dotenvx private key into the OS keychain when one exists. */
export async function protectPrivateKey(): Promise<boolean> {
  const key = readPrivateKeyFile();
  if (!key) return (await keychainGet()) !== null;
  if (!(await secretServiceAvailable())) {
    chmodSync(keysPath(), 0o600);
    return false;
  }
  const stored = await keychainPut(key);
  if (!stored) {
    chmodSync(keysPath(), 0o600);
    return false;
  }
  rmSync(keysPath(), { force: true });
  return true;
}

function pairs(secrets: SessionSecrets): Array<[SessionValueKey, string]> {
  return [
    ["SN_ACCOUNT_EMAIL", secrets.accountEmail],
    ["SN_REFRESH_TOKEN", secrets.refreshToken],
    ["SN_ACCESS_TOKEN", secrets.accessToken],
    ["SN_ACCESS_EXPIRATION", String(secrets.accessExpirationMs)],
    ["SN_REFRESH_EXPIRATION", String(secrets.refreshExpirationMs)],
    ["SN_ACCESS_COOKIE", secrets.accessCookie],
    ["SN_REFRESH_COOKIE", secrets.refreshCookie],
    ["SN_DB_KEY", secrets.dbKey],
  ];
}

/** True once .env.session carries its dotenvx public key; then set() never needs the private file. */
function sessionHasPublicKey(): boolean {
  if (!existsSync(sessionPath())) return false;
  try {
    return /DOTENV_PUBLIC_KEY_SESSION=/.test(readFileSync(sessionPath(), "utf8"));
  } catch {
    return false;
  }
}

export async function saveSession(secrets: SessionSecrets): Promise<{ keychain: boolean }> {
  if (!/^[0-9a-fA-F]{64}$/.test(secrets.dbKey)) {
    throw new UserError("refusing to store a database key that is not 64 hex characters");
  }
  ensureConfigDir();
  const keychainKey = await keychainGet();
  const inject = keychainKey !== null && !existsSync(keysPath()) && sessionHasPublicKey();
  const previousKey = process.env.DOTENV_PRIVATE_KEY_SESSION;
  if (inject) {
    // Keychain custody: hand dotenvx the key through the environment. Writing
    // .env.keys to disk on every save would undo what the keychain is for.
  } else {
    const existing = keychainKey ?? readPrivateKeyFile();
    if (existing && !existsSync(keysPath())) writePrivateKeyFile(existing);
  }
  // dotenvx prompts for private-key custody on a TTY unless CI is set.
  // File custody bootstraps the keypair; the keychain move happens after.
  const previousCi = process.env.CI;
  process.env.CI = "true";
  if (inject) process.env.DOTENV_PRIVATE_KEY_SESSION = keychainKey;
  try {
    for (const [key, value] of pairs(secrets)) {
      const result = await set(key, value, sessionOptions());
      const failed = result.processedEnvs.find((entry) => entry.error);
      if (failed?.error) throw new UserError(`could not encrypt ${failed.key}`);
    }
  } finally {
    if (previousCi === undefined) delete process.env.CI;
    else process.env.CI = previousCi;
    if (inject) {
      if (previousKey === undefined) delete process.env.DOTENV_PRIVATE_KEY_SESSION;
      else process.env.DOTENV_PRIVATE_KEY_SESSION = previousKey;
    }
  }
  chmodSync(sessionPath(), 0o600);
  const keychain = await protectPrivateKey();
  return { keychain };
}

export function sessionKeyNames(): string[] {
  if (!existsSync(sessionPath())) return [];
  const text = readFileSync(sessionPath(), "utf8");
  const names: string[] = [];
  for (const line of text.split("\n")) {
    const match = line.match(/^([A-Z0-9_]+)=/);
    if (match?.[1]) names.push(match[1]);
  }
  return names;
}

export async function loadSession(): Promise<SessionSecrets | null> {
  if (!existsSync(sessionPath())) return null;
  const privateKey = await readPrivateKey();
  if (!privateKey) {
    throw new UserError("session file is encrypted but the dotenvx private key is missing — run sns login");
  }
  let parsed: Record<string, string>;
  try {
    parsed = parse(readFileSync(sessionPath(), "utf8"), { privateKey });
  } catch {
    throw new UserError("could not decrypt .env.session — the dotenvx key does not match");
  }
  const unexpected = assertSessionKeyNames(Object.keys(parsed));
  if (unexpected) {
    throw new UserError(`session file contains an unexpected key (${unexpected})`);
  }
  for (const key of SESSION_VALUE_KEYS) {
    const value = parsed[key];
    if (value?.startsWith("encrypted:")) {
      throw new UserError("could not decrypt .env.session — the dotenvx key does not match");
    }
  }
  const dbKey = parsed.SN_DB_KEY ?? "";
  const refreshToken = parsed.SN_REFRESH_TOKEN ?? "";
  if (dbKey === "" || refreshToken === "") {
    throw new UserError("session file is missing the refresh token or database key — run sns login");
  }
  return {
    accountEmail: parsed.SN_ACCOUNT_EMAIL ?? "",
    refreshToken,
    accessToken: parsed.SN_ACCESS_TOKEN ?? "",
    accessExpirationMs: Number(parsed.SN_ACCESS_EXPIRATION ?? "0") || 0,
    refreshExpirationMs: Number(parsed.SN_REFRESH_EXPIRATION ?? "0") || 0,
    accessCookie: parsed.SN_ACCESS_COOKIE ?? "",
    refreshCookie: parsed.SN_REFRESH_COOKIE ?? "",
    dbKey,
  };
}

export async function deleteSession(): Promise<void> {
  if (existsSync(sessionPath())) rmSync(sessionPath(), { force: true });
  if (existsSync(keysPath())) rmSync(keysPath(), { force: true });
  await keychainDelete();
}
