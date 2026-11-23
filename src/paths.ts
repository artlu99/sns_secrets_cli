import { AsyncLocalStorage } from "node:async_hooks";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fchmodSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { assertApiUrl, assertPlainEnvValue } from "./env.ts";

export const DEFAULT_API_URL = "https://api.standardnotes.com";

const configStore = new AsyncLocalStorage<string>();

/** Tests use this so concurrent cases do not share SNS_CONFIG_DIR. */
export function withConfigDir<T>(dir: string, fn: () => T): T {
  return configStore.run(dir, fn);
}

export type PlainConfig = {
  email: string;
  apiUrl: string;
};

export function configDir(): string {
  const stored = configStore.getStore();
  if (stored) return stored;
  const override = process.env.SNS_CONFIG_DIR;
  if (override && override.trim() !== "") return override;
  return join(homedir(), ".config", "sn_secrets_cli");
}

export function envPath(): string {
  return join(configDir(), ".env");
}

export function sessionPath(): string {
  return join(configDir(), ".env.session");
}

export function keysPath(): string {
  return join(configDir(), ".env.keys");
}

export function dbPath(): string {
  return join(configDir(), "cache.db");
}

export function lockPath(): string {
  return join(configDir(), "sync.lock");
}

export function clipboardMarkerPath(): string {
  return join(configDir(), "clipboard-clear-at");
}

export function ensureConfigDir(): string {
  const dir = configDir();
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
  if (!existsSync(envPath())) {
    writeFileSync(envPath(), `SN_EMAIL=\nSN_API_URL=${DEFAULT_API_URL}\n`, { mode: 0o600 });
  }
  chmodSync(envPath(), 0o600);
  return dir;
}

function parseEnvFile(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    out[key] = value;
  }
  return out;
}

export function readPlainConfig(): PlainConfig {
  ensureConfigDir();
  const parsed = parseEnvFile(readFileSync(envPath(), "utf8"));
  // `||`, not `??`: the template .env writes an empty SN_EMAIL=, and a value
  // set in the environment must win over that placeholder.
  const email = parsed.SN_EMAIL || process.env.SN_EMAIL || "";
  const apiUrl = parsed.SN_API_URL || process.env.SN_API_URL || DEFAULT_API_URL;
  const normalized = apiUrl.replace(/\/+$/, "");
  // Config load is the gate every network command passes through: no
  // plaintext HTTP to a remote host. (Callers that must survive a broken
  // config — logout — catch this and fall back to the default host.)
  assertApiUrl(normalized);
  return { email, apiUrl: normalized };
}

/** The keys writePlainConfig owns; anything else in the file survives rewrites. */
const OWNED_ENV_KEYS = new Set(["SN_EMAIL", "SN_API_URL"]);

/**
 * Every file sns creates in the config directory. `sns purge` deletes
 * exactly these; anything else in the directory is left in place and named
 * (the same set doctor's unexpected-files check flags).
 */
export const KNOWN_CONFIG_FILES = new Set([
  ".env",
  ".env.session",
  ".env.keys",
  "cache.db",
  "cache.db-journal",
  "cache.db-wal",
  "cache.db-shm",
  "sync.lock",
  "clipboard-clear-at",
]);

export function writePlainConfig(patch: Partial<PlainConfig>): void {
  ensureConfigDir();
  const current = readPlainConfig();
  const email = patch.email ?? current.email;
  const apiUrl = patch.apiUrl ?? current.apiUrl;
  // The file is written unquoted; a control character here would forge lines
  // in the operator's .env. The URL gate applies at write time too, so a
  // plaintext remote never lands in the file in the first place (the
  // SNS_ALLOW_INSECURE_API escape hatch still applies, via assertApiUrl).
  assertPlainEnvValue("SN_EMAIL", email);
  assertPlainEnvValue("SN_API_URL", apiUrl);
  assertApiUrl(apiUrl);
  // Operators keep hand-added lines: every rewrite carries them through
  // instead of truncating the file to the two keys this program owns.
  const preserved: string[] = [];
  if (existsSync(envPath())) {
    for (const line of readFileSync(envPath(), "utf8").split("\n")) {
      const key = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=/);
      if (key === null || !OWNED_ENV_KEYS.has(key[1]!)) preserved.push(line);
    }
  }
  const tail = preserved.length > 0 ? `${preserved.join("\n").replace(/\n*$/, "")}\n` : "";
  writeFileSync(envPath(), `SN_EMAIL=${email}\nSN_API_URL=${apiUrl}\n${tail}`, { mode: 0o600 });
  chmodSync(envPath(), 0o600);
}

/**
 * Crash-safe write for credential files: temp file created O_EXCL|O_NOFOLLOW
 * at 0600, fully written and fchmod-asserted, then atomically renamed over
 * the destination — a crash never leaves a partial or half-written secret,
 * and a planted symlink at the destination is replaced, never written
 * through. Callers ensure the directory exists.
 */
export function writePrivateFileSync(path: string, data: string): void {
  const tmp = `${path}.tmp-${process.pid}-${Math.random().toString(36).slice(2, 8)}`;
  const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
  try {
    const buffer = Buffer.from(data, "utf8");
    let written = 0;
    while (written < buffer.length) written += writeSync(fd, buffer, written);
    fchmodSync(fd, 0o600);
  } catch (error) {
    try {
      rmSync(tmp, { force: true });
    } catch {
      // a partial 0600 temp file is the worst case; the next write retries
    }
    throw error;
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
}

export function unexpectedConfigFiles(): string[] {
  if (!existsSync(configDir())) return [];
  return readdirSync(configDir()).filter((name) => !KNOWN_CONFIG_FILES.has(name));
}
