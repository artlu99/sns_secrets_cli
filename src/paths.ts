import { AsyncLocalStorage } from "node:async_hooks";
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

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
  const email = parsed.SN_EMAIL ?? process.env.SN_EMAIL ?? "";
  const apiUrl = parsed.SN_API_URL || process.env.SN_API_URL || DEFAULT_API_URL;
  return { email, apiUrl: apiUrl.replace(/\/+$/, "") };
}

export function writePlainConfig(patch: Partial<PlainConfig>): void {
  ensureConfigDir();
  const current = readPlainConfig();
  const email = patch.email ?? current.email;
  const apiUrl = patch.apiUrl ?? current.apiUrl;
  writeFileSync(envPath(), `SN_EMAIL=${email}\nSN_API_URL=${apiUrl}\n`, { mode: 0o600 });
  chmodSync(envPath(), 0o600);
}

const ALLOWED_CONFIG_FILES = new Set([
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

export function unexpectedConfigFiles(): string[] {
  if (!existsSync(configDir())) return [];
  return readdirSync(configDir()).filter((name) => !ALLOWED_CONFIG_FILES.has(name));
}
