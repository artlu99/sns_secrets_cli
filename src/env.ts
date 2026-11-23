import { UserError } from "./errors.ts";

/**
 * Names that may appear in the dotenvx-encrypted session file.
 * The account password is never one of them.
 */
export const SESSION_VALUE_KEYS = [
  "SN_ACCOUNT_EMAIL",
  "SN_REFRESH_TOKEN",
  "SN_ACCESS_TOKEN",
  "SN_ACCESS_EXPIRATION",
  "SN_REFRESH_EXPIRATION",
  "SN_ACCESS_COOKIE",
  "SN_REFRESH_COOKIE",
  "SN_DB_KEY",
] as const;

export type SessionValueKey = (typeof SESSION_VALUE_KEYS)[number];

const PUBLIC_SN_ENV = new Set(["SN_EMAIL", "SN_API_URL"]);

/** True when a process environment name carries credential material. */
export function isSecretEnvName(name: string): boolean {
  if (name === "DOTENV_KEY" || name.startsWith("DOTENV_PRIVATE_KEY")) return true;
  if (name === "SNS_SESSION_PRIVATE_KEY") return true;
  if (name.startsWith("SN_") && !PUBLIC_SN_ENV.has(name)) return true;
  return false;
}

/**
 * The environment a child process starts with: secret-named variables
 * removed, plus every `SNS_` knob — pager, clipboard, and keychain children
 * never need this program's own settings, and a reserved namespace must not
 * leak even its non-secret values.
 */
export function scrubbedEnv(base: NodeJS.ProcessEnv = process.env): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(base)) {
    if (value === undefined) continue;
    if (isSecretEnvName(key) || key.startsWith("SNS_")) continue;
    out[key] = value;
  }
  return out;
}

const scrubbedNames: string[] = [];

/**
 * Secret-named variables the launch environment carried, recorded by
 * `scrubProcessEnv`. Names only — the values are gone for good. `sns doctor`
 * reports these so a scrubbed-at-launch secret is visible instead of silent.
 */
export function scrubbedEnvNames(): readonly string[] {
  return scrubbedNames;
}

/** Drop secret-named variables bun or a parent shell may have loaded. */
export function scrubProcessEnv(): void {
  for (const key of Object.keys(process.env)) {
    if (isSecretEnvName(key)) {
      delete process.env[key];
      if (!scrubbedNames.includes(key)) scrubbedNames.push(key);
    }
  }
}

/** Tests only: forget recorded names so a suite starts from a clean launch state. */
export function clearScrubbedEnvNames(): void {
  scrubbedNames.length = 0;
}

/**
 * Plain .env values are written unquoted (`SN_EMAIL=${email}`), so a control
 * character would forge additional lines in a file the operator reads and
 * edits. Reject rather than escape: a value that needs dotenvx quoting has no
 * business in the two keys sns owns.
 */
export function assertPlainEnvValue(name: string, value: string): void {
  if (/[\u0000-\u001f\u007f]/.test(value)) {
    throw new UserError(`${name} contains a control character — refusing to write it to .env`);
  }
}

function isLoopbackHost(host: string): boolean {
  const name = host.replace(/^\[/, "").replace(/\]$/, "").toLowerCase();
  return name === "localhost" || name === "127.0.0.1" || name === "::1";
}

/**
 * The API URL carries the refresh token and every sync across the network:
 * refuse plaintext HTTP to a non-loopback host at config load. Loopback is
 * allowed (local development against a local server never leaves the
 * machine), and `SNS_ALLOW_INSECURE_API=1` is the operator's explicit escape
 * hatch for a self-hosted plaintext endpoint.
 */
export function assertApiUrl(url: string): void {
  if (url === "") return;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new UserError(`SN_API_URL is not a valid URL (${url})`);
  }
  if (parsed.protocol === "https:") return;
  if (parsed.protocol !== "http:") {
    throw new UserError(`SN_API_URL must use https or http (got ${parsed.protocol})`);
  }
  if (process.env.SNS_ALLOW_INSECURE_API === "1") return;
  if (isLoopbackHost(parsed.hostname)) return;
  throw new UserError(
    "SN_API_URL is http on a non-loopback host — the refresh token would cross the network in plaintext; use https, a loopback host, or set SNS_ALLOW_INSECURE_API=1 to accept the risk",
  );
}

export function assertSessionKeyNames(names: readonly string[]): string | null {
  for (const name of names) {
    if (name.startsWith("DOTENV_PUBLIC_KEY")) continue;
    if (!(SESSION_VALUE_KEYS as readonly string[]).includes(name)) {
      return name;
    }
  }
  return null;
}
