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
  if (name.startsWith("SN_") && !PUBLIC_SN_ENV.has(name)) return true;
  return false;
}

export function scrubbedEnv(base: NodeJS.ProcessEnv = process.env): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(base)) {
    if (value === undefined) continue;
    if (isSecretEnvName(key)) continue;
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

export function assertSessionKeyNames(names: readonly string[]): string | null {
  for (const name of names) {
    if (name.startsWith("DOTENV_PUBLIC_KEY")) continue;
    if (!(SESSION_VALUE_KEYS as readonly string[]).includes(name)) {
      return name;
    }
  }
  return null;
}
