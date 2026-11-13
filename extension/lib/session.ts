/**
 * Session state. The master key and OAuth-ish tokens live ONLY in
 * chrome.storage.session — memory-backed, inaccessible to pages, wiped when
 * the browser exits. Nothing secret ever reaches disk: no storage.local
 * secrets, no decrypted notes outside session storage.
 */
import { browser } from "wxt/browser";

export const DEFAULT_API_URL = "https://api.standardnotes.com";

/** Ported from src/session-file.ts, minus dbKey (the CLI's disk cache key). */
export type SessionSecrets = {
  /** Non-secret label of the account this session belongs to. */
  accountEmail: string;
  refreshToken: string;
  accessToken: string;
  accessExpirationMs: number;
  refreshExpirationMs: number;
  accessCookie: string;
  refreshCookie: string;
};

export type VaultSession = {
  secrets: SessionSecrets;
  /** Argon2id-derived master key; unwraps SN|ItemsKey items. */
  masterKey: string;
  email: string;
  apiUrl: string;
};

const SESSION_KEY = "vaultSession";

export async function loadSession(): Promise<VaultSession | null> {
  const got = await browser.storage.session.get(SESSION_KEY);
  return (got[SESSION_KEY] as VaultSession | undefined) ?? null;
}

export async function saveSession(session: VaultSession): Promise<void> {
  await browser.storage.session.set({ [SESSION_KEY]: session });
}

export async function clearSession(): Promise<void> {
  await browser.storage.session.remove(SESSION_KEY);
}

/** Non-secret preferences (server, account label) — the only storage.local data. */
export type Settings = { apiUrl: string; email: string };

const SETTINGS_KEY = "settings";

export async function loadSettings(): Promise<Settings> {
  const got = await browser.storage.local.get(SETTINGS_KEY);
  const value = (got[SETTINGS_KEY] as Partial<Settings> | undefined) ?? {};
  return { apiUrl: value.apiUrl ?? DEFAULT_API_URL, email: value.email ?? "" };
}

export async function saveSettings(settings: Settings): Promise<void> {
  await browser.storage.local.set({ [SETTINGS_KEY]: settings });
}

/** Trim trailing slashes; refuse non-https unless it is local (self-hosted). */
export function normalizeApiUrl(raw: string): string {
  const trimmed = raw.trim().replace(/\/+$/, "");
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new Error("server must be a URL like https://api.standardnotes.com");
  }
  if (url.protocol !== "https:" && url.hostname !== "localhost" && url.hostname !== "127.0.0.1") {
    throw new Error("server must use https");
  }
  return trimmed;
}
