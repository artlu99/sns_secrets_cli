/**
 * The decrypted-item cache lives in chrome.storage.session alongside the
 * session: memory-only, wiped with the browser, invisible to pages. It holds
 * what a password-manager keeps in process memory — nothing hits disk. If
 * the cache outgrows the session quota (10 MB), the write fails; the failure
 * is surfaced (action badge + `cacheOverflow` flag the UIs render as a
 * banner) instead of silently losing the cache, and the vault still works,
 * just re-pulling on next open.
 */
import { browser } from "wxt/browser";
import { CACHE_KEY } from "./session.ts";
import type { ItemRow } from "./store.ts";
import { storedTypesMarker } from "./store.ts";

export type VaultCache = {
  items: ItemRow[];
  syncToken: string | null;
  storedTypes: string;
};

export async function loadCache(): Promise<VaultCache> {
  const got = await browser.storage.session.get(CACHE_KEY);
  const value = got[CACHE_KEY] as VaultCache | undefined;
  if (value && Array.isArray(value.items)) return value;
  return { items: [], syncToken: null, storedTypes: storedTypesMarker(null) };
}

/** Non-secret flag in storage.local marking the last cache write as failed
 * (session quota). Survives service-worker death so any surface can banner it. */
const OVERFLOW_KEY = "cacheOverflow";

export async function loadCacheOverflow(): Promise<boolean> {
  const got = await browser.storage.local.get(OVERFLOW_KEY);
  return got[OVERFLOW_KEY] === true;
}

async function setCacheOverflow(on: boolean): Promise<void> {
  try {
    if (on) {
      await browser.storage.local.set({ [OVERFLOW_KEY]: true });
      await browser.action.setBadgeBackgroundColor({ color: "#b45309" }).catch(() => {});
      await browser.action.setBadgeText({ text: "!" }).catch(() => {});
    } else {
      await browser.storage.local.remove(OVERFLOW_KEY);
      await browser.action.setBadgeText({ text: "" }).catch(() => {});
    }
  } catch {
    // Signalling must never break the sync itself.
  }
}

/**
 * Persist the decrypted cache. Resolves false when storage.session refused
 * the write (quota) — the caller is expected to surface that to the user.
 */
export async function saveCache(items: Map<string, ItemRow>, syncToken: string | null): Promise<boolean> {
  const cache: VaultCache = { items: [...items.values()], syncToken, storedTypes: storedTypesMarker(syncToken) };
  try {
    await browser.storage.session.set({ [CACHE_KEY]: cache });
  } catch {
    // QuotaExceededError: stay memory-only; next open does a full pull.
    await setCacheOverflow(true);
    return false;
  }
  await setCacheOverflow(false);
  return true;
}

export async function clearCache(): Promise<void> {
  await browser.storage.session.remove(CACHE_KEY);
  await setCacheOverflow(false);
}
