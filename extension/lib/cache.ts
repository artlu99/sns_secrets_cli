/**
 * The decrypted-item cache lives in chrome.storage.session alongside the
 * session: memory-only, wiped with the browser, invisible to pages. It holds
 * what a password-manager keeps in process memory — nothing hits disk. If
 * the cache outgrows the session quota (10 MB), saving is skipped silently
 * and the vault still works, just re-pulling on next open.
 */
import { browser } from "wxt/browser";
import type { ItemRow } from "./store.ts";
import { storedTypesMarker } from "./store.ts";

export type VaultCache = {
  items: ItemRow[];
  syncToken: string | null;
  storedTypes: string;
};

const CACHE_KEY = "vaultCache";

export async function loadCache(): Promise<VaultCache> {
  const got = await browser.storage.session.get(CACHE_KEY);
  const value = got[CACHE_KEY] as VaultCache | undefined;
  if (value && Array.isArray(value.items)) return value;
  return { items: [], syncToken: null, storedTypes: storedTypesMarker(null) };
}

export async function saveCache(items: Map<string, ItemRow>, syncToken: string | null): Promise<void> {
  const cache: VaultCache = { items: [...items.values()], syncToken, storedTypes: storedTypesMarker(syncToken) };
  try {
    await browser.storage.session.set({ [CACHE_KEY]: cache });
  } catch {
    // QuotaExceededError: stay memory-only; next open does a full pull.
  }
}

export async function clearCache(): Promise<void> {
  await browser.storage.session.remove(CACHE_KEY);
}
