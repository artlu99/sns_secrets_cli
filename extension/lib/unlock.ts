/**
 * Unlock + sync orchestration shared by the popup and the dashboard.
 * Unlock = keyParams → Argon2id (client-side) → login → session saved to
 * chrome.storage.session. Sync = incremental pull over the session cache.
 */
import { browser } from "wxt/browser";
import { UserError } from "../../src/errors.ts";
import { createApi, withAccess } from "./sn-api.ts";
import { loadCache, saveCache } from "./cache.ts";
import { lockMoved } from "./lock-schedule.ts";
import { getLockState, markUnlocked, performLock } from "./lock-state.ts";
import { DYNAMIC_ORIGIN_RULE_ID, originRuleForApi } from "./origin.ts";
import { REFRESH_MESSAGE_TYPE } from "./refresh-flight.ts";
import { normalizeApiUrl, saveSession, saveSettings, CACHE_KEY, SESSION_KEY, type SessionSecrets, type VaultSession } from "./session.ts";
import { runSync, type ItemRow, type SyncReport } from "./store.ts";

/** Request the host permission for a custom (self-hosted) API origin. */
async function ensureHostPermission(apiUrl: string): Promise<void> {
  const origin = `${new URL(apiUrl).origin}/*`;
  if (await browser.permissions.contains({ origins: [origin] })) return;
  const granted = await browser.permissions.request({ origins: [origin] });
  if (!granted) throw new UserError(`permission to talk to ${origin} was denied`);
}

/**
 * Strip Origin on the wire for self-hosted APIs too, scoped to this
 * extension's own requests like every origin rule. Runs on the click's user
 * gesture, alongside the host-permission request.
 */
async function installOriginRule(apiUrl: string): Promise<void> {
  const rule = originRuleForApi(apiUrl, browser.runtime.id);
  await browser.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [DYNAMIC_ORIGIN_RULE_ID],
    addRules: rule ? [rule] : [],
  });
}

export async function unlockVault(input: {
  email: string;
  password: string;
  apiUrl: string;
  onMfa: () => Promise<string>;
}): Promise<VaultSession> {
  const apiUrl = normalizeApiUrl(input.apiUrl);
  if (input.email.trim() === "" || input.password === "") {
    throw new UserError("email and password are both required");
  }
  // While the click's transient activation is still fresh, ask for any
  // self-hosted origin — after Argon2 (1–3 s) the gesture may be gone.
  await ensureHostPermission(apiUrl);
  await installOriginRule(apiUrl);
  const api = createApi(apiUrl);
  const { secrets, masterKey } = await api.login(input.email, input.password, input.onMfa);
  secrets.accountEmail = input.email;
  const session: VaultSession = { secrets, masterKey, email: input.email, apiUrl };
  await saveSession(session);
  await saveSettings({ apiUrl, email: input.email });
  // New session, new epoch: marks the vault unlocked, starts the idle clock,
  // and invalidates every write captured before this moment.
  await markUnlocked();
  return session;
}

/**
 * Surface-side half of the refresh single-flight (lib/refresh-flight.ts):
 * the service worker performs every refresh POST, so the popup and the
 * dashboard can never rotate against each other (Standard Notes rotates
 * refresh tokens on use). The worker refreshes and persists the STORED
 * session behind the epoch guard — the secrets argument is informational
 * only, since storage.session is always at least as fresh as this surface's
 * in-memory copy.
 */
async function requestSharedRefresh(): Promise<SessionSecrets> {
  const reply = (await browser.runtime.sendMessage({ type: REFRESH_MESSAGE_TYPE })) as
    | { ok: true; secrets: SessionSecrets }
    | { ok: false; message: string }
    | undefined;
  if (reply?.ok === true) return reply.secrets;
  throw new UserError(reply?.ok === false ? reply.message : "could not reach the service worker for a token refresh");
}

/**
 * The guard-to-write gap: a lock landing between the guard and the write
 * still lets the write land, so every guarded write is re-checked after it
 * resolves — a vault that locked meanwhile gets the key material it just
 * resurrected taken back out of storage.session.
 */
async function rollbackIfLocked(keys: string[]): Promise<void> {
  const state = await getLockState();
  if (!state.locked) return;
  await browser.storage.session.remove(keys);
}

/**
 * Incremental pull over the session cache. Every write is epoch-guarded:
 * refreshed tokens are persisted by the service worker's shared refresh
 * flight, and the decrypted cache write checks the epoch captured up front —
 * an in-flight sync must never resurrect key material the alarm just wiped.
 */
export async function syncVault(session: VaultSession): Promise<{
  report: SyncReport;
  items: Map<string, ItemRow>;
  /** False when storage.session refused the cache write (quota) — surface it. */
  cacheSaved: boolean;
}> {
  const api = createApi(session.apiUrl);
  const cache = await loadCache();
  const startEpoch = (await getLockState()).lockEpoch;
  const guard = () =>
    getLockState().then((state) => {
      if (lockMoved(startEpoch, state)) throw new UserError("vault locked while syncing — aborted");
    });
  const items = new Map(cache.items.map((row) => [row.uuid, row]));
  const report = await withAccess(
    session.secrets,
    async (next) => {
      await guard();
      await saveSession({ ...session, secrets: next });
      await rollbackIfLocked([SESSION_KEY]);
    },
    api,
    (current) =>
      runSync({
        items,
        syncToken: cache.syncToken,
        storedTypes: cache.storedTypes,
        fetchPage: (syncToken, cursorToken) => api.syncPage(current, syncToken, cursorToken),
        masterKey: session.masterKey,
        ensureMasterKey: async () => session.masterKey,
      }),
    requestSharedRefresh,
  );
  await guard();
  const cacheSaved = await saveCache(items, report.syncToken);
  await rollbackIfLocked([CACHE_KEY]);
  return { report, items, cacheSaved };
}

export async function lockVault(): Promise<void> {
  await performLock();
}

export async function signOut(session: VaultSession): Promise<void> {
  try {
    await createApi(session.apiUrl).logout(session.secrets);
  } catch {
    // Server-side revocation is best-effort; local state is what matters.
  }
  await lockVault();
}
