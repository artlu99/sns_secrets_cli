/**
 * Unlock + sync orchestration shared by the popup and the dashboard.
 * Unlock = keyParams → Argon2id (client-side) → login → session saved to
 * chrome.storage.session. Sync = incremental pull over the session cache.
 */
import { browser } from "wxt/browser";
import { UserError } from "../../src/errors.ts";
import { createApi, withAccess } from "./sn-api.ts";
import { clearCache, loadCache, saveCache } from "./cache.ts";
import { DYNAMIC_ORIGIN_RULE_ID, originRuleForApi } from "./origin.ts";
import { clearSession, normalizeApiUrl, saveSession, saveSettings, type VaultSession } from "./session.ts";
import { runSync, type ItemRow, type SyncReport } from "./store.ts";

/** Request the host permission for a custom (self-hosted) API origin. */
async function ensureHostPermission(apiUrl: string): Promise<void> {
  const origin = `${new URL(apiUrl).origin}/*`;
  if (await browser.permissions.contains({ origins: [origin] })) return;
  const granted = await browser.permissions.request({ origins: [origin] });
  if (!granted) throw new UserError(`permission to talk to ${origin} was denied`);
}

/**
 * Strip Origin on the wire for self-hosted APIs too (the static ruleset only
 * covers api.standardnotes.com). Runs on the click's user gesture, alongside
 * the host-permission request.
 */
async function installOriginRule(apiUrl: string): Promise<void> {
  const rule = originRuleForApi(apiUrl);
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
  return session;
}

export async function syncVault(session: VaultSession): Promise<{
  report: SyncReport;
  items: Map<string, ItemRow>;
}> {
  const api = createApi(session.apiUrl);
  const cache = await loadCache();
  const items = new Map(cache.items.map((row) => [row.uuid, row]));
  const report = await withAccess(
    session.secrets,
    (next) => saveSession({ ...session, secrets: next }),
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
  );
  await saveCache(items, report.syncToken);
  return { report, items };
}

export async function lockVault(): Promise<void> {
  await clearCache();
  await clearSession();
}

export async function signOut(session: VaultSession): Promise<void> {
  try {
    await createApi(session.apiUrl).logout(session.secrets);
  } catch {
    // Server-side revocation is best-effort; local state is what matters.
  }
  await lockVault();
}
