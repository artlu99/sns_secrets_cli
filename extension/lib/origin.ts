/**
 * The hosted Standard Notes API 500s on requests whose Origin header is a
 * non-http scheme — which is every fetch an extension page or the service
 * worker makes (`chrome-extension://…`). The CLI has no such header and
 * works; the official web app's https origin is allowed. The fix is to strip
 * Origin on the wire with a declarativeNetRequest rule, so the server sees
 * exactly what the CLI sends.
 *
 * The strip is scoped to this extension's own requests: `initiatorDomains`
 * matches the request initiator's host, and for chrome-extension://
 * initiators that host IS the extension id (a textual domain match in
 * Chromium). A tab running the official web app — or any other page — keeps
 * its Origin, so its CORS is untouched.
 *
 * A static ruleset cannot know the per-install id, so both rules are
 * dynamic: the hosted-API rule is (re)installed by the service worker on
 * every wake (background.ts), and a self-hosted API gets the same shape at
 * unlock time (lib/unlock.ts).
 */

/** Structural shape of a DNR modifyHeaders rule (kept local, browser-only use). */
export type OriginRule = {
  id: number;
  priority: number;
  action: {
    type: "modifyHeaders";
    requestHeaders: Array<{ header: string; operation: "remove" }>;
  };
  condition: {
    requestDomains: string[];
    initiatorDomains: string[];
    resourceTypes: Array<"xmlhttprequest">;
  };
};

/** Rule id of the hosted-API rule (formerly the static ruleset's rule 1). */
export const DEFAULT_ORIGIN_RULE_ID = 1;

/** Rule id used for the dynamic (self-hosted) rule; replaced on every unlock. */
export const DYNAMIC_ORIGIN_RULE_ID = 2;

export function removeOriginRule(id: number, requestDomains: string[], initiatorDomains: string[]): OriginRule {
  return {
    id,
    priority: 1,
    action: {
      type: "modifyHeaders",
      requestHeaders: [{ header: "Origin", operation: "remove" }],
    },
    condition: {
      requestDomains,
      initiatorDomains,
      resourceTypes: ["xmlhttprequest"],
    },
  };
}

/**
 * The dynamic rule for a custom API origin — or null for
 * api.standardnotes.com, which the service worker's default rule covers.
 */
export function originRuleForApi(apiUrl: string, extensionId: string): OriginRule | null {
  let host: string;
  try {
    host = new URL(apiUrl).hostname;
  } catch {
    return null;
  }
  if (host === "" || host === "api.standardnotes.com") return null;
  return removeOriginRule(DYNAMIC_ORIGIN_RULE_ID, [host], [extensionId]);
}

/**
 * Ask the service worker to (re)install the origin rules now, and wait for
 * the write. A fresh install's first login POST runs in the page context and
 * can otherwise beat the worker's fire-and-forget install — the request then
 * carries the chrome-extension:// Origin the hosted API 500s on. Surfaces
 * call this once at boot; a locked vault arms no alarm, so this message is
 * also what wakes the worker when nothing else would. Resolves false when
 * the worker is unreachable or the install failed (the worker's retry alarm
 * keeps trying) — callers proceed either way, since the request is then no
 * worse than without the check.
 */
export async function ensureOriginRules(): Promise<boolean> {
  try {
    const { browser } = await import("wxt/browser");
    return (await browser.runtime.sendMessage({ type: "sns:origin-rules" })) === true;
  } catch {
    return false;
  }
}
