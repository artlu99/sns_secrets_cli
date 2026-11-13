/**
 * The hosted Standard Notes API 500s on requests whose Origin header is a
 * non-http scheme — which is every fetch an extension page makes
 * (`chrome-extension://…`). The CLI has no such header and works; the
 * official web app's https origin is allowed. The fix is to strip Origin on
 * the wire with a declarativeNetRequest rule, so the server sees exactly
 * what the CLI sends.
 *
 * api.standardnotes.com is covered by the static ruleset (public/rules.json).
 * A self-hosted API gets the same rule installed dynamically at unlock time.
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
    resourceTypes: Array<"xmlhttprequest">;
  };
};

/** Rule id used for the dynamic (self-hosted) rule; replaced on every unlock. */
export const DYNAMIC_ORIGIN_RULE_ID = 2;

export function removeOriginRule(id: number, requestDomains: string[]): OriginRule {
  return {
    id,
    priority: 1,
    action: {
      type: "modifyHeaders",
      requestHeaders: [{ header: "Origin", operation: "remove" }],
    },
    condition: {
      requestDomains,
      resourceTypes: ["xmlhttprequest"],
    },
  };
}

/**
 * The dynamic rule for a custom API origin — or null for
 * api.standardnotes.com, which the static ruleset already covers.
 */
export function originRuleForApi(apiUrl: string): OriginRule | null {
  let host: string;
  try {
    host = new URL(apiUrl).hostname;
  } catch {
    return null;
  }
  if (host === "" || host === "api.standardnotes.com") return null;
  return removeOriginRule(DYNAMIC_ORIGIN_RULE_ID, [host]);
}
