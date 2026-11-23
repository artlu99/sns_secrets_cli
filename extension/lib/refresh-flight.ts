/**
 * Token-refresh ownership (audit M4): Standard Notes rotates refresh tokens
 * on use, so two contexts refreshing concurrently leave the loser persisting
 * a dead token and logging the user out spuriously. The service worker is
 * therefore the only context that POSTs a refresh: the popup and the
 * dashboard ask it over runtime messaging (REFRESH_MESSAGE_TYPE, wired in
 * background.ts and lib/unlock.ts) and share one in-flight flight —
 * concurrent callers receive the same outcome, a failed refresh is never
 * persisted, and the persisted write is epoch-guarded (lock-schedule.ts) so
 * a lock mid-refresh cannot resurrect key material.
 *
 * No browser APIs here: the coordinator's ports are injected, so lib tests
 * drive the races directly (the same contract as lock-schedule.ts), and the
 * service worker can own the refresh endpoint without importing the crypto
 * chain.
 */
import { UserError } from "../../src/errors.ts";
import { API_VERSION, CLIENT_HEADERS, asRecord, cookiePair, sendJson, unwrap, type FetchLike } from "./http.ts";
import { lockMoved, type LockState } from "./lock-schedule.ts";
import type { SessionSecrets, VaultSession } from "./session.ts";

/** runtime.onMessage type the surfaces send to ask the worker for a refresh. */
export const REFRESH_MESSAGE_TYPE = "sns:refresh";

function expirationMs(value: unknown): number {
  const n = typeof value === "number" ? value : typeof value === "string" ? Number(value) : 0;
  if (!Number.isFinite(n) || n <= 0) return 0;
  return n < 1e12 ? n * 1000 : n;
}

/** Parse a login/refresh response body into the stored session secrets.
 * Shape-for-shape the CLI's parser (src/sn-api.ts `parseSessionBody`): the
 * tokens live at `data.session`, with the capitalized `data.Session` as the
 * fallback — never at body root. One parse/decrypt semantics, three surfaces. */
export function parseSessionBody(body: unknown, setCookies: readonly string[]): SessionSecrets {
  const data = unwrap(body);
  const session = asRecord(data.session) ?? asRecord(data.Session) ?? {};
  const accessToken = String(session.access_token ?? "");
  const refreshToken = String(session.refresh_token ?? "");
  if (accessToken === "" || refreshToken === "") {
    throw new UserError("login response did not include session tokens");
  }
  return {
    accountEmail: "",
    accessToken,
    refreshToken,
    accessExpirationMs: expirationMs(session.access_expiration ?? session.access_token_expiration),
    refreshExpirationMs: expirationMs(session.refresh_expiration ?? session.refresh_token_expiration),
    accessCookie: cookiePair(setCookies, "access_token"),
    refreshCookie: cookiePair(setCookies, "refresh_token"),
  };
}

/**
 * The refresh POST only — no login, no Argon2, no sodium — kept identical to
 * the CLI's refresh (src/sn-api.ts), including the carry-over of the account
 * label and of cookies the server did not re-set.
 */
export function createRefreshClient(apiUrl: string, fetchImpl?: FetchLike): {
  refresh(secrets: SessionSecrets): Promise<SessionSecrets>;
} {
  const base = apiUrl.replace(/\/+$/, "");
  return {
    async refresh(secrets) {
      const headers: Record<string, string> = { Authorization: `Bearer ${secrets.refreshToken}` };
      if (secrets.refreshCookie) headers.Cookie = secrets.refreshCookie;
      const response = await sendJson(
        `${base}/v1/sessions/refresh`,
        {
          method: "POST",
          headers: { ...CLIENT_HEADERS, ...headers },
          body: JSON.stringify({ api: API_VERSION }),
        },
        { fetch: fetchImpl },
      );
      const next = parseSessionBody(response.body, response.setCookies);
      if (!next.accountEmail && secrets.accountEmail) next.accountEmail = secrets.accountEmail;
      if (!next.accessCookie && secrets.accessCookie) next.accessCookie = secrets.accessCookie;
      if (!next.refreshCookie && secrets.refreshCookie) next.refreshCookie = secrets.refreshCookie;
      return next;
    },
  };
}

export type SharedRefreshDeps = {
  /** The stored vault session — the single source of truth for tokens. */
  loadSession: () => Promise<VaultSession | null>;
  /** One refresh POST against the session's API. */
  apiRefresh: (session: VaultSession) => Promise<SessionSecrets>;
  /** Persist the rotated secrets; called only when the epoch still matches. */
  saveSession: (session: VaultSession) => Promise<void>;
  /**
   * Take a just-persisted session back out of storage when the settle check
   * passed but a lock landed before the persist itself committed — the
   * guard-to-write gap, closed the same way syncVault closes its cache write.
   */
  discardSession?: () => Promise<void>;
  getLockState: () => Promise<LockState>;
};

/**
 * One refresh at a time across every context. Callers arriving while a
 * flight is running await the same promise — same outcome, exactly one
 * rotation — and the slot clears on settle so the next caller starts fresh
 * from whatever was just persisted. A lock (or a fresh unlock) between the
 * epoch capture and the settle check aborts the save: the flight's outcome
 * dies with the vault it belongs to.
 */
export function createSharedRefresh(deps: SharedRefreshDeps): { refresh(): Promise<SessionSecrets> } {
  let inFlight: Promise<SessionSecrets> | null = null;

  const run = async (): Promise<SessionSecrets> => {
    const start = await deps.getLockState();
    if (start.locked) throw new UserError("vault locked while refreshing — aborted");
    const session = await deps.loadSession();
    if (session === null || session.secrets.refreshToken === "") {
      throw new UserError("no vault session to refresh — sign in again");
    }
    const next = await deps.apiRefresh(session);
    if (lockMoved(start.lockEpoch, await deps.getLockState())) {
      throw new UserError("vault locked while refreshing — aborted");
    }
    await deps.saveSession({ ...session, secrets: next });
    // The settle check cannot cover its own gap: if a LOCK landed between
    // that check and the persist, the just-written tokens are taken back out
    // — key material never outlives the vault it belongs to. A fresh UNLOCK
    // also moves the epoch, but it saved its own newer session after ours
    // committed — deleting here would strand a live vault on the login form,
    // so only a locked state discards.
    const settled = await deps.getLockState();
    if (settled.locked && lockMoved(start.lockEpoch, settled)) {
      await deps.discardSession?.();
    }
    return next;
  };

  return {
    refresh() {
      if (inFlight !== null) return inFlight;
      const flight = run();
      inFlight = flight;
      void flight.then(
        () => {
          if (inFlight === flight) inFlight = null;
        },
        () => {
          if (inFlight === flight) inFlight = null;
        },
      );
      return flight;
    },
  };
}
