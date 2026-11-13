import { createHash, randomBytes } from "node:crypto";
import { UserError } from "./errors.ts";
import { deriveRootKey, type KdfParams } from "./sn-crypto/kdf.ts";
import { API_VERSION, ApiError, CLIENT_HEADERS, cookiePair, sendJson, type FetchLike, type HttpOptions } from "./http.ts";
import type { SessionSecrets } from "./session-file.ts";
import type { EncryptedItem } from "./sn-crypto/004.ts";

export type SyncPage = {
  items: EncryptedItem[];
  syncToken: string | null;
  cursorToken: string | null;
  conflicts: number;
};

export function pkceChallenge(verifier: string): string {
  const hex = createHash("sha256").update(verifier).digest("hex");
  return Buffer.from(hex, "utf8").toString("base64url");
}

/** PKCE pair. The verifier keeps base64 padding; Standard Notes hashes that string. */
export function createPkce(): { verifier: string; challenge: string } {
  const verifier = Buffer.from(randomBytes(64)).toString("base64").replaceAll("+", "-").replaceAll("/", "_");
  return { verifier, challenge: pkceChallenge(verifier) };
}

type JsonRecord = Record<string, unknown>;

function asRecord(value: unknown): JsonRecord | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as JsonRecord;
}

function unwrap(body: unknown): JsonRecord {
  const root = asRecord(body) ?? {};
  return asRecord(root.data) ?? root;
}

export type MfaChallenge = { mfaKey: string; message: string };

export function mfaChallenge(body: unknown): MfaChallenge | null {
  const data = unwrap(body);
  const error = asRecord(data.error) ?? asRecord(asRecord(body)?.error);
  if (!error) return null;
  const tag = String(error.tag ?? "");
  if (tag !== "mfa-required" && tag !== "mfa-invalid") return null;
  const payload = asRecord(error.payload);
  const mfaKey = typeof payload?.mfa_key === "string" ? payload.mfa_key : "";
  if (mfaKey === "") return null;
  return { mfaKey, message: typeof error.message === "string" ? error.message : "Two-factor code required" };
}

export function parseKeyParams(body: unknown): KdfParams {
  const data = unwrap(body);
  const version = String(data.version ?? "");
  const identifier = String(data.identifier ?? "");
  const pwNonce = String(data.pw_nonce ?? data.pwNonce ?? "");
  const iterations = numberOrUndefined(data.kdf_iterations);
  const memory = numberOrUndefined(data.kdf_memory);
  const parallelism = numberOrUndefined(data.kdf_parallelism);
  if (version === "" || identifier === "" || pwNonce === "") {
    throw new UserError("login parameters were missing version, identifier, or salt seed");
  }
  return { version, identifier, pwNonce, iterations, memory, parallelism };
}

function numberOrUndefined(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value !== "" && Number.isFinite(Number(value))) return Number(value);
  return undefined;
}

function expirationMs(value: unknown): number {
  const n = typeof value === "number" ? value : typeof value === "string" ? Number(value) : 0;
  if (!Number.isFinite(n) || n <= 0) return 0;
  return n < 1e12 ? n * 1000 : n;
}

export function parseSessionBody(body: unknown, setCookies: readonly string[], dbKey: string): SessionSecrets {
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
    dbKey,
  };
}

export function parseSyncPage(body: unknown): SyncPage {
  const data = unwrap(body);
  const items = Array.isArray(data.retrieved_items) ? (data.retrieved_items as EncryptedItem[]) : [];
  const conflicts = Array.isArray(data.conflicts) ? data.conflicts.length : 0;
  const syncToken = typeof data.sync_token === "string" && data.sync_token !== "" ? data.sync_token : null;
  const cursorToken = typeof data.cursor_token === "string" && data.cursor_token !== "" ? data.cursor_token : null;
  return { items, syncToken, cursorToken, conflicts };
}

export type ApiClient = {
  login(email: string, password: string, mfaCode: () => Promise<string>, dbKey: string): Promise<{ secrets: SessionSecrets; masterKey: string }>;
  keyParams(email: string, mfaCode: () => Promise<string>): Promise<KdfParams>;
  refresh(secrets: SessionSecrets): Promise<SessionSecrets>;
  logout(secrets: SessionSecrets): Promise<void>;
  syncPage(secrets: SessionSecrets, syncToken: string | null, cursorToken: string | null): Promise<SyncPage>;
};

export function createApi(apiUrl: string, fetchImpl?: FetchLike): ApiClient {
  const base = apiUrl.replace(/\/+$/, "");
  const http = { fetch: fetchImpl };

  async function post(path: string, body: unknown, headers: Record<string, string>, options?: HttpOptions) {
    return sendJson(`${base}${path}`, {
      method: "POST",
      headers: { ...CLIENT_HEADERS, ...headers },
      body: JSON.stringify(body),
    }, { ...http, ...options });
  }

  type PostResponse = Awaited<ReturnType<typeof post>>;

  /**
   * One POST that handles an MFA challenge whether the server answers with it
   * in a 200 body or (the real shape) an HTTP error body. Prompts at most
   * once; a second challenge is a rejection, not another prompt.
   */
  async function postWithMfa(
    path: string,
    baseBody: Record<string, unknown>,
    headers: Record<string, string>,
    mfaCode: () => Promise<string>,
    seededExtra: Record<string, string> = {},
  ): Promise<{ response: PostResponse; extra: Record<string, string> }> {
    const extra: Record<string, string> = { ...seededExtra };
    for (let attempt = 0; attempt < 2; attempt++) {
      let response: PostResponse;
      try {
        response = await post(path, { ...baseBody, ...extra }, headers);
      } catch (error) {
        if (!(error instanceof ApiError)) throw error;
        const challenge = mfaChallenge(error.body);
        if (!challenge) throw error;
        if (attempt > 0) throw new UserError("two-factor authentication was rejected");
        extra[challenge.mfaKey] = await mfaCode();
        continue;
      }
      const challenge = mfaChallenge(response.body);
      if (!challenge) return { response, extra };
      if (attempt > 0) throw new UserError("two-factor authentication was rejected");
      extra[challenge.mfaKey] = await mfaCode();
    }
    throw new UserError("could not complete two-factor authentication");
  }

  return {
    async keyParams(email, mfaCode) {
      const pkce = createPkce();
      const { response } = await postWithMfa("/v2/login-params", {
        api: API_VERSION,
        email,
        code_challenge: pkce.challenge,
      }, {}, mfaCode);
      return parseKeyParams(response.body);
    },

    async login(email, password, mfaCode, dbKey) {
      const pkce = createPkce();
      const params = await postWithMfa("/v2/login-params", {
        api: API_VERSION,
        email,
        code_challenge: pkce.challenge,
      }, {}, mfaCode);
      const root = await deriveRootKey(password, parseKeyParams(params.response.body));
      const login = await postWithMfa("/v2/login", {
        api: API_VERSION,
        email,
        password: root.serverPassword,
        code_verifier: pkce.verifier,
        ephemeral: false,
      }, {}, mfaCode, params.extra);
      return { secrets: parseSessionBody(login.response.body, login.response.setCookies, dbKey), masterKey: root.masterKey };
    },

    async refresh(secrets) {
      const headers: Record<string, string> = { Authorization: `Bearer ${secrets.refreshToken}` };
      if (secrets.refreshCookie) headers.Cookie = secrets.refreshCookie;
      const response = await post("/v1/sessions/refresh", { api: API_VERSION }, headers);
      const next = parseSessionBody(response.body, response.setCookies, secrets.dbKey);
      if (!next.accountEmail && secrets.accountEmail) next.accountEmail = secrets.accountEmail;
      if (!next.accessCookie && secrets.accessCookie) next.accessCookie = secrets.accessCookie;
      if (!next.refreshCookie && secrets.refreshCookie) next.refreshCookie = secrets.refreshCookie;
      return next;
    },

    async logout(secrets) {
      const headers: Record<string, string> = {};
      if (secrets.accessToken) headers.Authorization = `Bearer ${secrets.accessToken}`;
      if (secrets.accessCookie && secrets.accessToken.startsWith("2:")) headers.Cookie = secrets.accessCookie;
      try {
        await post("/v1/logout", { api: API_VERSION }, headers);
      } catch (error) {
        if (!(error instanceof ApiError) || (error.status !== 404 && error.status !== 405)) throw error;
        await sendJson(`${base}/v1/sessions`, { method: "DELETE", headers: { ...CLIENT_HEADERS, ...headers } }, http);
      }
    },

    async syncPage(secrets, syncToken, cursorToken) {
      const body: Record<string, unknown> = { api: API_VERSION, items: [], limit: 150 };
      if (syncToken) body.sync_token = syncToken;
      if (cursorToken) body.cursor_token = cursorToken;
      const headers: Record<string, string> = { Authorization: `Bearer ${secrets.accessToken}` };
      if (secrets.accessCookie && secrets.accessToken.startsWith("2:")) headers.Cookie = secrets.accessCookie;
      const response = await post("/v1/items", body, headers);
      return parseSyncPage(response.body);
    },
  };
}

export function randomDbKey(): string {
  return randomBytes(32).toString("hex");
}

/**
 * Run one authenticated call. Refreshes an expired access token first, and
 * on 401/498 refreshes and retries the call exactly once.
 */
export async function withAccess<T>(
  secrets: SessionSecrets,
  save: (next: SessionSecrets) => Promise<unknown>,
  api: ApiClient,
  run: (current: SessionSecrets) => Promise<T>,
): Promise<T> {
  let current = secrets;
  const expiring = current.accessExpirationMs > 0 && current.accessExpirationMs <= Date.now() + 30_000;
  if (current.accessToken === "" || expiring) {
    current = await api.refresh(current);
    await save(current);
  }
  try {
    return await run(current);
  } catch (error) {
    if (!isAuthFailure(error)) throw error;
    try {
      current = await api.refresh(current);
      await save(current);
    } catch {
      throw new UserError("session expired — run sns login");
    }
    try {
      return await run(current);
    } catch (again) {
      if (isAuthFailure(again)) throw new UserError("session expired — run sns login");
      throw again;
    }
  }
}

function isAuthFailure(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 401 || error.status === 498);
}
