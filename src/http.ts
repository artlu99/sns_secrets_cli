import { UserError } from "./errors.ts";

export const API_VERSION = "20240226";

export const CLIENT_HEADERS: Record<string, string> = {
  "User-Agent":
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) StandardNotes/3.198.18 Chrome/134.0.6998.205 Electron/35.2.0 Safari/537.36",
  "X-SNJS-Version": "2.211.7",
  "X-Application-Version": "Desktop-3.201.27",
  "Content-Type": "application/json",
  Accept: "application/json",
};

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export type HttpOptions = {
  fetch?: FetchLike;
  sleep?: (ms: number) => Promise<void>;
  /** Called at most once when the server returns 401 or 498. */
  onUnauthorized?: () => Promise<void>;
};

function errorSummary(status: number, body: string): string {
  try {
    const json = JSON.parse(body) as {
      message?: string;
      error?: { tag?: string; message?: string };
      data?: { error?: { tag?: string; message?: string } };
    };
    const err = json.data?.error ?? json.error;
    const tag = err?.tag ?? "";
    const message = err?.message ?? json.message ?? "";
    const detail = [tag, message].filter(Boolean).join(": ").slice(0, 180);
    return detail ? `HTTP ${status} ${detail}` : `HTTP ${status}`;
  } catch {
    return `HTTP ${status}`;
  }
}

/**
 * An HTTP failure that keeps its status and parsed body, so callers can steer
 * on facts (MFA tags, 404/405 fallbacks, auth retries) instead of prose.
 * The message still summarizes the failure; it never contains secrets.
 */
export class ApiError extends UserError {
  readonly status: number;
  readonly body: unknown;

  constructor(status: number, text: string) {
    super(errorSummary(status, text));
    this.name = "ApiError";
    this.status = status;
    try {
      this.body = JSON.parse(text);
    } catch {
      this.body = null;
    }
  }
}

/**
 * Per-attempt client timeout. Bun's fetch (and a service-worker fetch) stays
 * pending forever against a connection that accepts and then sends no bytes
 * — a NAT idle drop or hung proxy wedged `sns sync` until Ctrl-C, and in the
 * extension it poisoned the shared refresh slot for every later caller. The
 * Rust client has carried this 120s guard since its first release
 * (rs/src/http.rs); this is the same guard on the TS side. The signal is
 * rebuilt each attempt, so every retry gets a fresh timer.
 */
const REQUEST_TIMEOUT_MS = 120_000;

/**
 * One request, with 429 backoff (3 tries) and a single 401/498 refresh.
 * The unauthorized hook runs at most once, so a bad refresh cannot loop.
 */
export async function sendJson(
  url: string,
  init: RequestInit,
  options: HttpOptions = {},
): Promise<{ status: number; body: unknown; setCookies: string[] }> {
  const fetchImpl = options.fetch ?? fetch;
  const sleep = options.sleep ?? ((ms: number) => Bun.sleep(ms));
  let unauthorizedUsed = false;
  let attempt = 0;
  while (true) {
    let response: Response;
    try {
      response = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
    } catch (error) {
      // AbortSignal.timeout names TimeoutError (some runtimes AbortError);
      // neither can be a caller abort — no caller passes a signal.
      if (error instanceof Error && (error.name === "TimeoutError" || error.name === "AbortError")) {
        throw new UserError(`the API did not answer within ${REQUEST_TIMEOUT_MS / 1000}s — request aborted`);
      }
      throw error;
    }
    if (response.status === 429 && attempt < 2) {
      await response.arrayBuffer().catch(() => undefined);
      await sleep(1000 * 2 ** attempt);
      attempt += 1;
      continue;
    }
    if ((response.status === 401 || response.status === 498) && !unauthorizedUsed && options.onUnauthorized) {
      unauthorizedUsed = true;
      await response.arrayBuffer().catch(() => undefined);
      await options.onUnauthorized();
      continue;
    }
    const text = await response.text();
    if (response.status >= 400) {
      throw new ApiError(response.status, text);
    }
    let body: unknown = null;
    if (text.trim() !== "") {
      try {
        body = JSON.parse(text);
      } catch {
        throw new UserError(`HTTP ${response.status} returned a non-JSON body`);
      }
    }
    const setCookies = typeof response.headers.getSetCookie === "function" ? response.headers.getSetCookie() : [];
    return { status: response.status, body, setCookies };
  }
}

export function cookiePair(setCookies: readonly string[], prefix: string): string {
  for (const header of setCookies) {
    const pair = header.split(";")[0]?.trim() ?? "";
    if (pair.startsWith(prefix)) return pair;
  }
  return "";
}
