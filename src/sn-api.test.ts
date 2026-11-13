import { expect, test } from "bun:test";
import { deriveRootKey } from "./sn-crypto/kdf.ts";
import { createApi, withAccess } from "./sn-api.ts";
import type { SessionSecrets } from "./session-file.ts";

test("login sends the server password and stores tokens", async () => {
  const email = "sn004@lessknown.co.uk";
  const pwNonce = "2c409996650e46c748856fbd6aa549f89f35be055a8f9bfacdf0c4b29b2152e9";
  const root = await deriveRootKey("debugtest", { version: "004", identifier: email, pwNonce });
  let seenPassword = "";
  const server = Bun.serve({
    port: 0,
    async fetch(request) {
      const body = (await request.json()) as Record<string, unknown>;
      const url = new URL(request.url);
      if (url.pathname === "/v2/login-params") {
        return Response.json({
          data: { version: "004", identifier: email, pw_nonce: pwNonce },
        });
      }
      if (url.pathname === "/v2/login") {
        seenPassword = String(body.password ?? "");
        return Response.json({
          data: {
            session: {
              access_token: "access-token",
              refresh_token: "refresh-token",
              access_expiration: 1_800_000_000_000,
              refresh_expiration: 1_900_000_000_000,
            },
            user: { uuid: "user", email },
          },
        });
      }
      return new Response("no", { status: 404 });
    },
  });
  try {
    const api = createApi(`http://127.0.0.1:${server.port}`);
    const result = await api.login(email, "debugtest", async () => {
      throw new Error("no mfa");
    }, "cd".repeat(32));
    expect(seenPassword).toBe(root.serverPassword);
    expect(result.secrets.refreshToken).toBe("refresh-token");
    expect(result.secrets.dbKey).toBe("cd".repeat(32));
    expect(result.masterKey).toBe(root.masterKey);
  } finally {
    server.stop(true);
  }
}, 20_000);

test("login completes when MFA arrives as an HTTP error challenge", async () => {
  const email = "mfa@example.test";
  let paramsCalls = 0;
  let loginCalls = 0;
  let seenMfaOnParams = "";
  let seenMfaOnLogin = "";
  const server = Bun.serve({
    port: 0,
    async fetch(request) {
      const body = (await request.json()) as Record<string, unknown>;
      const url = new URL(request.url);
      if (url.pathname === "/v2/login-params") {
        paramsCalls += 1;
        seenMfaOnParams = String(body.mfa_abc ?? "");
        if (paramsCalls === 1) {
          // The real challenge shape: an HTTP error carrying the mfa tag.
          return Response.json(
            { data: { error: { tag: "mfa-required", message: "code", payload: { mfa_key: "mfa_abc" } } } },
            { status: 401 },
          );
        }
        return Response.json({ data: { version: "004", identifier: email, pw_nonce: "aa".repeat(32) } });
      }
      if (url.pathname === "/v2/login") {
        loginCalls += 1;
        seenMfaOnLogin = String(body.mfa_abc ?? "");
        return Response.json({
          data: {
            session: {
              access_token: "access-1",
              refresh_token: "refresh-1",
              access_expiration: 1_800_000_000_000,
              refresh_expiration: 1_900_000_000_000,
            },
          },
        });
      }
      return new Response("no", { status: 404 });
    },
  });
  try {
    const api = createApi(`http://127.0.0.1:${server.port}`);
    let prompts = 0;
    const result = await api.login(email, "pw", async () => {
      prompts += 1;
      return "123456";
    }, "cd".repeat(32));
    expect(prompts).toBe(1); // prompted once, code reused for both calls
    expect(paramsCalls).toBe(2);
    expect(loginCalls).toBe(1);
    expect(seenMfaOnParams).toBe("123456");
    expect(seenMfaOnLogin).toBe("123456");
    expect(result.secrets.refreshToken).toBe("refresh-1");
    expect(result.secrets.dbKey).toBe("cd".repeat(32));
  } finally {
    server.stop(true);
  }
}, 20_000);

test("a persistent MFA challenge is a rejection, not a prompt loop", async () => {
  const server = Bun.serve({
    port: 0,
    async fetch() {
      return Response.json(
        { data: { error: { tag: "mfa-required", message: "code", payload: { mfa_key: "mfa_abc" } } } },
        { status: 401 },
      );
    },
  });
  try {
    const api = createApi(`http://127.0.0.1:${server.port}`);
    await expect(api.keyParams("x@y.z", async () => "000000")).rejects.toThrow(/two-factor/);
  } finally {
    server.stop(true);
  }
});

test("withAccess refreshes once on a 401 and retries with the new token", async () => {
  let syncCalls = 0;
  let refreshCalls = 0;
  let lastAuth = "";
  const server = Bun.serve({
    port: 0,
    async fetch(request) {
      const url = new URL(request.url);
      lastAuth = request.headers.get("authorization") ?? "";
      if (url.pathname === "/v1/items") {
        syncCalls += 1;
        if (syncCalls === 1) return new Response("{}", { status: 401 });
        return Response.json({ data: { retrieved_items: [], sync_token: "t1", cursor_token: null, conflicts: [] } });
      }
      if (url.pathname === "/v1/sessions/refresh") {
        refreshCalls += 1;
        return Response.json({
          data: {
            session: {
              access_token: "access-2",
              refresh_token: "refresh-2",
              access_expiration: 1_800_000_000_000,
              refresh_expiration: 1_900_000_000_000,
            },
          },
        });
      }
      return new Response("no", { status: 404 });
    },
  });
  const secrets: SessionSecrets = {
    accountEmail: "me@example.test",
    refreshToken: "refresh-1",
    accessToken: "access-1",
    accessExpirationMs: 0,
    refreshExpirationMs: 1_900_000_000_000,
    accessCookie: "",
    refreshCookie: "",
    dbKey: "cd".repeat(32),
  };
  try {
    const api = createApi(`http://127.0.0.1:${server.port}`);
    const saved: string[] = [];
    let savedAccountEmail = "";
    const page = await withAccess(secrets, async (next) => {
      saved.push(next.accessToken);
      savedAccountEmail = next.accountEmail;
    }, api, (current) => api.syncPage(current, null, null));
    expect(page.syncToken).toBe("t1");
    expect(refreshCalls).toBe(1);
    expect(syncCalls).toBe(2);
    expect(saved).toEqual(["access-2"]);
    expect(lastAuth).toBe("Bearer access-2");
    expect(savedAccountEmail).toBe("me@example.test"); // identity survives the refresh
  } finally {
    server.stop(true);
  }
});
