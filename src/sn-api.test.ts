import { expect, test } from "bun:test";
import { deriveRootKey } from "./sn-crypto/kdf.ts";
import { createApi } from "./sn-api.ts";

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
