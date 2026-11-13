import { expect, test } from "bun:test";
import { ApiError, sendJson } from "./http.ts";

function response(status: number, body = "{}"): Response {
  return new Response(body, { status, headers: { "content-type": "application/json" } });
}

test("429 backs off and stops after three tries", async () => {
  let calls = 0;
  const sleeps: number[] = [];
  await expect(
    sendJson("https://example.test/items", { method: "POST" }, {
      fetch: async () => {
        calls += 1;
        return response(429, JSON.stringify({ error: { message: "slow down" } }));
      },
      sleep: async (ms) => {
        sleeps.push(ms);
      },
    }),
  ).rejects.toThrow(/HTTP 429/);
  expect(calls).toBe(3);
  expect(sleeps).toEqual([1000, 2000]);
});

test("401 invokes refresh once and does not loop", async () => {
  let calls = 0;
  let refreshed = 0;
  await expect(
    sendJson("https://example.test/items", { method: "POST", headers: { Authorization: "Bearer old" } }, {
      fetch: async () => {
        calls += 1;
        return response(401, JSON.stringify({ error: { tag: "invalid-auth", message: "no" } }));
      },
      onUnauthorized: async () => {
        refreshed += 1;
      },
      sleep: async () => {},
    }),
  ).rejects.toThrow(/HTTP 401/);
  expect(refreshed).toBe(1);
  expect(calls).toBe(2);
});

test("a recovered 401 returns the second response", async () => {
  let calls = 0;
  const result = await sendJson("https://example.test/items", { method: "GET" }, {
    fetch: async () => {
      calls += 1;
      if (calls === 1) return response(498, "{}");
      return response(200, JSON.stringify({ data: { ok: true } }));
    },
    onUnauthorized: async () => {},
    sleep: async () => {},
  });
  expect(result.status).toBe(200);
  expect(calls).toBe(2);
});

test("HTTP failures keep their status and parsed body", async () => {
  const error: unknown = await sendJson("https://example.test/login-params", { method: "POST" }, {
    fetch: async () =>
      response(401, JSON.stringify({ data: { error: { tag: "mfa-required", payload: { mfa_key: "mfa_abc" } } } })),
  }).catch((caught) => caught);
  expect(error).toBeInstanceOf(ApiError);
  const apiError = error as ApiError;
  expect(apiError.status).toBe(401);
  expect((apiError.body as { data: { error: { tag: string } } }).data.error.tag).toBe("mfa-required");
  expect(apiError.message).toContain("HTTP 401");
});
