import { expect, test } from "bun:test";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createPkce, mfaChallenge, parseKeyParams, pkceChallenge } from "./sn-api.ts";
import { loadSession, saveSession, sessionKeyNames } from "./session-file.ts";
import { ensureConfigDir, withConfigDir } from "./paths.ts";

test("pkce challenge is base64url(hex(sha256(verifier)))", () => {
  const verifier = "sns-pkce-verifier-example";
  expect(pkceChallenge(verifier)).toBe(
    "OWU4OWI5NWY0YmRhMGJjNWY1ZGE3M2M3NDY5OGZmNGU2ODFjNWVhNjgwOTlkZTljNzVkOWQ2ZjNjYjAxOTFkNw",
  );
  const pair = createPkce();
  expect(pair.challenge).toBe(pkceChallenge(pair.verifier));
  expect(pair.verifier.endsWith("=")).toBe(true);
});

test("mfa and key-param bodies parse without echoing secrets", () => {
  expect(
    mfaChallenge({
      data: { error: { tag: "mfa-required", message: "code", payload: { mfa_key: "mfa_abc" } } },
    })?.mfaKey,
  ).toBe("mfa_abc");
  expect(
    parseKeyParams({
      data: { version: "004", identifier: "a@b.c", pw_nonce: "abc", kdf_iterations: 5, kdf_memory: 67108864 },
    }),
  ).toMatchObject({ version: "004", identifier: "a@b.c", pwNonce: "abc", memory: 67108864 });
});

test("session file round-trips and keeps mode 0600", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-session-"));
  try {
    await withConfigDir(dir, async () => {
      ensureConfigDir();
      await saveSession({
        accountEmail: "me@example.com",
        refreshToken: "refresh-1",
        accessToken: "access-1",
        accessExpirationMs: 1_700_000_000_000,
        refreshExpirationMs: 1_800_000_000_000,
        accessCookie: "",
        refreshCookie: "",
        dbKey: "ab".repeat(32),
      });
      const loaded = await loadSession();
      expect(loaded?.refreshToken).toBe("refresh-1");
      expect(loaded?.accountEmail).toBe("me@example.com");
      expect(loaded?.dbKey).toBe("ab".repeat(32));
      const names = sessionKeyNames();
      expect(names).toContain("SN_DB_KEY");
      expect(names).toContain("SN_REFRESH_TOKEN");
      expect(names.join(" ")).not.toContain(["SN", "PASSWORD"].join("_"));
      const mode = statSync(join(dir, ".env.session")).mode & 0o777;
      expect(mode).toBe(0o600);
      const keysMode = statSync(join(dir, ".env.keys")).mode & 0o777;
      expect(keysMode).toBe(0o600);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
