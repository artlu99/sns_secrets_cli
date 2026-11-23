import { expect, test } from "bun:test";
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createPkce, mfaChallenge, parseKeyParams, pkceChallenge } from "./sn-api.ts";
import { loadSession, saveSession, sessionKeyNames, type SessionSecrets } from "./session-file.ts";
import { ensureConfigDir, sessionPath, withConfigDir } from "./paths.ts";

// `security add-generic-password -U` is an upsert: without this guard a test
// saveSession would overwrite the developer's real keychain entry on macOS.
process.env.SNS_DISABLE_KEYCHAIN ??= "1";

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
      await saveSession(session());
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

function session(): SessionSecrets {
  return {
    accountEmail: "me@example.com",
    refreshToken: "refresh-1",
    accessToken: "access-1",
    accessExpirationMs: 1_700_000_000_000,
    refreshExpirationMs: 1_800_000_000_000,
    accessCookie: "",
    refreshCookie: "",
    dbKey: "ab".repeat(32),
  };
}

test("a token-refresh save and a wide crash leftover both land 0600", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-session2-"));
  try {
    await withConfigDir(dir, async () => {
      ensureConfigDir();
      await saveSession(session());
      // The refresh path (withAccess after a rotation) saves over an existing
      // session — the file must stay 0600 through that rewrite too.
      await saveSession({ ...session(), refreshToken: "refresh-2", accessToken: "access-2" });
      const loaded = await loadSession();
      expect(loaded?.refreshToken).toBe("refresh-2");
      expect(statSync(sessionPath()).mode & 0o777).toBe(0o600);
      // A save that crashed before the old trailing chmod could leave the
      // file wide; the next save tightens it before dotenvx writes.
      chmodSync(sessionPath(), 0o664);
      await saveSession({ ...session(), refreshToken: "refresh-3" });
      expect((await loadSession())?.refreshToken).toBe("refresh-3");
      expect(statSync(sessionPath()).mode & 0o777).toBe(0o600);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an empty .env.session left by a crashed save is replaced, not stranded", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-session4-"));
  try {
    await withConfigDir(dir, async () => {
      ensureConfigDir();
      // What ensureSessionFilePrivate leaves behind if the process dies
      // before dotenvx's first rename: an empty 0600 target.
      writeFileSync(sessionPath(), "", { mode: 0o600 });
      await saveSession(session());
      expect((await loadSession())?.refreshToken).toBe("refresh-1");
      expect(statSync(sessionPath()).mode & 0o777).toBe(0o600);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("saveSession refuses a symlink planted at .env.session", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-session3-"));
  try {
    await withConfigDir(dir, async () => {
      ensureConfigDir();
      const outside = join(dir, "outside.txt");
      writeFileSync(outside, "not a session\n", { mode: 0o600 });
      symlinkSync(outside, sessionPath());
      await expect(saveSession(session())).rejects.toThrow(/symlink/);
      // The planted target was never written through.
      expect(readFileSync(outside, "utf8")).toBe("not a session\n");
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
