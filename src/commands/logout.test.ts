import { expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { acquireSyncLock } from "../lock.ts";
import { ensureConfigDir, keysPath, sessionPath, withConfigDir } from "../paths.ts";
import { saveSession, type SessionSecrets } from "../session-file.ts";
import { logoutCommand } from "./logout.ts";

// A test logout must never touch the developer's real keychain entry.
process.env.SNS_DISABLE_KEYCHAIN ??= "1";

test("logout without a session is a clear error", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-logout0-"));
  try {
    await withConfigDir(dir, async () => {
      ensureConfigDir();
      await expect(logoutCommand()).rejects.toThrow(/not logged in/);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("logout deletes an unreadable session instead of throwing", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-logout1-"));
  try {
    await withConfigDir(dir, async () => {
      ensureConfigDir();
      // A session file that cannot be decrypted must not strand itself on disk:
      // logout is the recovery path, so it deletes it anyway.
      writeFileSync(sessionPath(), "encrypted:not-a-real-ciphertext", { mode: 0o600 });
      await expect(logoutCommand({ deleteCache: true })).resolves.toBeUndefined();
      expect(existsSync(sessionPath())).toBe(false);
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
    // Unexpired, so the revoke uses the current token without a refresh.
    accessExpirationMs: Date.now() + 3_600_000,
    refreshExpirationMs: Date.now() + 86_400_000,
    accessCookie: "",
    refreshCookie: "",
    dbKey: "cd".repeat(32),
  };
}

test("the sync lock is held across the server revoke, and logout cleans up", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-logout2-"));
  const originalFetch = globalThis.fetch;
  let lockContendedDuringRevoke = false;
  globalThis.fetch = (async () => {
    // The revoke request is in flight: a concurrent sync must not be able to
    // take the lock now — the refresh-within-revoke would otherwise rotate
    // the refresh token against that sync's own rotation.
    try {
      await acquireSyncLock(150);
    } catch {
      lockContendedDuringRevoke = true;
    }
    return new Response("{}", { status: 200 });
  }) as unknown as typeof fetch;
  try {
    await withConfigDir(dir, async () => {
      ensureConfigDir();
      await saveSession(session());
      expect(existsSync(sessionPath())).toBe(true);
      await expect(logoutCommand()).resolves.toBeUndefined();
      expect(lockContendedDuringRevoke).toBe(true);
      // Local custody is gone even though the revoke succeeded.
      expect(existsSync(sessionPath())).toBe(false);
      expect(existsSync(keysPath())).toBe(false);
    });
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("logout still deletes everything when the server revoke fails", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-logout3-"));
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response("nope", { status: 500 })) as unknown as typeof fetch;
  try {
    await withConfigDir(dir, async () => {
      ensureConfigDir();
      await saveSession(session());
      await expect(logoutCommand()).resolves.toBeUndefined();
      expect(existsSync(sessionPath())).toBe(false);
      expect(existsSync(keysPath())).toBe(false);
    });
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a revoke failure prints server error text with no escape bytes", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-logout4-"));
  const originalFetch = globalThis.fetch;
  const originalError = console.error;
  const sink: string[] = [];
  // The server controls the error body: CSI + OSC payload rides the ApiError
  // summary straight into logout's local display sink — it must be sanitized
  // there, since the top-level catch never sees this failure.
  globalThis.fetch = (async () =>
    new Response(JSON.stringify({ error: { message: "\u001b]0;owned\u0007\u001b[2Jraw" } }), { status: 500 })
  ) as unknown as typeof fetch;
  console.error = (...args: unknown[]) => sink.push(args.map(String).join(" "));
  try {
    await withConfigDir(dir, async () => {
      ensureConfigDir();
      await saveSession(session());
      await expect(logoutCommand()).resolves.toBeUndefined();
      expect(existsSync(sessionPath())).toBe(false);
    });
  } finally {
    globalThis.fetch = originalFetch;
    console.error = originalError;
    rmSync(dir, { recursive: true, force: true });
  }
  const printed = sink.join("\n");
  expect(printed).toContain("server revoke failed");
  expect(printed).toContain("raw");
  expect(printed).not.toContain("\u001b");
});
