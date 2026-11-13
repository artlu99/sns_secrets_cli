import { expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { logoutCommand } from "./logout.ts";
import { ensureConfigDir, sessionPath, withConfigDir } from "../paths.ts";

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
