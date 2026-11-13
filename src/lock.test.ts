import { expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { acquireSyncLock } from "./lock.ts";
import { ensureConfigDir, lockPath, withConfigDir } from "./paths.ts";

test("a second sync lock fails clearly instead of stacking writers", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-lock-"));
  try {
    await withConfigDir(dir, async () => {
      ensureConfigDir();
      const release = await acquireSyncLock(200);
      await expect(acquireSyncLock(400)).rejects.toThrow(/another sns sync/);
      release();
      const releaseAgain = await acquireSyncLock(200);
      releaseAgain();
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("release does not delete a successor's lock", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-lock2-"));
  try {
    await withConfigDir(dir, async () => {
      ensureConfigDir();
      const release = await acquireSyncLock(200);
      // Simulate a successor having taken over the path.
      writeFileSync(lockPath(), "999999 not-this-lock");
      release();
      expect(existsSync(lockPath())).toBe(true);
      expect(readFileSync(lockPath(), "utf8")).toBe("999999 not-this-lock");
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a lock whose holder is dead is taken over", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-lock3-"));
  try {
    await withConfigDir(dir, async () => {
      ensureConfigDir();
      writeFileSync(lockPath(), "4000000000 deadbeef- holder is gone");
      const release = await acquireSyncLock(400);
      expect(existsSync(lockPath())).toBe(true);
      release();
      expect(existsSync(lockPath())).toBe(false);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
