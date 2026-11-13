import { expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { acquireSyncLock } from "./lock.ts";
import { ensureConfigDir, withConfigDir } from "./paths.ts";

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
