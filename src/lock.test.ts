import { expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scrubbedEnv } from "./env.ts";
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
      expect(existsSync(lockPath())).toBe(true);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an empty sentinel is acquired immediately and left unchanged", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-lock-empty-"));
  try {
    await withConfigDir(dir, async () => {
      ensureConfigDir();
      writeFileSync(lockPath(), "");
      const started = Date.now();
      const release = await acquireSyncLock(2_000);
      expect(Date.now() - started).toBeLessThan(500);
      release();
      expect(readFileSync(lockPath(), "utf8")).toBe("");
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("file text is not the lock", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-lock-text-"));
  try {
    await withConfigDir(dir, async () => {
      ensureConfigDir();
      writeFileSync(lockPath(), "4000000000 deadbeef- holder is gone");
      const release = await acquireSyncLock(200);
      writeFileSync(lockPath(), "999999 not-this-lock");
      await expect(acquireSyncLock(300)).rejects.toThrow(/another sns sync/);
      release();
      expect(readFileSync(lockPath(), "utf8")).toBe("999999 not-this-lock");
      const again = await acquireSyncLock(200);
      again();
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a killed holder drops the lock even if a child is still running", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-lock-kill-"));
  const config = join(dir, "config");
  const ready = join(dir, "held");
  const holder = Bun.spawn(
    [
      process.execPath,
      "-e",
      `
        import { writeFileSync } from "node:fs";
        import { acquireSyncLock } from ${JSON.stringify(join(process.cwd(), "src/lock.ts"))};
        import { ensureConfigDir } from ${JSON.stringify(join(process.cwd(), "src/paths.ts"))};
        ensureConfigDir();
        const release = await acquireSyncLock(2_000);
        const sleeper = Bun.spawn([process.execPath, "-e", "await Bun.sleep(30_000)"], {
          stdin: "ignore",
          stdout: "ignore",
          stderr: "ignore",
        });
        writeFileSync(${JSON.stringify(ready)}, String(sleeper.pid));
        await Bun.sleep(60_000);
        sleeper.kill();
        release();
      `,
    ],
    {
      cwd: process.cwd(),
      env: { ...scrubbedEnv(), SNS_CONFIG_DIR: config },
      stdout: "ignore",
      stderr: "pipe",
    },
  );
  let sleeperPid = 0;
  try {
    const deadline = Date.now() + 8_000;
    while (!existsSync(ready)) {
      if (holder.exitCode !== null) {
        const err = await new Response(holder.stderr).text();
        throw new Error(`holder exited ${holder.exitCode}: ${err}`);
      }
      if (Date.now() > deadline) throw new Error("holder never acquired the lock");
      await Bun.sleep(20);
    }
    sleeperPid = Number(readFileSync(ready, "utf8"));
    await withConfigDir(config, async () => {
      await expect(acquireSyncLock(300)).rejects.toThrow(/another sns sync/);
      holder.kill("SIGKILL");
      await holder.exited;
      const started = Date.now();
      const release = await acquireSyncLock(1_000);
      expect(Date.now() - started).toBeLessThan(1_000);
      release();
    });
  } finally {
    holder.kill("SIGKILL");
    await holder.exited;
    if (sleeperPid > 0) {
      try {
        process.kill(sleeperPid, "SIGKILL");
      } catch {
        /* already gone */
      }
    }
    rmSync(dir, { recursive: true, force: true });
  }
}, 15_000);
