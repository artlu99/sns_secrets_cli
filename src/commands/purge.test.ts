import { expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { purgeCommand } from "./purge.ts";
import { withConfigDir } from "../paths.ts";
import { outputSpy } from "../test-output.ts";

// A test purge must never touch the developer's real keychain entry.
process.env.SNS_DISABLE_KEYCHAIN ??= "1";

function seededDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "sns-purge-"));
  for (const name of [
    "cache.db",
    "cache.db-wal",
    ".env",
    ".env.session",
    ".env.keys",
    "sync.lock",
    "clipboard-clear-at",
  ]) {
    writeFileSync(join(dir, name), "x", { mode: 0o600 });
  }
  return dir;
}

test("purge --yes deletes every known file — including a never-decryptable cache — and removes the empty dir", async () => {
  const dir = seededDir();
  const out = outputSpy();
  try {
    await withConfigDir(dir, async () => {
      await purgeCommand({ yes: true });
    });
    expect(existsSync(dir)).toBe(false);
    expect(out.text()).toContain("purged 7 file(s)");
    expect(out.text()).toContain("The config directory was removed");
    // The scripted path warns pre-deletion, while the advice can still be
    // acted on; the outro states the outcome without dead-end advice.
    expect(out.text()).toContain("will not be revoked");
    expect(out.text()).toContain("no longer be from this machine");
  } finally {
    out.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("purge without --yes refuses a non-terminal and deletes nothing", async () => {
  const dir = seededDir();
  try {
    await withConfigDir(dir, async () => {
      await expect(purgeCommand()).rejects.toThrow(/pass --yes/);
    });
    expect(existsSync(join(dir, "cache.db"))).toBe(true);
    expect(existsSync(join(dir, ".env.session"))).toBe(true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("unrecognized files are left in place and named; the directory is kept", async () => {
  const dir = seededDir();
  try {
    writeFileSync(join(dir, "operator-notes.txt"), "mine", { mode: 0o600 });
    const out = outputSpy();
    try {
      await withConfigDir(dir, async () => {
        await purgeCommand({ yes: true });
      });
      const remaining = readdirSync(dir);
      expect(remaining).toEqual(["operator-notes.txt"]);
      expect(out.text()).toContain("left in place");
      expect(out.text()).toContain("operator-notes.txt");
      expect(existsSync(join(dir, "cache.db"))).toBe(false);
    } finally {
      out.restore();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("purge on a missing config dir is a clear error", async () => {
  const dir = join(mkdtempSync(join(tmpdir(), "sns-purge-none-")), "absent");
  try {
    await withConfigDir(dir, async () => {
      await expect(purgeCommand({ yes: true })).rejects.toThrow(/nothing to purge/);
    });
  } finally {
    rmSync(join(dir, ".."), { recursive: true, force: true });
  }
});

test("purge on an already-empty config dir says so and removes it", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-purge-empty-"));
  try {
    // mkdtempSync leaves exactly one entry-free dir; ensure it is empty.
    mkdirSync(dir, { recursive: true });
    const out = outputSpy();
    try {
      await withConfigDir(dir, async () => {
        await purgeCommand({ yes: true });
      });
      expect(out.text()).toContain("had nothing in it");
      expect(existsSync(dir)).toBe(false);
    } finally {
      out.restore();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
