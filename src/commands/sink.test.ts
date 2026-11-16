import { expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { openDatabase, upsertItems, type ItemRow } from "../db.ts";
import { dbPath, ensureConfigDir, withConfigDir } from "../paths.ts";
import { saveSession, type SessionSecrets } from "../session-file.ts";
import { sinkCommand, writeSecretFile } from "./sink.ts";
import { outputSpy } from "../test-output.ts";

// `security add-generic-password -U` is an upsert: without this guard a test
// saveSession would overwrite the developer's real keychain entry on macOS.
process.env.SNS_DISABLE_KEYCHAIN ??= "1";

const NOTE: ItemRow = {
  uuid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  content_type: "Note",
  updated_at: 2,
  deleted: 0,
  title: "Release tokens",
  content: JSON.stringify({
    title: "Release tokens",
    text: "release credentials\nGITHUB_TOKEN=ghs_secret123\nFORGEJO_TOKEN=fj_secret456\n",
  }),
};

const SECRETS: SessionSecrets = {
  accountEmail: "me@example.com",
  refreshToken: "refresh-1",
  accessToken: "access-1",
  accessExpirationMs: 1_700_000_000_000,
  refreshExpirationMs: 1_800_000_000_000,
  accessCookie: "",
  refreshCookie: "",
  dbKey: "ab".repeat(32),
};

/** Synthetic cache under a temp SNS_CONFIG_DIR (the 2026-11-13 lesson). */
async function withSinkCache(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "sns-sink-"));
  try {
    await withConfigDir(dir, async () => {
      ensureConfigDir();
      await saveSession(SECRETS);
      const db = openDatabase(dbPath(), SECRETS.dbKey);
      upsertItems(db, [NOTE]);
      db.close();
      await fn(dir);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("sink writes the exact value at 0600, creates 0700 parents, and never echoes it", async () => {
  await withSinkCache(async (dir) => {
    const path = join(dir, "handoff", "github-token");
    const out = outputSpy();
    try {
      await sinkCommand("Release tokens", "GITHUB_TOKEN", path);
      expect(readFileSync(path, "utf8")).toBe("ghs_secret123");
      expect(statSync(path).mode & 0o777).toBe(0o600);
      expect(statSync(dirname(path)).mode & 0o777).toBe(0o700);
      expect(out.text()).toContain("wrote GITHUB_TOKEN (13 bytes)");
      expect(out.text()).toContain(path);
      expect(out.text()).not.toContain("ghs_secret123");
    } finally {
      out.restore();
    }
  });
});

test("sink refuses an existing file without --force and overwrites it 0600 with --force", async () => {
  await withSinkCache(async (dir) => {
    const path = join(dir, "tok");
    writeFileSync(path, "stale-value", { mode: 0o644 });
    await expect(sinkCommand("Release tokens", "GITHUB_TOKEN", path)).rejects.toThrow(/already exists.*--force/s);
    expect(readFileSync(path, "utf8")).toBe("stale-value");

    await sinkCommand("Release tokens", "GITHUB_TOKEN", path, { force: true });
    expect(readFileSync(path, "utf8")).toBe("ghs_secret123");
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });
});

test("sink refuses to write through a symlink", async () => {
  await withSinkCache(async (dir) => {
    const target = join(dir, "real-target");
    writeFileSync(target, "untouched", { mode: 0o600 });
    const link = join(dir, "tok-link");
    symlinkSync(target, link);
    await expect(sinkCommand("Release tokens", "GITHUB_TOKEN", link)).rejects.toThrow(/symlink/);
    expect(readFileSync(target, "utf8")).toBe("untouched");
    expect(existsSync(link)).toBe(true);
  });
});

test("a wrong key names the note's keys and writes nothing", async () => {
  await withSinkCache(async (dir) => {
    const path = join(dir, "tok");
    await expect(sinkCommand("Release tokens", "GITHUB_TOK", path)).rejects.toThrow(
      /no setting "GITHUB_TOK".*its keys: GITHUB_TOKEN, FORGEJO_TOKEN/s,
    );
    expect(existsSync(path)).toBe(false);
  });
});

test("an empty setting value still sinks as an empty 0600 file", async () => {
  await withSinkCache(async (dir) => {
    const db = openDatabase(dbPath(), SECRETS.dbKey);
    upsertItems(db, [
      {
        ...NOTE,
        uuid: "11111111-2222-3333-4444-555555555555",
        title: "Empty value",
        content: JSON.stringify({ title: "Empty value", text: "EMPTY_KEY=\n" }),
      },
    ]);
    db.close();
    const path = join(dir, "empty");
    await sinkCommand("Empty value", "EMPTY_KEY", path);
    expect(readFileSync(path, "utf8")).toBe("");
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });
});

test("the disk-backed warning walks up to an existing ancestor (new handoff dirs included)", async () => {
  await withSinkCache(async (dir) => {
    // /tmp on this VM is tmpfs in some setups and disk-backed in others; the
    // contract under test is that a MISSING directory does not silence the
    // warning — the verdict must match the existing ancestor's.
    const missing = join(dir, "new", "deep", "tok");
    const existing = join(dir, "tok");
    const { diskBackedWarning } = await import("./sink.ts");
    expect(diskBackedWarning(missing)).toBe(diskBackedWarning(existing));
  });
});

test("writeSecretFile removes a partial file when the write fails midway", () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-sinkw-"));
  try {
    const path = join(dir, "tok");
    const failingWrite = () => {
      throw new Error("simulated ENOSPC");
    };
    expect(() => writeSecretFile("ghs_secret123", path, {}, failingWrite)).toThrow(/simulated ENOSPC/);
    expect(existsSync(path)).toBe(false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
