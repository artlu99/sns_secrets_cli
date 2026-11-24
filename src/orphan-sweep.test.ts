import { expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  isOwnedConfigFileName,
  isOwnedSessionFileName,
  keysPath,
  sessionPath,
  unexpectedConfigFiles,
  withConfigDir,
  ensureConfigDir,
} from "./paths.ts";
import { deleteSession, keyDecryptsSession, loadSession, saveSession, type SessionSecrets } from "./session-file.ts";
import { purgeCommand } from "./commands/purge.ts";
import { warnIfKeychainItemSurvived } from "./keychain.ts";
import { openDatabase, upsertItems } from "./db.ts";
import { completeArgv } from "./completion.ts";
import { sanitizeUuid } from "./notes.ts";
import { outputSpy } from "./test-output.ts";

// A test must never touch the developer's real keychain entry.
process.env.SNS_DISABLE_KEYCHAIN ??= "1";

function secrets(): SessionSecrets {
  return {
    accountEmail: "me@example.com",
    refreshToken: "refresh-1",
    accessToken: "access-1",
    accessExpirationMs: 1,
    refreshExpirationMs: 2,
    accessCookie: "cookie-a",
    refreshCookie: "cookie-b",
    dbKey: "ab".repeat(32),
  };
}

test("owned-file predicates cover the exact names and the crash-orphan temp spellings", () => {
  for (const owned of [
    ".env.session",
    ".env.keys",
    ".env.session.GhK1a2", // write-file-atomic hash suffix
    ".env.keys.tmp-123-abc", // writePrivateFileSync orphan
    "cache.db",
    "cache.db-journal",
    "sync.lock",
    "clipboard-clear-at",
    ".env",
  ]) {
    expect(isOwnedConfigFileName(owned)).toBe(true);
  }
  expect(isOwnedSessionFileName(".env.session.19048")).toBe(true);
  expect(isOwnedSessionFileName(".env.keys.tmp-99-zz1")).toBe(true);
  for (const foreign of [".env.session.bak.old", "operator-notes.txt", ".envrc", "cache.db.backup", "other.env.keys.x"]) {
    expect(isOwnedConfigFileName(foreign)).toBe(false);
  }
  // A mid-name match is not owned: only the `.env.<name>.` prefix shape is.
  expect(isOwnedSessionFileName("x.env.keys.tmp-1-a")).toBe(false);
});

test("doctor's unexpected-files check treats orphan temps as owned, foreign files as unexpected", () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-owned-"));
  try {
    withConfigDir(dir, () => {
      ensureConfigDir();
      writeFileSync(join(dir, ".env.keys.tmp-77-xyz"), "orphan", { mode: 0o600 });
      writeFileSync(join(dir, ".env.session.Hh41bz"), "orphan", { mode: 0o600 });
      writeFileSync(join(dir, "operator-notes.txt"), "mine");
      expect(unexpectedConfigFiles()).toEqual(["operator-notes.txt"]);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deleteSession sweeps crash-orphan temps and a planted symlink, keeps foreign files", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-delsess-"));
  try {
    await withConfigDir(dir, async () => {
      ensureConfigDir();
      await saveSession(secrets());
      expect(existsSync(sessionPath())).toBe(true);
      writeFileSync(join(dir, ".env.keys.tmp-4242-orphan"), "plaintext key", { mode: 0o600 });
      writeFileSync(join(dir, "keep-me.txt"), "foreign");
      await deleteSession();
      expect(existsSync(sessionPath())).toBe(false);
      expect(existsSync(keysPath())).toBe(false);
      expect(existsSync(join(dir, ".env.keys.tmp-4242-orphan"))).toBe(false);
      expect(existsSync(join(dir, "keep-me.txt"))).toBe(true);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("deleteSession removes a symlink planted at .env.session itself, never through it", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-dellink-"));
  const target = join(dir, "innocent-target.txt");
  try {
    await withConfigDir(dir, async () => {
      ensureConfigDir();
      writeFileSync(target, "do not delete me");
      symlinkSync(target, sessionPath());
      await deleteSession();
      expect(existsSync(sessionPath())).toBe(false);
      expect(readFileSync(target, "utf8")).toBe("do not delete me");
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("purge sweeps orphan temps and planted symlinks with the exact names, still lists foreign files", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-purgeorphan-"));
  const out = outputSpy();
  try {
    await withConfigDir(dir, async () => {
      ensureConfigDir();
      writeFileSync(join(dir, ".env.keys.tmp-31-orphan"), "plaintext key", { mode: 0o600 });
      symlinkSync(join(dir, ".env"), join(dir, ".env.session"));
      writeFileSync(join(dir, "operator-notes.txt"), "mine");
      await purgeCommand({ yes: true });
    });
    expect(existsSync(join(dir, ".env.keys.tmp-31-orphan"))).toBe(false);
    expect(existsSync(join(dir, ".env.session"))).toBe(false);
    expect(out.text()).toContain("purged 3 file(s)"); // .env + symlinked .env.session + orphan temp
    expect(out.text()).toContain("operator-notes.txt");
    expect(existsSync(join(dir, "operator-notes.txt"))).toBe(true);
  } finally {
    out.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("keyDecryptsSession says true only for a key that opens the session", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-decrypt-"));
  try {
    await withConfigDir(dir, async () => {
      ensureConfigDir();
      await saveSession(secrets());
      const goodKey = readFileSync(keysPath(), "utf8").match(/DOTENV_PRIVATE_KEY_SESSION=(\S+)/)?.[1] ?? "";
      expect(keyDecryptsSession(goodKey)).toBe(true);
      // 64 hex chars of the wrong key: dotenvx hands back raw `encrypted:`
      // strings (or throws) — either way the answer must be false, without
      // leaking the ☠ noise lines on stderr.
      expect(keyDecryptsSession("00".repeat(32))).toBe(false);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("saveSession refuses to write over a session no available key opens", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-brickguard-"));
  try {
    await withConfigDir(dir, async () => {
      ensureConfigDir();
      await saveSession(secrets());
      // Custody loss: the keychain is disabled (no key there) and .env.keys
      // is gone — the session file is now encrypted to an orphaned key.
      rmSync(keysPath(), { force: true });
      const out = outputSpy();
      try {
        await expect(saveSession({ ...secrets(), refreshToken: "refresh-2" })).rejects.toThrow(
          /run `sns logout` to delete it/,
        );
      } finally {
        out.restore();
      }
      // The unreadable file was not silently replaced with a fresh one.
      expect(loadSession()).rejects.toThrow();
      expect(existsSync(sessionPath())).toBe(true);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("sanitizeUuid strips the newline and escape bytes sanitizeText keeps for prose", () => {
  expect(sanitizeUuid("\x1b]0;pwned\x07ab\x1b[31mcd\x1b[0m")).toBe("abcd");
  expect(sanitizeUuid("12\n34\t56")).toBe("123456");
  expect(sanitizeUuid("aaaaaaaa-1111-2222-3333-444444444444")).toBe("aaaaaaaa-1111-2222-3333-444444444444");
});

test("completion never offers a poisoned uuid prefix as a candidate", () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-complpoison-"));
  try {
    const path = join(dir, "cache.db");
    const db = openDatabase(path, "cd".repeat(32));
    upsertItems(db, [
      {
        uuid: "ab\ncd1234", // control char inside the 8-char prefix
        content_type: "Note",
        updated_at: 5,
        deleted: 0,
        title: "Poisoned",
        content: JSON.stringify({ title: "Poisoned", text: "x" }),
      },
      {
        uuid: "aaaaaaaa-1111-2222-3333-444444444444",
        content_type: "Note",
        updated_at: 6,
        deleted: 0,
        title: "Healthy",
        content: JSON.stringify({ title: "Healthy", text: "x" }),
      },
    ]);
    const candidates = completeArgv(["sns", "show", ""], 2, db);
    expect(candidates).toContain("Healthy");
    expect(candidates).toContain("aaaaaaaa");
    // The poisoned uuid is never offered — whole, sliced, or stripped.
    expect(candidates.some((candidate) => candidate.includes("\n"))).toBe(false);
    expect(candidates).not.toContain("abcd123");
    db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the keychain-survival warning is silent for file custody on a service-less machine", () => {
  const out = outputSpy();
  try {
    // Custody was the .env.keys file (it existed at delete time): the
    // keychain never held this key, so "unavailable" is expected silence.
    warnIfKeychainItemSurvived("unavailable", { fileCustody: true });
    expect(out.text()).not.toContain("keychain item could not be confirmed deleted");
    // Without file custody the warning fires.
    warnIfKeychainItemSurvived("unavailable", {});
    expect(out.text()).toContain("no secret service answered");
    expect(out.text()).toContain("secret-tool clear service sn_secrets_cli account dotenvkey");
    // A failed delete always warns, file custody or not.
    warnIfKeychainItemSurvived("unconfirmed", { fileCustody: true });
    expect(out.text()).toContain("the delete command failed");
  } finally {
    out.restore();
  }
});
