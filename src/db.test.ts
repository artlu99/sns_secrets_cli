import { expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { countItems, isWrongKeyDatabase, openDatabase, openDatabaseOrReplace, readSyncState, upsertItems, writeSyncState } from "./db.ts";

test("cache is encrypted at rest and rejects the wrong key", () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-db-"));
  const path = join(dir, "cache.db");
  const key = randomBytes(32).toString("hex");
  try {
    const db = openDatabase(path, key);
    upsertItems(db, [
      {
        uuid: crypto.randomUUID(),
        content_type: "Note",
        updated_at: 1,
        deleted: 0,
        title: "Pins",
        content: JSON.stringify({ title: "Pins", text: "plaintext-marker-zebra" }),
      },
    ]);
    writeSyncState(db, "token-1", 10);
    expect(countItems(db)).toBe(1);
    expect(readSyncState(db).syncToken).toBe("token-1");
    db.close();

    const raw = readFileSync(path);
    expect(raw.subarray(0, 16).toString("utf8").startsWith("SQLite format 3")).toBe(false);
    expect(raw.includes(Buffer.from("plaintext-marker-zebra"))).toBe(false);

    expect(() => openDatabase(path, randomBytes(32).toString("hex"))).toThrow(/could not open cache/);
    const again = openDatabase(path, key);
    expect(countItems(again)).toBe(1);
    again.close();

    const replaced = openDatabaseOrReplace(path, randomBytes(32).toString("hex"));
    expect(replaced.replaced).toBe(true);
    expect(countItems(replaced.db)).toBe(0);
    replaced.db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("only not-a-database failures count as wrong key", () => {
  const notadb = Object.assign(new Error("file is not a database"), { code: "SQLITE_NOTADB" });
  const busy = Object.assign(new Error("SQLITE_BUSY: database is locked"), { code: "SQLITE_BUSY" });
  const ioerr = new Error("SQLITE_IOERR: disk I/O error");
  expect(isWrongKeyDatabase(notadb)).toBe(true);
  expect(isWrongKeyDatabase(new Error("file is not a database"))).toBe(true);
  expect(isWrongKeyDatabase(busy)).toBe(false);
  expect(isWrongKeyDatabase(ioerr)).toBe(false);
  expect(isWrongKeyDatabase("not an error object")).toBe(false);
});
