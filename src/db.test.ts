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
    writeSyncState(db, "token-1", 10, "Note,SN|ItemsKey");
    expect(countItems(db)).toBe(1);
    expect(readSyncState(db).syncToken).toBe("token-1");
    expect(readSyncState(db).storedTypes).toBe("Note,SN|ItemsKey");
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

test("migrations run once and tolerate caches that applied them unrecorded", () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-db-migrate-"));
  const path = join(dir, "cache.db");
  const key = randomBytes(32).toString("hex");
  try {
    const db = openDatabase(path, key);
    // one version step per MIGRATIONS entry
    expect(db.pragma("user_version", { simple: true })).toBe(3);
    db.close();

    // reopen is a no-op: user_version already says every migration ran
    const again = openDatabase(path, key);
    expect(again.pragma("user_version", { simple: true })).toBe(3);
    again.close();

    // a cache from a build that added the column without recording it: the
    // ALTER fails with duplicate column and must not surface as an error
    const legacy = openDatabase(path, key);
    legacy.pragma("user_version = 0");
    legacy.close();
    const migrated = openDatabase(path, key);
    expect(migrated.pragma("user_version", { simple: true })).toBe(3);
    const columns = migrated.prepare("SELECT name FROM pragma_table_info('sync_state')").all() as Array<{
      name: string;
    }>;
    expect(columns.some((column) => column.name === "stored_types")).toBe(true);
    migrated.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the trashed column migrates and backfills caches from older builds", () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-db-trash-migrate-"));
  const path = join(dir, "cache.db");
  const key = randomBytes(32).toString("hex");
  try {
    const db = openDatabase(path, key);
    // rows written by an older build, then rewind the schema to its state
    // before the trashed column existed: the reopen must re-run the real
    // ALTER and backfill trash from the content JSON
    const insert = db.prepare(
      "INSERT INTO items (uuid, content_type, updated_at, deleted, title, content) VALUES (?, 'Note', ?, 0, ?, ?)",
    );
    insert.run("11111111-1111-4111-8111-111111111111", 3_000, "Bin", JSON.stringify({ title: "Bin", trashed: true }));
    insert.run("22222222-2222-4222-8222-222222222222", 2_000, "Kept", JSON.stringify({ title: "Kept", text: "stay" }));
    // trashed:1 is the JSON number, not the boolean — isTrashed says not trash
    insert.run("33333333-3333-4333-8333-333333333333", 1_000, "Numeric", '{"trashed":1}');
    // content that is not JSON at all must not raise mid-backfill
    insert.run("44444444-4444-4444-8444-444444444444", 500, "Broken", "not-json{{{");
    db.exec("ALTER TABLE items DROP COLUMN trashed");
    db.pragma("user_version = 1");
    db.close();

    const migrated = openDatabase(path, key);
    expect(migrated.pragma("user_version", { simple: true })).toBe(3);
    const rows = migrated.prepare("SELECT uuid, trashed FROM items ORDER BY updated_at DESC").all() as Array<{
      uuid: string;
      trashed: number;
    }>;
    expect(rows).toEqual([
      { uuid: "11111111-1111-4111-8111-111111111111", trashed: 1 },
      { uuid: "22222222-2222-4222-8222-222222222222", trashed: 0 },
      { uuid: "33333333-3333-4333-8333-333333333333", trashed: 0 },
      { uuid: "44444444-4444-4444-8444-444444444444", trashed: 0 },
    ]);
    migrated.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("upsertItems derives and maintains the trashed column from content", () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-db-trash-upsert-"));
  const path = join(dir, "cache.db");
  const key = randomBytes(32).toString("hex");
  const uuid = "55555555-5555-4555-8555-555555555555";
  const column = (db: ReturnType<typeof openDatabase>): number =>
    (db.prepare("SELECT trashed AS t FROM items WHERE uuid = ?").get(uuid) as { t: number }).t;
  try {
    const db = openDatabase(path, key);
    upsertItems(db, [
      { uuid, content_type: "Note", updated_at: 1_000, deleted: 0, title: "Bin", content: '{"trashed":true}' },
    ]);
    expect(column(db)).toBe(1);
    // a newer version that left the trash keeps the column current
    upsertItems(db, [
      { uuid, content_type: "Note", updated_at: 2_000, deleted: 0, title: "Back", content: '{"text":"restored"}' },
    ]);
    expect(column(db)).toBe(0);
    // a stale write loses to the WHERE guard and changes nothing
    upsertItems(db, [
      { uuid, content_type: "Note", updated_at: 1_500, deleted: 0, title: "Old", content: '{"trashed":true}' },
    ]);
    expect(column(db)).toBe(0);
    db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
