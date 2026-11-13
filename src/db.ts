import Sqlite from "better-sqlite3-multiple-ciphers";
import { existsSync, rmSync } from "node:fs";
import { UserError } from "./errors.ts";

export type CacheDb = InstanceType<typeof Sqlite>;

export type ItemRow = {
  uuid: string;
  content_type: string;
  updated_at: number;
  deleted: number;
  title: string | null;
  content: string;
};

const SCHEMA = `
CREATE TABLE IF NOT EXISTS items (
  uuid         TEXT PRIMARY KEY,
  content_type TEXT NOT NULL,
  updated_at   INTEGER NOT NULL,
  deleted      INTEGER NOT NULL DEFAULT 0,
  title        TEXT,
  content      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_items_type    ON items(content_type);
CREATE INDEX IF NOT EXISTS idx_items_updated ON items(updated_at);
CREATE TABLE IF NOT EXISTS sync_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  sync_token TEXT,
  last_sync INTEGER
);
`;

const MIGRATIONS: Array<{ name: string; sql: string }> = [
  {
    name: "sync_state.stored_types",
    sql: "ALTER TABLE sync_state ADD COLUMN stored_types TEXT",
  },
];

/**
 * True only for "this file is not a database we can read" — a wrong key or a
 * corrupt file (SQLITE_NOTADB). Busy and I/O errors must NOT match: they are
 * transient, and callers treat wrong-key as permission to delete the cache.
 */
export function isWrongKeyDatabase(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  if ((error as { code?: unknown }).code === "SQLITE_NOTADB") return true;
  return /file is not a database|unsupported file format/i.test(error.message);
}

export function openDatabase(path: string, dbKey: string): CacheDb {
  if (!/^[0-9a-fA-F]{64}$/.test(dbKey)) {
    throw new UserError("database key must be 64 hex characters");
  }
  const db = new Sqlite(path, { timeout: 5000 });
  try {
    db.pragma("cipher = 'chacha20'");
    db.pragma(`key = '${dbKey}'`);
    db.pragma("cipher_memory_security = ON");
    db.pragma("busy_timeout = 5000");
    db.prepare("SELECT count(*) AS n FROM sqlite_master").get();
    db.exec(SCHEMA);
    for (const migration of MIGRATIONS) {
      const [table, column] = migration.name.split(".");
      const columns = db.prepare("SELECT name FROM pragma_table_info(?)").all(table) as Array<{
        name: string;
      }>;
      if (columns.some((existing) => existing.name === column)) continue;
      db.exec(migration.sql);
    }
  } catch (error) {
    db.close();
    if (error instanceof UserError) throw error;
    if (isWrongKeyDatabase(error)) {
      throw new UserError("could not open cache.db with the stored database key");
    }
    throw error;
  }
  return db;
}

export function removeCacheFiles(path: string): void {
  rmSync(path, { force: true });
  for (const suffix of ["-journal", "-wal", "-shm"]) rmSync(`${path}${suffix}`, { force: true });
}

/**
 * Open the cache. A file left behind by logout is encrypted with a deleted key.
 * That file cannot be read, so replace it with an empty database for the current key.
 */
export function openDatabaseOrReplace(path: string, dbKey: string): { db: CacheDb; replaced: boolean } {
  const existed = existsSync(path);
  try {
    return { db: openDatabase(path, dbKey), replaced: false };
  } catch (error) {
    if (!existed || !(error instanceof UserError) || !error.message.includes("could not open cache.db")) throw error;
    removeCacheFiles(path);
    return { db: openDatabase(path, dbKey), replaced: true };
  }
}

export type SyncState = {
  syncToken: string | null;
  lastSync: number | null;
  storedTypes: string | null;
};

export function readSyncState(db: CacheDb): SyncState {
  const row = db
    .prepare("SELECT sync_token, last_sync, stored_types FROM sync_state WHERE id = 1")
    .get() as { sync_token: string | null; last_sync: number | null; stored_types: string | null } | undefined;
  if (!row) return { syncToken: null, lastSync: null, storedTypes: null };
  return { syncToken: row.sync_token, lastSync: row.last_sync, storedTypes: row.stored_types };
}

export function writeSyncState(
  db: CacheDb,
  syncToken: string | null,
  lastSync: number,
  storedTypes: string | null,
): void {
  db.prepare(
    `INSERT INTO sync_state (id, sync_token, last_sync, stored_types) VALUES (1, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET
       sync_token = excluded.sync_token, last_sync = excluded.last_sync, stored_types = excluded.stored_types`,
  ).run(syncToken, lastSync, storedTypes);
}

export function upsertItems(db: CacheDb, rows: ItemRow[]): void {
  const stmt = db.prepare(
    `INSERT INTO items (uuid, content_type, updated_at, deleted, title, content)
     VALUES (@uuid, @content_type, @updated_at, @deleted, @title, @content)
     ON CONFLICT(uuid) DO UPDATE SET
       content_type = excluded.content_type,
       updated_at = excluded.updated_at,
       deleted = excluded.deleted,
       title = excluded.title,
       content = excluded.content
     WHERE excluded.updated_at >= items.updated_at`,
  );
  const write = db.transaction((items: ItemRow[]) => {
    for (const item of items) stmt.run(item);
  });
  write(rows);
}

export function countItems(db: CacheDb): number {
  const row = db.prepare("SELECT count(*) AS n FROM items").get() as { n: number };
  return row.n;
}

export function sqliteMasterCount(db: CacheDb): number {
  const row = db.prepare("SELECT count(*) AS n FROM sqlite_master").get() as { n: number };
  return row.n;
}
