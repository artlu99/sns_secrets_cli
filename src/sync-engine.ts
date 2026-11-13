import { UserError } from "./errors.ts";
import type { CacheDb, ItemRow } from "./db.ts";
import { readSyncState, upsertItems, writeSyncState } from "./db.ts";
import { HIDDEN_TYPES } from "./notes.ts";
import {
  decryptItemContent,
  isItemsKey,
  itemsKeyFromContent,
  type EncryptedItem,
} from "./sn-crypto/004.ts";
import type { SyncPage } from "./sn-api.ts";

export type SyncReport = {
  upserted: number;
  skipped: number;
  conflicts: number;
  pages: number;
};

/** Notes are what we show. Items keys stay so later syncs can decrypt without the password. */
export function isStoredType(contentType: string): boolean {
  return contentType === "Note" || contentType === "SN|ItemsKey";
}

export function dropUnstoredTypes(db: CacheDb): void {
  db.prepare("DELETE FROM items WHERE content_type NOT IN ('Note', 'SN|ItemsKey')").run();
}

export function updatedAtMs(item: EncryptedItem): number {
  const stamp = item.updated_at_timestamp;
  if (typeof stamp === "number" && stamp > 0) return toUnixMs(stamp);
  if (typeof item.updated_at === "number" && item.updated_at > 0) return toUnixMs(item.updated_at);
  if (typeof item.updated_at === "string") {
    const parsed = Date.parse(item.updated_at);
    if (!Number.isNaN(parsed)) return parsed;
  }
  return 0;
}

/** Seconds, milliseconds, or microseconds (what the hosted API sends) → milliseconds. */
export function toUnixMs(value: number): number {
  if (value < 1e11) return Math.round(value * 1000);
  if (value < 1e14) return Math.round(value);
  return Math.round(value / 1000);
}

function titleFromContent(contentType: string, content: string): string | null {
  if (HIDDEN_TYPES.has(contentType)) return null;
  try {
    const parsed = JSON.parse(content) as { title?: unknown; name?: unknown };
    if (typeof parsed.title === "string" && parsed.title !== "") return parsed.title;
    if (typeof parsed.name === "string" && parsed.name !== "") return parsed.name;
  } catch {
    return null;
  }
  return null;
}

function tombstone(item: EncryptedItem): ItemRow {
  return {
    uuid: item.uuid,
    content_type: item.content_type,
    updated_at: updatedAtMs(item),
    deleted: 1,
    title: null,
    content: "{}",
  };
}

export function loadItemsKeys(db: CacheDb): Map<string, string> {
  const rows = db
    .prepare("SELECT uuid, content FROM items WHERE content_type = 'SN|ItemsKey' AND deleted = 0")
    .all() as Array<{ uuid: string; content: string }>;
  const keys = new Map<string, string>();
  for (const row of rows) {
    const key = itemsKeyFromContent(row.content);
    if (key) keys.set(row.uuid, key);
  }
  return keys;
}

async function decryptOne(
  item: EncryptedItem,
  itemsKeys: Map<string, string>,
  masterKey: string | null,
): Promise<ItemRow | "need-master" | "skip"> {
  if (item.deleted) return tombstone(item);
  if (isItemsKey(item)) {
    if (!masterKey) return "need-master";
    const content = await decryptItemContent(item, masterKey);
    const itemsKey = itemsKeyFromContent(content);
    if (itemsKey) itemsKeys.set(item.uuid, itemsKey);
    return {
      uuid: item.uuid,
      content_type: item.content_type,
      updated_at: updatedAtMs(item),
      deleted: 0,
      title: null,
      content,
    };
  }
  const parent = item.items_key_id ? itemsKeys.get(item.items_key_id) : undefined;
  if (!parent) return "skip";
  const content = await decryptItemContent(item, parent);
  return {
    uuid: item.uuid,
    content_type: item.content_type,
    updated_at: updatedAtMs(item),
    deleted: 0,
    title: titleFromContent(item.content_type, content),
    content,
  };
}

/**
 * Pull every cursor page, decrypt, and commit each page before the next.
 * The sync token is written only after the cursor is exhausted, so a crash
 * mid-sync retries the same token and upserts already-written rows.
 */
export async function runSync(options: {
  db: CacheDb;
  fetchPage: (syncToken: string | null, cursorToken: string | null) => Promise<SyncPage>;
  masterKey: string | null;
  ensureMasterKey: () => Promise<string>;
}): Promise<SyncReport> {
  const itemsKeys = loadItemsKeys(options.db);
  dropUnstoredTypes(options.db);
  let masterKey = options.masterKey;
  let prompted = options.masterKey !== null;
  const state = readSyncState(options.db);
  let syncToken = state.syncToken;
  let cursor: string | null = null;
  let newestToken = state.syncToken;
  const deferred: EncryptedItem[] = [];
  const report: SyncReport = { upserted: 0, skipped: 0, conflicts: 0, pages: 0 };

  const ensureMaster = async (): Promise<string> => {
    if (masterKey) return masterKey;
    if (prompted) throw new UserError("that password did not unwrap item keys");
    prompted = true;
    masterKey = await options.ensureMasterKey();
    return masterKey;
  };

  const consume = async (items: EncryptedItem[]): Promise<ItemRow[]> => {
    const rows: ItemRow[] = [];
    const ordered = [...items.filter((item) => isItemsKey(item)), ...items.filter((item) => !isItemsKey(item))];
    for (const item of ordered) {
      if (!item.uuid) continue;
      if (!isStoredType(item.content_type)) continue;
      try {
        let result = await decryptOne(item, itemsKeys, masterKey);
        if (result === "need-master") {
          await ensureMaster();
          result = await decryptOne(item, itemsKeys, masterKey);
        }
        if (result === "need-master" || result === "skip") {
          if (result === "need-master") throw new UserError("that password did not unwrap item keys");
          if (!item.deleted && item.items_key_id && !itemsKeys.has(item.items_key_id)) deferred.push(item);
          else report.skipped += 1;
          continue;
        }
        rows.push(result);
      } catch (error) {
        if (error instanceof UserError) throw error;
        if (isItemsKey(item)) throw new UserError("that password did not unwrap item keys");
        report.skipped += 1;
      }
    }
    return rows;
  };

  do {
    const page = await options.fetchPage(syncToken, cursor);
    report.pages += 1;
    report.conflicts += page.conflicts;
    if (page.syncToken) newestToken = page.syncToken;
    const rows = await consume(page.items);
    if (rows.length > 0) {
      upsertItems(options.db, rows);
      report.upserted += rows.length;
    }
    cursor = page.cursorToken;
  } while (cursor);

  if (deferred.length > 0) {
    const rows: ItemRow[] = [];
    for (const item of deferred) {
      const result = await decryptOne(item, itemsKeys, masterKey);
      if (result === "skip" || result === "need-master") {
        report.skipped += 1;
        continue;
      }
      rows.push(result);
    }
    if (rows.length > 0) {
      upsertItems(options.db, rows);
      report.upserted += rows.length;
    }
  }

  writeSyncState(options.db, newestToken, Date.now());
  return report;
}
