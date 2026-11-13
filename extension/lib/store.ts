/**
 * Port of src/sync-engine.ts over an in-memory item map instead of the
 * encrypted sqlite cache. The algorithm is kept line-for-line where it
 * matters: items keys decrypt first, notes whose key arrives in a later page
 * are deferred and retried, tombstones land even when content is gone, and
 * the sync token is only adopted after the cursor is exhausted. The
 * stored-types marker is kept for parity — if a future version stores more
 * types, the mismatch forces the same full re-pull.
 */
import { UserError } from "../../src/errors.ts";
import { HIDDEN_TYPES } from "../../src/notes.ts";
import { decryptItemContent, isItemsKey, itemsKeyFromContent, type EncryptedItem } from "./crypto.ts";
import type { SyncPage } from "./sn-api.ts";

export type ItemRow = {
  uuid: string;
  content_type: string;
  updated_at: number;
  deleted: number;
  title: string | null;
  content: string;
};

export type SyncReport = {
  upserted: number;
  skipped: number;
  conflicts: number;
  pages: number;
  /** The token to persist; only adopted after the cursor loop finished. */
  syncToken: string | null;
};

const STORED_TYPES = new Set(["Note", "SN|ItemsKey", "Tag"]);

/** Recorded with the token it was written for; a mismatch forces a full pull. */
export const STORED_TYPES_VERSION = [...STORED_TYPES].sort().join(",");

export function isStoredType(contentType: string): boolean {
  return STORED_TYPES.has(contentType);
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

function row(item: EncryptedItem, content: string): ItemRow {
  return {
    uuid: item.uuid,
    content_type: item.content_type,
    updated_at: updatedAtMs(item),
    deleted: 0,
    title: titleFromContent(item.content_type, content),
    content,
  };
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
    return row(item, content);
  }
  const parent = item.items_key_id ? itemsKeys.get(item.items_key_id) : undefined;
  if (!parent) return "skip";
  const content = await decryptItemContent(item, parent);
  return row(item, content);
}

/**
 * Pull every cursor page, decrypt into `options.items`, and commit each page
 * before the next. The sync token is returned (and persisted by the caller)
 * only after the cursor is exhausted, so a crash mid-sync retries the same
 * token and upserts already-written rows.
 */
export async function runSync(options: {
  items: Map<string, ItemRow>;
  syncToken: string | null;
  storedTypes: string;
  fetchPage: (syncToken: string | null, cursorToken: string | null) => Promise<SyncPage>;
  masterKey: string | null;
  ensureMasterKey?: () => Promise<string>;
}): Promise<SyncReport> {
  const itemsKeys = new Map<string, string>();
  for (const rowItem of options.items.values()) {
    if (rowItem.content_type !== "SN|ItemsKey" || rowItem.deleted) continue;
    const key = itemsKeyFromContent(rowItem.content);
    if (key) itemsKeys.set(rowItem.uuid, key);
  }
  let masterKey = options.masterKey;
  let prompted = masterKey !== null;
  const tokenMatchesTypes = options.storedTypes === `${STORED_TYPES_VERSION}|${options.syncToken ?? ""}`;
  let syncToken = tokenMatchesTypes ? options.syncToken : null;
  let cursor: string | null = null;
  let newestToken = syncToken;
  const deferred: EncryptedItem[] = [];
  const report: SyncReport = { upserted: 0, skipped: 0, conflicts: 0, pages: 0, syncToken: null };

  const ensureMaster = async (): Promise<string> => {
    if (masterKey) return masterKey;
    if (prompted) throw new UserError("that password did not unwrap item keys");
    prompted = true;
    const derived = await (options.ensureMasterKey?.() ?? Promise.reject(new UserError("no master key available")));
    masterKey = derived;
    return derived;
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
      for (const entry of rows) options.items.set(entry.uuid, entry);
      report.upserted += rows.length;
    }
    cursor = page.cursorToken;
  } while (cursor);

  if (deferred.length > 0) {
    for (const item of deferred) {
      const result = await decryptOne(item, itemsKeys, masterKey);
      if (result === "skip" || result === "need-master") {
        report.skipped += 1;
        continue;
      }
      options.items.set(result.uuid, result);
      report.upserted += 1;
    }
  }

  report.syncToken = newestToken;
  return report;
}

/** The stored-types marker persisted next to the sync token. */
export function storedTypesMarker(syncToken: string | null): string {
  return `${STORED_TYPES_VERSION}|${syncToken ?? ""}`;
}
