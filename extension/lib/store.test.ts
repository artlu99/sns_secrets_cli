import { describe, expect, test } from "bun:test";
import { encrypt004 } from "./crypto.ts";
import {
  runSync,
  STORED_TYPES_VERSION,
  storedTypesMarker,
  type ItemRow,
} from "./store.ts";
import type { SyncPage } from "./sn-api.ts";

const MASTER_KEY = "aa".repeat(32);
const ITEMS_KEY_A = "bb".repeat(32);
const ITEMS_KEY_B = "cc".repeat(32);

/** Deterministic 64-hex note item key derived from the note's uuid. */
function noteItemKey(uuid: string): string {
  return new Bun.CryptoHasher("sha256").update(uuid).digest("hex");
}

/**
 * 004 scheme: enc_item_key's plaintext IS the raw 64-hex key (no JSON
 * wrapper); the JSON `{itemsKey}` document lives in content, encrypted under
 * that key. Items keys wrap their enc_item_key with the master key; notes
 * wrap theirs with the items key named by items_key_id.
 */
async function itemsKeyItem(uuid: string, key: string) {
  return {
    uuid,
    content_type: "SN|ItemsKey",
    items_key_id: null,
    enc_item_key: await encrypt004(key, MASTER_KEY, { u: uuid, v: "SN|ItemsKey" }),
    content: await encrypt004(JSON.stringify({ itemsKey: key }), key, { u: uuid, v: "SN|ItemsKey" }),
    updated_at_timestamp: 1_700_000_000_000,
  };
}

async function noteItem(uuid: string, text: string, keyId: string, key: string) {
  const itemKey = noteItemKey(uuid);
  return {
    uuid,
    content_type: "Note",
    items_key_id: keyId,
    enc_item_key: await encrypt004(itemKey, key, { u: uuid, v: "Note" }),
    content: await encrypt004(JSON.stringify({ title: `t-${uuid}`, text }), itemKey, { u: uuid, v: "Note" }),
    updated_at_timestamp: 1_700_000_000_000,
  };
}

function page(items: unknown[], syncToken: string | null, cursorToken: string | null = null): SyncPage {
  return { items: items as SyncPage["items"], syncToken, cursorToken, conflicts: 0 };
}

function rowOf(uuid: string, rows: Map<string, ItemRow>): ItemRow {
  const row = rows.get(uuid);
  if (!row) throw new Error(`missing row ${uuid}`);
  return row;
}

describe("runSync", () => {
  test("decrypts items keys first, then notes under them", async () => {
    const items = new Map<string, ItemRow>();
    const fetchCalls: Array<string | null> = [];
    const report = await runSync({
      items,
      syncToken: null,
      storedTypes: storedTypesMarker(null),
      fetchPage: async (syncToken) => {
        fetchCalls.push(syncToken);
        return page(
          [await itemsKeyItem("key-a", ITEMS_KEY_A), await noteItem("note-1", "A=1", "key-a", ITEMS_KEY_A)],
          "tok-1",
        );
      },
      masterKey: MASTER_KEY,
    });
    expect(report.upserted).toBe(2);
    expect(report.syncToken).toBe("tok-1");
    const note = rowOf("note-1", items);
    expect(note.title).toBe("t-note-1");
    expect(JSON.parse(note.content).text).toBe("A=1");
  });

  test("defers a note whose items key arrives in a later page", async () => {
    const items = new Map<string, ItemRow>();
    const report = await runSync({
      items,
      syncToken: null,
      storedTypes: storedTypesMarker(null),
      fetchPage: async (_syncToken, cursor) => {
        if (cursor === null) {
          return page([await noteItem("note-2", "B=2", "key-b", ITEMS_KEY_B)], "tok-1", "cursor-1");
        }
        return page([await itemsKeyItem("key-b", ITEMS_KEY_B), await noteItem("note-2", "B=2", "key-b", ITEMS_KEY_B)], "tok-2");
      },
      masterKey: MASTER_KEY,
    });
    // key-b + note-2 (page 2) + note-2 again from the deferred retry — the CLI counts the same way.
    expect(report.upserted).toBe(3);
    expect(rowOf("note-2", items).title).toBe("t-note-2");
  });

  test("tombstones land even with no ciphertext", async () => {
    const items = new Map<string, ItemRow>();
    await runSync({
      items,
      syncToken: null,
      storedTypes: storedTypesMarker(null),
      fetchPage: async () =>
        page([{ uuid: "gone-1", content_type: "Note", deleted: true, updated_at_timestamp: 1_700_000_000_000 }], "tok-1"),
      masterKey: MASTER_KEY,
    });
    expect(rowOf("gone-1", items).deleted).toBe(1);
    expect(rowOf("gone-1", items).content).toBe("{}");
  });

  test("a stored-types mismatch forces a full pull (token dropped)", async () => {
    const items = new Map<string, ItemRow>();
    const fetchCalls: Array<string | null> = [];
    await runSync({
      items,
      syncToken: "stale-token",
      storedTypes: "not-the-current-marker",
      fetchPage: async (syncToken) => {
        fetchCalls.push(syncToken);
        return page([], "fresh-token");
      },
      masterKey: MASTER_KEY,
    });
    expect(fetchCalls[0]).toBeNull(); // incremental token ignored
  });

  test("a matching marker reuses the incremental token", async () => {
    const items = new Map<string, ItemRow>();
    const fetchCalls: Array<string | null> = [];
    await runSync({
      items,
      syncToken: "tok-9",
      storedTypes: storedTypesMarker("tok-9"),
      fetchPage: async (syncToken) => {
        fetchCalls.push(syncToken);
        return page([], "tok-10");
      },
      masterKey: MASTER_KEY,
    });
    expect(fetchCalls[0]).toBe("tok-9");
  });

  test("marker format matches the CLI's stored-type set", () => {
    expect(STORED_TYPES_VERSION).toBe("Note,SN|ItemsKey,Tag");
  });
});
