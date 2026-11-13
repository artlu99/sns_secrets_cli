import { expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { countItems, openDatabase } from "./db.ts";
import { listNotes, noteBody, resolveNote, searchNotes } from "./notes.ts";
import { canonicalJson, encrypt004 } from "./sn-crypto/004.ts";
import type { EncryptedItem } from "./sn-crypto/004.ts";
import { runSync, toUnixMs } from "./sync-engine.ts";
import type { SyncPage } from "./sn-api.ts";

function hex(): string {
  return randomBytes(32).toString("hex");
}

async function sealed(plaintext: string, key: string, aad: Record<string, unknown>): Promise<string> {
  return encrypt004(plaintext, key, aad);
}

async function fixture(): Promise<{ master: string; itemsKey: string; items: EncryptedItem[]; noteId: string }> {
  const master = hex();
  const itemsKey = hex();
  const itemsKeyId = crypto.randomUUID();
  const noteId = crypto.randomUUID();
  const wrap = hex();
  const noteKey = hex();
  const itemsAad = { u: itemsKeyId, v: "004" };
  const noteAad = { u: noteId, v: "004" };
  const items: EncryptedItem[] = [
    {
      uuid: itemsKeyId,
      content_type: "SN|ItemsKey",
      updated_at_timestamp: 1_000,
      enc_item_key: await sealed(wrap, master, itemsAad),
      content: await sealed(canonicalJson({ itemsKey, version: "004" }), wrap, itemsAad),
    },
    {
      uuid: noteId,
      content_type: "Note",
      items_key_id: itemsKeyId,
      updated_at_timestamp: 2_000,
      enc_item_key: await sealed(noteKey, itemsKey, noteAad),
      content: await sealed(JSON.stringify({ title: "Pins", text: "door code 2468" }), noteKey, noteAad),
    },
    {
      uuid: crypto.randomUUID(),
      content_type: "SN|UserPreferences",
      updated_at_timestamp: 3_000,
      content: "not-a-note",
    },
    {
      uuid: crypto.randomUUID(),
      content_type: "SN|File",
      updated_at_timestamp: 4_000,
      content: "not-a-note",
    },
  ];
  return { master, itemsKey, items, noteId };
}

test("server timestamps in microseconds become unix milliseconds", () => {
  expect(toUnixMs(1_794_530_346_281_266)).toBe(1_794_530_346_281);
  expect(toUnixMs(1_794_530_346_281)).toBe(1_794_530_346_281);
  expect(toUnixMs(1_794_530_346)).toBe(1_794_530_346_000);
});

test("sync writes decrypted notes, then an incremental pull is empty", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-sync-"));
  const { master, items, noteId } = await fixture();
  const db = openDatabase(join(dir, "cache.db"), hex());
  let calls = 0;
  try {
    const pages: SyncPage[] = [
      { items, syncToken: "sync-1", cursorToken: "cursor-1", conflicts: 1 },
      {
        items: [],
        syncToken: "sync-1",
        cursorToken: null,
        conflicts: 0,
      },
    ];
    const first = await runSync({
      db,
      masterKey: master,
      ensureMasterKey: async () => {
        throw new Error("should already have the master key");
      },
      fetchPage: async (syncToken, cursor) => {
        calls += 1;
        if (calls === 1) {
          expect(syncToken).toBeNull();
          expect(cursor).toBeNull();
        }
        if (calls === 2) expect(cursor).toBe("cursor-1");
        return pages[calls - 1] ?? pages[1]!;
      },
    });
    expect(first.upserted).toBe(2);
    expect(first.conflicts).toBe(1);
    expect(countItems(db)).toBe(2);
    const note = resolveNote(db, "Pins");
    expect(note.uuid).toBe(noteId);
    expect(noteBody(note).body).toBe("door code 2468");
    expect(listNotes(db, { limit: 10 }).map((row) => row.title)).toEqual(["Pins"]);
    expect(searchNotes(db, "2468", { limit: 10 })[0]?.snippet).toContain("2468");

    const second = await runSync({
      db,
      masterKey: master,
      ensureMasterKey: async () => master,
      fetchPage: async (syncToken) => {
        expect(syncToken).toBe("sync-1");
        return { items: [], syncToken: "sync-1", cursorToken: null, conflicts: 0 };
      },
    });
    expect(second.upserted).toBe(0);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a failed page does not advance the sync token", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-sync-crash-"));
  const { master, items } = await fixture();
  const db = openDatabase(join(dir, "cache.db"), hex());
  let calls = 0;
  try {
    await expect(
      runSync({
        db,
        masterKey: master,
        ensureMasterKey: async () => master,
        fetchPage: async () => {
          calls += 1;
          if (calls === 1) return { items: [items[0]!], syncToken: "sync-1", cursorToken: "more", conflicts: 0 };
          throw new Error("killed");
        },
      }),
    ).rejects.toThrow(/killed/);
    expect(countItems(db)).toBe(1);
    const row = db.prepare("SELECT sync_token FROM sync_state WHERE id = 1").get() as { sync_token: string } | undefined;
    expect(row).toBeUndefined();
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("missing master key is requested once", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-sync-pw-"));
  const { master, items } = await fixture();
  const db = openDatabase(join(dir, "cache.db"), hex());
  let prompts = 0;
  try {
    await runSync({
      db,
      masterKey: null,
      ensureMasterKey: async () => {
        prompts += 1;
        return master;
      },
      fetchPage: async () => ({ items, syncToken: "sync-1", cursorToken: null, conflicts: 0 }),
    });
    expect(prompts).toBe(1);
    expect(listNotes(db, { limit: 5 })).toHaveLength(1);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
