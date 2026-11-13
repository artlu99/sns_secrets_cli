import { existsSync } from "node:fs";
import { UserError } from "../errors.ts";
import { openDatabase, type CacheDb } from "../db.ts";
import { listNotes, renderTagGroups, resolveTag, taggedNoteUuids } from "../notes.ts";
import { dbPath } from "../paths.ts";
import { loadSession } from "../session-file.ts";
import { page } from "../pager.ts";

export async function openCache(): Promise<CacheDb> {
  const secrets = await loadSession();
  if (!secrets) throw new UserError("not logged in — run sns login");
  if (!existsSync(dbPath())) throw new UserError("no cache yet — run sns sync");
  return openDatabase(dbPath(), secrets.dbKey);
}

export async function listCommand(options: {
  type?: string;
  tag?: string;
  limit?: string;
  all?: boolean;
}): Promise<void> {
  const limit = Number(options.limit ?? "100");
  if (!Number.isInteger(limit) || limit < 1) throw new UserError("--limit must be a positive integer");
  const db = await openCache();
  try {
    const tagUuids = options.tag ? taggedNoteUuids(db, resolveTag(db, options.tag).uuid) : undefined;
    const notes = listNotes(db, { type: options.type, limit, all: options.all, tagUuids });
    if (notes.length === 0) {
      if (options.tag) console.log(`no notes under tag ${JSON.stringify(options.tag)}`);
      else if (options.type) console.log(`no notes of type ${options.type}`);
      else console.log("no notes in the cache — run sns sync");
      return;
    }
    const table = renderTagGroups(db, notes);
    const rows = table.split("\n").length;
    const screen = process.stdout.rows ?? 24;
    if (process.stdout.isTTY && rows > screen - 1) await page(table);
    else console.log(table);
  } finally {
    db.close();
  }
}
