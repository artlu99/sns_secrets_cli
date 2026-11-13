import { existsSync } from "node:fs";
import { UserError } from "../errors.ts";
import { openDatabase, type CacheDb } from "../db.ts";
import { listNotes, PROSE_TYPES, renderTagGroups, resolveTag, tagGraph, taggedNoteUuids } from "../notes.ts";
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
    // one graph for resolution, filtering, and rendering
    const graph = tagGraph(db);
    const tag = options.tag ? resolveTag(graph, options.tag) : undefined;
    const tagUuids = tag ? taggedNoteUuids(graph, tag.uuid) : undefined;
    // the default view is the secrets view: only notes whose prose carries
    // env-style settings; --all and explicit non-prose type selectors escape it
    const env = !options.all && (!options.type || PROSE_TYPES.has(options.type));
    const notes = listNotes(db, { type: options.type, limit, all: options.all, tagUuids, env });
    if (notes.length === 0) {
      const bare = !options.tag && !options.type;
      const where = options.tag
        ? `under tag ${JSON.stringify(options.tag)}`
        : options.type
          ? `of type ${options.type}`
          : "in the cache";
      const label = env ? "no notes with env-style values" : "no notes";
      const hint = env ? " — see everything with sns list --all" : bare ? " — run sns sync" : "";
      console.log(`${label} ${where}${hint}`);
      return;
    }
    const table = renderTagGroups(graph, notes);
    const rows = table.split("\n").length;
    const screen = process.stdout.rows ?? 24;
    if (process.stdout.isTTY && rows > screen - 1) await page(table);
    else console.log(table);
  } finally {
    db.close();
  }
}
