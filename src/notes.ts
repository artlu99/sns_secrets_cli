import type { CacheDb, ItemRow } from "./db.ts";
import { UserError } from "./errors.ts";

/** Key-bearing items are stored for decrypt and never listed. */
export const HIDDEN_TYPES = new Set(["SN|ItemsKey", "SN|KeySystemItemsKey", "SN|KeySystemRootKey"]);

const REDACTED_FIELDS = new Set([
  "itemsKey",
  "items_key",
  "key",
  "enc_item_key",
  "serverPassword",
  "masterKey",
  "privateKey",
]);

export type ListedNote = {
  uuid: string;
  content_type: string;
  updated_at: number;
  title: string;
  trashed: boolean;
  protected: boolean;
};

/** Standard Notes keeps trashed notes in the account with `trashed: true` on the decrypted content. */
export function isTrashed(content: string): boolean {
  try {
    const parsed = JSON.parse(content) as { trashed?: unknown };
    return parsed.trashed === true;
  } catch {
    return false;
  }
}

/** A note the app locks behind its own password. The field is omitted when the note is not protected. */
export function isProtected(content: string): boolean {
  try {
    const parsed = JSON.parse(content) as { protected?: unknown };
    return parsed.protected === true;
  } catch {
    return false;
  }
}

export function listNotes(
  db: CacheDb,
  options: { type?: string; limit: number; all?: boolean },
): ListedNote[] {
  const clauses = ["deleted = 0", "COALESCE(json_extract(content, '$.trashed'), 0) != 1"];
  const params: Array<string | number> = [];
  if (options.type) {
    clauses.push("content_type = ?");
    params.push(options.type);
  } else {
    clauses.push("content_type = 'Note'");
  }
  params.push(options.limit);
  const rows = db
    .prepare(
      `SELECT uuid, content_type, updated_at, title, content FROM items
       WHERE ${clauses.join(" AND ")}
       ORDER BY updated_at DESC
       LIMIT ?`,
    )
    .all(...params) as Array<Pick<ItemRow, "uuid" | "content_type" | "updated_at" | "title" | "content">>;
  return rows.map((row) => ({
    uuid: row.uuid,
    content_type: row.content_type,
    updated_at: row.updated_at,
    title: row.title ?? "(untitled)",
    trashed: isTrashed(row.content),
    protected: isProtected(row.content),
  }));
}

export type SearchHit = ListedNote & { snippet: string };

export function searchNotes(
  db: CacheDb,
  query: string,
  options: { regex?: boolean; limit: number; all?: boolean },
): SearchHit[] {
  let pattern: RegExp | null = null;
  if (options.regex) {
    try {
      pattern = new RegExp(query, "i");
    } catch {
      throw new UserError("that regular expression is invalid");
    }
  }
  const needle = query.toLowerCase();
  const rows = db
    .prepare(
      `SELECT uuid, content_type, updated_at, title, content FROM items
       WHERE deleted = 0
       ORDER BY updated_at DESC`,
    )
    .all() as ItemRow[];
  const hits: SearchHit[] = [];
  for (const row of rows) {
    if (row.content_type !== "Note" || isTrashed(row.content)) continue;
    const title = row.title ?? "";
    const haystack = `${title}\n${row.content}`;
    const matched = pattern ? pattern.test(haystack) : haystack.toLowerCase().includes(needle);
    if (!matched) continue;
    hits.push({
      uuid: row.uuid,
      content_type: row.content_type,
      updated_at: row.updated_at,
      title: title || "(untitled)",
      trashed: false,
      protected: isProtected(row.content),
      snippet: snippet(haystack, pattern, needle),
    });
    if (hits.length >= options.limit) break;
  }
  return hits;
}

function snippet(haystack: string, pattern: RegExp | null, needle: string): string {
  const flat = haystack.replace(/\s+/g, " ").trim();
  let index = -1;
  if (pattern) {
    const match = pattern.exec(flat);
    index = match?.index ?? -1;
  } else {
    index = flat.toLowerCase().indexOf(needle);
  }
  if (index < 0) return flat.slice(0, 80);
  const start = Math.max(0, index - 20);
  const end = Math.min(flat.length, index + 60);
  const slice = flat.slice(start, end);
  return `${start > 0 ? "…" : ""}${slice}${end < flat.length ? "…" : ""}`.slice(0, 80);
}

export function resolveNote(db: CacheDb, query: string, options: { all?: boolean } = {}): ItemRow {
  const rows = db
    .prepare("SELECT uuid, content_type, updated_at, deleted, title, content FROM items WHERE deleted = 0")
    .all() as ItemRow[];
  const visible = rows.filter((row) => row.content_type === "Note" && !isTrashed(row.content));
  const exact = visible.find((row) => row.uuid === query);
  if (exact) return exact;
  if (/^[0-9a-fA-F-]{8,}$/.test(query)) {
    const lowered = query.toLowerCase();
    const byPrefix = visible.filter((row) => row.uuid.toLowerCase().startsWith(lowered));
    if (byPrefix.length === 1) return byPrefix[0]!;
    if (byPrefix.length > 1) throw ambiguous(byPrefix);
  }
  const prefix = query.toLowerCase();
  const byTitle = visible.filter((row) => (row.title ?? "").toLowerCase().startsWith(prefix));
  if (byTitle.length === 1) return byTitle[0]!;
  if (byTitle.length > 1) throw ambiguous(byTitle);
  throw new UserError(`no note matches ${JSON.stringify(query)}`);
}

function ambiguous(rows: ItemRow[]): UserError {
  const sample = rows
    .slice(0, 8)
    .map((row) => `${row.uuid.slice(0, 8)}  ${row.title ?? "(untitled)"}`)
    .join("\n");
  return new UserError(`that matches ${rows.length} notes; be more specific:\n${sample}`);
}

export function noteBody(row: ItemRow): { title: string; body: string } {
  const title = row.title ?? "(untitled)";
  let parsed: unknown;
  try {
    parsed = JSON.parse(row.content);
  } catch {
    return { title, body: row.content };
  }
  if (!parsed || typeof parsed !== "object") return { title, body: row.content };
  const record = parsed as Record<string, unknown>;
  if (HIDDEN_TYPES.has(row.content_type)) {
    const redacted: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(record)) {
      redacted[key] = REDACTED_FIELDS.has(key) ? "[redacted]" : value;
    }
    return { title: title === "(untitled)" ? row.content_type : title, body: JSON.stringify(redacted, null, 2) };
  }
  if (typeof record.text === "string") return { title, body: record.text };
  return { title, body: JSON.stringify(record, null, 2) };
}

export function formatWhen(ms: number): string {
  if (!ms) return "";
  const date = new Date(ms);
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function renderTable(notes: ListedNote[]): string {
  const header = ["updated", "protected", "title", "uuid"];
  const lines = notes.map((note) => [
    formatWhen(note.updated_at),
    note.protected ? "yes" : "no",
    note.title.replace(/\s+/g, " "),
    note.uuid,
  ]);
  const widths = header.map((cell, index) =>
    Math.max(cell.length, ...lines.map((line) => line[index]?.length ?? 0)),
  );
  const format = (cells: string[]) => cells.map((cell, index) => cell.padEnd(widths[index] ?? 0)).join("  ").trimEnd();
  return [format(header), ...lines.map(format)].join("\n");
}
