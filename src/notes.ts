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

export function listNotes(
  db: CacheDb,
  options: { type?: string; limit: number; all?: boolean; tagUuids?: Set<string> },
): ListedNote[] {
  // No json_extract here: a cached row whose content is not valid JSON would
  // make SQLite raise mid-query and kill the whole listing. Trashed is
  // filtered in JS, where every other parser tolerates bad content.
  const clauses = ["deleted = 0"];
  const params: Array<string | number> = [];
  if (options.type) {
    clauses.push("content_type = ?");
    params.push(options.type);
  } else if (options.all) {
    // --all means "plus key-bearing items" — never tag rows, which would
    // otherwise land in the (untagged) group as junk
    const types = ["Note", ...HIDDEN_TYPES].map((type) => `'${type}'`).join(", ");
    clauses.push(`content_type IN (${types})`);
  } else {
    clauses.push("content_type = 'Note'");
  }
  const rows = db
    .prepare(
      `SELECT uuid, content_type, updated_at, title, content FROM items
       WHERE ${clauses.join(" AND ")}
       ORDER BY updated_at DESC`,
    )
    .all(...params) as Array<Pick<ItemRow, "uuid" | "content_type" | "updated_at" | "title" | "content">>;
  const listed: ListedNote[] = [];
  for (const row of rows) {
    if (isTrashed(row.content)) continue;
    if (options.tagUuids && !options.tagUuids.has(row.uuid)) continue;
    listed.push({
      uuid: row.uuid,
      content_type: row.content_type,
      updated_at: row.updated_at,
      title: row.title ?? label(row),
      trashed: false,
    });
    if (listed.length >= options.limit) break;
  }
  return listed;
}

function label(row: { content_type: string }): string {
  return HIDDEN_TYPES.has(row.content_type) ? row.content_type : "(untitled)";
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
  const visibleTypes = new Set(["Note", ...(options.all ? HIDDEN_TYPES : [])]);
  const rows = db
    .prepare(
      `SELECT uuid, content_type, updated_at, title, content FROM items
       WHERE deleted = 0
       ORDER BY updated_at DESC`,
    )
    .all() as ItemRow[];
  const hits: SearchHit[] = [];
  for (const row of rows) {
    if (isTrashed(row.content)) continue;
    if (!visibleTypes.has(row.content_type)) continue;
    const title = row.title ?? "";
    const haystack = `${title}\n${row.content}`;
    const matched = pattern ? pattern.test(haystack) : haystack.toLowerCase().includes(needle);
    if (!matched) continue;
    hits.push({
      uuid: row.uuid,
      content_type: row.content_type,
      updated_at: row.updated_at,
      title: title || label(row),
      trashed: false,
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
  const visibleTypes = new Set(["Note", ...(options.all ? HIDDEN_TYPES : [])]);
  const visible = rows.filter((row) => visibleTypes.has(row.content_type) && !isTrashed(row.content));
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

/** Tag→note and tag→parent links live in the encrypted content's references array. */
function contentReferences(content: string): Array<{ uuid: string; content_type: string }> {
  try {
    const parsed = JSON.parse(content) as { references?: unknown };
    if (!Array.isArray(parsed.references)) return [];
    const refs: Array<{ uuid: string; content_type: string }> = [];
    for (const entry of parsed.references) {
      const record = entry as { uuid?: unknown; content_type?: unknown };
      if (typeof record.uuid === "string" && typeof record.content_type === "string") {
        refs.push({ uuid: record.uuid, content_type: record.content_type });
      }
    }
    return refs;
  } catch {
    return [];
  }
}

export type ListedTag = {
  uuid: string;
  title: string;
  parent: string | null;
  notes: number;
};

type TagLinks = {
  titleOf: Map<string, string>;
  parentOf: Map<string, string | null>;
  tagToNotes: Map<string, Set<string>>;
};

/** Tag titles render and resolve everywhere, so whitespace is normalized once here. */
function normalizeTitle(title: string | null): string {
  return (title ?? "").replace(/\s+/g, " ").trim() || "(untitled)";
}

/**
 * Both link sides are unioned — the tag's references and the note's — since the
 * app keeps them in sync but either side can lag mid-update. References are
 * filtered to notes the cache can actually show (a hard-deleted note leaves a
 * deleted=1 tombstone that the tag's references still name). Parents only count
 * when the parent tag itself exists, so a dangling parent renders top-level.
 */
function tagLinks(db: CacheDb): TagLinks {
  const tagRows = db
    .prepare("SELECT uuid, title, content FROM items WHERE content_type = 'Tag' AND deleted = 0")
    .all() as Array<Pick<ItemRow, "uuid" | "title" | "content">>;
  const titleOf = new Map<string, string>(tagRows.map((row) => [row.uuid, normalizeTitle(row.title)]));
  const parentOf = new Map<string, string | null>(tagRows.map((row) => [row.uuid, null]));
  const tagToNotes = new Map<string, Set<string>>(tagRows.map((row) => [row.uuid, new Set<string>()]));
  for (const row of tagRows) {
    for (const ref of contentReferences(row.content)) {
      if (ref.content_type === "Note") tagToNotes.get(row.uuid)?.add(ref.uuid);
      else if (ref.content_type === "Tag" && parentOf.has(ref.uuid) && ref.uuid !== row.uuid) {
        parentOf.set(row.uuid, ref.uuid);
      }
    }
  }
  const noteRows = db
    .prepare("SELECT uuid, content FROM items WHERE content_type = 'Note' AND deleted = 0")
    .all() as Array<Pick<ItemRow, "uuid" | "content">>;
  const live = new Set<string>();
  for (const row of noteRows) {
    if (isTrashed(row.content)) continue;
    live.add(row.uuid);
    for (const ref of contentReferences(row.content)) {
      if (ref.content_type === "Tag") tagToNotes.get(ref.uuid)?.add(row.uuid);
    }
  }
  // Tombstones: notes deleted on another device (deleted=1, content "{}") are
  // still named by the tag's own references — drop them or counts never shrink.
  for (const set of tagToNotes.values()) {
    for (const uuid of [...set]) if (!live.has(uuid)) set.delete(uuid);
  }
  return { titleOf, parentOf, tagToNotes };
}

/**
 * Explicit parents (SN folders) win. Otherwise nesting is inferred from note
 * membership: a tag whose notes all also sit in another tag nests under the
 * smallest such tag (alphabetical tie-break). Equal sets fold onto the
 * alphabetically-first tag, which keeps the parent chain acyclic and makes a
 * note with overlapping tags render exactly once, under its deepest tag.
 */
function resolveParents(links: TagLinks): Map<string, string | null> {
  const tags = [...links.titleOf.keys()];
  const parentOf = new Map<string, string | null>();
  const byTitle = (a: string, b: string) =>
    (links.titleOf.get(a) ?? "").localeCompare(links.titleOf.get(b) ?? "") || a.localeCompare(b);
  for (const tag of tags) {
    const explicit = links.parentOf.get(tag);
    // check the INPUT map: parentOf (output) is half-built at this point, so
    // testing it here made explicit folders depend on SQLite row order
    if (explicit && links.parentOf.has(explicit)) {
      parentOf.set(tag, explicit);
      continue;
    }
    const mine = links.tagToNotes.get(tag) ?? new Set<string>();
    if (mine.size === 0) {
      // a noteless tag stays top-level rather than nesting under everything
      // that contains the empty set
      parentOf.set(tag, null);
      continue;
    }
    let best: string | null = null;
    for (const other of tags) {
      if (other === tag) continue;
      const theirs = links.tagToNotes.get(other) ?? new Set<string>();
      if (theirs.size < mine.size) continue;
      let contains = true;
      for (const note of mine) {
        if (!theirs.has(note)) {
          contains = false;
          break;
        }
      }
      if (!contains) continue;
      const strict = theirs.size > mine.size;
      const folds = !strict && byTitle(other, tag) < 0;
      if (!strict && !folds) continue;
      const bestSize = best !== null ? (links.tagToNotes.get(best)?.size ?? 0) : -1;
      if (best === null || theirs.size < bestSize || (theirs.size === bestSize && byTitle(other, best) < 0)) {
        best = other;
      }
    }
    parentOf.set(tag, best);
  }
  return parentOf;
}

/** Depth per tag, cutting explicit-parent cycles at the first revisit. */
function tagDepths(titleOf: Map<string, string>, parentOf: Map<string, string | null>): Map<string, number> {
  const depthOf = new Map<string, number>();
  const depth = (tag: string): number => {
    const cached = depthOf.get(tag);
    if (cached !== undefined) return cached;
    depthOf.set(tag, 0);
    const parent = parentOf.get(tag);
    const result = parent !== null && parent !== undefined && parentOf.has(parent) ? depth(parent) + 1 : 0;
    depthOf.set(tag, result);
    return result;
  };
  for (const tag of titleOf.keys()) depth(tag);
  return depthOf;
}

/** Read-only view of tags: title, resolved parent tag, and note count. */
export function listTags(db: CacheDb): ListedTag[] {
  const links = tagLinks(db);
  const parentOf = resolveParents(links);
  const tags: ListedTag[] = [...links.titleOf].map(([uuid, title]) => ({
    uuid,
    title,
    parent: parentOf.get(uuid) ?? null,
    notes: links.tagToNotes.get(uuid)?.size ?? 0,
  }));
  tags.sort((a, b) => a.title.localeCompare(b.title) || a.uuid.localeCompare(b.uuid));
  return tags;
}

/**
 * Note uuids under a tag or folder: the subtree's membership, so
 * `sns list --tag <folder>` finds notes that sit in its child tags.
 */
export function taggedNoteUuids(db: CacheDb, tagUuid: string): Set<string> {
  const links = tagLinks(db);
  const parentOf = resolveParents(links);
  const subtree = new Set<string>([tagUuid]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const [tag, parent] of parentOf) {
      if (parent !== null && subtree.has(parent) && !subtree.has(tag)) {
        subtree.add(tag);
        grew = true;
      }
    }
  }
  const uuids = new Set<string>();
  for (const tag of subtree) {
    for (const uuid of links.tagToNotes.get(tag) ?? []) uuids.add(uuid);
  }
  return uuids;
}

export function resolveTag(db: CacheDb, query: string): ListedTag {
  const tags = listTags(db);
  const exact = tags.find((tag) => tag.uuid === query);
  if (exact) return exact;
  if (/^[0-9a-fA-F-]{8,}$/.test(query)) {
    const lowered = query.toLowerCase();
    const byPrefix = tags.filter((tag) => tag.uuid.toLowerCase().startsWith(lowered));
    if (byPrefix.length === 1) return byPrefix[0]!;
    if (byPrefix.length > 1) throw ambiguousTags(byPrefix);
  }
  const prefix = query.toLowerCase();
  const byTitle = tags.filter((tag) => tag.title.toLowerCase().startsWith(prefix));
  if (byTitle.length === 1) return byTitle[0]!;
  if (byTitle.length > 1) throw ambiguousTags(byTitle);
  throw new UserError(`no tag matches ${JSON.stringify(query)}`);
}

function ambiguousTags(tags: ListedTag[]): UserError {
  const sample = tags.slice(0, 8).map((tag) => `${tag.uuid.slice(0, 8)}  ${tag.title}`).join("\n");
  return new UserError(`that matches ${tags.length} tags; be more specific:\n${sample}`);
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

const UNTAGGED = "(untagged)";

/**
 * Hierarchical `sns list`. Tags render as a forest — explicit SN folders win,
 * otherwise containment is inferred (see resolveParents) — and every listed
 * note is placed exactly once, under its deepest tag. Header counts come from
 * the notes argument (subtree totals), so --limit and --tag filters never
 * show a count for rows that are not listed. Tags with nothing under them are
 * left out (sns tags still shows them); untagged notes land in (untagged) last.
 */
export function renderTagGroups(db: CacheDb, notes: ListedNote[]): string {
  const links = tagLinks(db);
  const parentOf = resolveParents(links);
  const depthOf = tagDepths(links.titleOf, parentOf);
  const byTitle = (a: string, b: string) =>
    (links.titleOf.get(a) ?? "").localeCompare(links.titleOf.get(b) ?? "") || a.localeCompare(b);
  const byRecency = (a: ListedNote, b: ListedNote) => b.updated_at - a.updated_at || a.uuid.localeCompare(b.uuid);

  const childrenOf = new Map<string, string[]>();
  for (const [tag, parent] of parentOf) {
    if (parent === null || !parentOf.has(parent)) continue;
    const kids = childrenOf.get(parent) ?? [];
    kids.push(tag);
    childrenOf.set(parent, kids);
  }
  for (const kids of childrenOf.values()) kids.sort(byTitle);

  // Each note's home is its deepest tag; ties go to the alphabetically first.
  const placed = new Map<string, ListedNote[]>();
  const untagged: ListedNote[] = [];
  for (const note of notes) {
    let home: string | null = null;
    for (const [tag, set] of links.tagToNotes) {
      if (!set.has(note.uuid)) continue;
      if (home === null || depthOf.get(tag)! > depthOf.get(home)! || (depthOf.get(tag) === depthOf.get(home) && byTitle(tag, home) < 0)) {
        home = tag;
      }
    }
    if (home === null) untagged.push(note);
    else {
      const rows = placed.get(home) ?? [];
      rows.push(note);
      placed.set(home, rows);
    }
  }

  // Header counts are subtree totals over the listed notes only.
  const countOf = new Map<string, number>();
  const measure = (tag: string): number => {
    let total = placed.get(tag)?.length ?? 0;
    for (const child of childrenOf.get(tag) ?? []) total += measure(child);
    countOf.set(tag, total);
    return total;
  };
  for (const tag of links.titleOf.keys()) measure(tag);

  const widths = [
    Math.max(...notes.map((note) => note.title.replace(/\s+/g, " ").length), 5),
    Math.max(...notes.map((note) => formatWhen(note.updated_at).length), 16),
  ];
  const row = (note: ListedNote, depth: number) =>
    `${"  ".repeat(depth + 1)}${[
      note.title.replace(/\s+/g, " ").padEnd(widths[0] ?? 0),
      formatWhen(note.updated_at).padEnd(widths[1] ?? 0),
      note.uuid,
    ].join("  ").trimEnd()}`;

  // Roots are tags with no (live) parent, plus members of a parent cycle.
  const isRoot = (tag: string): boolean => {
    const parent = parentOf.get(tag);
    if (parent === null || parent === undefined || !parentOf.has(parent)) return true;
    let current: string | null = parent;
    const seen = new Set<string>();
    while (current !== null && parentOf.has(current) && !seen.has(current)) {
      if (current === tag) return true; // the parent chain loops through this tag
      seen.add(current);
      current = parentOf.get(current) ?? null;
    }
    return false;
  };

  // A block is [header, rows…, child blocks…]; null when nothing shows under it.
  const emitted = new Set<string>();
  const block = (tag: string, depth: number): string[] | null => {
    if (emitted.has(tag)) return null;
    emitted.add(tag);
    const rows = [...(placed.get(tag) ?? [])].sort(byRecency).map((note) => row(note, depth));
    const kids: string[] = [];
    for (const child of childrenOf.get(tag) ?? []) {
      const childBlock = block(child, depth + 1);
      if (childBlock) kids.push(...childBlock);
    }
    if (rows.length === 0 && kids.length === 0) return null;
    const count = countOf.get(tag) ?? 0;
    return [`${"  ".repeat(depth)}${links.titleOf.get(tag) ?? tag} (${count})`, ...rows, ...kids];
  };

  const out: string[] = [];
  for (const tag of [...links.titleOf.keys()].sort(byTitle)) {
    if (!isRoot(tag)) continue;
    const top = block(tag, 0);
    if (!top) continue;
    if (out.length > 0) out.push("");
    out.push(...top);
  }
  if (untagged.length > 0) {
    if (out.length > 0) out.push("");
    out.push(`${UNTAGGED} (${untagged.length})`);
    for (const note of [...untagged].sort(byRecency)) out.push(row(note, 0));
  }
  return out.join("\n");
}
