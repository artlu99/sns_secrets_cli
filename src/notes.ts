import type { CacheDb, ItemRow } from "./db.ts";
import { UserError } from "./errors.ts";
import { scanNote, type NoteScan } from "./note-env.ts";

/** Key-bearing items are stored for decrypt and never listed. */
export const HIDDEN_TYPES = new Set(["SN|ItemsKey", "SN|KeySystemItemsKey", "SN|KeySystemRootKey"]);

/**
 * The key-bearing item fields allowed to print when such an item's body is
 * surfaced (`sns search --all` snippets); everything else prints as
 * "[redacted]". An allowlist fails closed — a field the server adds later
 * cannot carry a secret to stdout by default, the way the blocklist it
 * replaced let any unlisted field print.
 */
const PRINTABLE_FIELDS = new Set(["version", "keySystemIdentifier", "keyParams"]);

export type ListedNote = {
  uuid: string;
  content_type: string;
  updated_at: number;
  title: string;
  trashed: boolean;
  /** env-style settings parsed from the note's prose body (0 when none). */
  settings: number;
};

/** Content types whose prose `text` carries the env-style settings the list counts. */
export const PROSE_TYPES = new Set(["Note"]);

/** A row's content JSON.parse-ed once as an object, or null when it is not one. */
function parseContentRecord(content: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(content);
    return parsed !== null && typeof parsed === "object" ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** A Note row's prose `text` out of an already-parsed content object — the
 * type gate shared by the settings count and the snippet source. */
function proseFromRecord(contentType: string, parsed: Record<string, unknown> | null): string | null {
  return PROSE_TYPES.has(contentType) && typeof parsed?.text === "string" ? parsed.text : null;
}

/** A Note row's prose `text`, or null for other types and unparseable content. */
function proseText(row: { content_type: string; content: string }): string | null {
  return proseFromRecord(row.content_type, parseContentRecord(row.content));
}

/** Settings count from prose text already pulled out of a row — the list and
 * search paths pre-extract, so a row is never JSON.parsed for a count alone. */
function settingsCount(contentType: string, text: string | null): number {
  return PROSE_TYPES.has(contentType) && text !== null ? scanNote(text, { prose: false }).settings.size : 0;
}

/**
 * Env-style settings parsed from a row's prose body. Notes parse their
 * `text`; anything else (and any unparseable content) has none.
 */
export function noteSettings(row: { content_type: string; content: string }): Map<string, string> {
  const text = proseText(row);
  // list and search call this for every cached row: skip the prose they never show
  return text === null ? new Map() : scanNote(text, { prose: false }).settings;
}

/**
 * Full scan of a row's prose body — settings, comments, and the skipped
 * lines — for `sns show`'s inventory. One walk per show; the hot paths use
 * noteSettings instead.
 */
export function noteScan(row: { content_type: string; content: string }): NoteScan {
  const text = proseText(row);
  return text === null ? { settings: new Map(), comments: new Map(), prose: "" } : scanNote(text);
}

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
  options: { type?: string; limit: number; all?: boolean; tagUuids?: Set<string>; env?: boolean },
): ListedNote[] {
  // Trash is the precomputed trashed column (upsertItems derives it from
  // content), so the query drops those rows without reading a body. The
  // prose for the settings count is extracted by SQLite behind json_valid:
  // a cached row whose content is not valid JSON yields NULL instead of
  // raising mid-query, and only the `text` value is pulled, never the whole
  // body. Everything still tolerates bad rows in JS where a parser can.
  const clauses = ["deleted = 0", "trashed = 0"];
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
      `SELECT uuid, content_type, updated_at, title,
              CASE WHEN json_valid(content) THEN json_extract(content, '$.text') END AS prose
       FROM items
       WHERE ${clauses.join(" AND ")}
       ORDER BY updated_at DESC`,
    )
    .all(...params) as Array<Pick<ItemRow, "uuid" | "content_type" | "updated_at" | "title"> & { prose: unknown }>;
  const listed: ListedNote[] = [];
  for (const row of rows) {
    if (options.tagUuids && !options.tagUuids.has(row.uuid)) continue;
    const prose = typeof row.prose === "string" ? row.prose : null;
    const settings = settingsCount(row.content_type, prose);
    // env view: the limit applies after filtering, so prose-only notes never crowd out a settings note
    if (options.env && settings === 0) continue;
    listed.push({
      uuid: row.uuid,
      content_type: row.content_type,
      updated_at: row.updated_at,
      title: sanitizeText(row.title ?? label(row)),
      trashed: false,
      settings,
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
  // trash drops out in SQL via the precomputed column; matching itself needs
  // the raw content, so the body still rides along on every row
  const rows = db
    .prepare(
      `SELECT uuid, content_type, updated_at, title, content FROM items
       WHERE deleted = 0 AND trashed = 0
       ORDER BY updated_at DESC`,
    )
    .all() as Array<Pick<ItemRow, "uuid" | "content_type" | "updated_at" | "title" | "content">>;
  const hits: SearchHit[] = [];
  for (const row of rows) {
    if (!visibleTypes.has(row.content_type)) continue;
    const title = sanitizeText(row.title ?? "");
    const haystack = `${title}\n${row.content}`;
    const matched = pattern ? pattern.test(haystack) : haystack.toLowerCase().includes(needle);
    if (!matched) continue;
    // one parse per hit row feeds both the settings count and the snippet
    const parsed = parseContentRecord(row.content);
    const text = proseFromRecord(row.content_type, parsed);
    hits.push({
      uuid: row.uuid,
      content_type: row.content_type,
      updated_at: row.updated_at,
      title: title || label(row),
      trashed: false,
      settings: settingsCount(row.content_type, text),
      snippet: snippet(snippetSource(row, parsed), pattern, needle),
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

/** An assignment line as the parser sees one: optional `export`, the key
 * charset, `=`, then a quoted span (which may cross lines) or the line's rest.
 * The key must not be preceded by an identifier character — a negative
 * lookbehind, so the anchor consumes nothing: two assignments fused together
 * (`K1="a"K2="b"`) each still find their non-identifier left neighbor after
 * the previous match ends, which a consuming `(^|[^A-Za-z0-9_])` anchor would
 * make the second one lose. */
const ASSIGNMENT_LINE =
  /(?<![A-Za-z0-9_])[ \t]*(?:export[ \t]+)?([A-Za-z0-9_.-]+)[ \t]*=(?:"[^"]*"|'[^']*'|`[^`]*`|[^\n]*)/gm;

/**
 * Collapse every assignment-shaped line to `KEY=[redacted]` — quoted spans,
 * unclosed quotes, and unquoted values included — then mask rejected inline
 * fragments the way the show inventory does. Escape sequences go first, so a
 * code cannot hide an assignment shape from either pass. The line-level pass
 * runs first because the fragment mask cannot catch a quoted value's
 * continuation lines: masking the decoded body this way is what lets a
 * snippet be cut from text a value may have once been in.
 */
function maskAssignments(text: string): string {
  return redactAssignments(sanitizeText(text).replace(ASSIGNMENT_LINE, "$1=[redacted]"));
}

/**
 * The only text a search snippet may be cut from, so matching full content
 * never puts a value on stdout. Notes: the decoded body (`text`, read from
 * the caller's single per-row parse), sanitized and with every assignment
 * collapsed (`maskAssignments`) — a hit on a value shows `KEY=[redacted]`,
 * never the value. Other rows (the key-bearing items `--all` can surface):
 * the JSON body noteBodyFrom already field-redacts.
 */
function snippetSource(
  row: Pick<ItemRow, "content_type" | "content" | "title">,
  parsed: Record<string, unknown> | null,
): string {
  const decoded = proseFromRecord(row.content_type, parsed);
  return decoded === null ? redactAssignments(sanitizeText(noteBodyFrom(row, parsed).body)) : maskAssignments(decoded);
}

/**
 * One prefix resolver for notes and tags: exact uuid, then uuid prefix (when
 * the query looks like one), then unique title prefix. Both sides of the
 * title comparison are trimmed — the completer offers trimmed titles, and a
 * stored title with stray padding still resolves. Ambiguity is an error
 * listing the first few matches; `kind` is singular ("note", "tag").
 */
function resolveByPrefix<T>(
  items: T[],
  query: string,
  kind: string,
  key: (item: T) => { uuid: string; title: string },
): T {
  const needle = query.trim();
  const exact = items.find((item) => key(item).uuid === needle);
  if (exact) return exact;
  if (/^[0-9a-fA-F-]{8,}$/.test(needle)) {
    const lowered = needle.toLowerCase();
    const byPrefix = items.filter((item) => key(item).uuid.toLowerCase().startsWith(lowered));
    if (byPrefix.length === 1) return byPrefix[0]!;
    if (byPrefix.length > 1) throw ambiguousItems(byPrefix, kind, key);
  }
  const prefix = needle.toLowerCase();
  const byTitle = items.filter((item) => key(item).title.trim().toLowerCase().startsWith(prefix));
  if (byTitle.length === 1) return byTitle[0]!;
  if (byTitle.length > 1) throw ambiguousItems(byTitle, kind, key);
  throw new UserError(`no ${kind} matches ${JSON.stringify(query)}`);
}

function ambiguousItems<T>(
  matches: T[],
  kind: string,
  key: (item: T) => { uuid: string; title: string },
): UserError {
  const sample = matches
    .slice(0, 8)
    .map((item) => {
      const entry = key(item);
      return `${entry.uuid.slice(0, 8)}  ${entry.title}`;
    })
    .join("\n");
  return new UserError(`that matches ${matches.length} ${kind}s; be more specific:\n${sample}`);
}

/**
 * The rows note commands can resolve: deleted=0, one of `types`, trash
 * dropped, newest first. `resolveNote`'s scan and completion's candidate list
 * share this fetch, so completion never drifts from what the CLI resolves.
 */
export function visibleNoteRows(db: CacheDb, types: readonly string[]): ItemRow[] {
  return db
    .prepare(
      `SELECT uuid, content_type, updated_at, deleted, title, content FROM items
       WHERE deleted = 0 AND trashed = 0 AND content_type IN (${types.map(() => "?").join(", ")})
       ORDER BY updated_at DESC`,
    )
    .all(...types) as ItemRow[];
}

export function resolveNote(db: CacheDb, query: string, options: { all?: boolean } = {}): ItemRow {
  const types = ["Note", ...(options.all ? HIDDEN_TYPES : [])];
  return resolveByPrefix(visibleNoteRows(db, types), query, "note", (row) => ({
    uuid: row.uuid,
    title: row.title ?? "(untitled)",
  }));
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

/** The tag graph, resolved once per command: links plus inferred/explicit parents. */
export type TagGraph = {
  links: TagLinks;
  parentOf: Map<string, string | null>;
};

/** Tag titles render and resolve everywhere, so whitespace is normalized and
 * terminal escape sequences stripped once here. */
function normalizeTitle(title: string | null): string {
  return sanitizeText(title ?? "").replace(/\s+/g, " ").trim() || "(untitled)";
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
    .prepare("SELECT uuid, content FROM items WHERE content_type = 'Note' AND deleted = 0 AND trashed = 0")
    .all() as Array<Pick<ItemRow, "uuid" | "content">>;
  const live = new Set<string>();
  for (const row of noteRows) {
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

/** The full tag graph: query it once, pass it everywhere. */
export function tagGraph(db: CacheDb): TagGraph {
  const links = tagLinks(db);
  return { links, parentOf: resolveParents(links) };
}

const titleComparator = (titleOf: Map<string, string>) => (a: string, b: string) =>
  (titleOf.get(a) ?? "").localeCompare(titleOf.get(b) ?? "") || a.localeCompare(b);

/**
 * Explicit parents (SN folders) win. Otherwise nesting is inferred from note
 * membership: a tag whose notes all also sit in another tag nests under the
 * smallest such tag (alphabetical tie-break). Equal sets fold onto the
 * alphabetically-first tag, which keeps the parent chain acyclic and makes a
 * note with overlapping tags render exactly once, under its deepest tag.
 * Exported for the extension's tag tree (extension/lib/tags.ts) — the CLI's
 * own callers go through tagGraph.
 */
export function resolveParents(links: TagLinks): Map<string, string | null> {
  const tags = [...links.titleOf.keys()];
  const parentOf = new Map<string, string | null>();
  const byTitle = titleComparator(links.titleOf);
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
function tagDepths(parentOf: Map<string, string | null>): Map<string, number> {
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
  for (const tag of parentOf.keys()) depth(tag);
  return depthOf;
}

/**
 * The forest both tag renderers draw: cycle-cut depths, children lists, and
 * root detection. A tag is a root when it has no live parent (dangling links
 * included) or when its parent chain loops back through it — a parent cycle
 * renders as one chain hanging off each of its members. `cycleRoot` says
 * which kind of root a tag is, so renderers can present cycles last.
 */
export function tagForest(parentOf: Map<string, string | null>): {
  depthOf: Map<string, number>;
  childrenOf: Map<string, string[]>;
  isRoot: (tag: string) => boolean;
  cycleRoot: (tag: string) => boolean;
} {
  const childrenOf = new Map<string, string[]>();
  for (const [tag, parent] of parentOf) {
    if (parent === null || !parentOf.has(parent)) continue;
    const kids = childrenOf.get(parent) ?? [];
    kids.push(tag);
    childrenOf.set(parent, kids);
  }
  const depthOf = tagDepths(parentOf);
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
  const cycleRoot = (tag: string): boolean => {
    if (!isRoot(tag)) return false;
    const parent = parentOf.get(tag);
    return parent !== null && parent !== undefined && parentOf.has(parent);
  };
  return { depthOf, childrenOf, isRoot, cycleRoot };
}

/** Read-only view of tags: title, resolved parent tag, and note count. */
export function listTags(db: CacheDb): ListedTag[] {
  return tagsOf(tagGraph(db));
}

function tagsOf(graph: TagGraph): ListedTag[] {
  const { links, parentOf } = graph;
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
export function taggedNoteUuids(graph: TagGraph, tagUuid: string): Set<string> {
  const subtree = new Set<string>([tagUuid]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const [tag, parent] of graph.parentOf) {
      if (parent !== null && subtree.has(parent) && !subtree.has(tag)) {
        subtree.add(tag);
        grew = true;
      }
    }
  }
  const uuids = new Set<string>();
  for (const tag of subtree) {
    for (const uuid of graph.links.tagToNotes.get(tag) ?? []) uuids.add(uuid);
  }
  return uuids;
}

export function resolveTag(graph: TagGraph, query: string): ListedTag {
  return resolveByPrefix(tagsOf(graph), query, "tag", (tag) => ({ uuid: tag.uuid, title: tag.title }));
}

export function noteBody(row: Pick<ItemRow, "title" | "content_type" | "content">): { title: string; body: string } {
  return noteBodyFrom(row, parseContentRecord(row.content));
}

/**
 * noteBody over a content object the caller already parsed, so a row is
 * never JSON.parsed twice on one command (the search snippet path). Same
 * output as noteBody for every row.
 */
function noteBodyFrom(
  row: Pick<ItemRow, "title" | "content_type" | "content">,
  record: Record<string, unknown> | null,
): { title: string; body: string } {
  const title = row.title ?? "(untitled)";
  if (!record) return { title, body: row.content };
  if (HIDDEN_TYPES.has(row.content_type)) {
    const redacted: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(record)) {
      redacted[key] = PRINTABLE_FIELDS.has(key) ? value : "[redacted]";
    }
    return { title: title === "(untitled)" ? row.content_type : title, body: JSON.stringify(redacted, null, 2) };
  }
  if (typeof record.text === "string") return { title, body: record.text };
  return { title, body: JSON.stringify(record, null, 2) };
}

/** Render a user-typed id inside a hint so it pastes back into a shell unchanged. */
export function shellish(text: string): string {
  return /^[A-Za-z0-9_.@:/-]+$/.test(text) ? text : `'${text.replaceAll("'", `'\\''`)}'`;
}

/**
 * The palette the inventory draws with. Real palettes come from picocolors,
 * which handles NO_COLOR, TERM=dumb, --no-color, and the tty check — so a
 * pipe, a dumb terminal, or an explicit opt-out renders monochrome, and the
 * whitespace-structural layout loses nothing. Draw with indexed ANSI (gray =
 * bright black) so the terminal's theme-aware palette picks contrast.
 */
export type InventoryColor = {
  bold(text: string): string;
  gray(text: string): string;
  italic(text: string): string;
};

/** The no-op palette: monochrome, for tests and unstyled callers. */
export const plainInventoryColor: InventoryColor = {
  bold: (text) => text,
  gray: (text) => text,
  italic: (text) => text,
};

/** Title with its ─ separator — the top of every show layout. */
export function noteHeader(title: string, color: InventoryColor = plainInventoryColor): string {
  return `${color.bold(title)}\n${color.gray("─".repeat(Math.min(title.length, 40)))}`;
}

/** The pasteable hint that names the two-argument copy form with a real key.
 *  Plain text, like every other hint in the flow — only annotation dims. */
function copyHint(query: string, firstKey: string): string {
  return `copy a value:  sns copy ${shellish(query)} ${firstKey}`;
}

/**
 * Strip terminal escape sequences from note- and server-derived text before a
 * display sink draws it — our styling goes around the result, and a poisoned
 * note or error message never gets to restyle, wipe, or retitle the pane.
 * Removes CSI sequences whatever their final byte (not just SGR `m`: cursor
 * moves and private modes too), OSC strings closed by BEL or ST (window
 * titles, hyperlinks; an unterminated one is cut to the end of the text,
 * since its payload has no honest end), DCS/APC/PM strings, and the leftover
 * bare control bytes: C0 except newline and tab, a lone ESC, DEL, and the C1
 * range (a lone 0x9B reopens CSI parsing on some terminals). Structured
 * sequences go first, so the ESC that opened a real sequence is never eaten
 * alone and left to print its payload raw.
 */
export function sanitizeText(text: string): string {
  return text
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "") // CSI … any final byte
    .replace(/\x1b\][\s\S]*?(?:\x07|\x1b\\|$)/g, "") // OSC … BEL or ST
    .replace(/\x1b[P^_][\s\S]*?(?:\x07|\x1b\\|$)/g, "") // DCS/APC/PM … ST or BEL
    .replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f]/g, ""); // stray C0/ESC/DEL/C1; \n and \t survive
}

/**
 * Mask `key=value` fragments in free text the inventory renders verbatim. The
 * parser rejects these lines (a commented-out `# OLD_KEY=…`, a mention
 * mid-sentence, one in parentheses or quotes), so a value written that way
 * would otherwise reach stdout — the one thing this view promises never
 * happens. An assignment counts when a line start or any non-identifier
 * character precedes the key — a negative lookbehind, so the anchor consumes
 * nothing and an assignment fused to the previous match's tail (`K1="a"K2="b"`)
 * still masks — so punctuation- and quote-prefixed fragments
 * mask too; a quoted value's whole quoted span (quotes included, lines
 * crossed) masks with it, so a multi-word or multi-line value never leaks its
 * tail; a candidate fused into a longer identifier never matches on its
 * own — the greedy key class absorbs the run, so `my_fooBAR=x` masks as the
 * one assignment its full token already is, and `run=` with no value after
 * the `=` (base64 padding) masks nothing. Only display: parsing itself is
 * untouched. Exported for the extension, whose prose view renders the same
 * redaction over the same prose.
 */
export function redactAssignments(text: string): string {
  return text.replace(
    /(?<![A-Za-z0-9_])([A-Za-z0-9_.-]+)[ \t]*=(?:"[^"]*"|'[^']*'|`[^`]*`|[ \t]*\S+)/gm,
    "$1=[redacted]",
  );
}

/**
 * The `sns show` inventory for a note with settings: its title, the prose the
 * parser skipped, then the setting keys — each drawn as its note line with
 * the value withheld (`KEY=[redacted]`, or `KEY=  (empty)` when the value is
 * empty) plus the trailing `#` comment when the note has one. Descriptive
 * text reads first, and the actionable keys sit last, directly above — on a
 * terminal only — the hint naming the copy form with a real key. Keys, prose,
 * and the hint stay plain text; comments and value markers dim via `color`,
 * with the key names popping by contrast. Everything the note supplies —
 * title, prose, comments — passes through sanitizeText before redaction, so
 * note-supplied terminal codes can never restyle our output. Pure so tests
 * can pin the layout.
 */
export function renderNoteInventory(input: {
  title: string;
  settings: Map<string, string>;
  comments: Map<string, string>;
  prose: string;
  query: string;
  terminal: boolean;
  color?: InventoryColor;
}): string {
  const color = input.color ?? plainInventoryColor;
  const title = sanitizeText(input.title);
  const lines = [noteHeader(title, color)];
  const prose = redactAssignments(sanitizeText(input.prose)).replace(/\n+$/, "");
  if (prose.trim() !== "") lines.push(prose, "");
  for (const [key, value] of input.settings) {
    const label = value === "" ? `${key}=  ${color.gray("(empty)")}` : `${key}=${color.gray("[redacted]")}`;
    const comment = input.comments.get(key);
    lines.push(
      comment === undefined
        ? label
        : `${label}  ${color.italic(color.gray(redactAssignments(sanitizeText(comment))))}`,
    );
  }
  if (input.terminal && input.settings.size > 0) {
    const firstKey = [...input.settings.keys()][0]!;
    lines.push("", copyHint(input.query, firstKey));
  }
  return lines.join("\n");
}

/** What `sns copy` should do for a resolved row. */
export type CopyPlan =
  | { kind: "value"; key: string; value: string }
  | { kind: "body"; body: string }
  | { kind: "keys"; keys: string[] };

/**
 * `sns copy <id> [key]`: an exact, case-sensitive key copies that parsed
 * value; no key on a settings note copies nothing (the caller lists the
 * keys); a note without settings still copies its body. A key that does not
 * exist — including a case mismatch — copies nothing and names the keys.
 */
export function planCopy(row: ItemRow, key: string | undefined): CopyPlan {
  const settings = noteSettings(row);
  if (settings.size === 0) {
    if (key !== undefined) {
      const title = row.title ?? "(untitled)";
      throw new UserError(`${JSON.stringify(title)} has no KEY=VALUE settings\nits whole body copies with: sns copy <id>`);
    }
    return { kind: "body", body: noteBody(row).body };
  }
  if (key === undefined) return { kind: "keys", keys: [...settings.keys()] };
  const value = settings.get(key);
  if (value === undefined) {
    const title = row.title ?? "(untitled)";
    throw new UserError(
      `no setting ${JSON.stringify(key)} in ${JSON.stringify(title)} (match is exact, case-sensitive)\nits keys: ${[...settings.keys()].join(", ")}`,
    );
  }
  return { kind: "value", key, value };
}

/** The `sns copy <id>` output on a settings note: the form, then the key names. */
export function renderCopyKeys(query: string, keys: string[]): string {
  return [copyHint(query, keys[0]!), ...keys.map((key) => `  ${key}`)].join("\n");
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
 * note is placed exactly once, under its deepest tag. Rows carry the note's
 * env-style setting count. Header counts come from the notes argument
 * (subtree totals), so --limit, --tag, and env filtering never show a count
 * for rows that are not listed. Tags with nothing under them are left out
 * (sns tags still shows them); untagged notes land in (untagged) last.
 */
export function renderTagGroups(graph: TagGraph, notes: ListedNote[]): string {
  const links = graph.links;
  const parentOf = graph.parentOf;
  const { depthOf, childrenOf, isRoot } = tagForest(parentOf);
  const byTitle = titleComparator(links.titleOf);
  const byRecency = (a: ListedNote, b: ListedNote) => b.updated_at - a.updated_at || a.uuid.localeCompare(b.uuid);

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

  // Header counts are subtree totals over the listed notes only. The visited
  // set cuts parent cycles: the second way around a loop adds nothing, so
  // server-supplied cycle data counts once instead of overflowing the stack.
  const countOf = new Map<string, number>();
  const measure = (tag: string, seen: Set<string>): number => {
    if (seen.has(tag)) return 0;
    seen.add(tag);
    let total = placed.get(tag)?.length ?? 0;
    for (const child of childrenOf.get(tag) ?? []) total += measure(child, seen);
    countOf.set(tag, total);
    return total;
  };
  for (const tag of links.titleOf.keys()) measure(tag, new Set());

  const widths = [
    Math.max(...notes.map((note) => note.title.replace(/\s+/g, " ").length), 5),
    Math.max(...notes.map((note) => formatWhen(note.updated_at).length), 16),
    Math.max(...notes.map((note) => String(note.settings).length), 1),
  ];
  const row = (note: ListedNote, depth: number) =>
    `${"  ".repeat(depth + 1)}${[
      note.title.replace(/\s+/g, " ").padEnd(widths[0] ?? 0),
      formatWhen(note.updated_at).padEnd(widths[1] ?? 0),
      String(note.settings).padStart(widths[2] ?? 0),
      note.uuid,
    ].join("  ").trimEnd()}`;

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
