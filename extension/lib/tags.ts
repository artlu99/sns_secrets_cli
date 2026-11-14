/**
 * The tag graph, built from in-memory rows instead of sqlite. tagLinks is the
 * CLI's src/notes.ts::tagLinks ported to take ItemRow[]; resolveParents,
 * tagForest, and taggedNoteUuids are imported from the CLI so nesting rules
 * (explicit folders, inferred containment, cycle handling) stay identical.
 */
import { isTrashed, resolveParents, tagForest, taggedNoteUuids } from "../../src/notes.ts";
import type { ItemRow } from "./store.ts";

export { tagForest, taggedNoteUuids };
export type TagLinks = {
  titleOf: Map<string, string>;
  parentOf: Map<string, string | null>;
  tagToNotes: Map<string, Set<string>>;
};

export type TagGraph = { links: TagLinks; parentOf: Map<string, string | null> };

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

/** Tag titles render and resolve everywhere, so whitespace is normalized once. */
function normalizeTitle(title: string | null): string {
  return (title ?? "").replace(/\s+/g, " ").trim() || "(untitled)";
}

/**
 * Both link sides are unioned — the tag's references and the note's — since the
 * app keeps them in sync but either side can lag mid-update. Tombstoned notes
 * (deleted on another device) are dropped so counts shrink.
 */
export function tagLinksFromRows(rows: ItemRow[]): TagLinks {
  const tagRows = rows.filter((row) => row.content_type === "Tag" && !row.deleted);
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
  const live = new Set<string>();
  for (const row of rows) {
    if (row.content_type !== "Note" || row.deleted) continue;
    if (isTrashed(row.content)) continue;
    live.add(row.uuid);
    for (const ref of contentReferences(row.content)) {
      if (ref.content_type === "Tag") tagToNotes.get(ref.uuid)?.add(row.uuid);
    }
  }
  for (const set of tagToNotes.values()) {
    for (const uuid of [...set]) if (!live.has(uuid)) set.delete(uuid);
  }
  return { titleOf, parentOf, tagToNotes };
}

/** The full tag graph: query it once, pass it everywhere. */
export function buildTagGraph(rows: ItemRow[]): TagGraph {
  const links = tagLinksFromRows(rows);
  return { links, parentOf: resolveParents(links) };
}

export type TagRow = { tag: string; depth: number };

/**
 * The sidebar tree as flat rows (tag + nesting depth), in render order.
 * Cycle-safe: explicit folders and inferred containment can disagree and
 * form a parent cycle (platforms → vercel → platforms); without the emitted
 * set the recursion never terminates — each tag renders exactly once, the
 * same cut `sns list`'s renderer makes.
 */
export function flattenTagTree(graph: TagGraph, forest: ReturnType<typeof tagForest>): TagRow[] {
  const rows: TagRow[] = [];
  const emitted = new Set<string>();
  const byTitle = (a: string, b: string) =>
    (graph.links.titleOf.get(a) ?? "").localeCompare(graph.links.titleOf.get(b) ?? "") || a.localeCompare(b);
  const walk = (tag: string, depth: number): void => {
    if (emitted.has(tag)) return;
    emitted.add(tag);
    rows.push({ tag, depth });
    for (const child of (forest.childrenOf.get(tag) ?? []).slice().sort(byTitle)) {
      walk(child, depth + 1);
    }
  };
  for (const tag of [...graph.links.titleOf.keys()].filter((t) => forest.isRoot(t)).sort(byTitle)) {
    walk(tag, 0);
  }
  return rows;
}
