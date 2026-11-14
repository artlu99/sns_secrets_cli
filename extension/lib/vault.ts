/**
 * The dashboard/popup view model over synced rows: note summaries, per-note
 * key inventories, and the tag forest — all derived, nothing stored.
 */
import {
  formatWhen,
  isTrashed,
  noteScan,
  redactAssignments,
} from "../../src/notes.ts";
import type { NoteScan } from "../../src/note-env.ts";
import { buildTagGraph, tagForest, taggedNoteUuids, type TagGraph } from "./tags.ts";
import type { ItemRow } from "./store.ts";

export type NoteSummary = {
  uuid: string;
  title: string;
  updatedAt: number;
  /** env-style KEY=VALUE pairs parsed from the note body (0 when prose-only). */
  settings: number;
};

export type KeyEntry = {
  key: string;
  value: string;
  comment: string | null;
};

/**
 * Display form for prose: blank lines (empty or whitespace-only) are dropped
 * from both ends — the padding around the parser's skipped lines reads as
 * noise in a panel — while interior blank lines and content indentation stay
 * exactly as written. Empty in, empty out.
 */
export function trimBlankLines(text: string): string {
  return text.replace(/^(\s*\n)+/, "").replace(/(\n\s*)+$/, "");
}

export type VaultView = {
  notes: NoteSummary[];
  noteRows: Map<string, ItemRow>;
  graph: TagGraph;
  /** Subtree membership per tag (the folder's child tags included). */
  notesInTag: (tagUuid: string) => Set<string>;
  /** Notes carrying no tag at all. */
  untagged: Set<string>;
  /** title/when helpers shared by both surfaces. */
  formatWhen: (ms: number) => string;
  scan: (row: ItemRow) => NoteScan;
  /** Prose safe to render: assignment-shaped fragments masked like `sns show`. */
  displayProse: (scan: NoteScan) => string;
  keysOf: (row: ItemRow) => KeyEntry[];
  forest: ReturnType<typeof tagForest>;
};

export function buildVault(items: Map<string, ItemRow>): VaultView {
  const rows = [...items.values()].filter((row) => !row.deleted);
  const notes: NoteSummary[] = rows
    .filter((row) => row.content_type === "Note" && !isTrashed(row.content))
    .map((row) => ({
      uuid: row.uuid,
      title: row.title ?? "(untitled)",
      updatedAt: row.updated_at,
      settings: noteScan(row).settings.size,
    }))
    .sort((a, b) => b.updatedAt - a.updatedAt || a.uuid.localeCompare(b.uuid));
  const noteRows = new Map(rows.filter((row) => row.content_type === "Note").map((row) => [row.uuid, row]));
  const graph = buildTagGraph(rows);
  const tagNotes = graph.links.tagToNotes;
  const untagged = new Set(
    [...noteRows.values()]
      .filter((row) => !isTrashed(row.content))
      .filter((row) => ![...tagNotes.values()].some((set) => set.has(row.uuid)))
      .map((row) => row.uuid),
  );
  return {
    notes,
    noteRows,
    graph,
    notesInTag: (tagUuid: string) => taggedNoteUuids(graph, tagUuid),
    untagged,
    formatWhen,
    scan: noteScan,
    displayProse: (scan) => trimBlankLines(redactAssignments(scan.prose)),
    keysOf: (row) => {
      const scanned = noteScan(row);
      return [...scanned.settings].map(([key, value]) => ({
        key,
        value,
        comment: scanned.comments.get(key) ?? null,
      }));
    },
    forest: tagForest(graph.parentOf),
  };
}

/** Flattened key index for the popup's search-and-copy: one entry per setting. */
export type KeyHit = {
  noteUuid: string;
  noteTitle: string;
  key: string;
  value: string;
};

export function keyIndex(view: VaultView): KeyHit[] {
  const hits: KeyHit[] = [];
  for (const note of view.notes) {
    const row = view.noteRows.get(note.uuid);
    if (!row) continue;
    for (const entry of view.keysOf(row)) {
      hits.push({ noteUuid: note.uuid, noteTitle: note.title, key: entry.key, value: entry.value });
    }
  }
  return hits;
}
