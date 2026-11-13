import { listTags, tagForest, type ListedTag } from "../notes.ts";
import { page } from "../pager.ts";
import { openCache } from "./list.ts";

/**
 * Tags nested under a parent tag (SN folders are nested tags) render indented;
 * a parent that no longer exists leaves the child at the top level. Parent
 * cycles render as one chain hanging off each cycle root, appended after the
 * clean tree. Same forest as `sns list` — see tagForest.
 */
export function renderTagTree(tags: ListedTag[]): string {
  const byUuid = new Map(tags.map((tag) => [tag.uuid, tag]));
  const parentOf = new Map<string, string | null>(
    tags.map((tag) => [tag.uuid, tag.parent && byUuid.has(tag.parent) ? tag.parent : null]),
  );
  const { childrenOf, isRoot, cycleRoot } = tagForest(parentOf);
  for (const kids of childrenOf.values()) {
    kids.sort(
      (a, b) =>
        (byUuid.get(a)?.title ?? "").localeCompare(byUuid.get(b)?.title ?? "") || a.localeCompare(b),
    );
  }

  const rows: Array<[string, string]> = [];
  const emitted = new Set<string>();
  const emit = (tag: string, depth: number): void => {
    // the guard cuts parent cycles: the second way around stops the walk
    if (emitted.has(tag)) return;
    emitted.add(tag);
    const entry = byUuid.get(tag)!;
    rows.push([`${"  ".repeat(depth)}${entry.title}`, countLabel(entry.notes)]);
    for (const child of childrenOf.get(tag) ?? []) emit(child, depth + 1);
  };
  for (const tag of tags) {
    if (emitted.has(tag.uuid) || !isRoot(tag.uuid) || cycleRoot(tag.uuid)) continue;
    emit(tag.uuid, 0);
  }
  for (const tag of tags) {
    if (emitted.has(tag.uuid) || !cycleRoot(tag.uuid)) continue;
    emit(tag.uuid, 0);
  }
  for (const tag of tags) {
    if (!emitted.has(tag.uuid)) rows.push([tag.title, countLabel(tag.notes)]);
  }

  const width = Math.max(...rows.map(([label]) => label.length));
  return rows.map(([label, count]) => `${label.padEnd(width)}  ${count}`).join("\n");
}

function countLabel(notes: number): string {
  if (notes === 0) return "(empty)";
  return `(${notes} ${notes === 1 ? "note" : "notes"})`;
}

export async function tagsCommand(): Promise<void> {
  const db = await openCache();
  try {
    const tags = listTags(db);
    if (tags.length === 0) {
      console.log("no tags in the cache — run sns sync");
      return;
    }
    const tree = renderTagTree(tags);
    const rows = tree.split("\n").length;
    const screen = process.stdout.rows ?? 24;
    if (process.stdout.isTTY && rows > screen - 1) await page(tree);
    else console.log(tree);
  } finally {
    db.close();
  }
}
