import { listTags, type ListedTag } from "../notes.ts";
import { openCache } from "./list.ts";

/**
 * Tags nested under a parent tag (SN folders are nested tags) render indented;
 * a parent that no longer exists leaves the child at the top level. Cycles are
 * cut at the first revisit.
 */
export function renderTagTree(tags: ListedTag[]): string {
  const known = new Set(tags.map((tag) => tag.uuid));
  const byUuid = new Map(tags.map((tag) => [tag.uuid, tag]));
  const depthOf = new Map<string, number>();
  const depth = (tag: ListedTag): number => {
    const cached = depthOf.get(tag.uuid);
    if (cached !== undefined) return cached;
    depthOf.set(tag.uuid, 0);
    const parent = tag.parent && byUuid.get(tag.parent);
    const result = parent ? depth(parent) + 1 : 0;
    depthOf.set(tag.uuid, result);
    return result;
  };
  for (const tag of tags) depth(tag);

  const rows: Array<[string, string]> = [];
  const emitted = new Set<string>();
  const emit = (parent: string | null): void => {
    for (const tag of tags) {
      if (emitted.has(tag.uuid)) continue;
      const actual = tag.parent && known.has(tag.parent) ? tag.parent : null;
      if (actual !== parent) continue;
      emitted.add(tag.uuid);
      rows.push([`${"  ".repeat(depthOf.get(tag.uuid) ?? 0)}${tag.title}`, countLabel(tag.notes)]);
      emit(tag.uuid);
    }
  };
  emit(null);
  // Tags caught in a parent cycle never hang off a root; show them flat.
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
    console.log(renderTagTree(tags));
  } finally {
    db.close();
  }
}
