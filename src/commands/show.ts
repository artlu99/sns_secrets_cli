import { noteBody, resolveNote } from "../notes.ts";
import { page } from "../pager.ts";
import { openCache } from "./list.ts";

export async function showCommand(query: string, options: { noPager?: boolean; all?: boolean } = {}): Promise<void> {
  const db = await openCache();
  try {
    const row = resolveNote(db, query, { all: options.all ?? false });
    const note = noteBody(row);
    const text = `${note.title}\n${"─".repeat(Math.min(note.title.length, 40))}\n\n${note.body}`;
    await page(text, { noPager: options.noPager });
  } finally {
    db.close();
  }
}
