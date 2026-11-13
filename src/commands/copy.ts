import { copyToClipboard } from "../clipboard.ts";
import { noteBody, resolveNote } from "../notes.ts";
import { openCache } from "./list.ts";

export async function copyCommand(query: string): Promise<void> {
  const db = await openCache();
  try {
    const row = resolveNote(db, query, { all: false });
    const note = noteBody(row);
    const message = await copyToClipboard(note.body);
    console.log(message);
  } finally {
    db.close();
  }
}
