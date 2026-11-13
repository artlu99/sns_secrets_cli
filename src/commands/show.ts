import { noteBody, noteHeader, noteScan, renderNoteInventory, resolveNote } from "../notes.ts";
import { page, pageIfTall } from "../pager.ts";
import { openCache } from "./list.ts";

export async function showCommand(
  query: string,
  options: { noPager?: boolean; all?: boolean; raw?: boolean } = {},
): Promise<void> {
  const db = await openCache();
  try {
    const row = resolveNote(db, query, { all: options.all ?? false });
    const note = noteBody(row);
    const scan = noteScan(row);
    // --raw and notes without settings show the full body, values included —
    // that content always goes through the pager path as before
    if (options.raw || scan.settings.size === 0) {
      await page(`${noteHeader(note.title)}\n\n${note.body}`, { noPager: options.noPager });
      return;
    }
    // inventory: the keys (with their trailing comments) and the prose the
    // parser skipped. No value reaches stdout — renderNoteInventory masks
    // assignment-shaped fragments in the prose — so a short inventory prints
    // directly and never warns.
    const text = renderNoteInventory({
      title: note.title,
      settings: scan.settings,
      comments: scan.comments,
      prose: scan.prose,
      query,
      terminal: Boolean(process.stdout.isTTY),
    });
    await pageIfTall(text, { warn: false });
  } finally {
    db.close();
  }
}
