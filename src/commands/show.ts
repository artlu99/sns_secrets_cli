import pc from "picocolors";
import type { CacheDb, ItemRow } from "../db.ts";
import { noteBody, noteScan, plainInventoryColor, renderNoteInventory, resolveNote } from "../notes.ts";
import { pageIfTall } from "../pager.ts";
import { openCache } from "./list.ts";

/**
 * The one rendering `sns` offers for a note: title, prose, keys — never a
 * value. `show` and the picker's View both draw it, so no command path leads
 * from a setting to stdout; values stay reachable only through `copy`. There
 * is no raw view: the full note belongs to Standard Notes' own apps.
 */
export function inventoryText(row: ItemRow, query: string): string {
  const note = noteBody(row);
  const scan = noteScan(row);
  // picocolors decides color support (tty, NO_COLOR, TERM=dumb); a pipe gets
  // the plain palette, and the whitespace-structural layout loses nothing.
  const terminal = Boolean(process.stdout.isTTY);
  return renderNoteInventory({
    title: note.title,
    settings: scan.settings,
    comments: scan.comments,
    prose: scan.prose,
    query,
    terminal,
    color: terminal && pc.isColorSupported ? pc : plainInventoryColor,
  });
}

/** Resolve, render, and print — show's body and the picker's View in one call. */
export async function printNoteInventory(
  db: CacheDb,
  query: string,
  options: { noPager?: boolean } = {},
): Promise<void> {
  const row = resolveNote(db, query, { all: false });
  await pageIfTall(inventoryText(row, query), { noPager: options.noPager, warn: false });
}

export async function showCommand(
  query: string,
  options: { noPager?: boolean } = {},
): Promise<void> {
  const db = await openCache();
  try {
    await printNoteInventory(db, query, options);
  } finally {
    db.close();
  }
}
