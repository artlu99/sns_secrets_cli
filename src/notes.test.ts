import { expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { openDatabase, upsertItems } from "./db.ts";
import { listNotes, renderTable } from "./notes.ts";

test("list hides trashed notes and non-note types", () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-trash-"));
  const db = openDatabase(join(dir, "cache.db"), randomBytes(32).toString("hex"));
  try {
    upsertItems(db, [
      {
        uuid: "11111111-1111-1111-1111-111111111111",
        content_type: "Note",
        updated_at: 2_000,
        deleted: 0,
        title: "Kept",
        content: JSON.stringify({ title: "Kept", text: "stay", trashed: false, protected: true }),
      },
      {
        uuid: "22222222-2222-2222-2222-222222222222",
        content_type: "Note",
        updated_at: 1_000,
        deleted: 0,
        title: "Gone",
        content: JSON.stringify({ title: "Gone", text: "bin", trashed: true }),
      },
      {
        uuid: "44444444-4444-4444-4444-444444444444",
        content_type: "Note",
        updated_at: 1_500,
        deleted: 0,
        title: "Open",
        content: JSON.stringify({ title: "Open", text: "plain" }),
      },
      {
        uuid: "33333333-3333-3333-3333-333333333333",
        content_type: "SN|UserPreferences",
        updated_at: 3_000,
        deleted: 0,
        title: "Prefs",
        content: "{}",
      },
    ]);
    const notes = listNotes(db, { limit: 10 });
    expect(notes.map((note) => note.title)).toEqual(["Kept", "Open"]);
    expect(notes[0]?.protected).toBe(true);
    expect(notes[1]?.protected).toBe(false);
    const table = renderTable(notes);
    expect(table.split("\n")[0]).toContain("protected");
    expect(table.split("\n")[0]).not.toContain("type");
    expect(table).toContain("yes");
    expect(table).toContain("no");
    expect(table).not.toContain("Gone");
    expect(table).not.toContain("Prefs");
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
