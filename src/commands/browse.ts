import { intro, outro, select } from "@clack/prompts";
import { copyToClipboard } from "../clipboard.ts";
import { listNotes, noteBody, resolveNote, searchNotes } from "../notes.ts";
import { page } from "../pager.ts";
import { openCache } from "./list.ts";
import { promptLine, unwrap } from "./prompt.ts";

export async function browseCommand(): Promise<void> {
  intro("sns");
  const db = await openCache();
  try {
    while (true) {
      const query = await promptLine("Filter", "title, or empty for recent");
      const notes = query === "" ? listNotes(db, { limit: 20 }) : searchNotes(db, query, { limit: 20 });
      if (notes.length === 0) {
        console.error("no matches");
        continue;
      }
      const selected = unwrap(
        await select({
          message: "Note",
          options: [
            ...notes.map((note) => ({
              value: note.uuid,
              label: note.title,
              hint: note.protected ? "protected" : "not protected",
            })),
            { value: "__quit", label: "Quit" },
          ],
        }),
      );
      if (selected === "__quit") break;
      const action = unwrap(
        await select({
          message: notes.find((note) => note.uuid === selected)?.title ?? "Note",
          options: [
            { value: "view", label: "View" },
            { value: "copy", label: "Copy" },
            { value: "back", label: "Back" },
            { value: "quit", label: "Quit" },
          ],
        }),
      );
      if (action === "quit") break;
      if (action === "back") continue;
      const row = resolveNote(db, selected, { all: false });
      const note = noteBody(row);
      if (action === "view") await page(`${note.title}\n\n${note.body}`);
      if (action === "copy") console.log(await copyToClipboard(note.body));
    }
  } finally {
    db.close();
  }
  outro("done");
}
