import { UserError } from "../errors.ts";
import { formatWhen, searchNotes } from "../notes.ts";
import { openCache } from "./list.ts";

export async function searchCommand(
  query: string,
  options: { regex?: boolean; limit?: string; all?: boolean },
): Promise<void> {
  if (query.trim() === "") throw new UserError("search query is empty");
  const limit = Number(options.limit ?? "50");
  if (!Number.isInteger(limit) || limit < 1) throw new UserError("--limit must be a positive integer");
  const db = await openCache();
  try {
    const hits = searchNotes(db, query, { regex: options.regex, limit, all: options.all });
    if (hits.length === 0) {
      console.log("no matches");
      return;
    }
    const lines = hits.map(
      (hit) => `${hit.uuid}  ${formatWhen(hit.updated_at)}  ${hit.title}\n  ${hit.snippet}`,
    );
    console.log(lines.join("\n"));
  } finally {
    db.close();
  }
}
