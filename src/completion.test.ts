import { expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { openDatabase, upsertItems, type ItemRow } from "./db.ts";
import { completeArgv, completionScript, SUBCOMMANDS } from "./completion.ts";
import { buildProgram } from "./program.ts";

function seededDb(extra: ItemRow[] = []) {
  const dir = mkdtempSync(join(tmpdir(), "sns-complete-"));
  const path = join(dir, "cache.db");
  const key = randomBytes(32).toString("hex");
  const db = openDatabase(path, key);
  upsertItems(db, [
    {
      uuid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      content_type: "Note",
      updated_at: 2,
      deleted: 0,
      title: "Staging",
      content: JSON.stringify({
        title: "Staging",
        text: "deploy notes\nAPI_KEY=secret\nDB_HOST=db.example\n",
      }),
    },
    {
      uuid: "11111111-2222-3333-4444-555555555555",
      content_type: "Note",
      updated_at: 1,
      deleted: 0,
      title: "Personal",
      content: JSON.stringify({ title: "Personal", text: "just prose" }),
    },
    ...extra,
  ]);
  return { dir, db };
}

test("completion's subcommand list matches the commander program", () => {
  // commander keeps the flag on a runtime `_hidden` field (typings omit it).
  const declared = buildProgram()
    .commands.filter((command) => !(command as unknown as { _hidden?: boolean })._hidden)
    .map((command) => command.name());
  const expected: string[] = SUBCOMMANDS.filter((name) => name !== "help");
  expect(expected).toEqual(declared);
});

test("subcommand completion filters by prefix", () => {
  expect(completeArgv(["sns", "sh"], 1, null)).toEqual(["show"]);
  expect(completeArgv(["sns"], 1, null)).toContain("copy");
  expect(completeArgv(["sns"], 1, null)).toContain("completion");
  expect(completeArgv(["sns"], 1, null)).toContain("sink");
});

test("completion shell argument lists bash and zsh", () => {
  expect(completeArgv(["sns", "completion", ""], 2, null)).toEqual(["bash", "zsh"]);
  expect(completeArgv(["sns", "completion", "z"], 2, null)).toEqual(["zsh"]);
});

test("show and copy complete note titles and short uuids", () => {
  const { dir, db } = seededDb();
  try {
    const show = completeArgv(["sns", "show", ""], 2, db);
    expect(show).toContain("Staging");
    expect(show).toContain("Personal");
    expect(show).toContain("aaaaaaaa");
    expect(show).toContain("11111111");

    const filtered = completeArgv(["sns", "copy", "Sta"], 2, db);
    expect(filtered).toEqual(["Staging"]);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("copy's second argument completes setting keys for the resolved note", () => {
  const { dir, db } = seededDb();
  try {
    const keys = completeArgv(["sns", "copy", "Staging", ""], 3, db);
    expect(keys).toEqual(["API_KEY", "DB_HOST"]);
    expect(completeArgv(["sns", "copy", "Staging", "DB"], 3, db)).toEqual(["DB_HOST"]);
    expect(completeArgv(["sns", "copy", "nope", ""], 3, db)).toEqual([]);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("sink's key argument completes like copy's; its path slot gets no candidates", () => {
  const { dir, db } = seededDb();
  try {
    expect(completeArgv(["sns", "sink", "Staging", ""], 3, db)).toEqual(["API_KEY", "DB_HOST"]);
    expect(completeArgv(["sns", "sink", "Staging", "DB", "/run/user/0/t"], 3, db)).toEqual(["DB_HOST"]);
    expect(completeArgv(["sns", "sink", "Staging", "API_KEY", ""], 4, db)).toEqual([]);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("completion scripts mention __complete and the shell hook", () => {
  const bash = completionScript("bash");
  expect(bash).toContain("sns __complete");
  expect(bash).toContain("complete -o nospace -F _sns sns");
  expect(bash).toContain("printf '%q'");
  const zsh = completionScript("zsh");
  expect(zsh).toContain("sns __complete");
  expect(zsh).toContain("compdef _sns sns");
  expect(zsh).not.toContain("compadd -Q");
});

test("note completion is case-insensitive, like the resolver", () => {
  const { dir, db } = seededDb();
  try {
    expect(completeArgv(["sns", "copy", "sta"], 2, db)).toEqual(["Staging"]);
    expect(completeArgv(["sns", "show", "PERSONAL"], 2, db)).toEqual(["Personal"]);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a title that is another title's prefix is never offered (it resolves as ambiguous)", () => {
  const { dir, db } = seededDb([
    {
      uuid: "99999999-8888-7777-6666-555555555555",
      content_type: "Note",
      updated_at: 3,
      deleted: 0,
      title: "API Keys",
      content: JSON.stringify({ title: "API Keys", text: "prose" }),
    },
    {
      uuid: "44444444-3333-2222-1111-000000000000",
      content_type: "Note",
      updated_at: 4,
      deleted: 0,
      title: "API Keys Old",
      content: JSON.stringify({ title: "API Keys Old", text: "prose" }),
    },
  ]);
  try {
    const candidates = completeArgv(["sns", "show", ""], 2, db);
    expect(candidates).toContain("API Keys Old"); // unique prefix — offered
    expect(candidates).not.toContain("API Keys"); // prefix of two notes — ambiguous
    expect(candidates).not.toContain("API Keys Old Old");
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("flags do not shift the note argument's position", () => {
  const { dir, db } = seededDb();
  try {
    expect(completeArgv(["sns", "show", "--no-pager", "Sta"], 3, db)).toEqual(["Staging"]);
    expect(completeArgv(["sns", "show", "--no-pager", ""], 3, db)).toContain("Staging");
    expect(completeArgv(["sns", "show", "--"], 2, db)).toEqual([]);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
