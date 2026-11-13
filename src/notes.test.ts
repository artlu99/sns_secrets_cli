import { expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { openDatabase, upsertItems } from "./db.ts";
import { listNotes, listTags, renderTagGroups, resolveTag, searchNotes, taggedNoteUuids } from "./notes.ts";
import { renderTagTree } from "./commands/tags.ts";
import { UserError } from "./errors.ts";

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
    const table = renderTagGroups(db, notes);
    expect(table).toContain("(untagged) (2)");
    const lines = table.split("\n");
    expect(lines.findIndex((line) => line.includes("Kept"))).toBeLessThan(
      lines.findIndex((line) => line.includes("Open")),
    );
    expect(table).not.toContain("Gone");
    expect(table).not.toContain("Prefs");
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a cached row that is not JSON does not kill the listing", () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-broken-"));
  const db = openDatabase(join(dir, "cache.db"), randomBytes(32).toString("hex"));
  try {
    upsertItems(db, [
      {
        uuid: "aaaaaaaa-1111-1111-1111-111111111111",
        content_type: "Note",
        updated_at: 2_000,
        deleted: 0,
        title: "Broken",
        content: "not-json{{{",
      },
      {
        uuid: "aaaaaaaa-2222-2222-2222-222222222222",
        content_type: "Note",
        updated_at: 1_000,
        deleted: 0,
        title: "Good",
        content: JSON.stringify({ title: "Good", text: "fine" }),
      },
    ]);
    const notes = listNotes(db, { limit: 10 });
    expect(notes.map((note) => note.title)).toEqual(["Broken", "Good"]);
    const hits = searchNotes(db, "fine", { limit: 10 });
    expect(hits.map((hit) => hit.title)).toEqual(["Good"]);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("--all includes key-bearing rows; the default hides them", () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-all-"));
  const db = openDatabase(join(dir, "cache.db"), randomBytes(32).toString("hex"));
  try {
    upsertItems(db, [
      {
        uuid: "bbbbbbbb-1111-1111-1111-111111111111",
        content_type: "Note",
        updated_at: 2_000,
        deleted: 0,
        title: "Note",
        content: JSON.stringify({ title: "Note", text: "hello" }),
      },
      {
        uuid: "bbbbbbbb-2222-2222-2222-222222222222",
        content_type: "SN|ItemsKey",
        updated_at: 1_000,
        deleted: 0,
        title: null,
        content: JSON.stringify({ itemsKey: "synthetic-key-not-real", version: "004" }),
      },
    ]);
    const base = listNotes(db, { limit: 10 });
    expect(base.map((note) => note.content_type)).toEqual(["Note"]);
    const all = listNotes(db, { limit: 10, all: true });
    expect(all.map((note) => note.content_type)).toEqual(["Note", "SN|ItemsKey"]);
    expect(all[1]?.title).toBe("SN|ItemsKey");
    const searchAll = searchNotes(db, "synthetic-key", { limit: 10, all: true });
    expect(searchAll.map((hit) => hit.content_type)).toEqual(["SN|ItemsKey"]);
    const searchBase = searchNotes(db, "synthetic-key", { limit: 10 });
    expect(searchBase).toEqual([]);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("tags union both link sides and tolerate broken rows", () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-tags-"));
  const db = openDatabase(join(dir, "cache.db"), randomBytes(32).toString("hex"));
  const noteA = "cccccccc-1111-1111-1111-111111111111";
  const noteB = "cccccccc-2222-2222-2222-222222222222";
  const prod = "cccccccc-aaaa-1111-1111-111111111111";
  const eu = "cccccccc-aaaa-2222-2222-222222222222";
  const gone = "cccccccc-aaaa-3333-3333-333333333333";
  try {
    upsertItems(db, [
      {
        uuid: noteA,
        content_type: "Note",
        updated_at: 4_000,
        deleted: 0,
        title: "Alpha",
        content: JSON.stringify({
          title: "Alpha",
          text: "a",
          references: [{ uuid: prod, content_type: "Tag" }],
        }),
      },
      {
        uuid: noteB,
        content_type: "Note",
        updated_at: 3_000,
        deleted: 0,
        title: "Beta",
        content: JSON.stringify({
          title: "Beta",
          text: "b",
          references: [{ uuid: prod, content_type: "Tag" }],
        }),
      },
      {
        uuid: prod,
        content_type: "Tag",
        updated_at: 2_000,
        deleted: 0,
        title: "prod",
        content: JSON.stringify({
          title: "prod",
          references: [{ uuid: noteB, content_type: "Note" }],
        }),
      },
      {
        uuid: eu,
        content_type: "Tag",
        updated_at: 1_000,
        deleted: 0,
        title: "eu",
        content: JSON.stringify({
          title: "eu",
          references: [
            { uuid: noteA, content_type: "Note" },
            { uuid: prod, content_type: "Tag" },
          ],
        }),
      },
      {
        // child of a tag that no longer exists -> counts as top level
        uuid: gone,
        content_type: "Tag",
        updated_at: 900,
        deleted: 0,
        title: "orphan",
        content: JSON.stringify({
          title: "orphan",
          references: [{ uuid: "cccccccc-aaaa-9999-9999-999999999999", content_type: "Tag" }],
        }),
      },
      {
        // a tag whose content is not JSON must not kill the listing
        uuid: "cccccccc-aaaa-4444-4444-444444444444",
        content_type: "Tag",
        updated_at: 800,
        deleted: 0,
        title: "broken",
        content: "not-json{{{",
      },
      {
        uuid: "cccccccc-aaaa-5555-5555-555555555555",
        content_type: "Tag",
        updated_at: 700,
        deleted: 1,
        title: "deleted",
        content: "{}",
      },
    ]);
    const tags = listTags(db);
    expect(tags.map((tag) => tag.title)).toEqual(["broken", "eu", "orphan", "prod"]);
    expect(tags.find((tag) => tag.title === "prod")?.notes).toBe(2); // Alpha + Beta
    // explicit parent (folder) wins over inference
    expect(tags.find((tag) => tag.title === "eu")?.parent).toBe(prod);
    expect(tags.find((tag) => tag.title === "eu")?.notes).toBe(1); // Alpha
    expect(tags.find((tag) => tag.title === "orphan")?.notes).toBe(0);
    expect(tags.find((tag) => tag.title === "broken")?.notes).toBe(0);

    const euUuids = taggedNoteUuids(db, eu);
    expect(euUuids.has(noteA)).toBe(true);
    expect(euUuids.has(noteB)).toBe(false);
    expect(taggedNoteUuids(db, "cccccccc-aaaa-dddd-dddd-dddddddddddd").size).toBe(0);

    expect(resolveTag(db, prod).title).toBe("prod");
    expect(resolveTag(db, "eu").title).toBe("eu");
    expect(() => resolveTag(db, "cccc")).toThrow(UserError);
    expect(() => resolveTag(db, "zzz")).toThrow(/no tag matches/);

    const underEu = listNotes(db, { limit: 10, tagUuids: euUuids });
    expect(underEu.map((row) => row.title)).toEqual(["Alpha"]);
    const underProd = listNotes(db, { limit: 10, tagUuids: taggedNoteUuids(db, prod) });
    expect(underProd.map((row) => row.title)).toEqual(["Alpha", "Beta"]);

    // hierarchical list: Alpha lives once, under eu (its deepest tag), nested
    // in prod; noteless tags (broken, orphan, deleted) do not render at all
    const listed = listNotes(db, { limit: 10 });
    const table = renderTagGroups(db, listed);
    const lines = table.split("\n");
    expect(lines[0]).toBe("prod (2)");
    expect(lines[1]).toContain("Beta");
    expect(lines[2]).toBe("  eu (1)");
    expect(lines[3]).toContain("Alpha");
    expect(table.match(/Alpha/g)?.length).toBe(1); // exactly once
    expect(table).not.toContain("orphan");
    expect(table).not.toContain("broken");
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("renderTagTree nests children and aligns counts", () => {
  const tags = [
    { uuid: "prod", title: "prod", parent: null, notes: 2 },
    { uuid: "eu", title: "eu", parent: "prod", notes: 1 },
    { uuid: "apac", title: "apac", parent: "prod", notes: 0 },
    { uuid: "misc", title: "misc", parent: null, notes: 5 },
    { uuid: "loop-a", title: "loop-a", parent: "loop-b", notes: 0 },
    { uuid: "loop-b", title: "loop-b", parent: "loop-a", notes: 0 },
  ];
  const lines = renderTagTree(tags).split("\n");
  expect(lines[0]).toBe("prod    (2 notes)");
  expect(lines[1]).toBe("  eu    (1 note)");
  expect(lines[2]).toBe("  apac  (empty)");
  expect(lines[3]).toBe("misc    (5 notes)");
  // cycle members fall back to the flat list at the end
  expect(lines).toContain("loop-a  (empty)");
  expect(lines).toContain("loop-b  (empty)");
});

test("list infers the hierarchy from note membership and renders each note once", () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-hierarchy-"));
  const db = openDatabase(join(dir, "cache.db"), randomBytes(32).toString("hex"));
  const tag = (suffix: string, title: string, refs: string[]) => ({
    uuid: `dddddddd-aaaa-${suffix}`,
    content_type: "Tag",
    updated_at: 1_000,
    deleted: 0,
    title,
    content: JSON.stringify({
      title,
      references: refs.map((r) => ({ uuid: `dddddddd-bbbb-${r}`, content_type: "Note" })),
    }),
  });
  const note = (suffix: string, title: string, updated: number, tags: string[]) => ({
    uuid: `dddddddd-bbbb-${suffix}`,
    content_type: "Note",
    updated_at: updated,
    deleted: 0,
    title,
    content: JSON.stringify({
      title,
      text: title,
      references: tags.map((t) => ({ uuid: `dddddddd-aaaa-${t}`, content_type: "Tag" })),
    }),
  });
  try {
    const n1 = "1111", n2 = "2222", n3 = "3333", n4 = "4444", n5 = "5555", n6 = "6666", n7 = "7777";
    upsertItems(db, [
      // {1,2,3} ⊂ infra, {4,5,6} ⊂ infra, apps = social = {7}
      tag("ta", "data", [n1, n2, n3]),
      tag("tb", "compute", [n4, n5, n6]),
      tag("tc", "apps", [n7]),
      tag("td", "social", [n7]),
      tag("te", "infra", [n1, n2, n3, n4, n5, n6]),
      note(n1, "one", 7_000, ["data", "infra"]),
      note(n2, "two", 6_000, ["data", "infra"]),
      note(n3, "three", 5_000, ["data", "infra"]),
      note(n4, "four", 4_000, ["compute", "infra"]),
      note(n5, "five", 3_000, ["compute", "infra"]),
      note(n6, "six", 2_000, ["compute", "infra"]),
      note(n7, "seven", 1_000, ["apps", "social"]),
    ]);
    // inference is visible in sns tags too
    const tags = listTags(db);
    expect(tags.find((t) => t.title === "data")?.parent).toBe(tags.find((t) => t.title === "infra")?.uuid);
    expect(tags.find((t) => t.title === "compute")?.parent).toBe(tags.find((t) => t.title === "infra")?.uuid);
    expect(tags.find((t) => t.title === "social")?.parent).toBe(tags.find((t) => t.title === "apps")?.uuid);
    expect(tags.find((t) => t.title === "infra")?.parent).toBeNull();

    const table = renderTagGroups(db, listNotes(db, { limit: 10 }));
    const lines = table.split("\n");
    // headers: alphabetical at each level, counts are full tag membership
    expect(lines[0]).toBe("apps (1)");
    expect(lines[1]).toBe("  social (1)");
    expect(lines[2]).toContain("dddddddd-bbbb-7777");
    expect(lines[3]).toBe("");
    expect(lines[4]).toBe("infra (6)");
    expect(lines[5]).toBe("  compute (3)");
    expect(lines[6]).toContain("dddddddd-bbbb-4444"); // newest first inside each group
    expect(lines[7]).toContain("dddddddd-bbbb-5555");
    expect(lines[8]).toContain("dddddddd-bbbb-6666");
    expect(lines[9]).toBe("  data (3)");
    expect(lines[10]).toContain("dddddddd-bbbb-1111");
    expect(lines[11]).toContain("dddddddd-bbbb-2222");
    expect(lines[12]).toContain("dddddddd-bbbb-3333");
    // exactly once across the whole tree
    const uuids = table.match(/dddddddd-bbbb-[0-9]{4}/g) ?? [];
    expect(new Set(uuids).size).toBe(7);
    expect(uuids.length).toBe(7);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an explicit folder wins over the inferred parent, untagged notes render last", () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-explicit-"));
  const db = openDatabase(join(dir, "cache.db"), randomBytes(32).toString("hex"));
  try {
    const big = "eeeeeeee-1111-1111-1111-111111111111";
    const small = "eeeeeeee-2222-2222-2222-222222222222";
    const tagged = "eeeeeeee-3333-3333-3333-333333333333";
    upsertItems(db, [
      {
        // explicit parent of `tagged`, but holds no notes itself
        uuid: big,
        content_type: "Tag",
        updated_at: 1_000,
        deleted: 0,
        title: "big",
        content: JSON.stringify({ title: "big", references: [] }),
      },
      {
        // would win inference (equal note set, alphabetically first), but has
        // no explicit link — `tagged` must stay under big
        uuid: small,
        content_type: "Tag",
        updated_at: 900,
        deleted: 0,
        title: "small",
        content: JSON.stringify({ title: "small", references: [] }),
      },
      {
        uuid: tagged,
        content_type: "Tag",
        updated_at: 800,
        deleted: 0,
        title: "leaf",
        content: JSON.stringify({
          title: "leaf",
          references: [{ uuid: big, content_type: "Tag" }],
        }),
      },
      {
        uuid: "eeeeeeee-4444-4444-4444-444444444444",
        content_type: "Note",
        updated_at: 5_000,
        deleted: 0,
        title: "child",
        content: JSON.stringify({
          title: "child",
          text: "x",
          references: [
            { uuid: tagged, content_type: "Tag" },
            { uuid: small, content_type: "Tag" },
          ],
        }),
      },
      {
        uuid: "eeeeeeee-5555-5555-5555-555555555555",
        content_type: "Note",
        updated_at: 4_000,
        deleted: 0,
        title: "loose",
        content: JSON.stringify({ title: "loose", text: "y" }),
      },
    ]);
    expect(listTags(db).find((t) => t.title === "leaf")?.parent).toBe(big);

    const table = renderTagGroups(db, listNotes(db, { limit: 10 }));
    const lines = table.split("\n");
    expect(lines[0]).toBe("big (0)");
    expect(lines[1]).toBe("  leaf (1)");
    // `small` holds the note too, but its set equals leaf's, so it folds under
    // leaf (alphabetical) — the note still renders exactly once, in the chain
    expect(lines[2]).toBe("    small (1)");
    expect(lines[3]).toContain("eeeeeeee-4444-4444-4444-444444444444");
    expect(lines[4]).toBe("");
    expect(lines[5]).toBe("(untagged) (1)");
    expect(lines[6]).toContain("eeeeeeee-5555-5555-5555-555555555555");
    expect(table.match(/eeeeeeee-4444/g)?.length).toBe(1);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
