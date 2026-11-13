import { expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { openDatabase, upsertItems, type ItemRow } from "./db.ts";
import {
  listNotes,
  listTags,
  planCopy,
  renderCopyKeys,
  renderNoteInventory,
  renderTagGroups,
  resolveNote,
  resolveTag,
  searchNotes,
  tagGraph,
  taggedNoteUuids,
} from "./notes.ts";
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
    const table = renderTagGroups(tagGraph(db), notes);
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
      {
        uuid: "bbbbbbbb-3333-3333-3333-333333333333",
        content_type: "Tag",
        updated_at: 500,
        deleted: 0,
        title: "prod",
        content: JSON.stringify({ title: "prod", references: [] }),
      },
    ]);
    const base = listNotes(db, { limit: 10 });
    expect(base.map((note) => note.content_type)).toEqual(["Note"]);
    const all = listNotes(db, { limit: 10, all: true });
    // --all adds key-bearing items, never tag rows
    expect(all.map((note) => note.content_type)).toEqual(["Note", "SN|ItemsKey"]);
    expect(all[1]?.title).toBe("SN|ItemsKey");
    const searchAll = searchNotes(db, "synthetic-key", { limit: 10, all: true });
    expect(searchAll.map((hit) => hit.content_type)).toEqual(["SN|ItemsKey"]);
    const searchBase = searchNotes(db, "synthetic-key", { limit: 10 });
    expect(searchBase).toEqual([]);
    const searchTag = searchNotes(db, "prod", { limit: 10, all: true });
    expect(searchTag).toEqual([]);
    // an explicit --type still reaches tags (debugging escape hatch)
    expect(listNotes(db, { type: "Tag", limit: 10 }).map((row) => row.title)).toEqual(["prod"]);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the env view lists only notes carrying KEY=VALUE settings, with per-note counts", () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-env-"));
  const db = openDatabase(join(dir, "cache.db"), randomBytes(32).toString("hex"));
  const creds = "eeeeeeee-1111-1111-1111-111111111111";
  const cert = "eeeeeeee-2222-2222-2222-222222222222";
  try {
    upsertItems(db, [
      {
        uuid: creds,
        content_type: "Note",
        updated_at: 3_000,
        deleted: 0,
        title: "Creds",
        content: JSON.stringify({
          title: "Creds",
          text: "staging secrets\n\nexport API_KEY=abc\nURL=https://x.test\nTOKEN=",
        }),
      },
      {
        uuid: cert,
        content_type: "Note",
        updated_at: 2_500,
        deleted: 0,
        title: "Cert",
        content: JSON.stringify({ title: "Cert", text: 'CERT="-----BEGIN\nMIIE\n-----END-----"' }),
      },
      {
        uuid: "eeeeeeee-3333-3333-3333-333333333333",
        content_type: "Note",
        updated_at: 2_000,
        deleted: 0,
        title: "Journal",
        content: JSON.stringify({ title: "Journal", text: "thoughts, and 1+1=2 inline" }),
      },
      {
        uuid: "eeeeeeee-4444-4444-4444-444444444444",
        content_type: "Note",
        updated_at: 1_500,
        deleted: 0,
        title: "TrashedCreds",
        content: JSON.stringify({ title: "TrashedCreds", text: "OLD=1", trashed: true }),
      },
    ]);
    const env = listNotes(db, { limit: 10, env: true });
    expect(env.map((note) => note.title)).toEqual(["Creds", "Cert"]);
    // export prefix, plain, and empty values all count; a multi-line quoted value counts once
    expect(env.map((note) => note.settings)).toEqual([3, 1]);
    // the default view and search still see prose-only notes
    expect(listNotes(db, { limit: 10 }).map((note) => note.title)).toEqual(["Creds", "Cert", "Journal"]);
    expect(searchNotes(db, "thoughts", { limit: 10 }).map((hit) => hit.title)).toEqual(["Journal"]);
    // count column sits between the timestamp and the uuid
    const table = renderTagGroups(tagGraph(db), env);
    const lines = table.split("\n");
    expect(lines.find((line) => line.includes("Creds"))?.endsWith(` 3  ${creds}`)).toBe(true);
    expect(lines.find((line) => line.includes("Cert"))?.endsWith(` 1  ${cert}`)).toBe(true);
    expect(table).toContain("(untagged) (2)");
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

    const euUuids = taggedNoteUuids(tagGraph(db), eu);
    expect(euUuids.has(noteA)).toBe(true);
    expect(euUuids.has(noteB)).toBe(false);
    expect(taggedNoteUuids(tagGraph(db), "cccccccc-aaaa-dddd-dddd-dddddddddddd").size).toBe(0);

    expect(resolveTag(tagGraph(db), prod).title).toBe("prod");
    expect(resolveTag(tagGraph(db), "eu").title).toBe("eu");
    // all four tags share the "cccccccc-aaaa" uuid prefix -> ambiguous
    expect(() => resolveTag(tagGraph(db), "cccccccc-aaaa")).toThrow(/matches 4 tags/);
    expect(() => resolveTag(tagGraph(db), "zzz")).toThrow(/no tag matches/);

    const underEu = listNotes(db, { limit: 10, tagUuids: euUuids });
    expect(underEu.map((row) => row.title)).toEqual(["Alpha"]);
    const underProd = listNotes(db, { limit: 10, tagUuids: taggedNoteUuids(tagGraph(db), prod) });
    expect(underProd.map((row) => row.title)).toEqual(["Alpha", "Beta"]);

    // hierarchical list: Alpha lives once, under eu (its deepest tag), nested
    // in prod; noteless tags (broken, orphan, deleted) do not render at all
    const listed = listNotes(db, { limit: 10 });
    const table = renderTagGroups(tagGraph(db), listed);
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
  expect(lines[0]).toBe("prod      (2 notes)");
  // children are sorted alphabetically, not by input order
  expect(lines[1]).toBe("  apac    (empty)");
  expect(lines[2]).toBe("  eu      (1 note)");
  expect(lines[3]).toBe("misc      (5 notes)");
  // parent cycles hang off their cycle root as one chain, after the clean tree
  expect(lines).toContain("loop-a    (empty)");
  expect(lines).toContain("  loop-b  (empty)");
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

    const table = renderTagGroups(tagGraph(db), listNotes(db, { limit: 10 }));
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

    const table = renderTagGroups(tagGraph(db), listNotes(db, { limit: 10 }));
    const lines = table.split("\n");
    // counts are subtree totals over the listed notes: big has none directly,
    // but its child chain lists one
    expect(lines[0]).toBe("big (1)");
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

test("explicit folder nesting does not depend on tag row order", () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-folder-order-"));
  const db = openDatabase(join(dir, "cache.db"), randomBytes(32).toString("hex"));
  const parent = "ffff0000-1111-1111-1111-111111111111";
  const child = "ffff0000-2222-2222-2222-222222222222";
  try {
    upsertItems(db, [
      {
        // synced first: when the child is processed, the parent is not yet in
        // the resolved map — the explicit link must survive anyway
        uuid: child,
        content_type: "Tag",
        updated_at: 1_000,
        deleted: 0,
        title: "child",
        content: JSON.stringify({
          title: "child",
          references: [{ uuid: parent, content_type: "Tag" }],
        }),
      },
      {
        uuid: parent,
        content_type: "Tag",
        updated_at: 2_000,
        deleted: 0,
        title: "zulu",
        content: JSON.stringify({ title: "zulu", references: [] }),
      },
    ]);
    expect(listTags(db).find((tag) => tag.title === "child")?.parent).toBe(parent);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("hard-deleted and trashed notes stop counting toward tags", () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-phantom-"));
  const db = openDatabase(join(dir, "cache.db"), randomBytes(32).toString("hex"));
  const work = "ffff1000-1111-1111-1111-111111111111";
  const dead = "ffff1000-2222-2222-2222-222222222222";
  const trashed = "ffff1000-3333-3333-3333-333333333333";
  const live = "ffff1000-4444-4444-4444-444444444444";
  try {
    upsertItems(db, [
      {
        // the tag's references still name a note deleted on another device
        uuid: work,
        content_type: "Tag",
        updated_at: 1_000,
        deleted: 0,
        title: "work",
        content: JSON.stringify({
          title: "work",
          references: [
            { uuid: dead, content_type: "Note" },
            { uuid: trashed, content_type: "Note" },
            { uuid: live, content_type: "Note" },
          ],
        }),
      },
      {
        uuid: dead,
        content_type: "Note",
        updated_at: 900,
        deleted: 1,
        title: null,
        content: "{}",
      },
      {
        uuid: trashed,
        content_type: "Note",
        updated_at: 800,
        deleted: 0,
        title: "Trashed",
        content: JSON.stringify({ title: "Trashed", trashed: true }),
      },
      {
        uuid: live,
        content_type: "Note",
        updated_at: 700,
        deleted: 0,
        title: "Live",
        content: JSON.stringify({ title: "Live", text: "x" }),
      },
    ]);
    const workTag = listTags(db).find((tag) => tag.title === "work");
    expect(workTag?.notes).toBe(1);
    const uuids = taggedNoteUuids(tagGraph(db), work);
    expect(uuids.has(live)).toBe(true);
    expect(uuids.has(dead)).toBe(false);
    expect(uuids.has(trashed)).toBe(false);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("list --tag on a folder reaches notes under its child tags", () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-subtree-"));
  const db = openDatabase(join(dir, "cache.db"), randomBytes(32).toString("hex"));
  const folder = "ffff2000-1111-1111-1111-111111111111";
  const leaf = "ffff2000-2222-2222-2222-222222222222";
  const note = "ffff2000-3333-3333-3333-333333333333";
  try {
    upsertItems(db, [
      {
        uuid: folder,
        content_type: "Tag",
        updated_at: 2_000,
        deleted: 0,
        title: "big",
        content: JSON.stringify({ title: "big", references: [] }),
      },
      {
        uuid: leaf,
        content_type: "Tag",
        updated_at: 1_000,
        deleted: 0,
        title: "leaf",
        content: JSON.stringify({
          title: "leaf",
          references: [
            { uuid: folder, content_type: "Tag" },
            { uuid: note, content_type: "Note" },
          ],
        }),
      },
      {
        uuid: note,
        content_type: "Note",
        updated_at: 3_000,
        deleted: 0,
        title: "child",
        content: JSON.stringify({
          title: "child",
          text: "x",
          references: [{ uuid: leaf, content_type: "Tag" }],
        }),
      },
    ]);
    // the list renders the note under big -> leaf; --tag big must find it too
    const uuids = taggedNoteUuids(tagGraph(db), folder);
    expect(uuids.has(note)).toBe(true);
    expect(listNotes(db, { limit: 10, tagUuids: uuids }).map((row) => row.title)).toEqual(["child"]);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("header counts reflect the listed notes, not the whole cache", () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-counts-"));
  const db = openDatabase(join(dir, "cache.db"), randomBytes(32).toString("hex"));
  const prod = "ffff3000-1111-1111-1111-111111111111";
  const noteA = "ffff3000-2222-2222-2222-222222222222";
  const noteB = "ffff3000-3333-3333-3333-333333333333";
  try {
    upsertItems(db, [
      {
        uuid: prod,
        content_type: "Tag",
        updated_at: 1_000,
        deleted: 0,
        title: "prod",
        content: JSON.stringify({
          title: "prod",
          references: [
            { uuid: noteA, content_type: "Note" },
            { uuid: noteB, content_type: "Note" },
          ],
        }),
      },
      {
        uuid: noteA,
        content_type: "Note",
        updated_at: 4_000,
        deleted: 0,
        title: "Alpha",
        content: JSON.stringify({ title: "Alpha", references: [{ uuid: prod, content_type: "Tag" }] }),
      },
      {
        uuid: noteB,
        content_type: "Note",
        updated_at: 3_000,
        deleted: 0,
        title: "Beta",
        content: JSON.stringify({ title: "Beta", references: [{ uuid: prod, content_type: "Tag" }] }),
      },
    ]);
    // --limit cut Beta out: the header must not claim it
    const table = renderTagGroups(tagGraph(db), listNotes(db, { limit: 1 }));
    expect(table.split("\n")[0]).toBe("prod (1)");
    expect(table).not.toContain("Beta");
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("tag titles are whitespace-normalized for rendering and matching", () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-title-"));
  const db = openDatabase(join(dir, "cache.db"), randomBytes(32).toString("hex"));
  const messy = "ffff4000-1111-1111-1111-111111111111";
  const note = "ffff4000-2222-2222-2222-222222222222";
  try {
    upsertItems(db, [
      {
        uuid: messy,
        content_type: "Tag",
        updated_at: 1_000,
        deleted: 0,
        title: "a\nb",
        content: JSON.stringify({ title: "a\nb", references: [{ uuid: note, content_type: "Note" }] }),
      },
      {
        uuid: note,
        content_type: "Note",
        updated_at: 2_000,
        deleted: 0,
        title: "child",
        content: JSON.stringify({ title: "child", references: [{ uuid: messy, content_type: "Tag" }] }),
      },
    ]);
    const table = renderTagGroups(tagGraph(db), listNotes(db, { limit: 10 }));
    expect(table.split("\n")[0]).toBe("a b (1)");
    expect(table).not.toContain("a\nb");
    // resolution matches the normalized title too
    expect(resolveTag(tagGraph(db), "a b").uuid).toBe(messy);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("renderNoteInventory lists keys, marks empties, and hints the copy form", () => {
  const settings = new Map([
    ["DB_HOST", "x"],
    ["TOKEN", ""],
    ["API_KEY", "y"],
  ]);
  const comments = new Map([
    ["DB_HOST", "# primary host"],
    ["TOKEN", "# rotate quarterly"],
  ]);
  const text = renderNoteInventory({
    title: "staging api",
    settings,
    comments,
    prose: "Notes on the staging API.\nAsk Alice before rotating.\n",
    query: "staging",
    terminal: true,
  });
  const lines = text.split("\n");
  expect(lines[0]).toBe("staging api");
  expect(lines[1]).toBe("───────────");
  // prose reads first, right under the title
  expect(lines.slice(2, 5)).toEqual(["Notes on the staging API.", "Ask Alice before rotating.", ""]);
  // keys sit below the prose in first-seen order, drawn as their note lines
  // with values withheld, empties marked, comments beside their key
  expect(lines.slice(5, 8)).toEqual(["DB_HOST=[redacted]  # primary host", "TOKEN=  (empty)  # rotate quarterly", "API_KEY=[redacted]"]);
  // the hint names one real key so the next command is pasteable
  expect(text.endsWith("copy a value:  sns copy staging DB_HOST")).toBe(true);
  // a query with a space is quoted so the hint pastes back correctly
  const quoted = renderNoteInventory({
    title: "t",
    settings,
    comments,
    prose: "",
    query: "prod db",
    terminal: true,
  });
  expect(quoted).toContain("sns copy 'prod db' DB_HOST");
  // blank-line-only prose adds no block, and a pipe gets no hint
  const bare = renderNoteInventory({
    title: "t",
    settings,
    comments: new Map(),
    prose: "\n\n",
    query: "t",
    terminal: false,
  });
  expect(bare.split("\n")).toEqual(["t", "─", "DB_HOST=[redacted]", "TOKEN=  (empty)", "API_KEY=[redacted]"]);
});

test("renderNoteInventory masks assignment-shaped fragments the parser rejected", () => {
  // a commented-out line and a mid-sentence mention carry values the parser
  // never parsed — the inventory still must not print them
  const text = renderNoteInventory({
    title: "t",
    settings: new Map([["TOKEN", "new"]]),
    comments: new Map([["TOKEN", "# OLD_TOKEN=hunter2 until Friday"]]),
    prose: "# DB_PASS=hunter2 (rotated)\nset KEY = abc midway through the note\nplain prose stays",
    query: "t",
    terminal: false,
  });
  expect(text).toContain("TOKEN=[redacted]  # OLD_TOKEN=[redacted] until Friday");
  expect(text).toContain("# DB_PASS=[redacted] (rotated)");
  expect(text).toContain("set KEY=[redacted] midway through the note");
  expect(text).toContain("plain prose stays");
  expect(text).not.toContain("hunter2");
  expect(text).not.toContain(" abc");
  // trailing base64 padding (`=` with nothing after it) and prose without an
  // assignment shape are left alone
  const harmless = renderNoteInventory({
    title: "t",
    settings: new Map([["A", "1"]]),
    comments: new Map(),
    prose: "ends with base64 cGFzc3dvcmQ=\nno equals here",
    query: "t",
    terminal: false,
  });
  expect(harmless).toContain("ends with base64 cGFzc3dvcmQ=");
  expect(harmless).toContain("no equals here");
});

test("renderCopyKeys shows the form first, then the key names", () => {
  expect(renderCopyKeys("staging", ["API_KEY", "API_URL", "TOKEN"])).toBe(
    ["copy a value:  sns copy staging API_KEY", "  API_KEY", "  API_URL", "  TOKEN"].join("\n"),
  );
});

test("planCopy picks the value, the key list, or the body", () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-copyplan-"));
  const db = openDatabase(join(dir, "cache.db"), randomBytes(32).toString("hex"));
  try {
    upsertItems(db, [
      {
        uuid: "cccccc00-0000-0000-0000-000000000001",
        content_type: "Note",
        updated_at: 2_000,
        deleted: 0,
        title: "Creds",
        content: JSON.stringify({
          title: "Creds",
          text: "staging secrets\nexport API_KEY=abc\nURL=https://x.test\nTOKEN=",
        }),
      },
      {
        uuid: "cccccc00-0000-0000-0000-000000000002",
        content_type: "Note",
        updated_at: 1_000,
        deleted: 0,
        title: "Journal",
        content: JSON.stringify({ title: "Journal", text: "thoughts" }),
      },
    ] satisfies ItemRow[]);
    const creds = resolveNote(db, "Creds");
    // an exact key copies its parsed value
    expect(planCopy(creds, "API_KEY")).toEqual({ kind: "value", key: "API_KEY", value: "abc" });
    // an empty value is still a value
    expect(planCopy(creds, "TOKEN")).toEqual({ kind: "value", key: "TOKEN", value: "" });
    // no key on a settings note copies nothing and lists the keys
    expect(planCopy(creds, undefined)).toEqual({ kind: "keys", keys: ["API_KEY", "URL", "TOKEN"] });
    // matching is exact and case-sensitive: neither API nor api_key selects API_KEY
    expect(() => planCopy(creds, "API")).toThrow(/no setting "API" in "Creds"/);
    expect(() => planCopy(creds, "api_key")).toThrow(/no setting "api_key" in "Creds"/);
    expect(() => planCopy(creds, "API")).toThrow(/its keys: API_KEY, URL, TOKEN/);
    // a note without settings still copies its body
    const journal = resolveNote(db, "Journal");
    expect(planCopy(journal, undefined)).toEqual({ kind: "body", body: "thoughts" });
    // a key on a note without settings is an error, not a silent body copy
    expect(() => planCopy(journal, "KEY")).toThrow(/has no KEY=VALUE settings/);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
