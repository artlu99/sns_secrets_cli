import { describe, expect, test } from "bun:test";
import { buildTagGraph, taggedNoteUuids } from "./tags.ts";
import { buildVault } from "./vault.ts";
import type { ItemRow } from "./store.ts";

function tagRow(uuid: string, title: string, parentUuid: string | null, noteUuids: string[]): ItemRow {
  const references = [
    ...(parentUuid ? [{ uuid: parentUuid, content_type: "Tag" }] : []),
    ...noteUuids.map((note) => ({ uuid: note, content_type: "Note" })),
  ];
  return {
    uuid,
    content_type: "Tag",
    updated_at: 1,
    deleted: 0,
    title,
    content: JSON.stringify({ title, references }),
  };
}

function noteRow(uuid: string, text: string, tagUuids: string[]): ItemRow {
  return {
    uuid,
    content_type: "Note",
    updated_at: 1,
    deleted: 0,
    title: `t-${uuid}`,
    content: JSON.stringify({
      title: `t-${uuid}`,
      text,
      references: tagUuids.map((tag) => ({ uuid: tag, content_type: "Tag" })),
    }),
  };
}

describe("tag graph", () => {
  test("inferred containment nests the child under the parent", () => {
    // child's notes ⊆ parent's notes, equal sets fold onto the alphabetically-first
    const rows = [
      tagRow("tag-parent", "Platforms", null, ["n1", "n2"]),
      tagRow("tag-child", "Vercel", null, ["n1", "n2"]),
      noteRow("n1", "A=1", ["tag-parent", "tag-child"]),
      noteRow("n2", "B=2", ["tag-parent", "tag-child"]),
    ];
    const graph = buildTagGraph(rows);
    expect(graph.parentOf.get("tag-child")).toBe("tag-parent");
    expect(graph.parentOf.get("tag-parent")).toBeNull();
    expect(taggedNoteUuids(graph, "tag-parent")).toEqual(new Set(["n1", "n2"]));
  });

  test("explicit SN folders win over inference, even with extra notes in the parent", () => {
    const rows = [
      tagRow("tag-parent", "Work", "tag-parent-explicit", ["n1", "n2"]),
      tagRow("tag-child", "Vercel", "tag-parent", ["n1"]),
      noteRow("n1", "A=1", ["tag-parent", "tag-child"]),
      noteRow("n2", "B=2", ["tag-parent"]),
    ];
    const graph = buildTagGraph(rows);
    expect(graph.parentOf.get("tag-child")).toBe("tag-parent");
    expect(taggedNoteUuids(graph, "tag-child")).toEqual(new Set(["n1"]));
  });

  test("a dangling parent renders top-level", () => {
    const rows = [tagRow("tag-orphan", "Lost", "tag-vanished", [])];
    const graph = buildTagGraph(rows);
    expect(graph.parentOf.get("tag-orphan")).toBeNull();
  });

  test("tombstoned notes drop out of tag counts", () => {
    const rows = [
      tagRow("tag-1", "T", null, ["n1", "n2"]),
      noteRow("n1", "A=1", ["tag-1"]),
      { ...noteRow("n2", "B=2", []), deleted: 1, content: "{}" },
    ];
    const graph = buildTagGraph(rows);
    expect(graph.links.tagToNotes.get("tag-1")?.size).toBe(1);
  });
});

describe("vault view", () => {
  test("keys parse, prose redacts assignment-shaped fragments", () => {
    const rows = [
      noteRow("n1", "# OLD_TOKEN=super-secret\nTOKEN=abc123\nprose line\n", []),
    ];
    const view = buildVault(new Map(rows.map((row) => [row.uuid, row])));
    expect(view.notes).toHaveLength(1);
    expect(view.notes[0]!.settings).toBe(1);
    const row = view.noteRows.get("n1")!;
    const keys = view.keysOf(row);
    expect(keys).toEqual([{ key: "TOKEN", value: "abc123", comment: null }]);
    const prose = view.displayProse(view.scan(row));
    expect(prose).toContain("OLD_TOKEN=[redacted]");
    expect(prose).not.toContain("super-secret");
    expect(prose).toContain("prose line");
  });

  test("untagged notes are counted, trashed notes are invisible", () => {
    const rows = [
      noteRow("n1", "A=1", []),
      noteRow("n2", "B=2", ["tag-1"]),
      tagRow("tag-1", "T", null, ["n2"]),
      { ...noteRow("n3", "C=3", []), content: JSON.stringify({ title: "t-n3", text: "", trashed: true }) },
    ];
    const view = buildVault(new Map(rows.map((row) => [row.uuid, row])));
    expect(view.notes.map((note) => note.uuid).sort()).toEqual(["n1", "n2"]);
    expect(view.untagged).toEqual(new Set(["n1"]));
  });
});
