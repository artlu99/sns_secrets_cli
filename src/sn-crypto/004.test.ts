import { expect, test } from "bun:test";
import { randomBytes } from "node:crypto";
import { canonicalJson, decrypt004, decryptItemContent, encrypt004, itemsKeyFromContent } from "./004.ts";

function hex(bytes = 32): string {
  return randomBytes(bytes).toString("hex");
}

test("004 round-trips a note through an items key", async () => {
  const master = hex();
  const itemsKey = hex();
  const itemsKeyId = crypto.randomUUID();
  const noteId = crypto.randomUUID();
  const wrappingKey = hex();
  const noteKey = hex();
  const itemsPayload = canonicalJson({ itemsKey, version: "004" });
  const itemsAad = { kp: { identifier: "a@b.c", version: "004" }, u: itemsKeyId, v: "004" };
  const noteAad = { u: noteId, v: "004" };
  const noteJson = JSON.stringify({ title: "Pins", text: "door code 2468" });

  const itemsItem = {
    uuid: itemsKeyId,
    content_type: "SN|ItemsKey",
    enc_item_key: await encrypt004(wrappingKey, master, itemsAad),
    content: await encrypt004(itemsPayload, wrappingKey, itemsAad),
  };
  const noteItem = {
    uuid: noteId,
    content_type: "Note",
    items_key_id: itemsKeyId,
    enc_item_key: await encrypt004(noteKey, itemsKey, noteAad),
    content: await encrypt004(noteJson, noteKey, noteAad),
  };

  const itemsPlain = await decryptItemContent(itemsItem, master);
  expect(itemsKeyFromContent(itemsPlain)).toBe(itemsKey);
  expect(await decryptItemContent(noteItem, itemsKey)).toBe(noteJson);
  await expect(decrypt004(noteItem.content, master)).rejects.toThrow(/decryption failed/);
});

test("a fifth signing component is not part of the authenticated data", async () => {
  const key = hex();
  const payload = await encrypt004("hello", key, { u: "1", v: "004" });
  const withSignature = `${payload}:${Buffer.from("signed-metadata").toString("base64")}`;
  expect(withSignature.split(":")).toHaveLength(5);
  expect(await decrypt004(withSignature, key)).toBe("hello");
});

test("tampered ciphertext does not decrypt", async () => {
  const key = hex();
  const payload = await encrypt004("hello", key, { u: "1", v: "004" });
  const parts = payload.split(":");
  parts[2] = `${parts[2]?.slice(0, -2)}aa`;
  await expect(decrypt004(parts.join(":"), key)).rejects.toThrow(/decryption failed/);
});
