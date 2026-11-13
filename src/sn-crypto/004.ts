import { getSodium, sodiumReady } from "./sodium.ts";

export type EncryptedItem = {
  uuid: string;
  content_type: string;
  content?: string;
  enc_item_key?: string;
  items_key_id?: string | null;
  deleted?: boolean;
  updated_at?: string | number;
  updated_at_timestamp?: number;
};

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
}

export async function encrypt004(
  plaintext: string,
  keyHex: string,
  authenticatedData: Record<string, unknown>,
  nonce?: Uint8Array,
): Promise<string> {
  await sodiumReady();
  const sodium = getSodium();
  const key = sodium.from_hex(keyHex);
  const publicNonce = nonce ?? sodium.randombytes_buf(24);
  const aad = Buffer.from(canonicalJson(authenticatedData), "utf8").toString("base64");
  const cipher = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, null, publicNonce, key);
  sodium.memzero(key);
  return `004:${sodium.to_hex(publicNonce)}:${Buffer.from(cipher).toString("base64")}:${aad}`;
}

export async function decrypt004(payload: string, keyHex: string): Promise<string> {
  const parts = payload.split(":");
  if (parts[0] !== "004" || parts.length < 4) {
    throw new Error("not a protocol 004 payload");
  }
  const nonceHex = parts[1] ?? "";
  const cipherB64 = parts[2] ?? "";
  // 004:nonce:ciphertext:authenticatedData[:additionalData]
  // The AEAD uses only the authenticated-data component. The fifth component
  // is signing metadata and is not part of the Poly1305 input.
  const aad = parts[3] ?? "";
  if (!/^[0-9a-fA-F]{48}$/.test(nonceHex)) throw new Error("protocol 004 nonce is invalid");
  if (!/^[0-9a-fA-F]{64}$/.test(keyHex)) throw new Error("decryption key is invalid");
  await sodiumReady();
  const sodium = getSodium();
  const key = sodium.from_hex(keyHex);
  const nonce = sodium.from_hex(nonceHex);
  const cipher = Buffer.from(cipherB64, "base64");
  try {
    const plain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, cipher, aad, nonce, key);
    return Buffer.from(plain).toString("utf8");
  } catch {
    throw new Error("decryption failed");
  } finally {
    sodium.memzero(key);
  }
}

/** Decrypt one item. Items keys use the master key; everything else uses an items key. */
export async function decryptItemContent(item: EncryptedItem, parentKeyHex: string): Promise<string> {
  if (!item.enc_item_key || !item.content) throw new Error("item is missing ciphertext");
  const itemKey = (await decrypt004(item.enc_item_key, parentKeyHex)).trim();
  if (!/^[0-9a-fA-F]{64}$/.test(itemKey)) throw new Error("item key did not decrypt");
  return decrypt004(item.content, itemKey);
}

export function itemsKeyFromContent(content: string): string | null {
  try {
    const parsed = JSON.parse(content) as { itemsKey?: unknown };
    if (typeof parsed.itemsKey === "string" && /^[0-9a-fA-F]{64}$/.test(parsed.itemsKey)) {
      return parsed.itemsKey.toLowerCase();
    }
  } catch {
    return null;
  }
  return null;
}

export const ITEMS_KEY_TYPE = "SN|ItemsKey";

export function isItemsKey(item: { content_type: string }): boolean {
  return item.content_type === ITEMS_KEY_TYPE;
}
