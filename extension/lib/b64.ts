/**
 * Buffer-free base64/hex helpers. The CLI's crypto modules lean on
 * node:Buffer; extension code runs in the browser, where these two primitives
 * (plus TextEncoder/TextDecoder) cover everything 004 and PKCE need.
 */

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function toHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * TextEncoder always yields a plain ArrayBuffer under the hood; the assertion
 * satisfies DOM's BufferSource (bun's types are looser than the DOM lib).
 */
export function utf8ToBytes(text: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(text) as Uint8Array<ArrayBuffer>;
}

export function bytesToUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

/** `+→-`, `/→_`, padding kept — matches node's manual replaceAll pairs. */
export function toBase64Url(b64: string): string {
  return b64.replaceAll("+", "-").replaceAll("/", "_");
}

/** node's `base64url` encoding: same alphabet, padding stripped. */
export function stripBase64Pad(b64Url: string): string {
  return b64Url.replace(/=+$/, "");
}
