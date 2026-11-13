import { describe, expect, test } from "bun:test";
import { decrypt004 as cliDecrypt, encrypt004 as cliEncrypt } from "../../src/sn-crypto/004.ts";
import { decrypt004, encrypt004 } from "./crypto.ts";

const KEY = "11".repeat(32);
const AAD = { u: "0f9e2c6e-0000-4000-8000-000000000001", v: "Note" };

describe("004 interop", () => {
  test("round trips within the extension", async () => {
    const payload = await encrypt004("hello secrets", KEY, AAD);
    expect(await decrypt004(payload, KEY)).toBe("hello secrets");
  });

  test("extension decrypts CLI ciphertext", async () => {
    const payload = await cliEncrypt("from the CLI", KEY, AAD);
    expect(await decrypt004(payload, KEY)).toBe("from the CLI");
  });

  test("CLI decrypts extension ciphertext", async () => {
    const payload = await encrypt004("from the extension", KEY, AAD);
    expect(await cliDecrypt(payload, KEY)).toBe("from the extension");
  });

  test("payload shape matches the CLI's exactly (nonce, aad placement)", async () => {
    const nonce = new Uint8Array(24).fill(7);
    const ext = await encrypt004("same nonce", KEY, AAD, nonce);
    const cli = await cliEncrypt("same nonce", KEY, AAD, nonce);
    expect(ext).toBe(cli); // deterministic inputs → identical strings
  });

  test("a wrong key fails closed", async () => {
    const payload = await encrypt004("x", KEY, AAD);
    expect(decrypt004(payload, "22".repeat(32))).rejects.toThrow("decryption failed");
  });
});
