import { describe, expect, test } from "bun:test";
// The CLI implementation (node:crypto) and the extension port (WebCrypto) must
// agree byte-for-byte — a drift here breaks login silently.
import { createPkce as cliCreatePkce, pkceChallenge as cliChallenge } from "../../src/sn-api.ts";
import { createPkce, pkceChallenge } from "./sn-api.ts";

describe("pkce", () => {
  test("extension challenge matches the CLI's for fixed verifiers", async () => {
    for (const verifier of [
      "abcdefghij",
      "abcdefgh+ij/k",
      "with=padding==",
      "A".repeat(86),
      "~= tilde is left alone in base64url ~=",
    ]) {
      expect(await pkceChallenge(verifier)).toBe(cliChallenge(verifier));
    }
  });

  test("CLI-generated verifier: extension challenge equals CLI challenge", async () => {
    const { verifier, challenge } = cliCreatePkce();
    expect(await pkceChallenge(verifier)).toBe(challenge);
  });

  test("extension-generated pair: CLI challenge equals extension challenge", async () => {
    const { verifier, challenge } = await createPkce();
    expect(verifier).toMatch(/^[A-Za-z0-9_-]+={0,2}$/); // +/ swapped, padding kept
    expect(cliChallenge(verifier)).toBe(challenge);
  });
});
