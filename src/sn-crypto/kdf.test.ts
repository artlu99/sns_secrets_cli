import { expect, test } from "bun:test";
import { deriveRootKey } from "./kdf.ts";

test("004 root key matches the published vector", async () => {
  const root = await deriveRootKey("debugtest", {
    version: "004",
    identifier: "sn004@lessknown.co.uk",
    pwNonce: "2c409996650e46c748856fbd6aa549f89f35be055a8f9bfacdf0c4b29b2152e9",
  });
  expect(root.masterKey).toBe("2396d6ac0bc70fe45db1d2bcf3daa522603e9c6fcc88dc933ce1a3a31bbc08ed");
  expect(root.serverPassword).toBe("a5eb9fbc767eafd6e54fd9d3646b19520e038ba2ccc9cceddf2340b37b788b47");
}, 20_000);

test("non-004 versions are refused", async () => {
  await expect(
    deriveRootKey("debugtest", { version: "003", identifier: "a@b.c", pwNonce: "abc" }),
  ).rejects.toThrow(/not supported/);
});
