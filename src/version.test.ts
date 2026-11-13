import { expect, test } from "bun:test";
import pkg from "../package.json" with { type: "json" };
import { VERSION } from "./version.ts";

test("the CLI version is the package version", () => {
  expect(VERSION).toBe(pkg.version);
  expect(VERSION).toMatch(/^\d+\.\d+\.\d+$/);
});
