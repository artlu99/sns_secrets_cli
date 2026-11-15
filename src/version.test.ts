import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import pkg from "../package.json" with { type: "json" };
import extensionPkg from "../extension/package.json" with { type: "json" };
import { VERSION } from "./version.ts";

test("the CLI version is the package version", () => {
  expect(VERSION).toBe(pkg.version);
  expect(VERSION).toMatch(/^\d+\.\d+\.\d+$/);
});

test("TS CLI, extension, and Rust crate share one release version", () => {
  expect(extensionPkg.version).toBe(pkg.version);
  const cargo = readFileSync(new URL("../rs/Cargo.toml", import.meta.url), "utf8");
  const match = cargo.match(/^version = "(\d+\.\d+\.\d+)"/m);
  expect(match?.[1]).toBe(pkg.version);
});
