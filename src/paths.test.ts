import { expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ensureConfigDir, readPlainConfig, withConfigDir } from "./paths.ts";

test("an empty SN_EMAIL in the template .env does not shadow the environment", () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-paths-"));
  const previous = process.env.SN_EMAIL;
  try {
    withConfigDir(dir, () => {
      ensureConfigDir(); // writes the template with an empty SN_EMAIL=
      process.env.SN_EMAIL = "env@example.com";
      expect(readPlainConfig().email).toBe("env@example.com");
      delete process.env.SN_EMAIL;
      expect(readPlainConfig().email).toBe("");
    });
  } finally {
    if (previous === undefined) delete process.env.SN_EMAIL;
    else process.env.SN_EMAIL = previous;
    rmSync(dir, { recursive: true, force: true });
  }
});
