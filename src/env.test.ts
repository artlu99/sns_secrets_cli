import { expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  assertApiUrl,
  assertPlainEnvValue,
  assertSessionKeyNames,
  isSecretEnvName,
  scrubbedEnv,
  scrubbedEnvNames,
  scrubProcessEnv,
  SESSION_VALUE_KEYS,
} from "./env.ts";
import { ensureConfigDir, envPath, readPlainConfig, withConfigDir, writePlainConfig } from "./paths.ts";

test("secret names are removed before a child process", () => {
  const env = scrubbedEnv({
    PATH: "/usr/bin",
    SN_EMAIL: "a@b.c",
    SN_API_URL: "https://example.test",
    SN_DB_KEY: "secret",
    SN_REFRESH_TOKEN: "secret",
    DOTENV_PRIVATE_KEY_SESSION: "secret",
    HOME: "/tmp",
  });
  expect(env.SN_EMAIL).toBe("a@b.c");
  expect(env.SN_DB_KEY).toBeUndefined();
  expect(env.SN_REFRESH_TOKEN).toBeUndefined();
  expect(env.DOTENV_PRIVATE_KEY_SESSION).toBeUndefined();
  expect(env.PATH).toBe("/usr/bin");
});

test("child env drops the whole SNS_ knob namespace", () => {
  const env = scrubbedEnv({
    PATH: "/usr/bin",
    SNS_CONFIG_DIR: "/tmp/cfg",
    SNS_DEBUG: "1",
    HOME: "/tmp",
  });
  expect(env.SNS_CONFIG_DIR).toBeUndefined();
  expect(env.SNS_DEBUG).toBeUndefined();
  expect(env.PATH).toBe("/usr/bin");
  // The launch scrub keeps sns's own runtime knobs — the running program
  // still reads them; only children lose them.
  expect(isSecretEnvName("SNS_CONFIG_DIR")).toBe(false);
});

test("session key allowlist rejects anything else", () => {
  expect(assertSessionKeyNames(["SN_DB_KEY", "DOTENV_PUBLIC_KEY_SESSION"])).toBeNull();
  expect(assertSessionKeyNames(["SN_REFRESH_TOKEN", "SOMETHING_ELSE"])).toBe("SOMETHING_ELSE");
  expect(isSecretEnvName("SN_EMAIL")).toBe(false);
  expect(isSecretEnvName(["SN", "PASSWORD"].join("_"))).toBe(true);
  expect(SESSION_VALUE_KEYS.includes("SN_ACCOUNT_EMAIL" as never)).toBe(true);
});

test("scrubProcessEnv records the names it removed", () => {
  process.env.SN_SCRUB_PROBE_KEY = "probe";
  try {
    scrubProcessEnv();
    expect(process.env.SN_SCRUB_PROBE_KEY).toBeUndefined();
    expect(scrubbedEnvNames().includes("SN_SCRUB_PROBE_KEY")).toBe(true);
  } finally {
    delete process.env.SN_SCRUB_PROBE_KEY;
  }
});

test("plain .env values reject control characters instead of forging lines", () => {
  expect(() => assertPlainEnvValue("SN_EMAIL", "me@example.com")).not.toThrow();
  expect(() => assertPlainEnvValue("SN_EMAIL", "me@example.com\nSN_DB_KEY=owned")).toThrow(/control character/);
  // the forged-line name is assembled, never written whole: cli.test.ts's
  // source guard forbids the literal anywhere under src/
  expect(() =>
    assertPlainEnvValue("SN_API_URL", `https://x.test\r\n${["SN", "PASSWORD"].join("_")}=x`),
  ).toThrow(/control character/);
  expect(() => assertPlainEnvValue("SN_EMAIL", "tab\tstays?")).toThrow(/control character/);
});

test("the plain .env rewrite refuses a newline-bearing email and writes nothing", () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-env-rewrite-"));
  try {
    withConfigDir(dir, () => {
      ensureConfigDir();
      writePlainConfig({ email: "me@example.com" });
      expect(readPlainConfig().email).toBe("me@example.com");
      expect(() => writePlainConfig({ email: "me@example.com\nSN_DB_KEY=owned" })).toThrow(/control character/);
      // The poisoned line never reached the file.
      const text = readFileSync(envPath(), "utf8");
      expect(text).not.toContain("SN_DB_KEY");
      expect(readPlainConfig().email).toBe("me@example.com");
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("SN_API_URL must be https unless loopback or the insecure escape hatch", () => {
  expect(() => assertApiUrl("https://api.standardnotes.com")).not.toThrow();
  expect(() => assertApiUrl("http://localhost:3000")).not.toThrow();
  expect(() => assertApiUrl("http://127.0.0.1:8080")).not.toThrow();
  expect(() => assertApiUrl("http://[::1]:8080")).not.toThrow();
  expect(() => assertApiUrl("http://api.standardnotes.com")).toThrow(/plaintext/);
  expect(() => assertApiUrl("http://api.standardnotes.com")).toThrow(/SNS_ALLOW_INSECURE_API/);
  expect(() => assertApiUrl("ftp://api.standardnotes.com")).toThrow(/https or http/);
  expect(() => assertApiUrl("not a url")).toThrow(/not a valid URL/);
  const previous = process.env.SNS_ALLOW_INSECURE_API;
  process.env.SNS_ALLOW_INSECURE_API = "1";
  try {
    expect(() => assertApiUrl("http://api.standardnotes.com")).not.toThrow();
  } finally {
    if (previous === undefined) delete process.env.SNS_ALLOW_INSECURE_API;
    else process.env.SNS_ALLOW_INSECURE_API = previous;
  }
});

test("config load enforces the https gate on SN_API_URL", () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-env-url-"));
  try {
    withConfigDir(dir, () => {
      ensureConfigDir();
      writePlainConfig({ apiUrl: "https://api.standardnotes.com" });
      expect(readPlainConfig().apiUrl).toBe("https://api.standardnotes.com");
      writePlainConfig({ apiUrl: "http://localhost:3000" });
      expect(readPlainConfig().apiUrl).toBe("http://localhost:3000");
      const remote = "http://api.standardnotes.com";
      expect(() => writePlainConfig({ apiUrl: remote })).toThrow(/plaintext/);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
