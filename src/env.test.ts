import { expect, test } from "bun:test";
import { assertSessionKeyNames, isSecretEnvName, scrubbedEnv } from "./env.ts";

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

test("session key allowlist rejects anything else", () => {
  expect(assertSessionKeyNames(["SN_DB_KEY", "DOTENV_PUBLIC_KEY_SESSION"])).toBeNull();
  expect(assertSessionKeyNames(["SN_REFRESH_TOKEN", "SOMETHING_ELSE"])).toBe("SOMETHING_ELSE");
  expect(isSecretEnvName("SN_EMAIL")).toBe(false);
  expect(isSecretEnvName(["SN", "PASSWORD"].join("_"))).toBe(true);
});
