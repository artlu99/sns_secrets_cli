import { existsSync, readFileSync } from "node:fs";
import pc from "picocolors";
import { scrubbedEnv, assertSessionKeyNames } from "../env.ts";
import { keychainGet, secretServiceAvailable } from "../keychain.ts";
import { configDir, dbPath, ensureConfigDir, envPath, sessionPath, unexpectedConfigFiles } from "../paths.ts";
import { loadSession, sessionKeyNames } from "../session-file.ts";
import { openDatabase, sqliteMasterCount } from "../db.ts";

type Status = "ok" | "FAIL" | "SKIP";

type Check = { name: string; status: Status; detail: string };

function line(check: Check): string {
  const label = check.status === "ok" ? pc.green("ok  ") : check.status === "SKIP" ? pc.yellow("SKIP") : pc.red("FAIL");
  return `${label}  ${check.name.padEnd(12)} ${check.detail}`;
}

export async function doctorChecks(): Promise<Check[]> {
  const checks: Check[] = [];
  checks.push({
    name: "runtime",
    status: "ok",
    detail: `bun ${Bun.version}`,
  });

  try {
    ensureConfigDir();
    readFileSync(envPath(), "utf8");
    checks.push({ name: "config", status: "ok", detail: configDir() });
  } catch {
    checks.push({ name: "config", status: "FAIL", detail: "config directory or .env is not readable" });
  }

  const keychain = await secretServiceAvailable();
  if (!keychain) {
    checks.push({
      name: "keychain",
      status: "SKIP",
      detail: "no secret service on this machine — dotenvx key stays in .env.keys",
    });
  } else if (!existsSync(sessionPath())) {
    checks.push({ name: "keychain", status: "SKIP", detail: "secret service is available; nothing stored yet" });
  } else {
    const stored = await keychainGet();
    checks.push(
      stored
        ? { name: "keychain", status: "ok", detail: "dotenvx key retrieved" }
        : { name: "keychain", status: "FAIL", detail: "session exists but the keychain has no dotenvx key" },
    );
  }

  if (!existsSync(sessionPath())) {
    checks.push({ name: "session", status: "SKIP", detail: "not logged in" });
  } else {
    try {
      const names = sessionKeyNames();
      const unexpected = assertSessionKeyNames(names);
      if (unexpected) {
        checks.push({ name: "session", status: "FAIL", detail: `unexpected session key ${unexpected}` });
      } else {
        await loadSession();
        checks.push({ name: "session", status: "ok", detail: `decrypts (${names.filter((name) => !name.startsWith("DOTENV_PUBLIC")).join(", ")})` });
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "could not decrypt";
      checks.push({ name: "session", status: "FAIL", detail: message });
    }
  }

  if (!existsSync(dbPath())) {
    checks.push({ name: "cache", status: "SKIP", detail: "no cache.db yet" });
  } else {
    try {
      const secrets = await loadSession();
      if (!secrets) {
        checks.push({ name: "cache", status: "FAIL", detail: "cache.db exists but there is no session key" });
      } else {
        const db = openDatabase(dbPath(), secrets.dbKey);
        const tables = sqliteMasterCount(db);
        db.close();
        checks.push({ name: "cache", status: "ok", detail: `opened (${tables} sqlite_master rows)` });
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "could not open cache";
      checks.push({ name: "cache", status: "FAIL", detail: message });
    }
  }

  const probe = scrubbedEnv({ ...process.env, SN_DB_KEY: "scrub-sentinel", DOTENV_PRIVATE_KEY_SESSION: "scrub-sentinel" });
  const child = Bun.spawn(
    [process.execPath, "-e", "process.stdout.write((process.env.SN_DB_KEY ?? '') + (process.env.DOTENV_PRIVATE_KEY_SESSION ?? ''))"],
    { env: probe, stdout: "pipe", stderr: "pipe" },
  );
  const leaked = await new Response(child.stdout).text();
  checks.push(
    leaked === ""
      ? { name: "scrub", status: "ok", detail: "child environment has no secret variables" }
      : { name: "scrub", status: "FAIL", detail: "a child process could see secret variables" },
  );

  const passwordVar = ["SN", "PASSWORD"].join("_");
  checks.push(
    passwordVar in process.env
      ? { name: "password", status: "FAIL", detail: `${passwordVar} is set in this process` }
      : { name: "password", status: "ok", detail: `${passwordVar} is not in the environment` },
  );

  if (existsSync(dbPath())) {
    const header = readFileSync(dbPath()).subarray(0, 16).toString("utf8");
    checks.push(
      header.startsWith("SQLite format 3")
        ? { name: "at-rest", status: "FAIL", detail: "cache.db is a plaintext SQLite file" }
        : { name: "at-rest", status: "ok", detail: "cache.db is not a plaintext SQLite file" },
    );
  } else {
    checks.push({ name: "at-rest", status: "SKIP", detail: "no cache.db yet" });
  }

  const extra = unexpectedConfigFiles();
  checks.push(
    extra.length === 0
      ? { name: "files", status: "ok", detail: "config dir has no unexpected files" }
      : { name: "files", status: "FAIL", detail: `unexpected files: ${extra.join(", ")}` },
  );

  return checks;
}

export async function doctorCommand(): Promise<number> {
  const checks = await doctorChecks();
  for (const check of checks) console.log(line(check));
  return checks.some((check) => check.status === "FAIL") ? 1 : 0;
}
