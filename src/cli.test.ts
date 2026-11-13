import { expect, test } from "bun:test";
import { Glob } from "bun";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { doctorChecks } from "./commands/doctor.ts";
import { scrubbedEnv } from "./env.ts";
import { ensureConfigDir, withConfigDir } from "./paths.ts";

test("doctor passes with skips on a fresh config", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-doctor-"));
  try {
    const checks = await withConfigDir(dir, async () => {
      ensureConfigDir();
      return doctorChecks();
    });
    expect(checks.some((check) => check.status === "FAIL")).toBe(false);
    expect(checks.find((check) => check.name === "runtime")?.status).toBe("ok");
    expect(checks.find((check) => check.name === "scrub")?.status).toBe("ok");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("cli help and doctor exit 0", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-cli-"));
  try {
    const help = Bun.spawn([process.execPath, "src/index.ts", "--help"], {
      cwd: process.cwd(),
      env: scrubbedEnv(),
      stdout: "pipe",
      stderr: "pipe",
    });
    const helpText = await new Response(help.stdout).text();
    expect(await help.exited).toBe(0);
    expect(helpText).toContain("Commands:");
    expect(helpText).toContain("sync");
    expect(helpText).toContain("copy <id>");

    const doctor = Bun.spawn([process.execPath, "src/index.ts", "doctor"], {
      cwd: process.cwd(),
      env: { ...scrubbedEnv(), SNS_CONFIG_DIR: dir },
      stdout: "pipe",
      stderr: "pipe",
    });
    const doctorText = await new Response(doctor.stdout).text();
    expect(await doctor.exited).toBe(0);
    expect(doctorText).toContain("SKIP");
    expect(doctorText).not.toContain("FAIL");

    const list = Bun.spawn([process.execPath, "src/index.ts", "list"], {
      cwd: process.cwd(),
      env: { ...scrubbedEnv(), SNS_CONFIG_DIR: dir },
      stdout: "pipe",
      stderr: "pipe",
    });
    const listErr = await new Response(list.stderr).text();
    expect(await list.exited).toBe(1);
    expect(listErr).toContain("not logged in");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("source does not name a password variable", async () => {
  const banned = ["SN", "PASSWORD"].join("_");
  const glob = new Glob("src/**/*.ts");
  for await (const file of glob.scan(".")) {
    const text = await Bun.file(file).text();
    expect(text.includes(banned), file).toBe(false);
  }
});
