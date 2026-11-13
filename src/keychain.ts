import { spawn } from "node:child_process";
import { scrubbedEnv } from "./env.ts";

const SERVICE = "sn_secrets_cli";
const ACCOUNT = "dotenvkey";

function run(command: string, args: string[], stdin?: string): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      env: scrubbedEnv(),
      stdio: ["pipe", "pipe", "pipe"],
    });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => out.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => err.push(chunk));
    child.on("error", reject);
    child.on("close", (code) => {
      resolve({
        code: code ?? 1,
        stdout: Buffer.concat(out).toString("utf8"),
        stderr: Buffer.concat(err).toString("utf8"),
      });
    });
    if (stdin !== undefined) child.stdin.end(stdin);
    else child.stdin.end();
  });
}

/** The OS secret service answered. A missing item still counts as available. */
export async function secretServiceAvailable(): Promise<boolean> {
  if (process.platform === "darwin") return Bun.which("security") !== null;
  if (process.platform !== "linux") return false;
  if (Bun.which("secret-tool") === null) return false;
  const result = await run("secret-tool", ["lookup", "service", SERVICE, "account", "__sns_probe__"]);
  if (result.code === 0) return true;
  if (/could not connect|cannot autolaunch|secret service|org\.freedesktop\.secrets|no such file or directory/i.test(result.stderr)) {
    return false;
  }
  return result.code === 1;
}

export async function keychainGet(): Promise<string | null> {
  if (!(await secretServiceAvailable())) return null;
  if (process.platform === "darwin") {
    const result = await run("security", ["find-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w"]);
    if (result.code !== 0) return null;
    return result.stdout.replace(/\n$/, "");
  }
  const result = await run("secret-tool", ["lookup", "service", SERVICE, "account", ACCOUNT]);
  if (result.code !== 0) return null;
  return result.stdout.replace(/\n$/, "");
}

export async function keychainPut(secret: string): Promise<boolean> {
  if (!(await secretServiceAvailable())) return false;
  if (process.platform === "darwin") {
    const result = await run("security", [
      "add-generic-password",
      "-U",
      "-s",
      SERVICE,
      "-a",
      ACCOUNT,
      "-w",
      secret,
    ]);
    return result.code === 0;
  }
  const result = await run(
    "secret-tool",
    ["store", `--label=${SERVICE} dotenvx key`, "service", SERVICE, "account", ACCOUNT],
    secret,
  );
  return result.code === 0;
}

export async function keychainDelete(): Promise<void> {
  if (!(await secretServiceAvailable())) return;
  if (process.platform === "darwin") {
    await run("security", ["delete-generic-password", "-s", SERVICE, "-a", ACCOUNT]);
    return;
  }
  await run("secret-tool", ["clear", "service", SERVICE, "account", ACCOUNT]);
}
