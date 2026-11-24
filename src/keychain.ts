import { spawn } from "node:child_process";
import pc from "picocolors";
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
  // Test escape hatch: `security add-generic-password -U` is an upsert, so a
  // test calling saveSession would clobber the developer's real keychain
  // entry on macOS. Tests set this before touching saveSession.
  if (process.env.SNS_DISABLE_KEYCHAIN === "1") return false;
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

/**
 * Outcome of a keychain removal. "deleted" — the tool exited 0. "unavailable"
 * — no secret service answered, so the item's state is unknown and it is
 * probably still there (login stored it while the service was up). "unconfirmed"
 * — the delete tool failed or could not be spawned; the item may be absent
 * (macOS reports missing items as failure) or may still exist, so callers
 * warn with the manual removal command either way.
 */
export type KeychainDeleteResult = "deleted" | "unconfirmed" | "unavailable";

/**
 * The one warning every keychain-removal path owes the operator when the
 * item's deletion could not be confirmed: logout/purge claim their cleanup
 * succeeded, and a live dotenvx key silently surviving in the keyring is
 * the one outcome this text exists to surface. Static text only — never a
 * secret value. `context.fileCustody` — true when `.env.keys` existed at
 * deletion time — silences the "unavailable" case: on a machine whose
 * secret service never answered, keychainPut always failed, custody was
 * necessarily the file, and no keychain item can exist to warn about.
 * "unconfirmed" (the service answered but the delete failed) always warns —
 * a missing item is indistinguishable from a live one.
 */
export function warnIfKeychainItemSurvived(
  result: KeychainDeleteResult,
  context: { fileCustody?: boolean } = {},
): void {
  if (result === "deleted") return;
  if (result === "unavailable" && context.fileCustody) return;
  const tool =
    process.platform === "darwin"
      ? "security delete-generic-password -s sn_secrets_cli -a dotenvkey"
      : "secret-tool clear service sn_secrets_cli account dotenvkey";
  const why = result === "unavailable" ? "no secret service answered" : "the delete command failed";
  console.error(pc.yellow(`the keychain item could not be confirmed deleted (${why}) — if present, remove it with: ${tool}`));
}

/**
 * Best-effort removal that never rejects and never no-ops silently: logout
 * and purge must finish their local deletions and say so even when the
 * keychain half cannot be confirmed — a live dotenvx key stranded in the
 * keyring with a success outro is the one outcome this return value exists
 * to prevent. (The Rust port's keychain_delete has always been infallible.)
 */
export async function keychainDelete(): Promise<KeychainDeleteResult> {
  if (!(await secretServiceAvailable())) return "unavailable";
  try {
    if (process.platform === "darwin") {
      const result = await run("security", ["delete-generic-password", "-s", SERVICE, "-a", ACCOUNT]);
      return result.code === 0 ? "deleted" : "unconfirmed";
    }
    const result = await run("secret-tool", ["clear", "service", SERVICE, "account", ACCOUNT]);
    return result.code === 0 ? "deleted" : "unconfirmed";
  } catch {
    // Spawn-level failure (binary missing, EACCES): report, don't abort.
    return "unconfirmed";
  }
}
