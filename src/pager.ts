import { spawn } from "node:child_process";
import { scrubbedEnv } from "./env.ts";
import { UserError } from "./errors.ts";

/**
 * stdout write that treats a closed pipe as done, not as a crash: piping
 * `sns show --no-pager | head -1` closes the pipe early by design.
 */
export function writeStdout(body: string): void {
  const out = process.stdout;
  if (out.destroyed || !out.writable) return;
  out.once("error", (error) => {
    if ((error as NodeJS.ErrnoException).code !== "EPIPE") throw error;
  });
  out.write(body);
}

export async function page(
  text: string,
  options: { noPager?: boolean; reason?: string; warn?: boolean } = {},
): Promise<void> {
  const body = text.endsWith("\n") ? text : `${text}\n`;
  const interactive = process.stdout.isTTY && !options.noPager && Bun.which("less") !== null;
  if (!interactive) {
    // warn: false for output that provably carries no values (the show
    // inventory) — the warning is about plaintext secrets, not titles.
    if (options.warn !== false) {
      const why = options.noPager
        ? "printing plaintext to stdout; a redirect or the scrollback keeps a copy"
        : "printing plaintext to stdout; the scrollback keeps a copy";
      console.error(why);
    }
    writeStdout(body);
    return;
  }
  await new Promise<void>((resolve, reject) => {
    const child = spawn("less", ["-R"], {
      env: scrubbedEnv(),
      stdio: ["pipe", "inherit", "inherit"],
    });
    child.on("error", () => reject(new UserError("could not start less")));
    child.on("close", (code) => {
      if (code === 0 || code === null) resolve();
      else reject(new UserError(`less exited ${code}`));
    });
    // less quitting before the body is drained (the user pressed q) closes the
    // pipe mid-write; that is a normal exit, not an error.
    child.stdin.on("error", () => resolve());
    child.stdin.end(body);
  });
}

/**
 * The list/show/tags rule in one place: page only when the output is taller
 * than the screen. The row count covers everything passed in — hints
 * included — so the decision always matches what actually prints. A pty can
 * report 0 rows: unknown, not tiny, so the screen falls back to 24.
 */
export async function pageIfTall(
  text: string,
  options: { noPager?: boolean; warn?: boolean } = {},
): Promise<void> {
  const rows = text.split("\n").length;
  const screen = process.stdout.rows || 24;
  if (process.stdout.isTTY && !options.noPager && rows > screen - 1) {
    await page(text, { warn: options.warn });
    return;
  }
  writeStdout(text.endsWith("\n") ? text : `${text}\n`);
}
