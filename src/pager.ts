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

export async function page(text: string, options: { noPager?: boolean; reason?: string } = {}): Promise<void> {
  const body = text.endsWith("\n") ? text : `${text}\n`;
  const interactive = process.stdout.isTTY && !options.noPager && Bun.which("less") !== null;
  if (!interactive) {
    const why = options.noPager
      ? "printing plaintext to stdout; a redirect or the scrollback keeps a copy"
      : "printing plaintext to stdout; the scrollback keeps a copy";
    console.error(why);
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
