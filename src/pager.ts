import { spawn } from "node:child_process";
import { scrubbedEnv } from "./env.ts";
import { UserError } from "./errors.ts";

export async function page(text: string, options: { noPager?: boolean; reason?: string } = {}): Promise<void> {
  const body = text.endsWith("\n") ? text : `${text}\n`;
  const interactive = process.stdout.isTTY && !options.noPager && Bun.which("less") !== null;
  if (!interactive) {
    const why = options.noPager
      ? "printing plaintext to stdout; a redirect or the scrollback keeps a copy"
      : "printing plaintext to stdout; the scrollback keeps a copy";
    console.error(why);
    process.stdout.write(body);
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
    child.stdin.end(body);
  });
}
