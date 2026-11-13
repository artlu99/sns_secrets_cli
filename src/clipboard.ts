import { spawn } from "node:child_process";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { openSync, writeSync, closeSync } from "node:fs";
import { scrubbedEnv } from "./env.ts";
import { UserError } from "./errors.ts";
import { clipboardMarkerPath, ensureConfigDir } from "./paths.ts";

const MAX_BYTES = 60_000;

export function osc52(text: string, tmux = Boolean(process.env.TMUX)): string {
  const payload = Buffer.from(text, "utf8").toString("base64");
  const sequence = `\x1b]52;c;${payload}\x07`;
  if (!tmux) return sequence;
  return `\x1bPtmux;${sequence.replaceAll("\x1b", "\x1b\x1b")}\x1b\\`;
}

export function clearSequence(tmux = Boolean(process.env.TMUX)): string {
  const sequence = "\x1b]52;c;\x07";
  if (!tmux) return sequence;
  return `\x1bPtmux;${sequence.replaceAll("\x1b", "\x1b\x1b")}\x1b\\`;
}

export function writeOsc(sequence: string): boolean {
  try {
    const fd = openSync("/dev/tty", "w");
    try {
      writeSync(fd, sequence);
    } finally {
      closeSync(fd);
    }
    return true;
  } catch {
    if (process.stdout.isTTY) {
      process.stdout.write(sequence);
      return true;
    }
    return false;
  }
}

function armClear(sequence: string): void {
  ensureConfigDir();
  writeFileSync(clipboardMarkerPath(), String(Date.now() + 30_000), { mode: 0o600 });
  // A detached (setsid) sleeper has no controlling terminal, so it cannot open
  // /dev/tty itself (ENXIO) — that silently swallowed every clear. Open the tty
  // here and hand the fd to the child; Bun passes inherited fds renumbered to
  // their stdio index, so the sleeper writes >&3.
  let ttyFd: number;
  try {
    ttyFd = openSync("/dev/tty", "w");
  } catch {
    return; // no tty now; the marker lets a later command clear instead
  }
  const child = spawn("sh", ["-c", "sleep 30; printf %s \"$1\" >&3 || true", "sns-clear", sequence], {
    detached: true,
    env: scrubbedEnv(),
    stdio: ["ignore", "ignore", "ignore", ttyFd],
  });
  child.unref();
  closeSync(ttyFd);
}

async function copyViaTool(text: string): Promise<boolean> {
  const tools: Array<[string, string[]]> = [
    ["wl-copy", []],
    ["xclip", ["-selection", "clipboard"]],
    ["pbcopy", []],
    ["clip.exe", []],
  ];
  for (const [bin, args] of tools) {
    const path = Bun.which(bin);
    if (!path) continue;
    const ok = await new Promise<boolean>((resolve) => {
      const child = spawn(path, args, { env: scrubbedEnv(), stdio: ["pipe", "ignore", "ignore"] });
      child.on("error", () => resolve(false));
      child.on("close", (code) => resolve(code === 0));
      // A helper that exits instantly (no DISPLAY, failed clip.exe) closes the
      // pipe before the write drains; that is a failed attempt, not a crash.
      child.stdin.on("error", () => resolve(false));
      child.stdin.end(text);
    });
    if (ok) return true;
  }
  return false;
}

export async function copyToClipboard(text: string, subject?: string): Promise<string> {
  const bytes = Buffer.byteLength(text);
  if (bytes > MAX_BYTES) {
    throw new UserError(`${subject ?? "note"} is ${bytes} bytes, over the ${MAX_BYTES} byte clipboard cap`);
  }
  const wrote = writeOsc(osc52(text));
  if (!wrote) {
    const tool = await copyViaTool(text);
    if (!tool) {
      throw new UserError("no clipboard path: OSC 52 needs a terminal, and wl-copy/xclip/pbcopy were not found");
    }
  }
  armClear(clearSequence());
  // a subject names the copied setting; the body copy stays anonymous
  return subject !== undefined
    ? `copied ${subject} (${bytes} bytes, clears in 30s)`
    : `Copied ${bytes} bytes (clears in 30s)`;
}

/** Next command clears a clipboard whose sleeper may have died. */
export function maybeClearStaleClipboard(): void {
  const path = clipboardMarkerPath();
  if (!existsSync(path)) return;
  const at = Number(readFileSync(path, "utf8"));
  if (!Number.isFinite(at) || Date.now() < at) return;
  try {
    writeOsc(clearSequence());
  } catch {
    /* nothing to clear into */
  }
  rmSync(path, { force: true });
}
