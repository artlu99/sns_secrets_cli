import { type StdioOptions, spawn } from "node:child_process";
import { closeSync, openSync } from "node:fs";
import { expect, test } from "bun:test";
import { clearSequence, osc52 } from "./clipboard.ts";

test("OSC 52 carries base64, not the note, and clears to an empty payload", () => {
  const note = "door code 2468";
  const previous = process.env.TMUX;
  delete process.env.TMUX;
  try {
    const sequence = osc52(note, false);
    expect(sequence.startsWith("\x1b]52;c;")).toBe(true);
    expect(sequence.endsWith("\x07")).toBe(true);
    expect(sequence.includes(note)).toBe(false);
    expect(sequence).toContain(Buffer.from(note).toString("base64"));
    expect(clearSequence(false)).toBe("\x1b]52;c;\x07");
    const wrapped = osc52(note, true);
    expect(wrapped.startsWith("\x1bPtmux;")).toBe(true);
    expect(wrapped.includes(note)).toBe(false);
  } finally {
    if (previous === undefined) delete process.env.TMUX;
    else process.env.TMUX = previous;
  }
});

function hasControllingTty(): boolean {
  try {
    closeSync(openSync("/dev/tty", "w"));
    return true;
  } catch {
    return false;
  }
}

/** Exit code of a setsid-detached one-liner; -1 if it could not even start. */
function detachedExit(script: string, stdio: StdioOptions): Promise<number> {
  return new Promise((resolve) => {
    const child = spawn("sh", ["-c", script], { detached: true, stdio });
    child.on("error", () => resolve(-1));
    child.on("close", (code) => resolve(code ?? -1));
  });
}

test.skipIf(!hasControllingTty())(
  "the clear sleeper needs an inherited tty fd: setsid detaches /dev/tty",
  async () => {
    const ttyFd = openSync("/dev/tty", "w");
    try {
      // what armClear does: the tty opened before setsid stays writable in the child
      expect(await detachedExit('printf %s "$1" >&3', ["ignore", "ignore", "ignore", ttyFd])).toBe(0);
      // why the fd must be handed over: a detached child cannot reopen /dev/tty
      expect(await detachedExit("printf %s x > /dev/tty", "ignore")).not.toBe(0);
    } finally {
      closeSync(ttyFd);
    }
  },
);
