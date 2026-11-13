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
