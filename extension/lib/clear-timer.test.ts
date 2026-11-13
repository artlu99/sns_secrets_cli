import { describe, expect, test } from "bun:test";
import { clearDelayMs } from "./clear-timer.ts";

const NOW = 1_000_000;

describe("clearDelayMs", () => {
  test("future timestamp gives the delta", () => {
    expect(clearDelayMs(NOW + 30_000, NOW)).toBe(30_000);
    expect(clearDelayMs(NOW + 1, NOW)).toBe(1);
  });

  test("past or due timestamp clamps to 0 (fire immediately)", () => {
    expect(clearDelayMs(NOW, NOW)).toBe(0);
    expect(clearDelayMs(NOW - 5_000, NOW)).toBe(0);
  });

  test("garbage values clamp to 0, never throw", () => {
    expect(clearDelayMs(undefined, NOW)).toBe(0);
    expect(clearDelayMs(null, NOW)).toBe(0);
    expect(clearDelayMs("soon", NOW)).toBe(0);
    expect(clearDelayMs(Number.NaN, NOW)).toBe(0);
  });
});
