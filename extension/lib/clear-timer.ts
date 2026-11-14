/**
 * Pure clipboard-clear schedule math — no browser APIs, so lib tests can
 * import it freely. The schedule is an absolute epoch timestamp handed to the
 * offscreen document (in its creation URL, or over runtime messaging).
 */

export const CLIPBOARD_TTL_MS = 30_000;

/** Milliseconds to wait from `now` until the scheduled clear; clamped ≥ 0. */
export function clearDelayMs(clearAt: unknown, now: number = Date.now()): number {
  if (typeof clearAt !== "number" || !Number.isFinite(clearAt)) return 0;
  return Math.max(0, clearAt - now);
}
