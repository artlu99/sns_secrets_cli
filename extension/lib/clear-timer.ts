/**
 * Pure clipboard-clear schedule math — no browser APIs, so lib tests can
 * import it freely. The schedule is an absolute timestamp in session storage
 * (key `clipboardClearAt`), which the offscreen document arms itself from.
 */

export const CLIPBOARD_TTL_MS = 30_000;

export const CLEAR_AT_KEY = "clipboardClearAt";

/** Milliseconds to wait from `now` until the scheduled clear; clamped ≥ 0. */
export function clearDelayMs(clearAt: unknown, now: number = Date.now()): number {
  if (typeof clearAt !== "number" || !Number.isFinite(clearAt)) return 0;
  return Math.max(0, clearAt - now);
}
