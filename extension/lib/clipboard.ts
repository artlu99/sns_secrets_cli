/**
 * Copy with a self-destruct timer. The value goes to the clipboard now; the
 * 30-second clear runs in an offscreen document — the popup dies on blur and
 * the MV3 service worker sleeps, so neither can host the timer, and offscreen
 * documents have no extension APIs beyond runtime messaging, so the schedule
 * travels to it as a message (acknowledged) or baked into its creation URL.
 * If the schedule cannot be confirmed, fall back to a best-effort in-page
 * timer and say so — the UI shows the difference.
 */
import { browser } from "wxt/browser";
import { CLIPBOARD_TTL_MS } from "./clear-timer.ts";

export { CLIPBOARD_TTL_MS };

export type CopySchedule = "scheduled" | "fallback";

export async function copySecret(value: string): Promise<CopySchedule> {
  // Runs with user activation (a click), so this write is always allowed.
  await navigator.clipboard.writeText(value);
  try {
    const ack = await browser.runtime.sendMessage({
      type: "sns:schedule-clear",
      delayMs: CLIPBOARD_TTL_MS,
    });
    if (ack === true) return "scheduled";
    console.warn("clipboard auto-clear was not acknowledged:", ack);
  } catch (error) {
    console.warn("clipboard auto-clear was not scheduled", error);
  }
  // Best-effort fallback: fires only if this context lives 30 s more (the
  // dashboard usually does; the popup usually does not). The offscreen path
  // above is the real mechanism — this is the net under it.
  setTimeout(() => {
    void navigator.clipboard.writeText("").catch(() => {});
  }, CLIPBOARD_TTL_MS);
  return "fallback";
}
