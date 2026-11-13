/**
 * Copy with a self-destruct timer. The value goes to the clipboard now; the
 * clear schedule is written as an absolute timestamp into session storage,
 * which the offscreen document arms itself from (at load and via
 * storage.onChanged) and fires even if this context dies first — the popup
 * dies on blur and the MV3 service worker sleeps, so neither can host the
 * timer. If scheduling the offscreen document fails entirely, fall back to
 * a best-effort in-page timer.
 */
import { browser } from "wxt/browser";
import { CLEAR_AT_KEY, CLIPBOARD_TTL_MS } from "./clear-timer.ts";

export { CLEAR_AT_KEY, CLIPBOARD_TTL_MS };

export async function copySecret(value: string): Promise<void> {
  // Runs with user activation (a click), so this write is always allowed.
  await navigator.clipboard.writeText(value);
  // Write the schedule BEFORE waking the background: an offscreen document
  // that loads at any point after this reads it and arms itself.
  await browser.storage.session.set({ [CLEAR_AT_KEY]: Date.now() + CLIPBOARD_TTL_MS });
  await scheduleOffscreenDocument();
}

async function scheduleOffscreenDocument(): Promise<void> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      // Wakes the service worker if asleep; its listener creates/reuses the
      // offscreen document. Delivery itself is the only thing we need — the
      // document picks the schedule up from storage.
      await browser.runtime.sendMessage({ type: "sns:ensure-offscreen" });
      return;
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 150));
    }
  }
  console.warn("clipboard auto-clear was not scheduled", lastError);
  // Best-effort fallback: fires only if this context lives 30 s more (the
  // dashboard usually does; the popup usually does not). The offscreen path
  // above is the real mechanism — this is the net under it.
  setTimeout(() => {
    void navigator.clipboard.writeText("").catch(() => {});
  }, CLIPBOARD_TTL_MS);
}
