export default defineBackground(() => {
  browser.runtime.onInstalled.addListener(() => {
    console.log("sns vault installed");
  });

  /** Guards against double-createDocument when two copies race. */
  let creating: Promise<unknown> | null = null;

  /** Create the document with the schedule baked into its URL. */
  async function createOffscreenDocument(clearAt: number): Promise<void> {
    creating ??= browser.offscreen
      .createDocument({
        url: `/offscreen.html?clearAt=${clearAt}`,
        reasons: ["CLIPBOARD"],
        justification: "Overwrite the clipboard with an empty value after the copy TTL",
      })
      .catch(() => {
        // "Only a single offscreen document" — an existing document just
        // raced this creation; the arm below covers it.
      })
      .finally(() => {
        creating = null;
      });
    await creating;
  }

  /**
   * Arm or re-arm the pending clear. An existing document is told over
   * runtime messaging — the only extension API an offscreen document has —
   * and acknowledges; a missing ack means it is mid-teardown (just fired) or
   * gone, so it is recreated with the schedule in its URL. The document arms
   * itself from that at script start, immune to the create/message race.
   */
  async function scheduleClear(delayMs: number): Promise<boolean> {
    const clearAt = Date.now() + Math.max(0, delayMs);
    try {
      // Receipt/observability only — the mechanism does not depend on it.
      await browser.storage.session.set({ clipboardClearAt: clearAt });
    } catch {
      // Storage is never load-bearing here.
    }
    let contexts: unknown[] = [];
    try {
      contexts = await browser.runtime.getContexts({ contextTypes: ["OFFSCREEN_DOCUMENT"] });
    } catch {
      // getContexts needs Chrome 116+; assume none and create.
    }
    if (contexts.length > 0) {
      const ack = await browser.runtime
        .sendMessage({ type: "sns:arm-clear", clearAt })
        .catch(() => undefined);
      if (ack === true) return true;
      await browser.offscreen.closeDocument().catch(() => {});
    }
    await createOffscreenDocument(clearAt);
    return true;
  }

  browser.runtime.onMessage.addListener((message) => {
    if (message?.type === "sns:schedule-clear") {
      // Returning the promise makes the sender's sendMessage resolve with
      // the boolean — the copy flow surfaces it in the UI.
      return scheduleClear(Number(message.delayMs) || 0).catch((error) => {
        console.warn("clipboard auto-clear scheduling failed", error);
        void browser.storage.local.set({ clipboardScheduleError: String(error) }).catch(() => {});
        return false;
      });
    }
    if (message?.type === "sns:clear-done") {
      void browser.storage.session
        .set({ lastClipboardClearAt: Date.now(), lastClipboardClearOk: message.ok === true })
        .catch(() => {});
      void browser.offscreen.closeDocument().catch(() => {
        // Already closed or never opened — either is fine.
      });
    }
  });
});
