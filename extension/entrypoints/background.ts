export default defineBackground(() => {
  browser.runtime.onInstalled.addListener(() => {
    console.log("sns vault installed");
  });

  const OFFSCREEN_URL = "/offscreen.html";
  /** Guards against double-createDocument when two copies race. */
  let creating: Promise<unknown> | null = null;

  async function ensureOffscreenDocument(): Promise<void> {
    try {
      const contexts = await browser.runtime.getContexts({
        contextTypes: ["OFFSCREEN_DOCUMENT"],
      });
      if (contexts.length > 0) return;
    } catch {
      // getContexts needs Chrome 116+; on older Chrome just try to create.
    }
    creating ??= browser.offscreen
      .createDocument({
        url: OFFSCREEN_URL,
        reasons: ["CLIPBOARD"],
        justification: "Overwrite the clipboard with an empty value after the copy TTL",
      })
      .catch(() => {
        // "Only a single offscreen document" — the existing document reads
        // the schedule from storage, so this race is harmless.
      })
      .finally(() => {
        creating = null;
      });
    await creating;
  }

  browser.runtime.onMessage.addListener((message) => {
    if (message?.type === "sns:ensure-offscreen") {
      void ensureOffscreenDocument().catch((error) =>
        console.warn("clipboard auto-clear scheduling failed", error),
      );
    } else if (message?.type === "sns:clear-done") {
      void browser.offscreen.closeDocument().catch(() => {
        // Already closed or never opened — either is fine.
      });
    }
  });
});
