import { browser } from "wxt/browser";
import { CLEAR_AT_KEY, clearDelayMs } from "../../lib/clear-timer.ts";

/**
 * The offscreen document's whole job: hold the pending clipboard-clear timer.
 * The schedule is an absolute timestamp in session storage, not a relayed
 * message — so this document arms itself from storage on load AND re-arms on
 * every change, which removes the createDocument/message race entirely: no
 * matter when this document was created relative to the copy, it sees the
 * schedule. A later copy bumps the timestamp and re-arms (restarts the 30 s).
 * When the clear fires, this document asks the background to close it — no
 * hidden page lingers holding the extension open.
 */
let timer: ReturnType<typeof setTimeout> | undefined;

function armFrom(value: unknown): void {
  if (timer !== undefined) clearTimeout(timer);
  timer = setTimeout(() => {
    timer = undefined;
    void onClearDue();
  }, clearDelayMs(value));
}

async function onClearDue(): Promise<void> {
  setClipboard("");
  await browser.storage.session.remove(CLEAR_AT_KEY).catch(() => {});
  // Wakes the background; it closes this document.
  void browser.runtime.sendMessage({ type: "sns:clear-done" }).catch(() => {});
}

browser.storage.onChanged.addListener((changes, area) => {
  if (area !== "session") return;
  const change = changes[CLEAR_AT_KEY];
  // newValue undefined = the key was removed (our own post-fire cleanup).
  if (change?.newValue === undefined || change.newValue === null) return;
  armFrom(change.newValue);
});

// Cover the recreated-document case: a schedule written before this
// document existed is picked up here.
void browser.storage.session
  .get(CLEAR_AT_KEY)
  .then((got) => {
    const clearAt = got[CLEAR_AT_KEY];
    if (clearAt !== undefined) armFrom(clearAt);
  })
  .catch(() => {});

/**
 * navigator.clipboard.writeText requires a focused document, which an
 * offscreen page never has; the execCommand path under the clipboardWrite
 * permission is the supported write without focus (the same technique as
 * Chrome's offscreen-clipboard sample). If execCommand reports failure, try
 * the async API once before giving up.
 */
function setClipboard(text: string): void {
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  const ok = document.execCommand("copy");
  area.remove();
  if (!ok) void navigator.clipboard.writeText(text).catch(() => {});
}
