import { clearDelayMs } from "../../lib/clear-timer.ts";

/**
 * The offscreen document's whole job: hold the pending clipboard-clear timer.
 * Offscreen documents get no extension APIs beyond runtime messaging — no
 * storage, and no self-close — so the schedule reaches this page over
 * channels that provably work here:
 *
 * 1. Baked into the creation URL (`?clearAt=<ms>`): the document arms itself
 *    from location.search at startup, so the first timer cannot be lost to a
 *    create-then-message race.
 * 2. `sns:arm-clear` runtime messages: a later copy bumps the schedule while
 *    this document already exists; each arm is acknowledged so the background
 *    knows the message landed.
 *
 * When the timer fires, this page writes an empty value — the execCommand
 * path, because the async clipboard API requires a focused document — and
 * reports the result with its schedule id. The background records the
 * receipt, closes this document, and acks; the ack is retried with backoff
 * until it lands, so the clipboard-write context never outlives the promise
 * it exists for — a lost message while the service worker restarts cannot
 * leave this page lingering past the 30 s TTL. A newer schedule keeps the
 * document alive on purpose: the background skips the close when the
 * reported clearAt is older than the one it last recorded.
 */

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

let timer: ReturnType<typeof setTimeout> | undefined;

function arm(clearAt: number): void {
  if (timer !== undefined) clearTimeout(timer);
  // The schedule travels inside the timer's own closure: reading the mutable
  // `armedClearAt` after the awaited clipboard write would let a newer copy's
  // re-arm make THIS fire report the NEWER clearAt — the background's
  // superseded check would then keep the document (and the newer timer)
  // alive while this fire's close decision is based on the wrong schedule.
  const scheduled = clearAt;
  timer = setTimeout(() => {
    timer = undefined;
    void fire(scheduled);
  }, clearDelayMs(clearAt));
}

const bootClearAt = Number(new URLSearchParams(location.search).get("clearAt"));
if (Number.isFinite(bootClearAt) && bootClearAt > 0) arm(bootClearAt);

browser.runtime.onMessage.addListener((message) => {
  if (message?.type === "sns:arm-clear" && Number.isFinite(message.clearAt)) {
    arm(message.clearAt);
    return Promise.resolve(true);
  }
});

async function fire(clearAt: number): Promise<void> {
  const ok = await setClipboard("");
  // Retry until the background acks (it closes this document on ack) — a
  // rejected sendMessage just means the worker was restarting.
  for (let attempt = 0; ; attempt++) {
    const acked = await browser.runtime
      .sendMessage({ type: "sns:clear-done", ok, clearAt })
      .then((reply) => reply === true, () => false);
    if (acked) return;
    await sleep(Math.min(1_000 * 2 ** attempt, 5_000));
  }
}

/**
 * Blanking is the whole point, and the two write paths fail differently:
 * navigator.clipboard.writeText handles an empty string natively but may be
 * refused without a focused document; execCommand("copy") runs without focus
 * under the clipboardWrite permission, yet an empty selection cannot be
 * copied — it returns true and silently writes nothing. So: async API first,
 * and when it refuses, fall back to execCommand copying a single space —
 * something the clipboard will actually take.
 */
async function setClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // fall through to execCommand
  }
  const area = document.createElement("textarea");
  area.value = text === "" ? " " : text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  const ok = document.execCommand("copy");
  area.remove();
  return ok;
}
