/**
 * End-to-end check of the clipboard auto-clear, in a real (headless) Chromium.
 * Loads the built extension from .output/chrome-mv3, performs a copy exactly
 * the way the popup/dashboard do (writeText + sns:schedule-clear), and
 * asserts the offscreen document fires and blanks the clipboard.
 * Run: `bun scripts/e2e-clipboard.ts` (after `wxt build`).
 *
 * Requires the full chromium build (bunx playwright install chromium).
 * Exit 0 = mechanism verified; non-zero with a printed receipt otherwise.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { chromium } from "playwright";

// page.evaluate callbacks run in extension pages where the raw chrome global
// exists; this file itself never touches it outside those callbacks.
declare const chrome: any;

const EXT_PATH = resolve(import.meta.dir, "../.output/chrome-mv3");
const userDataDir = mkdtempSync(join(tmpdir(), "sns-vault-e2e-"));

const context = await chromium.launchPersistentContext(userDataDir, {
  headless: true,
  channel: "chromium", // full build, new headless — extensions work here
  args: [
    `--disable-extensions-except=${EXT_PATH}`,
    `--load-extension=${EXT_PATH}`,
    "--no-sandbox",
    "--disable-dev-shm-usage",
  ],
});

try {
  let [sw] = context.serviceWorkers();
  if (!sw) sw = await context.waitForEvent("serviceworker", { timeout: 15_000 });
  const extId = new URL(sw!.url()).host;
  console.log("extension id:", extId);

  const page = await context.newPage();
  await page.goto(`chrome-extension://${extId}/dashboard.html`);
  try {
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  } catch (error) {
    console.log("grantPermissions unavailable:", String(error));
  }

  // The exact steps copySecret performs, from an extension page.
  const ack = await page.evaluate(async () => {
    await navigator.clipboard.writeText("TOPSECRET-VALUE");
    return await chrome.runtime.sendMessage({ type: "sns:schedule-clear", delayMs: 30_000 });
  });
  console.log("schedule ack:", ack);
  if (ack !== true) {
    console.log("FAIL: the schedule was not acknowledged");
    process.exit(1);
  }

  await page.waitForTimeout(2_000);
  const docUrl = await page.evaluate(async () => {
    const contexts = await chrome.runtime.getContexts({ contextTypes: ["OFFSCREEN_DOCUMENT"] });
    return contexts.map((context: { documentUrl?: string }) => context.documentUrl ?? "(no url)").join(", ");
  });
  console.log("offscreen document:", docUrl || "NOT CREATED");

  console.log("waiting 32s past the 30s TTL…");
  await page.waitForTimeout(32_000);

  const receipt = await page.evaluate(async () => {
    const get = async (key: string) => (await chrome.storage.session.get(key))[key];
    return {
      lastClearAt: await get("lastClipboardClearAt"),
      lastOk: await get("lastClipboardClearOk"),
      clipboardNow: await navigator.clipboard.readText(),
    };
  });

  console.log("receipt:", JSON.stringify(receipt, null, 2));
  const fired = typeof receipt.lastClearAt === "number";
  // "": the empty write succeeded. " ": the browser refused an empty write
  // and the fallback copied a single space — the secret is gone either way.
  const blanked = receipt.clipboardNow === "" || receipt.clipboardNow === " ";
  if (!fired) console.log("FAIL: the offscreen document never fired the clear");
  else if (receipt.lastOk !== true) console.log("FAIL: the clear fired but its write failed");
  else if (!blanked) console.log("FAIL: receipt says ok but the clipboard still holds the secret");
  else if (receipt.clipboardNow === "") console.log("PASS: offscreen document fired and blanked the clipboard");
  else console.log("PASS (space fallback): secret overwritten with a single space");
  process.exit(fired && receipt.lastOk === true && blanked ? 0 : 1);
} finally {
  await context.close().catch(() => {});
  rmSync(userDataDir, { recursive: true, force: true });
}
