/**
 * Visual harness: drives the built extension with mocked SN API responses and
 * fake vault data, then screenshots the dashboard (locked + unlocked) and the
 * popup to /tmp/ui/*.png — so UI work gets reviewed with eyes before it
 * ships. Run: `bun scripts/e2e-screens.ts` (after `wxt build`).
 */
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { chromium, type BrowserContext } from "playwright";

// page.evaluate callbacks run in extension pages where the raw chrome global
// exists; this file itself never touches it outside those callbacks.
declare const chrome: any;

const EXT_PATH = resolve(import.meta.dir, "../.output/chrome-mv3");
const OUT_DIR = "/tmp/ui";
const userDataDir = mkdtempSync(join(tmpdir(), "sns-vault-shots-"));

/** Fake decrypted rows: one env-style note, one prose note, tags, a note in two tags. */
function fakeItems(): unknown[] {
  const note = (uuid: string, title: string, text: string, tags: string[]) =>
    JSON.stringify({ title, text, references: tags.map((tag) => ({ uuid: tag, content_type: "Tag" })) });
  return [
    {
      uuid: "note-stripe",
      content_type: "Note",
      updated_at: Date.now() - 3_600_000,
      deleted: 0,
      title: "Stripe keys",
      content: note("note-stripe", "Stripe keys", "# rotate quarterly\nSTRIPE_SECRET=sk_live_51Hx\nSTRIPE_PUBLISH=pk_live_51Hx", ["tag-platforms", "tag-work"]),
    },
    {
      uuid: "note-db",
      content_type: "Note",
      updated_at: Date.now() - 7_200_000,
      deleted: 0,
      title: "Database — prod",
      content: note("note-db", "Database — prod", "DATABASE_URL=postgres://app:pw@db.internal:5432/prod", ["tag-work"]),
    },
    {
      uuid: "note-vercel",
      content_type: "Note",
      updated_at: Date.now() - 86_400_000,
      deleted: 0,
      title: "Vercel",
      content: note("note-vercel", "Vercel", "VERCEL_TOKEN=a1b2c3", ["tag-platforms"]),
    },
    {
      uuid: "note-idea",
      content_type: "Note",
      updated_at: Date.now() - 172_800_000,
      deleted: 0,
      title: "Naming ideas",
      content: note("note-idea", "Naming ideas", "wordmarks that survive lowercase:\n- lumen\n- ferry", []),
    },
    {
      uuid: "tag-platforms",
      content_type: "Tag",
      updated_at: Date.now(),
      deleted: 0,
      title: "Platforms",
      content: JSON.stringify({ title: "Platforms", references: [
        { uuid: "tag-vercel", content_type: "Tag" },
        { uuid: "note-stripe", content_type: "Note" },
      ] }),
    },
    {
      uuid: "tag-vercel",
      content_type: "Tag",
      updated_at: Date.now(),
      deleted: 0,
      title: "Vercel",
      content: JSON.stringify({ title: "Vercel", references: [{ uuid: "note-vercel", content_type: "Note" }] }),
    },
    {
      uuid: "tag-work",
      content_type: "Tag",
      updated_at: Date.now(),
      deleted: 0,
      title: "Work",
      content: JSON.stringify({ title: "Work", references: [{ uuid: "note-db", content_type: "Note" }] }),
    },
  ];
}

async function seedVault(context: BrowserContext, extId: string): Promise<void> {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extId}/dashboard.html`);
  await page.evaluate(
    ({ items }) =>
      new Promise<void>((resolve, reject) => {
        void chrome.storage.session
          .set({
            vaultSession: {
              secrets: {
                accountEmail: "you@example.com",
                refreshToken: "fake",
                accessToken: "fake",
                accessExpirationMs: Date.now() + 3_600_000,
                refreshExpirationMs: Date.now() + 86_400_000,
                accessCookie: "",
                refreshCookie: "",
              },
              masterKey: "aa".repeat(32),
              email: "you@example.com",
              apiUrl: "https://api.standardnotes.com",
            },
            vaultCache: { items, syncToken: null, storedTypes: "Note,SN|ItemsKey,Tag|" },
          })
          .then(() => resolve())
          .catch(reject);
      }),
    { items: fakeItems() },
  );
  await page.close();
}

const context = await chromium.launchPersistentContext(userDataDir, {
  headless: true,
  channel: "chromium",
  viewport: { width: 1440, height: 860 },
  args: [
    `--disable-extensions-except=${EXT_PATH}`,
    `--load-extension=${EXT_PATH}`,
    "--no-sandbox",
    "--disable-dev-shm-usage",
  ],
});
console.error("browser launched");

try {
  mkdirSync(OUT_DIR, { recursive: true });
  let [sw] = context.serviceWorkers();
  if (!sw) sw = await context.waitForEvent("serviceworker", { timeout: 15_000 });
  const extId = new URL(sw!.url()).host;
  console.error("extension id:", extId);

  // Mock the SN API so the dashboard syncs "successfully" against fake data.
  await context.route("**/api.standardnotes.com/**", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ data: { retrieved_items: [], sync_token: "tok", cursor_token: null, conflicts: 0 } }),
    }),
  );
  console.error("api mocked");

  const SEED = process.env.SEED !== "0";
  if (SEED) {
    await seedVault(context, extId);
    console.error("vault seeded");
  } else {
    console.error("seed skipped (SEED=0)");
  }

  const dashboard = await context.newPage();
  dashboard.on("pageerror", (error) => console.error("pageerror:", String(error).slice(0, 200)));
  dashboard.on("console", (message) => {
    if (message.type() === "error") console.error("console.error:", message.text().slice(0, 200));
  });
  // Profiler runs off the main thread — if the page wedges, the profile says
  // exactly which function is spinning.
  const cdp = await context.newCDPSession(dashboard);
  await cdp.send("Profiler.enable");
  await cdp.send("Profiler.start");
  await dashboard.goto(`chrome-extension://${extId}/dashboard.html`);
  console.error("dashboard opened");
  try {
    await dashboard.waitForSelector(".detail, .unlock", { timeout: 6_000 });
  } catch {
    try {
      const { profile } = await cdp.send("Profiler.stop");
      const hot = profile.nodes
        .map((node) => ({
          name: node.callFrame.functionName || "(anonymous)",
          url: node.callFrame.url.replace(/^chrome-extension:\/\/\w+/, ""),
          line: node.callFrame.lineNumber + 1,
          hits: (node as { hitCount?: number }).hitCount ?? 0,
        }))
        .sort((a, b) => b.hits - a.hits)
        .slice(0, 10);
      console.error("HOT FRAMES:\n" + hot.map((h) => `${h.hits}\t${h.name} @ ${h.url}:${h.line}`).join("\n"));
    } catch (error) {
      console.error("profiler stop failed:", String(error).slice(0, 120));
    }
    const text = await dashboard
      .locator("body")
      .innerText({ timeout: 5_000 })
      .catch((error) => `<<innerText failed: ${String(error).slice(0, 120)}>>`);
    console.error("DASHBOARD DID NOT SETTLE. Body text:\n" + text);
    throw new Error("dashboard stuck");
  }
  console.error("dashboard settled");
  console.error("dashboard ready");
  await dashboard.waitForTimeout(600);
  await dashboard.screenshot({ path: `${OUT_DIR}/dashboard${SEED ? "" : "-locked"}.png` });
  if (!SEED) process.exit(0);

  // Detail view: click a note with keys.
  await dashboard.getByText("Stripe keys").first().click();
  await dashboard.waitForTimeout(300);
  await dashboard.screenshot({ path: `${OUT_DIR}/dashboard-detail.png` });

  // Locked form.
  const gate = await context.newPage();
  await gate.setViewportSize({ width: 1440, height: 860 });
  // A page without a session would sync-fail; the popup without session shows the form.
  const popup = await context.newPage();
  await popup.setViewportSize({ width: 384, height: 580 });
  await popup.goto(`chrome-extension://${extId}/popup.html`);
  await popup.waitForSelector(".hits, .unlock", { timeout: 10_000 });
  await popup.waitForTimeout(400);
  await popup.screenshot({ path: `${OUT_DIR}/popup.png` });
  await gate.close();

  console.error("screenshots written to", OUT_DIR);
} finally {
  await context.close().catch(() => {});
  rmSync(userDataDir, { recursive: true, force: true });
}
