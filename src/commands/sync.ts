import { intro, outro, spinner } from "@clack/prompts";
import { UserError } from "../errors.ts";
import { openDatabaseOrReplace } from "../db.ts";
import { acquireSyncLock } from "../lock.ts";
import { deriveRootKey } from "../sn-crypto/kdf.ts";
import { createApi, withAccess, type ApiClient } from "../sn-api.ts";
import { dbPath, readPlainConfig } from "../paths.ts";
import { loadSession, saveSession, type SessionSecrets } from "../session-file.ts";
import { runSync, type SyncReport } from "../sync-engine.ts";
import { promptSecret } from "./prompt.ts";

export async function pullNotes(options: {
  secrets: SessionSecrets;
  api: ApiClient;
  email: string;
  masterKey: string | null;
}): Promise<{ report: SyncReport; replaced: boolean }> {
  const release = await acquireSyncLock();
  const spin = spinner();
  try {
    const opened = openDatabaseOrReplace(dbPath(), options.secrets.dbKey);
    const db = opened.db;
    try {
      spin.start("pulling notes");
      const report = await withAccess(options.secrets, saveSession, options.api, async (current) =>
        runSync({
          db,
          masterKey: options.masterKey,
          fetchPage: (syncToken, cursorToken) => options.api.syncPage(current, syncToken, cursorToken),
          ensureMasterKey: async () => {
            spin.stop("item keys are not in the cache yet");
            const password = await promptSecret("Account password (used once to unwrap item keys)");
            const params = await options.api.keyParams(options.email, () => promptSecret("Two-factor code"));
            const root = await deriveRootKey(password, params);
            spin.start("pulling notes");
            return root.masterKey;
          },
        }),
      );
      spin.stop("sync finished");
      return { report, replaced: opened.replaced };
    } catch (error) {
      spin.stop("sync failed");
      throw error;
    } finally {
      db.close();
    }
  } finally {
    release();
  }
}

export function syncSummary(report: SyncReport, replaced: boolean): string {
  const cache = replaced ? "previous cache.db could not be opened with the current key and was removed\n" : "";
  return `${cache}upserted ${report.upserted}, skipped ${report.skipped}, conflicts ${report.conflicts}, pages ${report.pages}\nnext: sns list`;
}

export async function syncCommand(): Promise<void> {
  intro("sns sync");
  const secrets = await loadSession();
  if (!secrets) throw new UserError("not logged in — run sns login");
  const plain = readPlainConfig();
  if (plain.email === "") throw new UserError("SN_EMAIL is empty — run sns login");
  const { report, replaced } = await pullNotes({
    secrets,
    api: createApi(plain.apiUrl),
    email: plain.email,
    masterKey: null,
  });
  outro(syncSummary(report, replaced));
}

