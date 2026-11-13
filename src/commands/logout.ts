import { intro, outro } from "@clack/prompts";
import pc from "picocolors";
import { existsSync } from "node:fs";
import { UserError } from "../errors.ts";
import { removeCacheFiles } from "../db.ts";
import { acquireSyncLock } from "../lock.ts";
import { createApi, withAccess } from "../sn-api.ts";
import { dbPath, readPlainConfig, sessionPath } from "../paths.ts";
import { deleteSession, loadSession, saveSession, type SessionSecrets } from "../session-file.ts";

export async function logoutCommand(options: { deleteCache?: boolean } = {}): Promise<void> {
  intro("sns logout");
  let secrets: SessionSecrets | null = null;
  if (existsSync(sessionPath())) {
    try {
      secrets = await loadSession();
    } catch (error) {
      // A broken session must not strand its secrets on disk: delete them anyway.
      const reason = error instanceof Error ? error.message : "unreadable session file";
      console.error(pc.yellow(`cannot read the session to revoke it server-side (${reason})`));
    }
  } else {
    throw new UserError("not logged in");
  }

  const plain = readPlainConfig();
  const api = createApi(plain.apiUrl);
  let revoked = false;
  if (secrets) {
    try {
      // Refresh first if needed, so logout works after the access token expired —
      // the common case, since access tokens are short-lived.
      await withAccess(secrets, saveSession, api, (current) => api.logout(current));
      revoked = true;
    } catch (error) {
      const message = error instanceof Error ? error.message : "revoke failed";
      console.error(`server revoke failed (${message}); local secrets will still be deleted`);
    }
  }

  // Hold the sync lock: deleting cache.db under a running sync would send its
  // writes into a deleted inode while it reports success.
  const release = await acquireSyncLock();
  try {
    await deleteSession();
    if (options.deleteCache) removeCacheFiles(dbPath());
  } finally {
    release();
  }

  const cacheNote = options.deleteCache
    ? " The encrypted cache was removed with the database key."
    : " The encrypted cache stays; the next sync replaces it because its key is gone.";
  outro(
    revoked
      ? `session revoked and local secrets deleted.${cacheNote}`
      : `local secrets deleted; the server session may still be valid until it expires.${cacheNote}`,
  );
}
