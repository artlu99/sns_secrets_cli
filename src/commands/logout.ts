import { intro, outro } from "@clack/prompts";
import pc from "picocolors";
import { existsSync } from "node:fs";
import { UserError } from "../errors.ts";
import { removeCacheFiles } from "../db.ts";
import { acquireSyncLock } from "../lock.ts";
import { sanitizeText } from "../notes.ts";
import { createApi, withAccess } from "../sn-api.ts";
import { DEFAULT_API_URL, dbPath, readPlainConfig, sessionPath } from "../paths.ts";
import { deleteSession, loadSession, saveSession, type SessionSecrets } from "../session-file.ts";

/**
 * Revoke the server session (best-effort) and delete local secrets.
 * Used by `sns logout` and by login when switching accounts.
 * Returns whether the server revoke succeeded.
 */
export async function clearSession(options: { deleteCache?: boolean } = {}): Promise<{ revoked: boolean }> {
  let apiUrl = DEFAULT_API_URL;
  try {
    apiUrl = readPlainConfig().apiUrl;
  } catch (error) {
    // Logout is the recovery path: a config that fails the https gate must
    // not strand the secrets it exists to delete. Revoke best-effort
    // against the default host instead.
    const reason = sanitizeText(error instanceof Error ? error.message : "unreadable .env");
    console.error(pc.yellow(`cannot read .env (${reason})`));
  }
  const api = createApi(apiUrl);

  // Hold the sync lock BEFORE reading the session. A concurrent sync holding
  // the lock can rotate the refresh token while logout waits; reading the
  // session first would refresh and revoke with the pre-rotation token, be
  // rejected (refresh tokens are single-use), and still delete the file —
  // the only local copy of the rotation the sync just saved. The server
  // session then stays valid until natural expiry with no way to revoke it
  // from this machine. Reading under the lock shares the serialization every
  // rotation goes through (the revoke below may itself refresh — withAccess
  // -> saveSession — and a refresh racing a running sync's own refresh
  // rotates the refresh token twice, one rotation invalidating the other).
  // It also keeps the deletion below from pulling the ground out of that
  // sync's writes.
  const release = await acquireSyncLock();
  let revoked = false;
  try {
    let secrets: SessionSecrets | null = null;
    if (existsSync(sessionPath())) {
      try {
        secrets = await loadSession();
      } catch (error) {
        // A broken session must not strand its secrets on disk: delete them anyway.
        // Local display sinks bypass index.ts's sanitized top-level catch, so
        // file- and server-derived text is sanitized here too.
        const reason = sanitizeText(error instanceof Error ? error.message : "unreadable session file");
        console.error(pc.yellow(`cannot read the session to revoke it server-side (${reason})`));
      }
    } else {
      throw new UserError("not logged in");
    }

    if (secrets) {
      try {
        // Refresh first if needed, so logout works after the access token expired —
        // the common case, since access tokens are short-lived.
        await withAccess(secrets, saveSession, api, (current) => api.logout(current));
        revoked = true;
      } catch (error) {
        // ApiError summaries embed up to 180 characters of server-supplied
        // tag/message text: sanitize before it touches the terminal (this
        // sink never passes through the top-level boundary).
        const message = sanitizeText(error instanceof Error ? error.message : "revoke failed");
        console.error(`server revoke failed (${message}); local secrets will still be deleted`);
      }
    }

    await deleteSession();
    if (options.deleteCache) removeCacheFiles(dbPath());
  } finally {
    release();
  }

  return { revoked };
}

export async function logoutCommand(options: { deleteCache?: boolean } = {}): Promise<void> {
  intro("sns logout");
  const { revoked } = await clearSession(options);
  const cacheNote = options.deleteCache
    ? " The encrypted cache was removed with the database key."
    : " The encrypted cache stays; the next sync replaces it because its key is gone.";
  outro(
    revoked
      ? `session revoked and local secrets deleted.${cacheNote}`
      : `local secrets deleted; the server session may still be valid until it expires.${cacheNote}`,
  );
}
