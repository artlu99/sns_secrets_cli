import { existsSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { intro, outro } from "@clack/prompts";
import { UserError } from "../errors.ts";
import { keychainDelete, warnIfKeychainItemSurvived } from "../keychain.ts";
import { acquireSyncLock } from "../lock.ts";
import { configDir, isOwnedConfigFileName, sessionPath } from "../paths.ts";
import { promptConfirm } from "./prompt.ts";

/**
 * `sns purge` — local amnesia. Deletes every file sns created in the config
 * directory (including a cache that is still readable, and one whose key is
 * long gone), removes the directory when nothing unrecognized remains, and
 * never touches the network: it works with no session, an expired lease, or
 * zero credentials. Revoking the server session is `sns logout`'s job — run
 * it first if you want that; purge cannot do it and will not pretend to.
 */
export async function purgeCommand(options: { yes?: boolean } = {}): Promise<void> {
  intro("sns purge");
  const dir = configDir();
  if (!existsSync(dir)) {
    throw new UserError(`nothing to purge — ${dir} does not exist`);
  }
  // Ownership is pattern-based, not exact-name: a crash mid-write leaves
  // `.env.keys.tmp-<pid>-<rand>` / `.env.session.<hash>` temps on disk, and
  // the .env.keys ones carry the plaintext session private key — the
  // scorched-earth contract ("every file sns created") has to cover them or
  // a decommission purge silently keeps a live credential. Only regular
  // files are swept; anything else is left for the operator to inspect.
  const dirents = readdirSync(dir, { withFileTypes: true });
  const known = dirents
    .filter((entry) => (entry.isFile() || entry.isSymbolicLink()) && isOwnedConfigFileName(entry.name))
    .map((entry) => entry.name);
  const unknown = dirents.filter((entry) => !isOwnedConfigFileName(entry.name)).map((entry) => entry.name);
  // Captured before the deletion: a keys file among the owned names means
  // custody was the file, which silences the unavailable-service warning.
  const fileCustody = known.includes(".env.keys");
  if (known.length === 0 && unknown.length === 0) {
    rmSync(dir, { recursive: true, force: true });
    outro(`${dir} had nothing in it — removed`);
    return;
  }

  // The revocation warning is only actionable BEFORE the deletion: purge
  // removes the session credentials, so `sns logout` after the fact is a
  // dead end — the outro states the outcome instead of pointing at it.
  const sessionExisted = existsSync(sessionPath());
  const sessionNote = sessionExisted
    ? " A server session exists — purge does not revoke it; cancel and run `sns logout` first if you want that."
    : " Any server session left over stays valid until its natural expiry.";
  if (!options.yes) {
    if (!process.stdin.isTTY) {
      throw new UserError("`sns purge` deletes every local file and cannot be undone — pass --yes to run without a terminal");
    }
    const readableCache = sessionExisted || existsSync(join(dir, ".env.keys")) ? " — its contents are currently readable" : "";
    const confirmed = await promptConfirm(
      `delete ${known.length} file(s) in ${dir} (including the note cache${readableCache})? This cannot be undone.${sessionNote}`,
      false,
    );
    if (!confirmed) throw new UserError("purge cancelled");
  } else if (sessionExisted) {
    console.error(`note: the server session will not be revoked — run sns logout first if you want that (proceeding with purge)`);
  }

  // Hold the sync lock: deleting cache.db under a running sync would send
  // its writes into a deleted inode while it reports success. sync.lock is
  // itself purged; the kernel flock lives on the inode, so unlocking an
  // unlinked file afterwards is fine.
  const release = await acquireSyncLock();
  try {
    for (const name of known) rmSync(join(dir, name), { force: true });
    // A purge that cannot confirm the keychain item's deletion must say so:
    // the dotenvx key is the one secret that outlives every file above.
    warnIfKeychainItemSurvived(await keychainDelete(), { fileCustody });
  } finally {
    release();
  }

  let note = "";
  if (unknown.length > 0) {
    note = ` ${unknown.length} unrecognized file(s) left in place for you to inspect: ${unknown.join(", ")}`;
  } else {
    rmSync(dir, { recursive: true, force: true });
    note = " The config directory was removed.";
  }
  outro(
    `purged ${known.length} file(s) from ${dir}.${note} The server session was not revoked and can no longer be from this machine — it expires on its own schedule.`,
  );
}
