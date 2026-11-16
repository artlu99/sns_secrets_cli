import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  rmSync,
  statfsSync,
  writeSync,
} from "node:fs";
import { dirname } from "node:path";
import pc from "picocolors";
import { UserError } from "../errors.ts";
import { planCopy, resolveNote } from "../notes.ts";
import { openCache } from "./list.ts";

/** Linux TMPFS_MAGIC, compared against statfs().ftype when detectable. */
const TMPFS_MAGIC = 0x01021994;

function openForWrite(path: string, force: boolean): number {
  // lstat catches a symlink target with a clear message (the O_EXCL create
  // would surface it as EEXIST), and O_NOFOLLOW backs it up on the --force
  // reopen where O_EXCL is absent. lstat-to-open is same-user-race territory,
  // outside the threat model.
  if (lstatSync(path, { throwIfNoEntry: false })?.isSymbolicLink()) {
    throw new UserError(`${path} is a symlink — refusing to write through it`);
  }
  const nofollow = constants.O_NOFOLLOW ?? 0;
  const flags =
    constants.O_WRONLY | constants.O_CREAT | (force ? constants.O_TRUNC : constants.O_EXCL) | nofollow;
  try {
    return openSync(path, flags, 0o600);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException)?.code;
    if (code === "EEXIST") throw new UserError(`${path} already exists — pass --force to overwrite`);
    if (code === "ELOOP") throw new UserError(`${path} is a symlink — refusing to write through it`);
    throw error;
  }
}

/**
 * One-line warning when the destination's filesystem is not tmpfs; null when
 * undetectable. statfs needs an existing path, so this walks up to the
 * nearest existing ancestor — the first sink into a brand-new handoff dir
 * is exactly the case the warning exists for.
 */
export function diskBackedWarning(path: string): string | null {
  if (process.platform !== "linux" || typeof statfsSync !== "function") return null;
  let dir = dirname(path);
  for (let hop = 0; hop < 8; hop++) {
    try {
      if (statsType(dir) === TMPFS_MAGIC) return null;
      return `${path} is on disk-backed storage — a handoff dir under $XDG_RUNTIME_DIR or /dev/shm leaves no disk remnants`;
    } catch {
      const parent = dirname(dir);
      if (parent === dir) return null;
      dir = parent;
    }
  }
  return null;
}

function statsType(dir: string): number {
  return statfsSync(dir).type;
}

/**
 * Write a secret value to a file that is 0600 from the instant it exists:
 * O_EXCL|O_NOFOLLOW create at 0600 (never a wider mode, never through a
 * symlink), an umask-proof fchmod immediately after, and an fstat assertion
 * before the fd closes. Any failure inside the write removes the partial
 * file. Deleting the file afterwards is the reader's obligation.
 */
export function writeSecretFile(
  value: string,
  path: string,
  options: { force?: boolean } = {},
  write: (fd: number, data: string) => void = writeSync,
): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const fd = openForWrite(path, options.force === true);
  try {
    fchmodSync(fd, 0o600);
    write(fd, value);
    const stat = fstatSync(fd);
    if ((stat.mode & 0o777) !== 0o600) {
      throw new UserError(
        `${path} is not 0600 after the write (mode 0${(stat.mode & 0o777).toString(8)}) — removing it`,
      );
    }
    // write(2) may return a short count without erroring — never report a
    // secret as fully written when it is not on the disk.
    if (stat.size !== Buffer.byteLength(value)) {
      throw new UserError(
        `${path} is truncated after the write (${stat.size} of ${Buffer.byteLength(value)} bytes) — removing it`,
      );
    }
  } catch (error) {
    try {
      rmSync(path, { force: true });
    } catch {
      // removal failed; the file is at worst a partial 0600 copy owned by us
    }
    throw error;
  } finally {
    closeSync(fd);
  }
}

/**
 * `sns sink <id> <key> <path>` — the sanctioned value-exit to a file for
 * agent handoff. Exactly one key into one file; the clipboard is never
 * touched and stdout is never a destination; the value is never echoed.
 */
export async function sinkCommand(
  id: string,
  key: string,
  path: string,
  options: { force?: boolean } = {},
): Promise<void> {
  const db = await openCache();
  try {
    const row = resolveNote(db, id, { all: false });
    const plan = planCopy(row, key);
    if (plan.kind !== "value") {
      throw new UserError("sink needs one KEY=VALUE setting — `sns copy <id>` lists a note's keys");
    }
    const warning = diskBackedWarning(path);
    if (warning) console.error(pc.yellow(`warning: ${warning}`));
    writeSecretFile(plan.value, path, options);
    console.log(`wrote ${plan.key} (${Buffer.byteLength(plan.value)} bytes) → ${path} (0600)`);
  } finally {
    db.close();
  }
}
