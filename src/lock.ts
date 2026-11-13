import { randomUUID } from "node:crypto";
import { closeSync, constants, existsSync, openSync, readFileSync, statSync, unlinkSync, writeSync } from "node:fs";
import { UserError } from "./errors.ts";
import { lockPath } from "./paths.ts";

const STALE_MS = 30 * 60 * 1000;

/** Tokens of locks this process created; one leaked by a crashed run can be reclaimed after STALE_MS. */
const ours = new Set<string>();

function lockContents(path: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return "";
  }
}

function pidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/** Linux only: a recycled pid belonging to an unrelated process must not wedge the lock. */
function looksLikeSns(pid: number): boolean {
  try {
    const cmdline = readFileSync(`/proc/${pid}/cmdline`, "utf8");
    return /sns|bun/.test(cmdline);
  } catch {
    return true; // no /proc (macOS) or the process just exited — assume it is a real holder
  }
}

/**
 * Stale when the holder is dead, when the pid was recycled by a non-sns
 * process, or when it is our own leaked lock that aged out. A lock held by a
 * live foreign sns process is only taken over after STALE_MS.
 */
function lockIsStale(path: string): boolean {
  const content = lockContents(path).trim();
  const [pidText, token] = content.split(" ");
  const pid = Number(pidText);
  if (!Number.isInteger(pid) || pid <= 0) return true;
  if (!pidAlive(pid)) return true;
  if (token !== undefined && ours.has(token)) {
    try {
      return Date.now() - statSync(path).mtimeMs > STALE_MS;
    } catch {
      return false;
    }
  }
  if (!looksLikeSns(pid)) return true;
  try {
    return Date.now() - statSync(path).mtimeMs > STALE_MS;
  } catch {
    return false;
  }
}

/** Exclusive sync lock. A second sync waits, then fails with a clear message. */
export async function acquireSyncLock(waitMs = 30_000): Promise<() => void> {
  const path = lockPath();
  const started = Date.now();
  while (true) {
    const token = randomUUID();
    let fd: number;
    try {
      fd = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_RDWR, 0o600);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "EEXIST") throw error;
      if (existsSync(path) && lockIsStale(path)) {
        // Unlink only when the content is still what we judged stale — never
        // a fresh lock a racing waiter just created.
        const judged = lockContents(path);
        if (judged !== "" && lockContents(path) === judged) {
          try {
            unlinkSync(path);
          } catch {
            /* raced with the holder */
          }
        }
        continue;
      }
      if (Date.now() - started >= waitMs) {
        throw new UserError("another sns sync is still running — wait for it to finish, then retry");
      }
      await Bun.sleep(200);
      continue;
    }
    try {
      writeSync(fd, `${process.pid} ${token}`);
    } catch {
      /* pid/token are advisory; the O_EXCL create is the real lock */
    }
    ours.add(token);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      ours.delete(token);
      // Delete only if the file still holds OUR token — never a successor's lock.
      if (lockContents(path).trim() === `${process.pid} ${token}`) {
        try {
          unlinkSync(path);
        } catch {
          /* another process may have cleared a stale lock */
        }
      }
      try {
        closeSync(fd);
      } catch {
        /* already closed */
      }
    };
  }
}
