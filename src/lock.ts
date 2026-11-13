import { closeSync, constants, existsSync, openSync, readFileSync, statSync, unlinkSync, writeSync } from "node:fs";
import { UserError } from "./errors.ts";
import { lockPath } from "./paths.ts";

function pidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function lockIsStale(path: string): boolean {
  let pid = 0;
  try {
    pid = Number(readFileSync(path, "utf8").trim());
  } catch {
    return true;
  }
  if (!pidAlive(pid)) return true;
  try {
    const age = Date.now() - statSync(path).mtimeMs;
    return age > 30 * 60 * 1000 && pid === process.pid;
  } catch {
    return false;
  }
}

/** Exclusive sync lock. A second sync waits, then fails with a clear message. */
export async function acquireSyncLock(waitMs = 30_000): Promise<() => void> {
  const path = lockPath();
  const started = Date.now();
  while (true) {
    try {
      const fd = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_RDWR, 0o600);
      writeSync(fd, String(process.pid));
      let released = false;
      return () => {
        if (released) return;
        released = true;
        try {
          closeSync(fd);
        } catch {
          /* already closed */
        }
        try {
          unlinkSync(path);
        } catch {
          /* another process may have cleared a stale lock */
        }
      };
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "EEXIST") throw error;
      if (existsSync(path) && lockIsStale(path)) {
        try {
          unlinkSync(path);
        } catch {
          /* raced with the holder */
        }
        continue;
      }
      if (Date.now() - started >= waitMs) {
        throw new UserError("another sns sync is still running — wait for it to finish, then retry");
      }
      await Bun.sleep(200);
    }
  }
}
