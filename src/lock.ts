import { dlopen, read, type Pointer } from "bun:ffi";
import { closeSync, constants, openSync } from "node:fs";
import { UserError } from "./errors.ts";
import { lockPath } from "./paths.ts";

function cloexecFlag(): number {
  const known = constants as typeof constants & { O_CLOEXEC?: number };
  if (typeof known.O_CLOEXEC === "number") return known.O_CLOEXEC;
  // `fs.constants` types omit O_CLOEXEC. Linux is 02000000, macOS is 0x01000000.
  return process.platform === "darwin" ? 0x01000000 : 0o2000000;
}

function errnoValue(location: Pointer | bigint | null): number {
  if (location === null) throw new UserError("could not read errno");
  return read.i32(location);
}

/** Linux and macOS agree on these `flock(2)` operations. */
const LOCK_UN = 8;
const LOCK_EX = 2;
const LOCK_NB = 4;
const EINTR = 4;

type Posix = {
  flock: (fd: number, operation: number) => number;
  errno: () => number;
  /** `flock` returns this when another holder has the lock. */
  again: number;
};

let posix: Posix | undefined;

function loadPosix(): Posix {
  if (process.platform === "linux") {
    const lib = dlopen("libc.so.6", {
      flock: { args: ["i32", "i32"], returns: "i32" },
      __errno_location: { args: [], returns: "ptr" },
    });
    return {
      flock: (fd, operation) => lib.symbols.flock(fd, operation),
      errno: () => errnoValue(lib.symbols.__errno_location()),
      again: 11,
    };
  }
  if (process.platform === "darwin") {
    const lib = dlopen("libSystem.B.dylib", {
      flock: { args: ["i32", "i32"], returns: "i32" },
      __error: { args: [], returns: "ptr" },
    });
    return {
      flock: (fd, operation) => lib.symbols.flock(fd, operation),
      errno: () => errnoValue(lib.symbols.__error()),
      again: 35,
    };
  }
  throw new UserError(`sync lock needs flock (${process.platform})`);
}

function os(): Posix {
  posix ??= loadPosix();
  return posix;
}

/**
 * Exclusive lock for sync, and for logout while it deletes the cache.
 *
 * `sync.lock` is a durable sentinel. Mutual exclusion is `flock` on that
 * file, which the kernel drops when this process exits — a crash between
 * create and any later write cannot stick. The file's bytes are not read
 * and not part of the protocol. A live holder is never taken over; a waiter
 * fails after `waitMs`.
 */
export async function acquireSyncLock(waitMs = 30_000): Promise<() => void> {
  const held = os();
  const fd = openSync(lockPath(), constants.O_CREAT | constants.O_RDWR | cloexecFlag(), 0o600);
  const started = Date.now();
  try {
    while (true) {
      if (held.flock(fd, LOCK_EX | LOCK_NB) === 0) {
        let released = false;
        return () => {
          if (released) return;
          released = true;
          held.flock(fd, LOCK_UN);
          try {
            closeSync(fd);
          } catch {
            /* already closed */
          }
        };
      }
      const err = held.errno();
      if (err !== held.again && err !== EINTR) {
        throw new UserError(`could not lock sync (${err})`);
      }
      if (Date.now() - started >= waitMs) {
        throw new UserError("another sns sync is still running — wait for it to finish, then retry");
      }
      await Bun.sleep(200);
    }
  } catch (error) {
    try {
      closeSync(fd);
    } catch {
      /* already closed */
    }
    throw error;
  }
}
