/**
 * Lock-state ownership: chrome.storage.session is the single source of truth,
 * shared by every extension context. Only the service WRITER mutates it —
 * surfaces report traffic (activity/hidden/visible/unlock) to the worker over
 * runtime messaging, and the worker applies every mutation (reports plus its
 * own alarm locks) through one serialized queue, so two writes can never
 * interleave between the read and the set. Everyone watches the writes to
 * re-gate the UI the instant `locked` flips, and the worker watches them to
 * (re)arm the one-shot auto-lock alarm. All state transitions are the pure
 * reducers in lock-schedule.ts — this module is only storage I/O and
 * transport.
 */
import { browser } from "wxt/browser";
import { clearCache } from "./cache.ts";
import { SESSION_KEY } from "./session.ts";
import {
  applyActivity,
  applyHidden,
  applyLock,
  applyUnlock,
  applyVisible,
  defaultLockState,
  LOCK_STATE_KEY,
  type LockState,
} from "./lock-schedule.ts";

export async function getLockState(): Promise<LockState> {
  const got = await browser.storage.session.get(LOCK_STATE_KEY);
  return (got[LOCK_STATE_KEY] as LockState | undefined) ?? defaultLockState();
}

/** The lock-state mutation a surface asks the service worker to apply. */
export type LockOp = "activity" | "hidden" | "visible" | "unlock" | "lock";

/** What performed a lock — surfaces show the inactivity notice only for "auto". */
export type LockReason = "manual" | "auto";

/** runtime.onMessage type the surfaces send to the single writer. */
export const LOCK_OP_MESSAGE_TYPE = "sns:lock-op";

function reduceOp(op: LockOp, state: LockState, now: number, reason?: LockReason): LockState {
  switch (op) {
    case "activity":
      return applyActivity(state, now);
    case "hidden":
      return applyHidden(state, now);
    case "visible":
      return applyVisible(state, now);
    case "unlock":
      return applyUnlock(state, now);
    case "lock":
      return applyLock(state, now, reason ?? "manual");
  }
}

async function mutate(reduce: (state: LockState) => LockState): Promise<LockState> {
  const next = reduce(await getLockState());
  await browser.storage.session.set({ [LOCK_STATE_KEY]: next });
  return next;
}

/**
 * Worker-side mutation queue: every lockState write the service worker makes
 * (a surface's report, the alarm's lock) chains through here, so the
 * get→reduce→set sequence of one mutation can never interleave with another.
 * Without it, a surface's activity report that read the state before the
 * alarm's lock would land after it and regress `locked`/`lockEpoch` — the
 * stale state that let an in-flight refresh write past a lock.
 */
let writerQueue: Promise<unknown> = Promise.resolve();

export function queueLockOp(op: LockOp, reason?: LockReason): Promise<LockState> {
  const run = writerQueue.then(() => mutate((state) => reduceOp(op, state, Date.now(), reason)));
  // The queue itself never rejects; callers still see their own run's errors.
  writerQueue = run.catch(() => {});
  return run;
}

/**
 * Surfaces ask the worker (the single writer) to apply the op; only when the
 * worker is unreachable — mid-reload — does the surface fall back to writing
 * directly, accepting the old race rather than a dead lock button.
 */
async function report(op: LockOp, reason?: LockReason): Promise<LockState> {
  try {
    const reply = (await browser.runtime.sendMessage({ type: LOCK_OP_MESSAGE_TYPE, op, reason })) as
      | LockState
      | undefined;
    if (reply && typeof reply === "object" && "locked" in reply) return reply;
  } catch {
    // fall through to the direct write
  }
  return mutate((state) => reduceOp(op, state, Date.now(), reason));
}

/** Vault activity in a visible surface (input events, copy, reveal, search). */
export function markActivity(): Promise<LockState> {
  return report("activity");
}

/** The dashboard tab (the only surface that outlives hiding) went hidden. */
export function markHidden(): Promise<LockState> {
  return report("hidden");
}

/** A surface became visible again (or booted into a live vault). */
export function markVisible(): Promise<LockState> {
  return report("visible");
}

/** Fresh credentials just saved — the new vault session starts unlocked. */
export function markUnlocked(): Promise<LockState> {
  return report("unlock");
}

/**
 * Wipe the master key, session tokens, and decrypted cache from session
 * storage, then record the lock (new epoch). Used by the lock button, sign
 * out, and the service worker's alarm handler — one code path for all. The
 * locked flag lands BEFORE the key removals: every surface's storage watcher
 * re-gates as soon as the epoch moves, and an interruption mid-wipe still
 * leaves a locked (not half-unlocked) state behind. `reason` distinguishes
 * the alarm ("auto" — surfaces show the inactivity notice) from a deliberate
 * lock ("manual" — they do not).
 */
export async function performLock(reason: LockReason = "manual"): Promise<void> {
  // In the worker (no window) the write goes through the local single-writer
  // queue; runtime messages from the background never loop back to it.
  if (typeof window === "undefined") await queueLockOp("lock", reason);
  else await report("lock", reason);
  await browser.storage.session.remove(SESSION_KEY);
  // clearCache, not a bare CACHE_KEY removal: the quota-overflow flag in
  // storage.local and the "!" action badge must not outlive the lock — a
  // stale flag would banner every future vault, even a fresh account.
  await clearCache();
}
