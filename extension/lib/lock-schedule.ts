/**
 * Pure lock-state math for the MV3 lock owner — no browser APIs, so lib tests
 * import it freely (the same contract as clear-timer.ts). The single source of
 * truth for lock state is one `lockState` record in chrome.storage.session:
 * it survives service-worker death (storage.session is memory-backed but
 * shared across contexts) and every surface reacts to its writes via
 * storage.onChanged. The service worker arms a one-shot chrome.alarms timer
 * for `remainingLockMs`; when it fires, the worker wipes the key material and
 * re-locks, whatever the UIs are doing.
 */

/** Idle budget: lock 5 minutes after the last reported vault activity. */
export const AUTO_LOCK_IDLE_MS = 5 * 60_000;
/**
 * Walk-away budget: 2 minutes after the dashboard tab became hidden (the
 * only surface that outlives hiding; a closed popup simply stops reporting
 * activity, so the idle budget governs). `hiddenSince` is a STATE, not a
 * timer: only the dashboard's visible report clears it — popup activity
 * cannot, because the popup dying would leave a still-hidden dashboard with
 * no event to re-derive the state from. The price is that active popup use
 * while the dashboard sits hidden still walks away at 2 minutes — honest and
 * deterministic beats a budget that silently degrades to idle-only.
 */
export const AUTO_LOCK_HIDDEN_MS = 2 * 60_000;

/** chrome.alarms name of the one-shot auto-lock timer (re-created on re-arm). */
export const LOCK_ALARM_NAME = "sns-autolock";

/**
 * Activity reports are throttled per surface so a streaming pointermove never
 * wakes the service worker per event; the alarm budget absorbs the staleness
 * (a lock can fire at most one throttle window earlier than promised).
 */
export const ACTIVITY_PING_THROTTLE_MS = 10_000;

/** storage.session key of the lock-state record. */
export const LOCK_STATE_KEY = "lockState";

export type LockState = {
  /** True once the alarm (or the lock button) has wiped the session. */
  locked: boolean;
  /** Epoch ms of the last activity report (0 while locked). */
  lastActivity: number;
  /** When the dashboard went hidden; null while it is visible. */
  hiddenSince: number | null;
  /** Bumped on every lock and unlock; guards in-flight writes (sync, refresh). */
  lockEpoch: number;
  /** What performed the last lock — surfaces show the inactivity notice only
   * for "auto", so a manual lock in one surface never lies in the others. */
  lockReason: "manual" | "auto" | null;
};

export function defaultLockState(): LockState {
  // Absent state means "no live vault" — the browser wipes storage.session on
  // exit, so a fresh start is always locked.
  return { locked: true, lastActivity: 0, hiddenSince: null, lockEpoch: 0, lockReason: null };
}

/** Milliseconds until the auto-lock alarm should fire; 0 means "now". */
export function remainingLockMs(state: LockState, now: number): number {
  if (state.locked) return 0;
  const idleAt = state.lastActivity + AUTO_LOCK_IDLE_MS;
  const hiddenAt = state.hiddenSince === null ? Infinity : state.hiddenSince + AUTO_LOCK_HIDDEN_MS;
  return Math.max(0, Math.min(idleAt, hiddenAt) - now);
}

/**
 * True when a write captured at `startEpoch` must be aborted: the epoch moved
 * (a lock or a fresh unlock happened) or the vault is locked right now. This
 * is the guard that stops an in-flight sync from rewriting session/cache
 * after the alarm wiped them.
 */
export function lockMoved(startEpoch: number, state: LockState): boolean {
  return state.locked || state.lockEpoch !== startEpoch;
}

/** Whether a surface should send an activity report now (per-surface throttle). */
export function activityPingDue(lastSent: number, now: number): boolean {
  return now - lastSent >= ACTIVITY_PING_THROTTLE_MS;
}

/** Reducers: pure (state, now) -> state. Locked vaults ignore traffic reports. */

/** Activity moves the idle clock but NOT the walk-away state: only the
 * dashboard's visible report can clear `hiddenSince` (see the hidden-budget
 * doc — a popup's activity report cannot vouch for a tab it cannot see). */
export function applyActivity(state: LockState, now: number): LockState {
  if (state.locked) return state;
  return { ...state, lastActivity: now };
}

export function applyHidden(state: LockState, now: number): LockState {
  if (state.locked || state.hiddenSince !== null) return state;
  return { ...state, hiddenSince: now };
}

export function applyVisible(state: LockState, now: number): LockState {
  if (state.locked) return state;
  return { ...state, lastActivity: now, hiddenSince: null };
}

/** A fresh unlock (new credentials): new epoch, activity clock starts now. */
export function applyUnlock(state: LockState, now: number): LockState {
  return {
    locked: false,
    lastActivity: now,
    hiddenSince: null,
    lockEpoch: state.lockEpoch + 1,
    lockReason: null,
  };
}

/**
 * The alarm fired ("auto") or the lock button/sign-out was pressed
 * ("manual"): wipe markers, bump the epoch. Idempotent on an already-locked
 * state — a surface's redundant lock write must not bump the epoch again
 * (that would strand in-flight guarded writes) or overwrite the reason a
 * concurrent lock just recorded.
 */
export function applyLock(state: LockState, _now: number, reason: "manual" | "auto" = "manual"): LockState {
  if (state.locked) return state;
  return { locked: true, lastActivity: 0, hiddenSince: null, lockEpoch: state.lockEpoch + 1, lockReason: reason };
}
