import { describe, expect, test } from "bun:test";
import {
  activityPingDue,
  applyActivity,
  applyHidden,
  applyLock,
  applyUnlock,
  applyVisible,
  AUTO_LOCK_HIDDEN_MS,
  AUTO_LOCK_IDLE_MS,
  defaultLockState,
  lockMoved,
  remainingLockMs,
} from "./lock-schedule.ts";
import type { LockState } from "./lock-schedule.ts";

const NOW = 1_000_000;

function unlocked(overrides: Partial<LockState> = {}): LockState {
  return { locked: false, lastActivity: NOW, hiddenSince: null, lockEpoch: 7, lockReason: null, ...overrides };
}

describe("remainingLockMs", () => {
  test("idle budget runs from the last activity", () => {
    const state = unlocked({ lastActivity: NOW - 60_000 });
    expect(remainingLockMs(state, NOW)).toBe(AUTO_LOCK_IDLE_MS - 60_000);
  });

  test("a hidden surface tightens the budget to the walk-away window", () => {
    const state = unlocked({ lastActivity: NOW, hiddenSince: NOW - 90_000 });
    expect(remainingLockMs(state, NOW)).toBe(AUTO_LOCK_HIDDEN_MS - 90_000);
  });

  test("the tighter of the two clocks wins", () => {
    // Idle almost exhausted, hidden recently.
    const tightIdle = unlocked({ lastActivity: NOW - 4 * 60_000, hiddenSince: NOW });
    expect(remainingLockMs(tightIdle, NOW)).toBe(60_000);
    // Walk-away almost exhausted, idle plenty left.
    const tightHidden = unlocked({ lastActivity: NOW, hiddenSince: NOW - 110_000 });
    expect(remainingLockMs(tightHidden, NOW)).toBe(10_000);
  });

  test("overdue budgets clamp to 0, never negative", () => {
    const state = unlocked({ lastActivity: NOW - AUTO_LOCK_IDLE_MS - 1, hiddenSince: null });
    expect(remainingLockMs(state, NOW)).toBe(0);
    const hidden = unlocked({ hiddenSince: NOW - AUTO_LOCK_HIDDEN_MS - 1 });
    expect(remainingLockMs(hidden, NOW)).toBe(0);
  });

  test("locked state has no pending budget", () => {
    expect(remainingLockMs(defaultLockState(), NOW)).toBe(0);
  });
});

describe("reducers", () => {
  test("activity bumps the idle clock but leaves the walk-away claim alone", () => {
    // Only the dashboard's visible report clears hiddenSince — a popup's
    // activity cannot vouch for a tab it cannot see, and a popup dying after
    // its activity must not leave a hidden dashboard with no clock running.
    const state = unlocked({ lastActivity: NOW - 60_000, hiddenSince: NOW - 30_000 });
    const next = applyActivity(state, NOW);
    expect(next.lastActivity).toBe(NOW);
    expect(next.hiddenSince).toBe(NOW - 30_000);
    expect(next.lockEpoch).toBe(7);
    expect(remainingLockMs(next, NOW)).toBe(AUTO_LOCK_HIDDEN_MS - 30_000);
  });

  test("the first hidden report starts the walk-away clock; later ones do not restart it", () => {
    const once = applyHidden(unlocked(), NOW);
    expect(once.hiddenSince).toBe(NOW);
    const again = applyHidden(once, NOW + 5_000);
    expect(again.hiddenSince).toBe(NOW);
  });

  test("visible restarts the idle clock and clears the walk-away claim", () => {
    const state = unlocked({ lastActivity: NOW - 120_000, hiddenSince: NOW - 60_000 });
    const next = applyVisible(state, NOW);
    expect(next.hiddenSince).toBeNull();
    expect(next.lastActivity).toBe(NOW);
  });

  test("unlock opens the vault on a fresh epoch and clock", () => {
    const next = applyUnlock(defaultLockState(), NOW);
    expect(next.locked).toBe(false);
    expect(next.lockEpoch).toBe(1);
    expect(next.lastActivity).toBe(NOW);
    expect(next.hiddenSince).toBeNull();
    expect(next.lockReason).toBeNull();
  });

  test("lock bumps the epoch, resets the traffic markers, and records its reason", () => {
    const next = applyLock(unlocked({ lastActivity: NOW, hiddenSince: NOW }), NOW);
    expect(next.locked).toBe(true);
    expect(next.lockEpoch).toBe(8);
    expect(next.lastActivity).toBe(0);
    expect(next.hiddenSince).toBeNull();
    expect(next.lockReason).toBe("manual");
    expect(applyLock(unlocked(), NOW, "auto").lockReason).toBe("auto");
  });

  test("locking an already-locked vault changes nothing (no epoch bump, no reason overwrite)", () => {
    const locked = applyLock(unlocked(), NOW, "auto");
    expect(applyLock(locked, NOW + 1_000, "manual")).toBe(locked);
  });

  test("locked vaults ignore traffic reports (only unlock/lock move them)", () => {
    const locked = applyLock(unlocked(), NOW);
    expect(applyActivity(locked, NOW)).toBe(locked);
    expect(applyHidden(locked, NOW)).toBe(locked);
    expect(applyVisible(locked, NOW)).toBe(locked);
  });
});

describe("lockMoved", () => {
  test("epoch drift aborts the guarded write", () => {
    expect(lockMoved(7, unlocked({ lockEpoch: 8 }))).toBe(true);
  });

  test("a locked vault aborts even at the same epoch", () => {
    expect(lockMoved(7, { ...unlocked(), locked: true })).toBe(true);
  });

  test("an unchanged vault does not", () => {
    expect(lockMoved(7, unlocked())).toBe(false);
  });
});

describe("activityPingDue", () => {
  test("first report is always due", () => {
    expect(activityPingDue(0, NOW)).toBe(true);
  });

  test("inside the throttle window is not due; at the window's edge it is", () => {
    expect(activityPingDue(NOW - 1_000, NOW)).toBe(false);
    expect(activityPingDue(NOW - 10_000, NOW)).toBe(true);
  });
});
