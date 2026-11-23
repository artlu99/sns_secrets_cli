import { useEffect, useRef } from "react";
import { browser } from "wxt/browser";
import {
  activityPingDue,
  AUTO_LOCK_HIDDEN_MS,
  AUTO_LOCK_IDLE_MS,
  LOCK_STATE_KEY,
  remainingLockMs,
  type LockState,
} from "../lib/lock-schedule.ts";
import { getLockState, markActivity, markHidden, markVisible, performLock, type LockReason } from "../lib/lock-state.ts";

/** Re-exported for readability; defined (with the semantics) in lib/lock-schedule.ts. */
export { AUTO_LOCK_HIDDEN_MS, AUTO_LOCK_IDLE_MS };

const ACTIVITY_EVENTS = ["pointermove", "pointerdown", "keydown", "wheel"] as const;

/**
 * Auto-lock, owned by the MV3 service worker. Surfaces no longer hold the
 * clock (a closed popup used to leave the vault open until browser exit) —
 * the lock clock lives in chrome.storage.session + a one-shot chrome.alarms
 * timer in the background worker, so it survives popup death, tab closing,
 * and service-worker shutdown. This hook does three things:
 *
 * 1. Reports vault traffic to the lock owner: input activity (throttled —
 *    it moves the idle clock only) and, with `watchVisibility` (the
 *    dashboard tab is the only surface that outlives hiding), hide/show
 *    transitions — the visible report is also what cancels the walk-away
 *    clock, so arming reports the CURRENT visibility instead of pretending
 *    a hidden tab is active.
 * 2. Reacts to lock-state writes: when `locked` flips true — alarm fired in
 *    the worker, or the lock button in ANY surface — `onLock` re-gates this
 *    surface immediately, clearing whatever it has in memory, and tells it
 *    whether the lock was automatic (inactivity notice) or deliberate.
 * 3. Watches the deadline itself as a fallback: if the background entry
 *    point is dead (evaluation failure, missing API), no alarm will ever
 *    fire — the surface checks the deadline every 30s and performs the lock
 *    directly when it has passed, restoring the guarantee the old per-surface
 *    timers gave. With a healthy worker this never trips: the alarm locks
 *    first and the reducer ignores locks on an already-locked state.
 */

export function useAutoLock(
  enabled: boolean,
  onLock: (reason: LockReason) => void,
  options: { watchVisibility?: boolean } = {},
): void {
  const onLockRef = useRef(onLock);
  onLockRef.current = onLock;
  const watchVisibility = options.watchVisibility === true;

  // The lock watcher registers regardless of phase: a lock landing during
  // boot (before `enabled` turns the reporting half on) still re-gates this
  // surface — the warm-cache view must never outlive its session unnoticed.
  useEffect(() => {
    const onStorage: Parameters<typeof browser.storage.onChanged.addListener>[0] = (changes, area) => {
      if (area !== "session") return;
      const next = changes[LOCK_STATE_KEY]?.newValue as LockState | undefined;
      if (next?.locked === true) onLockRef.current(next.lockReason === "auto" ? "auto" : "manual");
    };
    browser.storage.onChanged.addListener(onStorage);
    return () => {
      browser.storage.onChanged.removeListener(onStorage);
    };
  }, []);

  useEffect(() => {
    if (!enabled) return;
    let lastPing = 0;
    const ping = () => {
      const now = Date.now();
      if (!activityPingDue(lastPing, now)) return;
      lastPing = now;
      void markActivity();
    };
    const onVisibility = () => {
      if (document.visibilityState === "hidden") void markHidden();
      else void markVisible();
    };
    // The watchdog must not trust its first read before the arming report
    // has landed — a vault unlocked seconds ago can still show a stale
    // lastActivity. Skipping ticks until the deadline is at least a window
    // old keeps the fallback from racing the owner's first arm.
    let armedAt = 0;
    const watchdog = () => {
      void (async () => {
        if (Date.now() - armedAt < 15_000) return;
        const state = await getLockState();
        if (!state.locked && state.lastActivity > 0 && remainingLockMs(state, Date.now()) === 0) {
          await performLock("auto");
        }
      })();
    };

    for (const type of ACTIVITY_EVENTS) {
      window.addEventListener(type, ping, { passive: true });
    }
    if (watchVisibility) {
      document.addEventListener("visibilitychange", onVisibility);
      // Arming reports the truth: a hidden dashboard starts (or keeps) the
      // walk-away clock; a visible one counts as activity. The popup — no
      // watchVisibility — always pings: it is visible while it exists.
      if (document.visibilityState === "hidden") void markHidden();
      else ping();
    } else {
      // Arming counts as activity: the vault is live and visible right now.
      ping();
    }
    armedAt = Date.now();
    const watchdogTimer = window.setInterval(watchdog, 30_000);

    return () => {
      for (const type of ACTIVITY_EVENTS) {
        window.removeEventListener(type, ping);
      }
      if (watchVisibility) document.removeEventListener("visibilitychange", onVisibility);
      window.clearInterval(watchdogTimer);
    };
  }, [enabled, watchVisibility]);
}
