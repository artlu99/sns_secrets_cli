import { useEffect, useRef } from "react";

/**
 * Auto-lock: re-gate the vault after inactivity. Two independent timers, per
 * the roadmap spec — idle (any pointer/key/wheel/scroll activity resets it)
 * and a stricter walk-away timer that starts when the page is hidden and is
 * cancelled when it comes back. Either expiry calls the same lock the button
 * does, so the vault session and the decrypted cache are wiped from session
 * storage and both surfaces show the login form again.
 */

export const AUTO_LOCK_IDLE_MS = 5 * 60_000;
export const AUTO_LOCK_HIDDEN_MS = 2 * 60_000;

const ACTIVITY_EVENTS = ["pointermove", "pointerdown", "keydown", "wheel"] as const;

/**
 * Arms the timers while `enabled` (the vault is unlocked). `onLock` is kept
 * in a ref so the timers never reset because a render re-created the
 * callback — only real user activity restarts the clock.
 */
export function useAutoLock(enabled: boolean, onLock: () => void): void {
  const onLockRef = useRef(onLock);
  onLockRef.current = onLock;

  useEffect(() => {
    if (!enabled) return;
    let idleTimer: number | undefined;
    let hiddenTimer: number | undefined;

    const resetIdle = () => {
      if (idleTimer !== undefined) window.clearTimeout(idleTimer);
      idleTimer = window.setTimeout(() => onLockRef.current(), AUTO_LOCK_IDLE_MS);
    };
    const onVisibility = () => {
      if (document.visibilityState === "hidden") {
        if (hiddenTimer === undefined) {
          hiddenTimer = window.setTimeout(() => onLockRef.current(), AUTO_LOCK_HIDDEN_MS);
        }
      } else if (hiddenTimer !== undefined) {
        window.clearTimeout(hiddenTimer);
        hiddenTimer = undefined;
      }
    };

    for (const type of ACTIVITY_EVENTS) {
      window.addEventListener(type, resetIdle, { passive: true });
    }
    document.addEventListener("visibilitychange", onVisibility);
    resetIdle();

    return () => {
      if (idleTimer !== undefined) window.clearTimeout(idleTimer);
      if (hiddenTimer !== undefined) window.clearTimeout(hiddenTimer);
      for (const type of ACTIVITY_EVENTS) {
        window.removeEventListener(type, resetIdle);
      }
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [enabled]);
}
