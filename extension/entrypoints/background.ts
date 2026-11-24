import { clearCache } from "../lib/cache.ts";
import { LOCK_ALARM_NAME, LOCK_STATE_KEY, remainingLockMs } from "../lib/lock-schedule.ts";
import { getLockState, LOCK_OP_MESSAGE_TYPE, performLock, queueLockOp, type LockReason } from "../lib/lock-state.ts";
import { DEFAULT_ORIGIN_RULE_ID, removeOriginRule } from "../lib/origin.ts";
import { REFRESH_MESSAGE_TYPE, createRefreshClient, createSharedRefresh } from "../lib/refresh-flight.ts";
import { loadSession, saveSession, SESSION_KEY } from "../lib/session.ts";

export default defineBackground(() => {
  browser.runtime.onInstalled.addListener(() => {
    console.log("sns vault installed");
  });

  // ── Origin-strip ownership ─────────────────────────────────────────────
  // The hosted API 500s on the chrome-extension:// Origin scheme, so the
  // strip is still needed — but scoped: initiatorDomains is this extension's
  // id (the host of a chrome-extension:// initiator), so a tab running the
  // official web app keeps its Origin and its CORS. A static ruleset cannot
  // know the per-install id (lib/origin.ts), so this rule is installed here
  // on every wake — dynamic rules persist, the write is idempotent. A failed
  // install must not be fire-and-forget: while the vault is locked nothing
  // else wakes this worker, so a retry alarm re-arms until the rule lands
  // (surfaces also await a rules check before their first POST — the
  // `sns:origin-rules` message below).
  const ORIGIN_RETRY_ALARM = "sns-origin-retry";

  async function installDefaultOriginRule(): Promise<void> {
    await browser.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: [DEFAULT_ORIGIN_RULE_ID],
      addRules: [
        removeOriginRule(DEFAULT_ORIGIN_RULE_ID, ["api.standardnotes.com"], [browser.runtime.id]),
      ],
    });
  }

  function installOriginRuleWithRetry(): Promise<boolean> {
    return installDefaultOriginRule()
      .then(() => {
        void browser.alarms.clear(ORIGIN_RETRY_ALARM).catch(() => {});
        return true;
      })
      .catch((error) => {
        console.warn("origin-rule install failed; retrying", error);
        void browser.alarms
          .create(ORIGIN_RETRY_ALARM, { when: Date.now() + 30_000 })
          .catch(() => {});
        return false;
      });
  }

  void installOriginRuleWithRetry();

  // ── Token-refresh ownership (M4) ───────────────────────────────────────
  // Standard Notes rotates refresh tokens on use, so the popup and the
  // dashboard refreshing concurrently would leave the loser persisting a
  // dead token. Every surface asks over runtime messaging; one in-flight
  // flight shares the outcome, and its persisted write is epoch-guarded.
  const sharedRefresh = createSharedRefresh({
    loadSession,
    apiRefresh: (session) => createRefreshClient(session.apiUrl).refresh(session.secrets),
    saveSession: (session) => saveSession(session),
    // The settle check cannot cover its own gap: a lock landing between the
    // check and the persist takes the tokens back out (refresh-flight.ts).
    discardSession: () => browser.storage.session.remove(SESSION_KEY),
    getLockState,
  });

  // ── Auto-lock ownership ────────────────────────────────────────────────
  // The worker is the only place with a clock that outlives the surfaces: a
  // closed popup used to leave the vault unlocked until browser exit. The
  // source of truth is `lockState` in chrome.storage.session (survives this
  // worker being killed; surfaces report activity by writing it). Every
  // write to it re-arms a one-shot chrome.alarms timer for the remaining
  // budget; when the alarm fires, the key material and decrypted cache are
  // wiped and `locked` flips true, which re-gates every open surface via
  // their storage.onChanged watchers. Alarms persist across worker death;
  // they do not persist across browser restarts — none is needed, since
  // storage.session (and the vault with it) is wiped on browser exit.

  /** Serialization for the arms below (the queue itself never rejects). */
  let armQueue: Promise<unknown> = Promise.resolve();

  /**
   * Idempotent key-material wipe for the lock path. performLock removes the
   * session and the decrypted cache after the locked flag lands; when that
   * half fails or never runs — a storage.session error, or the pressing
   * surface dying between the worker's lockState write and its follow-up
   * removal — this backstop finishes the job. Every lock observation the
   * worker makes (its own lock op, an arm while locked, a stale alarm fire)
   * re-runs it: removing an already-removed key and clearing an empty cache
   * are no-ops, so this is safe on every failure shape and cannot strand
   * the master key, tokens, and cache in session storage behind locked=true.
   */
  async function wipeLockedSession(): Promise<void> {
    await browser.storage.session.remove(SESSION_KEY).catch(() => {});
    await clearCache().catch(() => {});
  }

  /** (Re)create the auto-lock alarm from the stored state; clears it if locked. */
  function armAutoLockAlarm(minDelayMs = 0): Promise<void> {
    // Serialized: each arm reads the state and creates the alarm only after
    // the previous arm finished, so two out-of-order arms (an activity report
    // racing a hidden report) can never leave a stale later deadline
    // overriding the newest one — the last create is always from the freshest
    // read. Same name replaces any pending alarm — an activity write pushes
    // the deadline forward, a hidden report pulls it closer.
    const run = armQueue.then(async () => {
      const state = await getLockState();
      if (state.locked) {
        await browser.alarms.clear(LOCK_ALARM_NAME);
        // locked=true with material still present is exactly the half-done
        // wipe state — retry the removals instead of only clearing the timer.
        await wipeLockedSession();
        return;
      }
      const fireAt = Date.now() + Math.max(minDelayMs, remainingLockMs(state, Date.now()));
      await browser.alarms.create(LOCK_ALARM_NAME, { when: fireAt });
    });
    armQueue = run.catch(() => {});
    return run;
  }

  browser.storage.onChanged.addListener((changes, area) => {
    if (area === "session" && changes[LOCK_STATE_KEY]) void armAutoLockAlarm();
  });

  browser.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === ORIGIN_RETRY_ALARM) {
      void installOriginRuleWithRetry();
      return;
    }
    if (alarm.name !== LOCK_ALARM_NAME) return;
    void (async () => {
      const state = await getLockState();
      if (state.locked) {
        // A fire on an already-locked state is a retry signal for a wipe
        // that never finished; complete it instead of returning bare.
        await wipeLockedSession();
        return;
      }
      // Stale fire (activity landed after the alarm was scheduled): re-arm
      // for what is left instead of locking an active vault.
      if (remainingLockMs(state, Date.now()) > 0) {
        await armAutoLockAlarm();
        return;
      }
      // "auto" is what lets the surfaces show the inactivity notice instead
      // of pretending the user pressed Lock.
      await performLock("auto");
    })().catch((error) => {
      console.warn("auto-lock failed", error);
      // The fired alarm is consumed: re-arm so a failed wipe is retried at
      // the (floored) deadline instead of leaving the key material in
      // storage.session with no timer left to clear it.
      void armAutoLockAlarm(5_000).catch((armError) => {
        console.warn("auto-lock re-arm failed", armError);
      });
    });
  });

  // Browser start / extension install: nothing to arm (storage.session — the
  // vault — is gone on restart), but keep the invariant explicit and cheap.
  browser.runtime.onStartup.addListener(() => void armAutoLockAlarm());
  void armAutoLockAlarm();

  /** Guards against double-createDocument when two copies race. */
  let creating: Promise<unknown> | null = null;

  /** Create the document with the schedule baked into its URL. */
  async function createOffscreenDocument(clearAt: number): Promise<void> {
    creating ??= browser.offscreen
      .createDocument({
        url: `/offscreen.html?clearAt=${clearAt}`,
        reasons: ["CLIPBOARD"],
        justification: "Overwrite the clipboard with an empty value after the copy TTL",
      })
      .catch(() => {
        // "Only a single offscreen document" — an existing document just
        // raced this creation; the arm below covers it.
      })
      .finally(() => {
        creating = null;
      });
    await creating;
  }

  /**
   * Arm or re-arm the pending clear. An existing document is told over
   * runtime messaging — the only extension API an offscreen document has —
   * and acknowledges; a missing ack means it is mid-teardown (just fired) or
   * gone, so it is recreated with the schedule in its URL. The document arms
   * itself from that at script start, immune to the create/message race.
   */
  async function scheduleClear(delayMs: number): Promise<boolean> {
    const clearAt = Date.now() + Math.max(0, delayMs);
    try {
      // Receipt/observability only — the mechanism does not depend on it.
      await browser.storage.session.set({ clipboardClearAt: clearAt });
    } catch {
      // Storage is never load-bearing here.
    }
    let contexts: unknown[] = [];
    try {
      contexts = await browser.runtime.getContexts({ contextTypes: ["OFFSCREEN_DOCUMENT"] });
    } catch {
      // getContexts needs Chrome 116+; assume none and create.
    }
    if (contexts.length > 0) {
      const ack = await browser.runtime
        .sendMessage({ type: "sns:arm-clear", clearAt })
        .catch(() => undefined);
      if (ack === true) return true;
      await browser.offscreen.closeDocument().catch(() => {});
    }
    await createOffscreenDocument(clearAt);
    return true;
  }

  browser.runtime.onMessage.addListener((message) => {
    if (message?.type === "sns:schedule-clear") {
      // Returning the promise makes the sender's sendMessage resolve with
      // the boolean — the copy flow surfaces it in the UI.
      return scheduleClear(Number(message.delayMs) || 0).catch((error) => {
        console.warn("clipboard auto-clear scheduling failed", error);
        void browser.storage.local.set({ clipboardScheduleError: String(error) }).catch(() => {});
        return false;
      });
    }
    if (message?.type === "sns:clear-done") {
      // Ack immediately so the offscreen document stops retrying; the close
      // itself must not clobber a newer schedule — a copy that re-armed the
      // timer while this clear was in flight keeps the document alive (its
      // clearAt would be lower than the recorded one). The document's
      // schedule is trusted when it is at least as new as the record, which
      // also covers a lost clipboardClearAt write.
      void (async () => {
        let recorded: number | undefined;
        try {
          recorded = (await browser.storage.session.get("clipboardClearAt")).clipboardClearAt as number | undefined;
        } catch {
          // The receipt is observability only.
        }
        void browser.storage.session
          .set({ lastClipboardClearAt: Date.now(), lastClipboardClearOk: message.ok === true })
          .catch(() => {});
        const clearAt = Number(message.clearAt);
        const superseded = typeof recorded === "number" && Number.isFinite(clearAt) && clearAt < recorded;
        if (!superseded) {
          await browser.offscreen.closeDocument().catch(() => {
            // Already closed or never opened — either is fine.
          });
        }
      })();
      // A resolved promise (not the literal `true`) — the document treats
      // the resolved value as the ack.
      return Promise.resolve(true);
    }
    if (message?.type === LOCK_OP_MESSAGE_TYPE) {
      // The single-writer endpoint: surfaces report activity/hidden/visible/
      // unlock (and ask for a lock, with its reason) here, and this worker
      // applies every lockState mutation through one serialized queue — a
      // surface's report can never interleave with the alarm's lock and
      // regress the state. When the op locked the vault, the worker also
      // runs the key-material removals itself: the surface's own follow-up
      // wipe stays as a redundant second backstop, so a surface dying in the
      // milliseconds after the flag landed can no longer strand the session
      // and cache behind locked=true.
      return queueLockOp(message.op as Parameters<typeof queueLockOp>[0], message.reason as LockReason | undefined).then(
        async (state) => {
          if (state.locked) await wipeLockedSession();
          return state;
        },
      );
    }
    if (message?.type === "sns:origin-rules") {
      // Surfaces await this before their first API POST, so a fresh
      // install's login never races the dynamic rule install. Resolves
      // false when the install failed (the retry alarm keeps trying).
      return installOriginRuleWithRetry();
    }
    if (message?.type === REFRESH_MESSAGE_TYPE) {
      return sharedRefresh
        .refresh()
        .then((secrets) => ({ ok: true as const, secrets }))
        .catch((error: unknown) => ({
          ok: false as const,
          message: error instanceof Error ? error.message : String(error),
        }));
    }
  });
});
