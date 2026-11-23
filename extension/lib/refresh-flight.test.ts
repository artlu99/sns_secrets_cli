import { describe, expect, test } from "bun:test";
import { applyLock, applyUnlock, type LockState } from "./lock-schedule.ts";
import { createRefreshClient, createSharedRefresh, parseSessionBody, type SharedRefreshDeps } from "./refresh-flight.ts";
import type { SessionSecrets, VaultSession } from "./session.ts";


const NOW = 1_000_000;

function secrets(overrides: Partial<SessionSecrets> = {}): SessionSecrets {
  return {
    accountEmail: "a@b.c",
    refreshToken: "R1",
    accessToken: "A1",
    accessExpirationMs: NOW + 60_000,
    refreshExpirationMs: NOW + 3_600_000,
    accessCookie: "access_token=1",
    refreshCookie: "refresh_token=1",
    ...overrides,
  };
}

function session(current: SessionSecrets = secrets()): VaultSession {
  return { secrets: current, masterKey: "mk", email: "a@b.c", apiUrl: "https://api.standardnotes.com" };
}

function unlockedState(epoch = 3): LockState {
  return { locked: false, lastActivity: NOW, hiddenSince: null, lockEpoch: epoch, lockReason: null };
}

/** One macrotask tick: lets the flight reach its first await (the epoch read). */
const tick = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0));

/**
 * A coordinator over injectable fakes whose refresh flight is held open
 * until the test resolves (or rejects) it — races are driven by hand.
 */
function harness(start: LockState = unlockedState(), stored: VaultSession | null = session()) {
  let state = start;
  let current = stored;
  let release: ((next: SessionSecrets) => void) | null = null;
  let abort: ((reason: unknown) => void) | null = null;
  const log = { refreshes: 0, saves: [] as SessionSecrets[] };
  const deps: SharedRefreshDeps = {
    getLockState: () => Promise.resolve(state),
    loadSession: () => Promise.resolve(current),
    apiRefresh: () => {
      log.refreshes += 1;
      return new Promise<SessionSecrets>((resolve, reject) => {
        release = resolve;
        abort = reject;
      });
    },
    saveSession: (next) => {
      log.saves.push(next.secrets);
      current = next;
      return Promise.resolve();
    },
  };
  return {
    coordinator: createSharedRefresh(deps),
    log,
    resolve(next: SessionSecrets): void {
      release?.(next);
    },
    reject(reason: unknown): void {
      abort?.(reason);
    },
    lock(): void {
      state = applyLock(state, NOW);
    },
    unlock(): void {
      state = applyUnlock(state, NOW);
    },
    get stored(): VaultSession | null {
      return current;
    },
  };
}

describe("createSharedRefresh", () => {
  test("concurrent callers share one flight and one outcome", async () => {
    const h = harness();
    const first = h.coordinator.refresh();
    const second = h.coordinator.refresh();
    expect(first).toBe(second);
    await tick();
    expect(h.log.refreshes).toBe(1);
    h.resolve(secrets({ refreshToken: "R2", accessToken: "A2" }));
    const [a, b] = await Promise.all([first, second]);
    expect(a.refreshToken).toBe("R2");
    expect(b.refreshToken).toBe("R2");
    expect(h.log.saves).toEqual([secrets({ refreshToken: "R2", accessToken: "A2" })]);
    expect(h.stored?.secrets.refreshToken).toBe("R2");
  });

  test("a caller arriving after settle starts a fresh flight", async () => {
    const h = harness();
    const first = h.coordinator.refresh();
    await tick();
    h.resolve(secrets({ refreshToken: "R2" }));
    await first;
    const second = h.coordinator.refresh();
    await tick();
    expect(h.log.refreshes).toBe(2);
    h.resolve(secrets({ refreshToken: "R3" }));
    expect((await second).refreshToken).toBe("R3");
  });

  test("a failed refresh persists nothing; every joiner gets the same rejection", async () => {
    const h = harness();
    const first = h.coordinator.refresh();
    const second = h.coordinator.refresh();
    await tick();
    h.reject(new Error("HTTP 401 expired_refresh_token:"));
    const settled = await Promise.allSettled([first, second]);
    expect(settled.map((r) => (r.status === "rejected" ? r.reason.message : ""))).toEqual([
      "HTTP 401 expired_refresh_token:",
      "HTTP 401 expired_refresh_token:",
    ]);
    expect(h.log.saves).toEqual([]);
    expect(h.stored?.secrets.refreshToken).toBe("R1");
  });

  test("a lock mid-refresh aborts the persisted write", async () => {
    const h = harness();
    const flight = h.coordinator.refresh();
    await tick();
    h.resolve(secrets({ refreshToken: "R2" }));
    // The lock lands before the flight's settle check reads the clock again.
    h.lock();
    await expect(flight).rejects.toThrow("vault locked while refreshing — aborted");
    expect(h.log.saves).toEqual([]);
    expect(h.stored?.secrets.refreshToken).toBe("R1");
  });

  test("an unlock that moved the epoch aborts the write even while unlocked", async () => {
    const h = harness();
    const flight = h.coordinator.refresh();
    await tick();
    h.resolve(secrets({ refreshToken: "R2" }));
    h.lock();
    h.unlock();
    await expect(flight).rejects.toThrow("vault locked while refreshing — aborted");
    expect(h.log.saves).toEqual([]);
  });

  test("a lock landing inside the persist takes the just-written tokens back out", async () => {
    let state = unlockedState();
    let stored: VaultSession | null = session();
    const log = { saves: 0, discards: 0 };
    const deps: SharedRefreshDeps = {
      getLockState: () => Promise.resolve(state),
      loadSession: () => Promise.resolve(stored),
      apiRefresh: () => Promise.resolve(secrets({ refreshToken: "R2" })),
      saveSession: (next) => {
        log.saves += 1;
        stored = next;
        // The alarm's wipe lands between the settle check and the persist.
        state = applyLock(state, NOW);
        return Promise.resolve();
      },
      discardSession: () => {
        log.discards += 1;
        stored = null;
        return Promise.resolve();
      },
    };
    const next = await createSharedRefresh(deps).refresh();
    expect(next.refreshToken).toBe("R2");
    expect(log.saves).toBe(1);
    expect(log.discards).toBe(1);
    expect(stored).toBeNull();
  });

  test("a fresh UNLOCK landing inside the persist keeps the newer session (no discard)", async () => {
    let state = unlockedState();
    let stored: VaultSession | null = session();
    const log = { saves: 0, discards: 0 };
    const newerSession: VaultSession = { ...session(), secrets: secrets({ refreshToken: "fresh" }) };
    const deps: SharedRefreshDeps = {
      getLockState: () => Promise.resolve(state),
      loadSession: () => Promise.resolve(stored),
      apiRefresh: () => Promise.resolve(secrets({ refreshToken: "R2" })),
      saveSession: () => {
        log.saves += 1;
        // The unlock's own save lands after the flight's: storage ends up
        // holding the NEWER session, and the settle check must leave it.
        stored = newerSession;
        state = applyUnlock(state, NOW + 1);
        return Promise.resolve();
      },
      discardSession: () => {
        log.discards += 1;
        stored = null;
        return Promise.resolve();
      },
    };
    await createSharedRefresh(deps).refresh();
    expect(log.saves).toBe(1);
    expect(log.discards).toBe(0);
    expect(stored).toBe(newerSession);
  });

  test("an already-locked vault rejects before any network call", async () => {
    const h = harness(applyLock(unlockedState(), NOW));
    await expect(h.coordinator.refresh()).rejects.toThrow("vault locked while refreshing — aborted");
    expect(h.log.refreshes).toBe(0);
    expect(h.log.saves).toEqual([]);
  });

  test("no stored session rejects before any network call", async () => {
    const h = harness(unlockedState(), null);
    await expect(h.coordinator.refresh()).rejects.toThrow("no vault session to refresh");
    expect(h.log.refreshes).toBe(0);
  });

  test("an empty vault record rejects like a missing one", async () => {
    const h = harness(unlockedState(), session(secrets({ refreshToken: "" })));
    await expect(h.coordinator.refresh()).rejects.toThrow("no vault session to refresh");
    expect(h.log.refreshes).toBe(0);
  });
});

describe("parseSessionBody", () => {
  test("extracts tokens, expirations, and cookie pairs from a session body", () => {
    const got = parseSessionBody(
      {
        data: {
          session: { access_token: "A1", refresh_token: "R1", access_expiration: 1700000000, refresh_expiration: 1700003600 },
        },
      },
      ["access_token=x; Path=/; HttpOnly", "refresh_token=y; Path=/"],
    );
    expect(got).toEqual({
      accountEmail: "",
      accessToken: "A1",
      refreshToken: "R1",
      accessExpirationMs: 1_700_000_000_000,
      refreshExpirationMs: 1_700_003_600_000,
      accessCookie: "access_token=x",
      refreshCookie: "refresh_token=y",
    });
  });

  test("a body without session tokens rejects", () => {
    expect(() => parseSessionBody({ data: {} }, [])).toThrow("did not include session tokens");
  });

  test("the capitalized data.Session fallback parses exactly like the CLI's parser", () => {
    // Same shapes src/sn-api.ts accepts — one parse semantics, three
    // surfaces. unwrap falls back to the body root, so both the
    // {data:{Session}} wrapper and a bare root {Session} parse; the old
    // extension-only root lookup missed the wrapped shape the CLIs accept.
    const wrapped = parseSessionBody({ data: { Session: { access_token: "A2", refresh_token: "R2" } } }, []);
    expect(wrapped.accessToken).toBe("A2");
    expect(wrapped.refreshToken).toBe("R2");
    const bare = parseSessionBody({ Session: { access_token: "A3", refresh_token: "R3" } }, []);
    expect(bare.accessToken).toBe("A3");
    expect(bare.refreshToken).toBe("R3");
    expect(() => parseSessionBody({ data: { other: 1 } }, [])).toThrow("did not include session tokens");
  });
});

describe("createRefreshClient", () => {
  test("POSTs to /v1/sessions/refresh with the refresh bearer", async () => {
    let seenUrl = "";
    let seenAuth = "";
    const client = createRefreshClient("https://api.standardnotes.com", async (url, init) => {
      seenUrl = url;
      seenAuth = (init?.headers as Record<string, string>).Authorization ?? "";
      return new Response(JSON.stringify({ data: { session: { access_token: "A2", refresh_token: "R2" } } }), {
        status: 200,
      });
    });
    const next = await client.refresh(secrets());
    expect(seenUrl).toBe("https://api.standardnotes.com/v1/sessions/refresh");
    expect(seenAuth).toBe("Bearer R1");
    expect(next.accessToken).toBe("A2");
    expect(next.refreshToken).toBe("R2");
  });

  test("carries the account label and falls back to cookies the server did not re-set", async () => {
    const client = createRefreshClient("https://api.standardnotes.com", async () =>
      new Response(JSON.stringify({ data: { session: { access_token: "A2", refresh_token: "R2" } } }), { status: 200 }),
    );
    const next = await client.refresh(secrets({ accessCookie: "access_token=old", refreshCookie: "" }));
    expect(next.accountEmail).toBe("a@b.c");
    expect(next.accessCookie).toBe("access_token=old");
    expect(next.refreshCookie).toBe("");
  });

  test("a server rejection surfaces as an ApiError with its status", async () => {
    const client = createRefreshClient("https://api.standardnotes.com", async () =>
      new Response(JSON.stringify({ error: { tag: "expired_refresh_token" } }), { status: 401 }),
    );
    await expect(client.refresh(secrets())).rejects.toThrow("HTTP 401");
  });
});
