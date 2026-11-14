import { useEffect, useRef, useState } from "react";
import { browser } from "wxt/browser";
import {
  CheckIcon,
  CopyIcon,
  EmptyVaultIcon,
  ExternalIcon,
  KeyIcon,
  LockIcon,
  SearchIcon,
} from "../../components/icons.tsx";
import { useAutoLock } from "../../components/auto-lock.ts";
import { MfaForm, UnlockForm } from "../../components/UnlockForm.tsx";
import { copySecret } from "../../lib/clipboard.ts";
import { loadSession, loadSettings, type VaultSession } from "../../lib/session.ts";
import { lockVault, syncVault, unlockVault } from "../../lib/unlock.ts";
import { buildVault, keyIndex, type KeyHit, type VaultView } from "../../lib/vault.ts";

type Phase = "boot" | "locked" | "working" | "mfa" | "ready";

function messageOf(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

export default function App() {
  const [phase, setPhase] = useState<Phase>("boot");
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [apiUrl, setApiUrl] = useState("");
  const [mfaMessage, setMfaMessage] = useState("");
  const [session, setSession] = useState<VaultSession | null>(null);
  const [view, setView] = useState<VaultView | null>(null);
  const [query, setQuery] = useState("");
  const [copied, setCopied] = useState<string | null>(null);
  const [autoLocked, setAutoLocked] = useState(false);
  const copyTimer = useRef<number | null>(null);
  const mfaResolver = useRef<((code: string) => void) | null>(null);
  useAutoLock(phase === "ready", () => void lock("auto"));

  useEffect(() => {
    void boot();
    return () => {
      if (copyTimer.current !== null) window.clearTimeout(copyTimer.current);
    };
  }, []);

  async function boot(): Promise<void> {
    // A boot failure must never strand the popup on "Loading…" — the login
    // form (with the error) is always a safe landing.
    try {
      const [settings, existing] = await Promise.all([loadSettings(), loadSession()]);
      setEmail(settings.email);
      setApiUrl(settings.apiUrl);
      if (existing) {
        setSession(existing);
        await refresh(existing);
      } else {
        setPhase("locked");
      }
    } catch (caught) {
      setError(messageOf(caught));
      setPhase("locked");
    }
  }

  async function refresh(current: VaultSession): Promise<void> {
    setPhase("working");
    setStatus("Syncing…");
    setError("");
    try {
      const { items } = await syncVault(current);
      setView(buildVault(items));
      setPhase("ready");
    } catch (caught) {
      setError(messageOf(caught));
      setPhase("locked");
    }
  }

  async function submitUnlock(): Promise<void> {
    setError("");
    setAutoLocked(false);
    setPhase("working");
    setStatus("Deriving keys…");
    try {
      const next = await unlockVault({
        email,
        password,
        apiUrl,
        onMfa: () =>
          new Promise<string>((resolve) => {
            mfaResolver.current = resolve;
            setMfaMessage("Enter the code from your authenticator app");
            setPhase("mfa");
          }),
      });
      setPassword("");
      setSession(next);
      await refresh(next);
    } catch (caught) {
      setError(messageOf(caught));
      setPhase("locked");
    }
  }

  function submitMfa(code: string): void {
    const resolve = mfaResolver.current;
    mfaResolver.current = null;
    setPhase("working");
    setStatus("Deriving keys…");
    resolve?.(code);
  }

  function copyValue(hit: KeyHit): void {
    void copySecret(hit.value).then((schedule) => {
      setCopied(schedule === "scheduled" ? `${hit.noteUuid}:${hit.key}:30s` : `${hit.noteUuid}:${hit.key}:!30s`);
      if (copyTimer.current !== null) window.clearTimeout(copyTimer.current);
      copyTimer.current = window.setTimeout(() => setCopied(null), 2500);
    });
  }

  async function lock(reason?: "auto"): Promise<void> {
    await lockVault();
    setAutoLocked(reason === "auto");
    setSession(null);
    setView(null);
    setQuery("");
    setPhase("locked");
  }

  function openDashboard(noteUuid?: string): void {
    const hash = noteUuid ? `#note=${noteUuid}` : "";
    void browser.tabs.create({ url: `${browser.runtime.getURL("/dashboard.html")}${hash}` });
    window.close();
  }

  if (phase === "boot") return <p className="hint padded">Loading…</p>;

  if (phase === "locked" || phase === "working") {
    return (
      <main className="popup">
        <UnlockForm
          email={email}
          onEmail={setEmail}
          password={password}
          onPassword={setPassword}
          apiUrl={apiUrl}
          onApiUrl={setApiUrl}
          busy={phase === "working"}
          status={status}
          error={error}
          notice={autoLocked ? "Locked after inactivity — sign in again." : ""}
          compact
          onSubmit={() => void submitUnlock()}
        />
      </main>
    );
  }

  if (phase === "mfa") {
    return (
      <main className="popup">
        <MfaForm message={mfaMessage} busy={false} onSubmit={submitMfa} />
      </main>
    );
  }

  const needle = query.trim().toLowerCase();
  const keyHits = needle === ""
    ? []
    : keyIndex(view!)
      .filter((hit) => hit.key.toLowerCase().includes(needle) || hit.noteTitle.toLowerCase().includes(needle))
      .slice(0, 20);
  const noteHits = needle === ""
    ? []
    : (view?.notes ?? [])
      .filter((note) => note.title.toLowerCase().includes(needle))
      .filter((note) => !keyHits.some((hit) => hit.noteUuid === note.uuid))
      .slice(0, 5);

  return (
    <main className="popup">
      <header className="bar">
        <span className="brand-mark"><KeyIcon size={14} /></span>
        <span className="brand-name">sns vault</span>
        <span className="spacer" />
        <button className="icon-btn" type="button" title="Open dashboard" onClick={() => openDashboard()}>
          <ExternalIcon size={15} />
        </button>
        <button className="icon-btn" type="button" title="Lock now" onClick={() => void lock()}>
          <LockIcon size={15} />
        </button>
      </header>

      <div className="search-wrap">
        <SearchIcon size={14} className="search-icon" />
        <input
          className="search"
          type="search"
          placeholder="Search keys…"
          autoFocus
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          spellCheck={false}
        />
      </div>

      <ul className="hits">
        {keyHits.map((hit) => {
          const hitId = `${hit.noteUuid}:${hit.key}`;
          const copiedThis = copied === `${hitId}:30s`;
          const failedThis = copied === `${hitId}:!30s`;
          return (
            <li key={hitId}>
              <button
                className={`hit ${copied !== null && copied.startsWith(hitId) ? "hit-active" : ""}`}
                type="button"
                onClick={() => copyValue(hit)}
                title={`${hit.noteTitle} — ${hit.key}`}
              >
                <span className="hit-key">{hit.key}</span>
                <span className="hit-note">{hit.noteTitle}</span>
                <span className={`hit-action ${copiedThis ? "ok" : ""} ${failedThis ? "warn" : ""}`}>
                  {copiedThis || failedThis ? (
                    <>
                      {copiedThis ? <CheckIcon size={13} /> : null}
                      {copiedThis ? "blanks in 30s" : "clear NOT scheduled"}
                    </>
                  ) : (
                    <CopyIcon size={13} />
                  )}
                </span>
              </button>
            </li>
          );
        })}
        {noteHits.map((note) => (
          <li key={note.uuid}>
            <button className="hit note-hit" type="button" onClick={() => openDashboard(note.uuid)}>
              <span className="hit-note">{note.title}</span>
              <span className="hit-action">{note.settings === 0 ? "open" : `${note.settings} keys`}</span>
            </button>
          </li>
        ))}
      </ul>
      {needle !== "" && keyHits.length === 0 && noteHits.length === 0 ? (
        <div className="empty"><SearchIcon size={18} /><p>No key or note matches.</p></div>
      ) : null}
      {needle === "" ? <p className="hint footer-hint">{view ? `${view.notes.length} notes synced — type to search` : ""}</p> : null}
    </main>
  );
}
