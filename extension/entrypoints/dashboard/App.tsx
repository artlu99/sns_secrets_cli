import { useEffect, useRef, useState, type ReactNode } from "react";
import { noteBody } from "../../../src/notes.ts";
import { MfaForm, UnlockForm } from "../../components/UnlockForm.tsx";
import { copySecret } from "../../lib/clipboard.ts";
import { loadSession, loadSettings, type VaultSession } from "../../lib/session.ts";
import { lockVault, syncVault, unlockVault } from "../../lib/unlock.ts";
import { buildVault, type NoteSummary, type VaultView } from "../../lib/vault.ts";

type Phase = "boot" | "locked" | "working" | "mfa" | "ready";
type Selection = { kind: "all" } | { kind: "untagged" } | { kind: "tag"; uuid: string };

function messageOf(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

const byTitle = (a: string, b: string) => a.localeCompare(b);

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
  const [selection, setSelection] = useState<Selection>({ kind: "all" });
  const [noteUuid, setNoteUuid] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [revealed, setRevealed] = useState<Set<string>>(new Set());
  const [copied, setCopied] = useState<string | null>(null);
  const [syncedAt, setSyncedAt] = useState<number | null>(null);
  const [syncing, setSyncing] = useState(false);
  const copyTimer = useRef<number | null>(null);
  const mfaResolver = useRef<((code: string) => void) | null>(null);

  useEffect(() => {
    void boot();
    return () => {
      if (copyTimer.current !== null) window.clearTimeout(copyTimer.current);
    };
  }, []);

  async function boot(): Promise<void> {
    // Same contract as the popup's boot: a failure lands on the login form.
    try {
      const [settings, existing] = await Promise.all([loadSettings(), loadSession()]);
      setEmail(settings.email);
      setApiUrl(settings.apiUrl);
      // The popup hands over "#note=<uuid>" when it opens a note here.
      const wanted = /^#note=([0-9a-f-]+)$/.exec(location.hash)?.[1];
      if (wanted) setNoteUuid(wanted);
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
      const { items, report } = await syncVault(current);
      setView(buildVault(items));
      setSyncedAt(report.pages > 0 ? Date.now() : null);
      setPhase("ready");
    } catch (caught) {
      setError(messageOf(caught));
      setPhase("locked");
    }
  }

  async function submitUnlock(): Promise<void> {
    setError("");
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

  function copy(label: string, text: string): void {
    void copySecret(text).then(() => {
      setCopied(label);
      if (copyTimer.current !== null) window.clearTimeout(copyTimer.current);
      copyTimer.current = window.setTimeout(() => setCopied(null), 1500);
    });
  }

  function toggleReveal(id: string): void {
    setRevealed((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function lock(): Promise<void> {
    await lockVault();
    setSession(null);
    setView(null);
    setPhase("locked");
  }

  if (phase === "boot") return <p className="hint padded">Loading…</p>;

  if (phase === "locked" || phase === "working" || phase === "mfa") {
    return (
      <main className="gate">
        {phase === "mfa" ? (
          <MfaForm message={mfaMessage} busy={false} onSubmit={submitMfa} />
        ) : (
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
            onSubmit={() => void submitUnlock()}
          />
        )}
      </main>
    );
  }

  if (!view || !session) return <p className="hint padded">Loading…</p>;

  const notes = notesForSelection(view, selection);
  const needle = query.trim().toLowerCase();
  const filtered = needle === ""
    ? notes
    : notes.filter((note) => note.title.toLowerCase().includes(needle));
  const selectedRow = noteUuid ? view.noteRows.get(noteUuid) ?? null : null;
  const scan = selectedRow ? view.scan(selectedRow) : null;
  const keys = selectedRow ? view.keysOf(selectedRow) : [];
  const body = selectedRow ? noteBody(selectedRow).body : "";

  // Every isRoot tag renders top-level — including parent-cycle members, which
  // the forest hangs as separate chains (same as `sns list` does).
  const treeRoots = [...view.graph.links.titleOf.keys()]
    .filter((tag) => view.forest.isRoot(tag))
    .sort(byTitle);

  return (
    <div className="shell">
      <header className="topbar">
        <span className="brand compact">sns vault</span>
        <span className="account" title={`${session.email} · ${session.apiUrl}`}>
          {session.email}
        </span>
        <span className="spacer" />
        <span className="synced">{syncedAt ? `synced ${view.formatWhen(syncedAt)}` : ""}</span>
        <button
          className="ghost"
          type="button"
          disabled={syncing}
          onClick={() => {
            setSyncing(true);
            void syncVault(session)
              .then(({ items, report }) => {
                setView(buildVault(items));
                setSyncedAt(report.pages > 0 ? Date.now() : null);
              })
              .finally(() => setSyncing(false));
          }}
        >
          {syncing ? "syncing…" : "sync"}
        </button>
        <button className="ghost" type="button" onClick={() => void lock()}>lock</button>
      </header>

      <div className="columns">
        <nav className="sidebar">
          <button
            className={`tree-row ${selection.kind === "all" ? "active" : ""}`}
            type="button"
            onClick={() => { setSelection({ kind: "all" }); }}
          >
            <span>All notes</span>
            <span className="count">{view.notes.length}</span>
          </button>
          {treeRoots.map((tag) => (
            <TagNode
              key={tag}
              tag={tag}
              view={view}
              selection={selection}
              onSelect={(uuid) => { setSelection({ kind: "tag", uuid }); setNoteUuid(null); }}
            />
          ))}
          {view.untagged.size > 0 ? (
            <button
              className={`tree-row ${selection.kind === "untagged" ? "active" : ""}`}
              type="button"
              onClick={() => { setSelection({ kind: "untagged" }); setNoteUuid(null); }}
            >
              <span>(untagged)</span>
              <span className="count">{view.untagged.size}</span>
            </button>
          ) : null}
        </nav>

        <section className="note-list">
          <input
            className="search"
            type="search"
            placeholder="Filter by title"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            spellCheck={false}
          />
          <ul>
            {filtered.map((note) => (
              <li key={note.uuid}>
                <button
                  className={`note-row ${note.uuid === noteUuid ? "active" : ""}`}
                  type="button"
                  onClick={() => setNoteUuid(note.uuid)}
                >
                  <span className="note-title">{note.title}</span>
                  <span className="note-meta">
                    {note.settings > 0 ? <span className="pill">{note.settings} keys</span> : null}
                    <span className="when">{view.formatWhen(note.updatedAt)}</span>
                  </span>
                </button>
              </li>
            ))}
            {filtered.length === 0 ? <li className="hint padded">No notes here.</li> : null}
          </ul>
        </section>

        <section className="detail">
          {selectedRow && scan ? (
            <>
              <h2 className="detail-title">{selectedRow.title ?? "(untitled)"}</h2>
              {keys.length > 0 ? (
                <table className="keys">
                  <tbody>
                    {keys.map((entry) => {
                      const id = `${selectedRow.uuid}:${entry.key}`;
                      const shown = revealed.has(id);
                      return (
                        <tr key={entry.key}>
                          <td className="key-name">{entry.key}</td>
                          <td
                            className={`key-value ${shown ? "" : "masked"}`}
                            onClick={() => toggleReveal(id)}
                            title={shown ? "Click to hide" : "Click to reveal"}
                          >
                            {shown ? entry.value : "••••••••••••"}
                          </td>
                          <td className="key-comment">{entry.comment ?? ""}</td>
                          <td className="key-actions">
                            <button className="ghost" type="button" onClick={() => toggleReveal(id)}>
                              {shown ? "hide" : "show"}
                            </button>
                            <button
                              className="ghost"
                              type="button"
                              onClick={() => copy(`${selectedRow.uuid}:${entry.key}`, entry.value)}
                            >
                              {copied === `${selectedRow.uuid}:${entry.key}` ? "copied ✓" : "copy"}
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              ) : (
                <p className="hint">No KEY=VALUE settings in this note.</p>
              )}
              {view.displayProse(scan).trim() !== "" ? (
                <details className="prose" open={keys.length === 0}>
                  <summary>prose</summary>
                  <pre>{view.displayProse(scan)}</pre>
                </details>
              ) : null}
              <div className="detail-actions">
                <button className="ghost" type="button" onClick={() => copy(`${selectedRow.uuid}:body`, body)}>
                  {copied === `${selectedRow.uuid}:body` ? "copied ✓" : "copy whole body"}
                </button>
              </div>
            </>
          ) : (
            <p className="hint padded">Select a note to see its keys.</p>
          )}
        </section>
      </div>
      {error !== "" ? <p className="error" role="alert">{error}</p> : null}
    </div>
  );
}

function TagNode(props: {
  tag: string;
  view: VaultView;
  selection: Selection;
  onSelect: (uuid: string) => void;
}): ReactNode {
  const { view, tag } = props;
  const children = (view.forest.childrenOf.get(tag) ?? []).sort(byTitle);
  const active = props.selection.kind === "tag" && props.selection.uuid === tag;
  const count = view.notesInTag(tag).size;
  return (
    <>
      <button
        className={`tree-row ${active ? "active" : ""}`}
        type="button"
        style={{ paddingLeft: `${8 + (view.forest.depthOf.get(tag) ?? 0) * 14}px` }}
        onClick={() => props.onSelect(tag)}
      >
        <span className="tag-name">{view.graph.links.titleOf.get(tag) ?? tag}</span>
        <span className="count">{count}</span>
      </button>
      {children.map((child) => (
        <TagNode key={child} tag={child} view={view} selection={props.selection} onSelect={props.onSelect} />
      ))}
    </>
  );
}

/** Notes under the current sidebar selection, newest first. */
function notesForSelection(view: VaultView, selection: Selection): NoteSummary[] {
  const newestFirst = (a: NoteSummary, b: NoteSummary) =>
    b.updatedAt - a.updatedAt || a.uuid.localeCompare(b.uuid);
  if (selection.kind === "all") return view.notes;
  const uuids = selection.kind === "untagged"
    ? view.untagged
    : view.notesInTag(selection.uuid);
  return view.notes.filter((note) => uuids.has(note.uuid)).sort(newestFirst);
}
