import { useState } from "react";

export type UnlockFormProps = {
  email: string;
  onEmail: (value: string) => void;
  password: string;
  onPassword: (value: string) => void;
  apiUrl: string;
  onApiUrl: (value: string) => void;
  busy: boolean;
  status: string;
  error: string;
  /** Dim positive line above the error — e.g. why the form re-gated. */
  notice?: string;
  compact?: boolean;
  onSubmit: () => void;
};

/** Email + password (+ collapsed server field). Plain fields; no styling tricks. */
export function UnlockForm(props: UnlockFormProps) {
  const [showServer, setShowServer] = useState(false);
  return (
    <form className="unlock" onSubmit={(event) => { event.preventDefault(); props.onSubmit(); }}>
      <h1 className={props.compact ? "brand compact" : "brand"}>sns vault</h1>
      <p className="sub">Signs in to Standard Notes. Your password never leaves this window —
        key derivation and decryption happen here.</p>
      <label>
        <span>Email</span>
        <input
          type="email"
          autoComplete="username"
          autoFocus
          value={props.email}
          onChange={(event) => props.onEmail(event.target.value)}
          disabled={props.busy}
        />
      </label>
      <label>
        <span>Password</span>
        <input
          type="password"
          autoComplete="current-password"
          value={props.password}
          onChange={(event) => props.onPassword(event.target.value)}
          disabled={props.busy}
        />
      </label>
      {showServer ? (
        <label>
          <span>Server</span>
          <input
            type="url"
            value={props.apiUrl}
            onChange={(event) => props.onApiUrl(event.target.value)}
            disabled={props.busy}
            spellCheck={false}
          />
        </label>
      ) : null}
      <button className="linkish" type="button" onClick={() => setShowServer((shown) => !shown)}>
        {showServer ? "hide server" : "self-hosted server…"}
      </button>
      {props.notice ? <p className="notice">{props.notice}</p> : null}
      {props.error !== "" ? <p className="error" role="alert">{props.error}</p> : null}
      <button className="primary" type="submit" disabled={props.busy}>
        {props.busy ? props.status || "Working…" : "Unlock"}
      </button>
    </form>
  );
}

export function MfaForm(props: { message: string; busy: boolean; onSubmit: (code: string) => void }) {
  const [code, setCode] = useState("");
  return (
    <form className="unlock" onSubmit={(event) => { event.preventDefault(); props.onSubmit(code); }}>
      <h1 className="brand compact">Two-factor code</h1>
      <p className="sub">{props.message}</p>
      <label>
        <span>Code</span>
        <input
          inputMode="numeric"
          autoComplete="one-time-code"
          autoFocus
          value={code}
          onChange={(event) => setCode(event.target.value)}
          disabled={props.busy}
          spellCheck={false}
        />
      </label>
      <button className="primary" type="submit" disabled={props.busy || code === ""}>
        Continue
      </button>
    </form>
  );
}
