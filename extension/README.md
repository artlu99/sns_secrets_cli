# sns vault — Chrome extension

A Chrome extension over the same crypto core as the `sns` CLI: your Standard
Notes secrets, browsable by tag, keys masked until revealed, one click to
clipboard. **All cryptography runs in the extension** — Argon2id key
derivation (64 MiB / 5 iterations, per the server's key params) and
XChaCha20-Poly1305 decryption never leave this window.

## Load it (unpacked)

```sh
bun install          # from the repo root (workspaces)
cd extension && bunx wxt build
```

Then in Chrome: `chrome://extensions` → enable **Developer mode** →
**Load unpacked** → select `extension/.output/chrome-mv3`.

One rule when rebuilding: `wxt build` wipes and rewrites that directory over
a second or two — reloading the card or opening the popup mid-build produces
"Could not load manifest" / `ERR_FILE_NOT_FOUND` noise. Wait for the build to
print **Finished**, then Reload.

- **Popup** (toolbar icon): type to search across every `KEY` in every note;
  Enter/click copies the value. Notes without settings open the dashboard.
- **Dashboard** (tab): tag hierarchy on the left (SN folders win; nesting is
  inferred the same way `sns list` does it), notes in the middle, and the
  per-key inventory on the right with show/hide and copy. Prose is rendered
  with assignment-shaped fragments redacted, exactly like `sns show`.
- **Clipboard auto-clear**: every copy schedules an overwrite after 30
  seconds. The timer lives in an offscreen document — the only context that
  can host it (popups die on focus loss; the MV3 service worker sleeps; and
  offscreen documents get no extension APIs beyond runtime messaging, so the
  schedule travels as a message or baked into the document's creation URL,
  with the arm acknowledged). Copying again restarts the 30 s; the offscreen
  page exits once the clear fires. Browsers cannot *clear* the clipboard,
  only overwrite it — and some refuse an empty write entirely, so the
  fallback overwrites with a single space: pasting after the clear yields a
  space, never the secret. `bun scripts/e2e-clipboard.ts` verifies the whole
  chain in a headless Chromium.

## Security model

- The master key and session tokens live only in `chrome.storage.session`:
  memory-backed, invisible to pages, **wiped when the browser exits**. Nothing
  secret touches disk.
- The decrypted-item cache also lives in session storage; a full re-pull
  happens on the next browser start (incremental syncs use the sync token).
- **No content scripts** — the extension never touches web pages. Its only
  network traffic is to the Standard Notes API (declared:
  `api.standardnotes.com`; a self-hosted server URL is requested as an
  optional permission at first login, on the click's user gesture).
- **Auto-lock**: after 5 minutes without input (pointer, keys, wheel, scroll)
  — or after 2 minutes with the dashboard tab hidden — both surfaces re-gate
  to the login form and the session is wiped from session storage, exactly
  like the lock button. The durations are constants at the top of
  `components/auto-lock.ts`.
- MV3 CSP: no remote code; `'wasm-unsafe-eval'` is present solely so
  libsodium's WASM can run.

## Development

```sh
bun run dev      # wxt dev — loads a dev build into a Chromium it launches
bun run build    # production build to .output/chrome-mv3
bun run typecheck
bun test         # lib tests (PKCE/004 interop with the CLI, sync, tags)
```

Icons are PNG (16/32/48/128), generated from the SVG in
`scripts/make-icons.ts` — edit the SVG and run `bun scripts/make-icons.ts`
to regenerate.

The crypto core is **shared, not forked**: `lib/crypto.ts` re-exports the
CLI's `src/sn-crypto/kdf.ts` verbatim and ports only `004.ts`'s Buffer calls
to base64 helpers. Parity is pinned by tests — `pkce.test.ts` asserts the
WebCrypto PKCE matches `node:crypto` byte-for-byte, and `crypto.test.ts`
decrypts CLI-encrypted payloads (and vice versa). The sync engine
(`lib/store.ts`) mirrors `src/sync-engine.ts`'s semantics: items keys decrypt
first, later-page keys retry deferred notes, tokens adopt only after the
cursor exhausts. The tag graph reuses `resolveParents`/`tagForest` from
`src/notes.ts` directly.

## Roadmap

- **v2 — editing**: notes are read-only today. Writing means the sync write
  path (encrypted content + item key upload) and server-side conflict
  handling — the one area where a bug can destroy secrets, so it is being
  built deliberately.
- Store listing (unpacked loading is per-browser).
- Optional: encrypted-at-rest cache via IndexedDB for instant reopen across
  browser restarts (password re-entry per session would still be required).
