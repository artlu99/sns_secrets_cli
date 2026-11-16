# sn-secrets-cli

A **secure, read-only** companion for [Standard Notes](https://standardnotes.com) — the same vault on two surfaces:

| Surface | When you use it |
|---|---|
| **CLI** (`sns`) | SSH sessions, scripts, and any machine where a terminal is the right tool |
| **Chrome extension** | Next to the browser: search a key, reveal one value, copy, done |

Neither surface writes notes back to Standard Notes. Create, edit, tag, and export in the official apps (or [sn-cli](https://github.com/jonhadfield/sn-cli)). This project only logs in, syncs, and lets you **find and copy** what is already there.

The binary is named `sns` so it does not collide with sn-cli’s `sn`.

## The model: tagged notes, a few conventions

There is no separate “secrets” schema. Each item is an ordinary Standard Notes note. Tags and folders organize them the same way they do in the apps; both surfaces render the same tag tree (explicit SN folders win; otherwise nesting is inferred from note membership).

Secrets inside a note are plain `KEY=value` lines — env-style settings with a short list of rules both surfaces share:

- An assignment starts a line (`KEY = value`); keys are `[\w.-]+`, matched **exactly** and **case-sensitively**.
- Last assignment wins; keys stay in first-seen order.
- Quoted values (`"…"`, `'…'`, `` `…` ``) may span lines; nothing is shell-expanded.
- A whitespace-preceded `#` is a trailing comment (shown beside the key, never copied).
- Empty values are marked `(empty)`. Prose around the assignments stays prose; assignment-shaped fragments in comments or mid-sentence are redacted in every view.

A note with no settings is still a note — the CLI can copy its whole body; the extension does not (one click dumping every value is too easy in a browser).

## Secure and read-only

Shared invariants across CLI and extension:

- **Values never print.** Inventories show keys (and redacted prose); only `copy` / a click puts a value on the clipboard, one key at a time.
- **Clipboard clears in ~30 seconds.** The terminal uses [OSC 52](https://invisible-island.net/xterm/ctlseqs/ctlseqs.html) (with a platform-tool fallback); the extension overwrites via an offscreen document (space if the browser refuses empty).
- **Password is ephemeral.** Prompted without echo, used to derive keys, then dropped — never written to a file, env var, argv, or log.
- **No page injection.** The extension has no content scripts; its only network traffic is the Standard Notes API.
- **Crypto stays local.** Argon2id + protocol 004 (XChaCha20-Poly1305) run in-process (CLI) or as WASM in the extension. The crypto core is shared, not forked — parity is tested both ways.

Threat model and unlock chain for the CLI’s on-disk cache: [SECURITY.md](SECURITY.md). Extension session posture and auto-lock: [extension/README.md](extension/README.md).

## Portability

Designed to move with you without dragging secrets into the wrong place:

- **SSH-first CLI.** `sns copy` sends a value to *your local* clipboard over OSC 52, so a remote shell can paste into a local password field. The terminal prints a byte count, never the secret.
- **Offline after sync (CLI).** `list` / `search` / `show` / `copy` / browse read the encrypted local cache; they do not need the network or a live access token.
- **Nothing secret on disk (extension).** Master key, tokens, and the decrypted vault live in `chrome.storage.session` only — wiped when the browser exits. Auto-lock after 5 minutes idle (or 2 minutes with the dashboard tab hidden).
- **Same account, same rules.** Tag nesting, key parsing, and redaction match on both surfaces so a note that looks safe in the terminal looks safe in the popup.
- **Small config surface (CLI).** Everything under `~/.config/sn_secrets_cli/` (or `SNS_CONFIG_DIR`). Plain `.env` is non-secret (`SN_EMAIL`, `SN_API_URL`); session material is dotenvx-encrypted. Prefer an OS keychain for the dotenvx private key when a secret service is available.
- **Small static CLI.** Prebuilt Rust binaries are coming soon. Until then, build from [`rs/`](rs/) (`bun run build:rust`) or run the TypeScript tip of spear under [Bun](https://bun.sh) while developing (`bun src/index.ts` / `bun run build`).

## Install

- **CLI** — download a release binary when published, or build as above. Then `sns login` (password + MFA if required), which syncs into the encrypted cache and drops the password. Login always confirms the email (pre-filled from `SN_EMAIL`); choose another address to switch accounts — you will be asked to logout the current session first.
- **Extension** — load unpacked from a build of [`extension/`](extension/) (see [extension/README.md](extension/README.md)). Store listing is not in v1.

Config lives in `~/.config/sn_secrets_cli/` (or `SNS_CONFIG_DIR`): plain `.env` (email, API URL), dotenvx-encrypted `.env.session`, optional `.env.keys` when there is no OS secret service, and `cache.db` (whole-file `chacha20`). Details: [SECURITY.md](SECURITY.md).

Tab completion for `show` / `copy` / `sink` (note ids, then setting keys):

```bash
eval "$(sns completion bash)"   # or: eval "$(sns completion zsh)"
```

## CLI

```bash
sns list
sns tags
sns list --tag <tag-or-folder>
sns search <query>
sns show <id>
sns copy <id> <key>
sns sink <id> <key> <path>   # value → a 0600 file, never displayed (agent handoff)
sns                 # interactive browse
sns sync
sns logout
sns purge -y        # delete the entire local config dir (never touches the server)
sns doctor
sns completion bash|zsh
```

`<id>` is a note uuid, a uuid prefix (≥ 8 hex chars), or a title prefix that matches exactly one note. `show` prints prose and a key inventory with values withheld; `copy` puts one value on the clipboard and prints only a byte count (`copied API_KEY (32 bytes, clears in 30s)`). On a settings note, `copy` without a key lists keys and does nothing. `sink` writes one value straight to a `0600` file — the value never touches the screen or the clipboard; deleting the file is the reader's job (see [SECURITY.md](SECURITY.md) for handoff-directory guidance). `list` / `search` hide key-bearing crypto items unless `--all`; search snippets are cut from masked text. No command writes plaintext note bodies to a temp file.

```text
staging api
───────────
Notes on the staging API.

DB_HOST=[redacted]  # primary host
API_KEY=[redacted]
TOKEN=  (empty)

copy a value:  sns copy staging DB_HOST
```

## Chrome extension

Same vault rules in the browser. Popup searches every `KEY` and copies on click; dashboard shows the tag tree and a reveal/copy inventory. Clipboard clears in 30 s; auto-lock after idle / hidden tab. No content scripts; editing is not in v1. Setup and security model: [extension/README.md](extension/README.md).

## Repository layout

| Path | Role |
|---|---|
| [`src/`](src/) | **Tip of the spear** for CLI features — executable spec the Rust port tracks. |
| [`extension/`](extension/) | Chrome MV3 surface; shares crypto / tag / note-env rules with `src/` where possible. |
| [`rs/`](rs/) | Portable Rust CLI for distribution. Stays **mostly caught up** with `src/` — no Rust-only product behavior. |

Build, test, porting rules, and security invariants for contributors: [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
