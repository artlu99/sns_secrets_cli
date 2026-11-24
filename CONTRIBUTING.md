# Contributing

This repo has three surfaces. Product behavior for the CLI lands in TypeScript first; the Rust crate is a portable distribution port; the Chrome extension shares crypto / note / tag rules with `src/` where possible.

| Path | Role |
|---|---|
| [`src/`](src/) | Tip of the spear for CLI features. Default `bun run test` (`bun test src`) is the executable spec. |
| [`extension/`](extension/) | Chrome MV3 vault UI. Do not invent a third parse/decrypt semantics. |
| [`rs/`](rs/) | Portable Rust CLI for distribution. Stays **mostly caught up** with `src/` — no Rust-only product behavior. |

Land new CLI behavior in `src/` with tests, then port to `rs/` against the same golden vectors / fixtures. Extension changes that touch parsing or 004 crypto should stay parity-tested against the CLI.

Threat model and unlock chain: [SECURITY.md](SECURITY.md). Extension setup: [extension/README.md](extension/README.md).

## Prerequisites

- [Bun](https://bun.sh) (project verified on 1.4.x) for `src/` and `extension/`
- Rust toolchain (edition 2024) for `rs/`

```bash
bun install
```

`bun.lock` is tracked — it is the integrity record for the dependency graph
that `bun build --compile` bakes into `dist/sns` and that ships in the
extension zip (the Rust side's equivalent, `rs/Cargo.lock`, is tracked too).
Release-style installs should fail rather than re-resolve:

```bash
bun install --frozen-lockfile
```

Bump dependencies deliberately: change the manifest, run a plain `bun
install` to move the lockfile, commit both together.

## Scripts (repo root)

```bash
bun run test               # tip of spear — bun test src
bun run check
bun run build              # Bun-compiled dist/sns

bun run test:extension
bun run build:extension

bun run test:rust
bun run build:rust         # first build compiles vendored sqlite3mc (slow)
bun run check:rust
bun run clippy:rust

bun run test:ts            # src + extension/lib
bun run test:all           # test:ts then test:rust
```

Inside `rs/` you can also use `cargo check` / `cargo test` / `cargo clippy --all-targets` directly.

## TypeScript / Bun

Prefer Bun over Node for this tree:

- `bun <file>`, `bun test`, `bun check`, `bun install`, `bun run <script>`, `bunx …`
- Bun auto-loads plain `.env` — do not add `dotenv` for that
- Prefer `Bun.file` over `node:fs` read/write helpers where practical

**Exceptions for this project:**

- The encrypted cache uses `better-sqlite3-multiple-ciphers` (cipher `chacha20`), not `bun:sqlite` — bun:sqlite has no encryption support. The Rust port uses the same cipher via vendored sqlite3mc in [`rs/libsqlite3-sys/`](rs/libsqlite3-sys/).
- Plain `.env` is non-secret only (`SN_EMAIL`, `SN_API_URL`). Session secrets live in dotenvx-encrypted `.env.session` in this tree (library decrypt via `@dotenvx/dotenvx`, not `dotenvx run --`); the Rust port encrypts the same field names with its own `enc1:` format instead — the two session formats are not interoperable (SECURITY.md). Never put `SN_PASSWORD` in any env file.

SN protocol crypto stays inside [`src/sn-crypto/`](src/sn-crypto/). The MIT tree uses `libsodium-wrappers-sumo` (Argon2id + XChaCha20-Poly1305); do not pull AGPL `@standardnotes/sncrypto-node`.

### Test hygiene

Any script or test that imports sns path/session modules must set `SNS_CONFIG_DIR` to a temp directory **before** the first path-helper call. Otherwise helpers resolve the real `~/.config/sn_secrets_cli/` and can overwrite a live session.

## Rust port (`rs/`)

`rs/` exists for distribution: a small static binary with the same command surface as the TypeScript CLI. Bun/Node conventions above do not apply under `rs/`.

Discipline that keeps the port honest:

- Do not invent product behavior in Rust first — land it in `src/` (`bun test src`), then port and pin parity against the same vectors (`src/lib.rs` states that contract).
- Prefer `cargo check` while iterating; use `cargo build` for release artifacts. The first clean build compiles the vendored sqlite3mc amalgamation and can take minutes — do not kill or retry it casually.
- Own data by default (`String` over borrowed fields in structs); this is a short-lived CLI. No async (reqwest blocking is deliberate). Errors follow `src/errors.rs` (per-module types converging on `UserError`) — do not introduce a second error strategy.
- Look for an existing helper before adding one (hex/base64, id parsing, clipboard, timestamps already have homes).
- End a task with `cargo clippy --all-targets` and `cargo test`. The test profile uses opt-level 2 (Argon2 at 64 MiB is unusable in debug); the first test build is slow.

## Standing invariants

Before merging CLI or extension work that touches secrets, session, cache, or crypto:

- `SN_PASSWORD` must not appear in any file, env var, argv, or log.
- `.env.session` holds session material only (tokens, cookies, expirations, `SN_DB_KEY`, account email label, the session public key — dotenvx's `DOTENV_PUBLIC_KEY_SESSION` or the Rust `enc1:` header's `SNS_SESSION_PUBLIC_KEY`) — never the account password, master key, or note plaintext.
- Scrub secret-named env vars before spawning children (pager, clipboard helpers, editors).
- Plaintext note content is never written to disk (no temp files; pager via stdin; OSC 52 on stdout).
- Values never print on inventory paths; only copy / one-key clipboard flows expose a value.
- `.env.session`, `.env.keys`, and `*.db` stay gitignored.
- `bun check` / relevant surface checks pass.

v1 stays read-mostly: sync / list / search / show / copy / browse. No writes to Standard Notes and no Files API.

## Versioning

One version across root `package.json`, `extension/package.json`, and `rs/Cargo.toml`. Root `package.json` is the source of truth for the TypeScript CLI (`src/version.ts`); Rust binaries report `CARGO_PKG_VERSION`. `src/version.test.ts` guards the three-way match. Tag releases `v<version>`.

## Scope out of v1

Writes to SN, Files API, multi-account, self-hosted toggle, and a full-TUI framework are out of scope for v1.
