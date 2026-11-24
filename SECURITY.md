# Security

`sns` stores synced notes and session credentials as ciphertext. One private key opens all of them. Two postures decide where that key lives: the OS keychain, or a file next to the ciphertext. They are the same program on two kinds of machine; what differs is what a disk thief gets away with. The planned third posture — an off-box OpenBao server as the store of record, with the machine holding only a revocable lease — is deferred, not built: its design lives in docs/bao.md. Consumer machines never run sns at all: values reach them through narrow OpenBao paths the operator pushes by hand (docs/bao.md), so no deploy job ever holds a key that unlocks more than its own paths.

Local files stay until `sns logout`. There is no idle timeout and no automatic wipe. `sns purge` is the scorched-earth complement: it deletes every file sns created in the config directory — a cache whose key is long gone included — and removes the directory, but it is offline by design and never revokes the server session; run `logout` first when the session should end.

## The unlock chain

The account password is prompted without echo, used to derive the Standard Notes master key, and discarded. It is not written to a file, an environment variable, an argument list, or a log. The master key stays in memory for the sync that needs it.

Sync decrypts notes and writes the decrypted JSON into `cache.db`. That file is a whole-database `chacha20` database (SQLite3MultipleCiphers), sealed with a random 32-byte `SN_DB_KEY`. The account password does not derive this key and cannot reopen the file. Item keys for notes already synced are rows in the same database, so the Standard Notes wrapping is not a second lock on the cache.

`SN_DB_KEY`, the refresh token, the access token, both expirations, and the cookie pair live in `.env.session` under the same field names in both binaries, encrypted in one format: dotenvx public-key encryption. The file carries a `DOTENV_PUBLIC_KEY_SESSION=` header — a 66-char compressed secp256k1 point — above one `encrypted:` record per field, each record `encrypted:` + standard padded base64 of `ephemeral_public(65, uncompressed) || iv(16) || auth_tag(16) || ciphertext`: ECIES over secp256k1 with the ECDH shared point serialized uncompressed, HKDF-SHA256 over `ephemeral_public || shared_point` with a 32-zero-byte salt and empty info, AES-256-GCM with a 16-byte IV. Both binaries implement this format natively — the Rust CLI does not shell out to dotenvx ([why](#why-the-rust-cli-does-not-shell-out-to-the-dotenvx-cli)) — and the `dotenvx` CLI itself reads and writes the same file. `DOTENV_PRIVATE_KEY_SESSION` — a 32-byte hex secp256k1 scalar in `.env.keys` or the keychain — decrypts it; wrong key and tampered records are the same GCM failure.

One property of the format is disclosed rather than fixed: dotenvx records carry no associated data, so a record is not bound to its field name — a record moved from one field name to another still decrypts. The legacy Rust `enc1:` format did authenticate the name; dotenvx compatibility was chosen knowing this difference, and it is the format's own cost, not an sns addition. What still stands between a swapped record and a working secret: the Rust session loader rejects any key outside the known field-name contract before decrypting (the TypeScript loader rejects it as well, after decrypting inside dotenvx's parse), and a within-contract swap surfaces as a credential that fails at use — a token the server rejects, a cookie that does not open the session, a database key that will not decrypt `cache.db`. The swap is not detected structurally; it is detected by the stolen value not working.

The two binaries are therefore interchangeable over this file: either reads, refreshes, and re-encrypts the session the other wrote, and so can the `dotenvx` CLI (break-glass, not required — see the section below). Sessions still in the legacy Rust-only `enc1:` format (P-256 ephemeral-static ECDH, the field name as associated data, an `SNS_SESSION_PUBLIC_KEY=` header) remain decryptable, and migrate once: the first run of the current Rust binary opens such a file with the old scalar, re-encrypts every field to a freshly generated dotenvx key (the enc1 file carries no dotenvx key of its own), and settles the new key's custody; a fresh `sns login` is the alternative. Key custody lands in the same places for both binaries — one keychain item (`service=sn_secrets_cli`, `account=dotenvkey`) and one `.env.keys` file (`DOTENV_PRIVATE_KEY_SESSION=`) — so a login with either binary replaces what the other stored. The keychain and `.env.keys` sections below describe this custody from the TypeScript CLI's side; the Rust binary uses the same slots and the same key semantics.

Whoever has that private key can read every synced note and can use the refresh token to pull new notes encrypted to item keys already in the cache. A note that arrives under a new item key still requires the account password once.

`list`, `search`, `show`, `copy`, `sink`, and the no-argument browser open this chain on disk. They do not contact the server, and they do not look at token expiry. An expired server session still leaves the notes readable.

`sns logout` refreshes the access token first if it has expired, then revokes the server session when the network allows it (`POST /v1/logout`, and `DELETE /v1/sessions` if that returns 404 or 405). It then deletes `.env.session`, `.env.keys`, and the keychain item, including when revoke fails. `cache.db` stays unless `--delete-cache` is given — either way it is unreadable, because its database key lived in the deleted session; the next login generates a fresh key and replaces the file.

Plain `.env` holds `SN_EMAIL` and `SN_API_URL` only; lines sns does not own survive every rewrite. The config directory is `~/.config/sn_secrets_cli/`, mode `0700`.

`.env.session` is never on disk at a wider mode with content inside, in either binary. The Rust CLI writes the whole file through a temp file created `O_EXCL|O_NOFOLLOW` at `0600`, fully written, mode-asserted, fsync-ed, atomically renamed over the destination, with the parent directory fsync-ed after the rename — a crash or power cut never leaves a partial or wide-mode session file, and the bytes are on disk before the command reports success. The TypeScript CLI pre-creates `.env.session` empty at `0600` (`O_EXCL|O_NOFOLLOW`, a symlink refusal, an umask-proof `fchmod` and an `fstat` assertion) before dotenvx's first write; dotenvx then replaces the file through write-file-atomic, whose temp copies the destination's existing mode, so every content-bearing rename lands `0600`. A crashed TS save leaves behind at most the empty `0600` target (removed by the next save) and a stray `0600` temp — the `.env.session` temps carry ciphertext only, but a crash during the rarer `.env.keys` write leaves the plaintext session private key in its `0600` temp until the next `sns logout` or `sns purge` sweeps it (both delete every owned `.env.session`/`.env.keys` temp spelling); never a wide mode. The TS path does not fsync; only the Rust binary flushes to disk before reporting success.

## Consumers

Machines that consume secrets do so through OpenBao, the way they consume everything else on those servers. The operator pushes specific values from settings notes into `sns/consumers/<name>/<KEY>` with native bao CLI (docs/bao.md carries the ceremony and its trade-offs); a consumer's policy is read-only on its own subtree, so a leaked consumer credential reads only that consumer's values, for the life of its lease. Consumers never run `sns`, never see a session private key (the dotenvx session key), never hold a Standard Notes session, and never sync the corpus. Values published to consumers live in OpenBao; the source note is deleted by the operator, by hand, in any Standard Notes surface — sns has no write path into Standard Notes.

## CI (deferred)

This repository runs no CI today. The design for a CI posture — GitHub OIDC login, a `sns/ci/session` path holding a dedicated revocable SN session, rotate-and-write-back — is kept in docs/bao.md for the day a workflow exists. Nothing in the current code path serves CI.

## Value exits: the clipboard, files, and where handoff files should live

Values leave the cache through exactly three doors, and none of them is stdout:

- **`sns copy`** puts one value on the clipboard over OSC 52 (a wl-copy/xclip/pbcopy fallback when there is no terminal to write the sequence to), prints the byte count, and arms a best-effort clear: a detached sleeper writes the OSC 52 clear sequence to the same terminal 30 seconds later — honored only by terminals that implement OSC 52 — and a marker file lets the next `sns` command sweep the paste if the sleeper died or there was no terminal at copy time. The value is never displayed.
- **`sns sink <id> <key> <path>`** writes one value to a file for agent handoff. The file is created `O_EXCL|O_NOFOLLOW` at mode `0600` (`O_TRUNC` on the `--force` reopen), never through a symlink; the fd is `fchmod`-ed to `0600` before the first byte lands and `fstat`-asserted `0600` and full-length before it closes, and a failed write removes the partial file (the Rust binary additionally fsyncs the bytes before reporting success). Existing targets are refused unless `--force`. The command prints the key name, byte count, path, and mode — the value is never displayed. **Deleting the file is the reader's obligation**; the command governs creation, not lifecycle. stdout is never a sink, and piping `sns show` into a file remains the operator writing plaintext — `sink` is the disciplined version of that act, not a license for it.
- **The OpenBao push** (manual ceremony today, `sns publish` later) moves values to consumers off-box.

A handoff file is memory-backed when it can be: on Linux prefer a directory under `$XDG_RUNTIME_DIR` (per-user, `0700`, tmpfs — the OS enforces the ownership), then a `0700` subdirectory under `/dev/shm`; `/tmp` counts only when it is mounted tmpfs. `sns sink` warns when `statfs` reports a disk-backed destination, because a disk-backed handoff file leaves recoverable plaintext on the disk image. On macOS no tmpfs exists — the honest ceiling there is `0600` plus lifecycle, with FileVault carrying the at-rest half. One caveat no CLI can promise away: tmpfs pages still land in swap under memory pressure, so on a server the swap posture (no swap, zram, or encrypted swap) is the other half of the guarantee. For the full worked protocol — how this repository's own release credentials move from vault to pushing agent, and why no paste-or-prompt-card flow is used instead — see [docs/credential-handoff.md](docs/credential-handoff.md).

## With a keychain

Linux uses `secret-tool` with `service=sn_secrets_cli` and `account=dotenvkey`, when the secret service answers. macOS uses the login keychain through `security`, with the same service and account. Both binaries store the session private key in this one slot — the same dotenvx secp256k1 scalar, whichever binary logged in last. After the key is stored, `.env.keys` is removed, and saves keep the key out of files for as long as the keychain answers: the TypeScript CLI hands dotenvx its key through the process environment, the Rust CLI reads its scalar in-process.

A cold copy of the disk (a stopped VM image, a backup, a machine that is off) contains `cache.db` and `.env.session` as ciphertext. The private key is inside the login keyring, and that file is encrypted with the login password. The password is not on the disk. The config directory by itself does not open the notes.

This depends on the keyring having a password. A keyring with an empty password decrypts with no secret, and the posture is the one in the next section: the key is in a different file on the same disk.

While the keyring is unlocked, this program sets no ACL and asks for no extra prompt. Any process of the same user can read the key with `secret-tool lookup service sn_secrets_cli account dotenvkey`, or `security find-generic-password -s sn_secrets_cli -a dotenvkey -w`. Those processes are outside the threat model. On a single-user machine that includes an agent runtime.

A copy of the keyring daemon's memory, or a hibernation image taken while the keyring is unlocked, includes the key. On macOS the key is an argument to `security` while it is being stored, so it shows up in the process list for that command.

## Without a keychain

`sns doctor` reports the keychain check as SKIP. Login leaves the session private key in `~/.config/sn_secrets_cli/.env.keys` at mode `0600` — one `DOTENV_PRIVATE_KEY_SESSION=` line, identical custody in both binaries — beside `.env.session` and `cache.db`.

A copy of that directory opens every synced note and includes the refresh token. Mode `0600` matters to other accounts on a shared machine. A snapshot, a backup, or any reader running as root receives the key and both ciphertexts together.

Cloud VMs, and this project's dev machine, are usually in this posture. The database encryption is real, and the key is stored next to it.

Removing `.env.keys` does not leave a cache that login can reopen. `SN_DB_KEY` is random. The next login that can proceed generates a new one and replaces `cache.db`. The notes come back by syncing from the server. Offline, the old file stays unreadable.

## Why the Rust CLI does not shell out to the dotenvx CLI

The Rust binary could have reached dotenvx compatibility by invoking the `dotenvx` executable instead of implementing the format. That option was measured and rejected; the evidence, gathered by probing the CLI during design:

- **`dotenvx set` takes the secret value as a process argument.** Captured live in `ps` during probing: the refresh token would sit readable in the process list for the duration of every save — the same argv exposure the unlock chain above refuses for the account password.
- **`dotenvx get` prints plaintext to stdout.** stdout is the one exit this program keeps shut for values; `get` would reopen it on every read.
- **Even the argv-free path leaks.** `dotenvx encrypt -f` (file in, file out, nothing on the command line) still leaves plaintext in a temp file on disk and in a second process's heap.
- **The crypto would be resolved from PATH at runtime, unpinned by the repo's lockfiles.** The wire format that guards every future save would be whatever brew-latest shipped that week — drift between runs, discovered by breakage or not at all, instead of a pinned dependency and committed golden vectors.
- **One vendor compromise would hit both binaries.** Making the dotenvx CLI a hard dependency turns the npm package into part of the secrets posture itself: a poisoned release would compromise the TypeScript CLI's library and, through the subprocess, every Rust save in the same breath.
- **The distribution cost is ~67 MB or a Node requirement.** Vendoring the dotenvx binary means shipping a ~67 MB payload that embeds Node next to a Rust binary that exists precisely to shed that weight; not vendoring means every machine the binary lands on needs npm or Node installed.

Contrast the custody path the program actually uses for this key: the OS keychain is OS-pinned, stores opaque blobs, and is spoken to over a protocol with no argv and no stdout plaintext (`secret-tool` and `security` receive label arguments and print nothing of the secret's kind). Implementing the dotenvx wire natively keeps that boundary intact and still gets the interop: the format is pinned byte-for-byte by golden vectors generated from the pinned @dotenvx/primitives 3.3.1 (`rs/tests/fixtures/session-vectors.json`, asserted by tests on both the Rust and the TypeScript side), so drift fails a test rather than silently changing the wire. The `dotenvx` CLI remains usable on the same files — break-glass when an operator wants it — without being required by a single save.

## Shared limits

Same-user processes are outside the threat model on every machine.

Child processes, including the pager and clipboard helpers, are started with secret-named environment variables removed. Clipboard copies go out over OSC 52, the command prints the byte count rather than the note, and the clear is best-effort: an OSC 52 clear ~30 seconds later that only an OSC 52-capable terminal honors, re-fired by the next `sns` command if the detached sleeper died.

Both binaries are Linux and macOS programs. The Rust crate refuses to compile on Windows, and the TypeScript CLI is only partially usable there — no OS keychain integration, no wl-copy/xclip/pbcopy fallback, POSIX path assumptions — so Windows has no supported posture in this document.

The cache holds every synced note under one database key. There is no separate lock per note.
