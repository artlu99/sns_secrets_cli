# Security

`sns` stores synced notes and session credentials as ciphertext. One private key opens all of them. Two postures decide where that key lives: the OS keychain, or a file next to the ciphertext. They are the same program on two kinds of machine; what differs is what a disk thief gets away with. The planned third posture — an off-box OpenBao server as the store of record, with the machine holding only a revocable lease — is deferred, not built: its design lives in docs/bao.md. Consumer machines never run sns at all: values reach them through narrow OpenBao paths the operator pushes by hand (docs/bao.md), so no deploy job ever holds a key that unlocks more than its own paths.

Local files stay until `sns logout`. There is no idle timeout and no automatic wipe.

## The unlock chain

The account password is prompted without echo, used to derive the Standard Notes master key, and discarded. It is not written to a file, an environment variable, an argument list, or a log. The master key stays in memory for the sync that needs it.

Sync decrypts notes and writes the decrypted JSON into `cache.db`. That file is a whole-database `chacha20` database (SQLite3MultipleCiphers), sealed with a random 32-byte `SN_DB_KEY`. The account password does not derive this key and cannot reopen the file. Item keys for notes already synced are rows in the same database, so the Standard Notes wrapping is not a second lock on the cache.

`SN_DB_KEY`, the refresh token, the access token, both expirations, and the cookie pair live in `.env.session`, encrypted by dotenvx. The public key is in that file. `DOTENV_PRIVATE_KEY_SESSION` decrypts it.

Whoever has that private key can read every synced note and can use the refresh token to pull new notes encrypted to item keys already in the cache. A note that arrives under a new item key still requires the account password once.

`list`, `search`, `show`, `copy`, `sink`, and the no-argument browser open this chain on disk. They do not contact the server, and they do not look at token expiry. An expired server session still leaves the notes readable.

`sns logout` refreshes the access token first if it has expired, then revokes the server session when the network allows it (`POST /v1/logout`, and `DELETE /v1/sessions` if that returns 404 or 405). It then deletes `.env.session`, `.env.keys`, and the keychain item, including when revoke fails. `cache.db` stays unless `--delete-cache` is given — either way it is unreadable, because its database key lived in the deleted session; the next login generates a fresh key and replaces the file.

Plain `.env` holds `SN_EMAIL` and `SN_API_URL` only; lines sns does not own survive every rewrite. The config directory is `~/.config/sn_secrets_cli/`, mode `0700`.

## Consumers

Machines that consume secrets do so through OpenBao, the way they consume everything else on those servers. The operator pushes specific values from settings notes into `sns/consumers/<name>/<KEY>` with native bao CLI (docs/bao.md carries the ceremony and its trade-offs); a consumer's policy is read-only on its own subtree, so a leaked consumer credential reads only that consumer's values, for the life of its lease. Consumers never run `sns`, never see the dotenvx private key, never hold a Standard Notes session, and never sync the corpus. Values published to consumers live in OpenBao; the source note is deleted by the operator, by hand, in any Standard Notes surface — sns has no write path into Standard Notes.

## CI (deferred)

This repository runs no CI today. The design for a CI posture — GitHub OIDC login, a `sns/ci/session` path holding a dedicated revocable SN session, rotate-and-write-back — is kept in docs/bao.md for the day a workflow exists. Nothing in the current code path serves CI.

## Value exits: the clipboard, files, and where handoff files should live

Values leave the cache through exactly three doors, and none of them is stdout:

- **`sns copy`** puts one value on the clipboard over OSC 52, prints the byte count, and clears the paste after 30 seconds. The value is never displayed.
- **`sns sink <id> <key> <path>`** writes one value to a file for agent handoff. The file is `0600` from the instant it exists — created `O_EXCL|O_NOFOLLOW` at mode `0600`, never through a symlink, then `fchmod`-ed (umask-proof) and `fstat`-asserted before the fd closes; a failed write removes the partial file. Existing targets are refused unless `--force`. The command prints the key name, byte count, path, and mode — the value is never displayed. **Deleting the file is the reader's obligation**; the command governs creation, not lifecycle. stdout is never a sink, and piping `sns show` into a file remains the operator writing plaintext — `sink` is the disciplined version of that act, not a license for it.
- **The OpenBao push** (manual ceremony today, `sns publish` later) moves values to consumers off-box.

A handoff file is memory-backed when it can be: on Linux prefer a directory under `$XDG_RUNTIME_DIR` (per-user, `0700`, tmpfs — the OS enforces the ownership), then a `0700` subdirectory under `/dev/shm`; `/tmp` counts only when it is mounted tmpfs. `sns sink` warns when `statfs` reports a disk-backed destination, because a disk-backed handoff file leaves recoverable plaintext on the disk image. On macOS no tmpfs exists — the honest ceiling there is `0600` plus lifecycle, with FileVault carrying the at-rest half. One caveat no CLI can promise away: tmpfs pages still land in swap under memory pressure, so on a server the swap posture (no swap, zram, or encrypted swap) is the other half of the guarantee.

## With a keychain

Linux uses `secret-tool` with `service=sn_secrets_cli` and `account=dotenvkey`, when the secret service answers. macOS uses the login keychain through `security`, with the same service and account. After the key is stored, `.env.keys` is removed and never recreated: later saves hand dotenvx the key through the process environment, not a file.

A cold copy of the disk (a stopped VM image, a backup, a machine that is off) contains `cache.db` and `.env.session` as ciphertext. The private key is inside the login keyring, and that file is encrypted with the login password. The password is not on the disk. The config directory by itself does not open the notes.

This depends on the keyring having a password. A keyring with an empty password decrypts with no secret, and the posture is the one in the next section: the key is in a different file on the same disk.

While the keyring is unlocked, this program sets no ACL and asks for no extra prompt. Any process of the same user can read the key with `secret-tool lookup service sn_secrets_cli account dotenvkey`, or `security find-generic-password -s sn_secrets_cli -a dotenvkey -w`. Those processes are outside the threat model. On a single-user machine that includes an agent runtime.

A copy of the keyring daemon's memory, or a hibernation image taken while the keyring is unlocked, includes the key. On macOS the key is an argument to `security` while it is being stored, so it shows up in the process list for that command.

## Without a keychain

`sns doctor` reports the keychain check as SKIP. Login leaves `DOTENV_PRIVATE_KEY_SESSION` in `~/.config/sn_secrets_cli/.env.keys` at mode `0600`, beside `.env.session` and `cache.db`.

A copy of that directory opens every synced note and includes the refresh token. Mode `0600` matters to other accounts on a shared machine. A snapshot, a backup, or any reader running as root receives the key and both ciphertexts together.

Cloud VMs, and this project's dev machine, are usually in this posture. The database encryption is real, and the key is stored next to it.

Removing `.env.keys` does not leave a cache that login can reopen. `SN_DB_KEY` is random. The next login that can proceed generates a new one and replaces `cache.db`. The notes come back by syncing from the server. Offline, the old file stays unreadable.

## Shared limits

Same-user processes are outside the threat model on every machine.

Child processes, including the pager and clipboard helpers, are started with secret-named environment variables removed. Clipboard copies go out over OSC 52, the command prints the byte count rather than the note, and the paste is cleared after 30 seconds.

The cache holds every synced note under one database key. There is no separate lock per note.
