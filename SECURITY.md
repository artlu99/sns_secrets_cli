# Security

`sns` stores synced notes and session credentials as ciphertext. One private key opens all of them. The two postures below are the same program on two kinds of machine: one where that key is in the OS keychain, and one where it is a file next to the ciphertext.

Local files stay until `sns logout`. There is no idle timeout and no automatic wipe.

## The unlock chain

The account password is prompted without echo, used to derive the Standard Notes master key, and discarded. It is not written to a file, an environment variable, an argument list, or a log. The master key stays in memory for the sync that needs it.

Sync decrypts notes and writes the decrypted JSON into `cache.db`. That file is a whole-database `chacha20` database (SQLite3MultipleCiphers), sealed with a random 32-byte `SN_DB_KEY`. The account password does not derive this key and cannot reopen the file. Item keys for notes already synced are rows in the same database, so the Standard Notes wrapping is not a second lock on the cache.

`SN_DB_KEY`, the refresh token, the access token, both expirations, and the cookie pair live in `.env.session`, encrypted by dotenvx. The public key is in that file. `DOTENV_PRIVATE_KEY_SESSION` decrypts it.

Whoever has that private key can read every synced note and can use the refresh token to pull new notes encrypted to item keys already in the cache. A note that arrives under a new item key still requires the account password once.

`list`, `search`, `show`, `copy`, and the no-argument browser open this chain on disk. They do not contact the server, and they do not look at token expiry. An expired server session still leaves the notes readable.

`sns logout` revokes the server session when the network allows it (`POST /v1/logout`, and `DELETE /v1/sessions` if that returns 404 or 405). It then deletes `.env.session`, `.env.keys`, the keychain item, and `cache.db`, including when revoke fails.

Plain `.env` holds `SN_EMAIL` and `SN_API_URL` only. The config directory is `~/.config/sn_secrets_cli/`, mode `0700`.

## With a keychain

Linux uses `secret-tool` with `service=sn_secrets_cli` and `account=dotenvkey`, when the secret service answers. macOS uses the login keychain through `security`, with the same service and account. After the key is stored, `.env.keys` is removed.

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

Same-user processes are outside the threat model on both machines.

Child processes, including the pager and clipboard helpers, are started with secret-named environment variables removed. Piping `sns show` into a file is the operator writing plaintext. Clipboard copies go out over OSC 52, the command prints the byte count rather than the note, and the paste is cleared after 30 seconds.

The cache holds every synced note under one database key. There is no separate lock per note.
