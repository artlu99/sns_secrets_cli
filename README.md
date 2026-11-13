# sn-secrets-cli

`sns` is a terminal client for reading a [Standard Notes](https://standardnotes.com) account. It logs in, pulls your notes, and stores them in an encrypted local cache. After that, listing, searching, showing, and copying read the cache on this machine.

The copy command is built for an SSH session. It sends the note to your local clipboard with [OSC 52](https://invisible-island.net/xterm/ctlseqs/ctlseqs.html) and clears it after 30 seconds. The terminal prints how many bytes were copied, not the note.

[sn-cli](https://github.com/jonhadfield/sn-cli) is the Standard Notes client to use when you want to edit, tag, or export. It is actively maintained, and `sns` borrows what it learned about login and sync. The gap `sns` fills is local storage and the clipboard: sn-cli keeps decrypted notes in a plaintext database, and it has no OSC 52 path. The command here is `sns` so it does not take the `sn` name.

## First session

Install [Bun](https://bun.sh), then:

```bash
bun install
bun src/index.ts login
```

`login` asks for the account password, and for a two-factor code when the server requires one. The password is used to derive keys and then dropped. It is not written to a file, an environment variable, or a log. The same command syncs notes into the cache.

`package.json` exposes the `sns` command. After `bun link`, the examples below are the program. `bun src/index.ts` runs it without linking.

```bash
sns list
sns search <query>
sns show <id-or-title-prefix>
sns copy <id-or-title-prefix>
sns
sns sync
sns logout
```

`sns` with no arguments asks for a filter, then offers to view or copy the note you pick. `list` and `search` hide key-bearing items unless you pass `--all`. `show` pages the note on standard input so the text is not written to a temp file; `--no-pager` prints it to standard output. `sync` pulls again and asks for the password only when a new items key cannot be unwrapped with keys already in the cache. `logout` revokes the server session and deletes the local session, the cache key, and the cache. `doctor` reports whether the runtime, keychain, session file, and cache look right.

## Where the files are

Everything lives in `~/.config/sn_secrets_cli/` (override with `SNS_CONFIG_DIR`):

| File | What it holds |
|---|---|
| `.env` | Email and API URL. Not secret. |
| `.env.session` | Refresh token, access token, and the cache key, encrypted with dotenvx. |
| `.env.keys` | The dotenvx private key, only on a machine with no OS secret service. Mode `0600`. |
| `cache.db` | Decrypted notes, inside a `chacha20` database. |

The cache key is random. The account password cannot reopen `cache.db`. One key opens every synced note. When a secret service is available, the dotenvx private key is stored in the OS keychain and `.env.keys` is removed. [SECURITY.md](SECURITY.md) describes what a disk copy can read in that case, and what it can read when the key stays in `.env.keys`.

## Development

```bash
bun test
bun check
bun run build    # standalone binary at dist/sns
```

The cache uses `better-sqlite3-multiple-ciphers` rather than `bun:sqlite`, because Bun's built-in SQLite cannot encrypt a file at rest. Other Bun conventions for this repo are in [CLAUDE.md](CLAUDE.md).

## License

MIT. See [LICENSE](LICENSE).
