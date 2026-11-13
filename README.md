# sn-secrets-cli

`sns` is a terminal client for reading a [Standard Notes](https://standardnotes.com) account. It logs in, pulls your notes, and stores them in an encrypted local cache. After that, listing, searching, showing, and copying read the cache on this machine.

The copy command is built for an SSH session. It sends one setting's value — or a whole note — to your local clipboard with [OSC 52](https://invisible-island.net/xterm/ctlseqs/ctlseqs.html) and clears it after 30 seconds. The terminal prints how many bytes were copied, never the value itself.

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
sns tags
sns list --tag <tag-or-folder>
sns search <query>
sns show <id>
sns copy <id> <key>
sns
sns sync
sns logout
```

## Reading a note

`<id>` is the note's uuid, a uuid prefix of at least eight hex characters, or a title prefix that matches exactly one note. Every reading command accepts all three.

Notes that hold env-style settings (`KEY=value` lines) get an inventory flow. `sns list` shows how many settings each note holds, and on a terminal appends one line after the table:

```text
a title or a uuid, a prefix is enough:  sns show <id>
```

The hint is omitted when the listing is piped, so a script that reads the table stays a table.

`sns show <id>` prints what the note holds without the values: the prose around the assignments, then each key with its value withheld, in the order the keys first appear, then a hint you can paste:

```text
staging api
───────────
Notes on the staging API.
Ask Alice before rotating.

DB_HOST=[redacted]  # primary host
API_KEY=[redacted]
API_URL=[redacted]
TOKEN=  (empty)

copy a value:  sns copy staging DB_HOST
```

An empty value is marked `(empty)`, and a trailing `# comment` from the note shows beside its key with the value redacted out — assignment-shaped text the parser rejected (`# OLD_KEY=…`, a mention mid-sentence) is masked the same way, so no value reaches the terminal. On a terminal, comments and the redaction markers render dim and keys stay bright; piped output and `NO_COLOR` are plain monochrome. `sns show <id> --raw` prints the note's full text instead.

`sns copy <id> <key>` copies one setting's value. The key is matched exactly and case-sensitively; `API` does not select `API_KEY`. Only the byte count is printed:

```text
copied API_KEY (32 bytes, clears in 30s)
```

`sns copy <id>` with no key copies nothing when the note has settings — it prints the key names and the two-argument form, so the short command stays the safe one. A missing key exits non-zero the same way. A note without settings still copies its whole body; for that note, the body is the only copy there is. Values reach the clipboard only through `copy`, one key at a time — `show` prints keys and prose only, and puts values on the terminal only through `--raw`. Two paths still print a whole note: `search` matches full content, so a hit's snippet can carry a value, and the interactive picker's View pages the full text.

## Everything else

`sns` with no arguments asks for a filter, then offers to view or copy the note you pick. `list` renders the tag tree: explicit SN folders (nested tags) win, otherwise containment is inferred from note membership — a tag whose notes all also sit in a bigger tag nests under it (so `data` folds inside `infra` when every data note is also tagged infra). Each note appears exactly once, under its deepest tag; group headers show the tag's full note count, newest first within each, untagged notes last. `list` and `search` hide key-bearing items unless you pass `--all`. `tags` lists every tag and folder as a tree with note counts — read-only, the CLI never creates or edits them. `list --tag` filters notes under a tag or folder, matched by title or uuid prefix. `show` sends full-text output (and `--raw`) through a pager on standard input so the text is never written to a temp file; the key inventory, which carries no values, prints directly and pages only when taller than the screen; `--no-pager` prints to standard output. `sync` pulls again and asks for the password only when a new items key cannot be unwrapped with keys already in the cache. `logout` revokes the server session and deletes the local session, the cache key, and the cache. `doctor` reports whether the runtime, keychain, session file, and cache look right.

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
