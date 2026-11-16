# sns and OpenBao

`sns` touches OpenBao in exactly two roles:

1. **Operator custody** — the dotenvx private key that decrypts `~/.config/sn_secrets_cli/.env.session` lives in bao instead of the operator's machine. The machine would hold a short lease, not a key. **Deferred, not built**: the `sns bao` commands and the bao-first key resolution are designed here and exist as a tested module on the deferred branch of this file's history — today the operator postures are the keychain and `.env.keys` (SECURITY.md).
2. **Consumer publishing** — values you author in Standard Notes are pushed into narrow bao paths so machines and deploy jobs can read *only* what was published to them. Consumers never run `sns`, never see a Standard Notes session, and never hold a key that unlocks anything else. **Usable today**: this half is native bao CLI, no sns code involved.

Everything in this document is expressed in native bao CLI. Nothing here makes bao depend on sns.

## Server preparation

Run once, on the bao server, with an admin token. Mount a dedicated KV v2 mount so `sns` paths can never collide with other tenants:

```sh
bao secrets enable -path=sns -version=2 kv
```

Operator policy — full control of the `sns/` namespace and nothing else:

```sh
bao policy write sns-operator - <<'EOF'
path "sns/data/*" {
  capabilities = ["create", "read", "update", "delete"]
}
path "sns/metadata/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF
```

Operator auth. Any method your workflows already use is fine; `userpass` shown for completeness:

```sh
bao auth enable userpass
bao write auth/userpass/users/<you> policies=sns-operator token_ttl=1h token_max_ttl=4h
```

## Operator custody (`sns bao`) — DEFERRED

The commands in this section describe the deferred posture; none of them exist in the shipped CLI yet. Kept as the design of record for when the bridge lands.

Point `sns` at the server by adding one non-secret line to the plain `.env` in the config directory (next to `SN_EMAIL` / `SN_API_URL`):

```
SNS_BAO_ADDR=https://bao.example.internal:8200
```

Then:

```sh
sns bao login     # prompts for userpass credentials (or --token-file <path> for a pre-issued token)
sns bao status    # shows the lease: accessor, time left, renewable
sns bao logout    # revokes the lease server-side and deletes the local token file
```

The only bao material on the machine is the lease in `~/.config/sn_secrets_cli/bao-token.json` (mode `0600`). Tokens are renewed automatically when a command needs one and fewer than ten minutes remain. Token and lease values are never printed.

With `SNS_BAO_ADDR` set, the dotenvx private key is resolved **bao → keychain → `.env.keys`, in that order, with no silent fallback**: a missing lease, an expired lease, a server error, or an unreachable server is a hard error naming the fix (`sns bao login`). An operator who believes the key is off-box must never be served by a file left on disk. `sns login` pushes the session key straight to bao and leaves no local copy (`sns/local/dotenvx-key`, one KV version per login).

Two custody edges worth knowing:

- **One operator machine at a time.** The key is stored at a single path. A second machine's `sns login` overwrites it; the first machine must re-login afterwards. Per-host paths would change this — a deliberate future decision, not an accident.
- **Turning bao off.** If you remove `SNS_BAO_ADDR` after using bao custody, there is no local key — run `sns login` to establish keychain/`.env.keys` custody. (A keychain entry from before bao mode may exist but can be stale; `sns login` replaces it.)

`sns logout` revokes the lease server-side (best-effort — local secrets are deleted even if the revoke fails) and deletes `bao-token.json`.

A dev-mode `bao server -dev` is a **test fixture** (`src/openbao.fixture.test.ts`), never a posture: unsealed, no TLS, state lost on restart.

## Consumer contract

Every consumer gets a namespace and a policy, and nothing else:

- **Paths:** `sns/consumers/<name>/<KEY>` — one KV entry per consumer; each key its own entry so reads, versioning, and deletion are per-key.
- **Policy:** read-only on that subtree:

  ```sh
  bao policy write sns-consumer-<name> - <<'EOF'
  path "sns/data/consumers/<name>/*" {
    capabilities = ["read"]
  }
  EOF
  ```

  Add a `read` on `sns/metadata/consumers/<name>/*` only if the consumer must list its keys; omit it and the consumer can read known paths but cannot enumerate them.
- **Credentials:** issued the way your servers already issue everything else (approle, kubernetes, tokens, whatever your existing workflows do). The only contract this project makes is the path scope above; credential issuance is yours.

A leaked consumer credential reads only that consumer's subtree, for the life of its lease, and dies by the same revocation machinery every other bao secret uses.

## Publishing values (the manual ceremony)

`sns` is deliberately read-only toward Standard Notes: it never writes to your vault. The publish ritual is therefore human-paced:

1. **Author** the value in a settings note in any Standard Notes surface (terminal, web, phone).
2. **Push** it into the consumer's bao path.
3. **Delete** it from the note — in any SN surface, by hand. `sns` has no write path to SN, so this step stays yours. Until you delete it, the value exists in both places (source of truth for published values is bao from the moment of the push).

Step 2 today, with native bao only. Every manual form has a leak trade-off; pick per situation:

```sh
# Prompt form — no shell history, but the value is visible in terminal scrollback
# until it scrolls off / is cleared:
sns copy prod-web-1 API_KEY            # clipboard; clears itself in 30s
bao kv put sns/consumers/prod-web-1 API_KEY=-
# paste at the prompt, then end input (Ctrl-D)

# File form — no scrollback, but the value transits a temp file:
umask 077
bao kv put sns/consumers/prod-web-1 API_KEY=@/tmp/api-key.txt
rm /tmp/api-key.txt
```

Avoid the argv form (`API_KEY=secret` on the command line): it lands in shell history and `ps` output. When `sns publish` exists it will read from the local encrypted cache and write over TLS — no clipboard, no temp file, no shell — and this section's trade-offs disappear.

**Rotation:** edit the value in SN (if the source still exists there), push as a new version (bao KV v2 keeps history), delete the source. If the source was already deleted, edit in bao and treat bao as authoritative from then on.

## CI (deferred)

The design exists and the client already speaks the protocol (`loginJwt`), but nothing in this repository runs CI today. Deferred shape, for the day it is wanted: GitHub signs a short-lived OIDC token for the workflow; a `jwt` auth role bound to repo/ref/environment issues a credential with a policy reading `sns/ci/session` only (`sns/local/*` denied); that path holds a refresh token, database key, and email for a dedicated SN session used by nothing else; the rotated refresh token is written back after each run, which requires a *writable* off-box store — the reason GitHub secrets cannot substitute. Revisit when a workflow exists.
