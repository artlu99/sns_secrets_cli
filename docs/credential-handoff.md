# Credential handoff: the sink path, end to end

How this repository publishes itself with its own handoff verb. Release
credentials — the Forgejo and GitHub tokens — live in the vault, in a
`forgejo` note holding `FORGEJO_TOKEN` and `GITHUB_TOKEN`. They cross from
the operator to the agent only as `sns sink` files: never pasted into chat,
never typed into a prompt card, never in argv, env vars, git URLs, or shell
history. The agent never asks for the value; the operator moves it — the
same posture as the SSH copy flow, where the human is the one who carries it
across.

## Roles

- **Operator** — holds the vault session, runs `sink`, and sees its metadata
  line — key name, byte count, path, mode — never the value.
- **Agent** — holds no credential of its own; consumes only the sunk files,
  and only through the staged helpers and the staged API header; burns the
  staging directory when done.

## The ceremony

Worked pushing v0.4.0 and v0.5.0 (`main`, the release branch, the release
tag) to both forges. Four steps; the middle two belong to different people.

**1. The agent stages** — a tmpfs directory (`0700`; `$XDG_RUNTIME_DIR`, a
`/dev/shm` subdirectory, or `/tmp` where it is tmpfs — the placement rules in
[SECURITY.md](../SECURITY.md#value-exits-the-clipboard-files-and-where-handoff-files-should-live)
apply unchanged) plus two credential helpers. Token paths are *not*
pre-created: `sink` refuses an existing target, and the refusal is the
handshake. (`mkdir -m` styles only the last component of each operand, so
the staging dir and `bin/` are named separately — a `-p` chain would leave
the parent at its umask default.)

```sh
mkdir -m 700 -p /tmp/sns-v050 /tmp/sns-v050/bin
cat > /tmp/sns-v050/bin/gh-cred <<'EOF'
#!/bin/sh
echo "username=sns-release"            # GitHub ignores the username
echo "password=$(cat /tmp/sns-v050/github_token)"
EOF
cat > /tmp/sns-v050/bin/fj-cred <<'EOF'
#!/bin/sh
echo "username=artlu99"                # Forgejo wants the real one
echo "password=$(cat /tmp/sns-v050/forgejo_token)"
EOF
chmod 700 /tmp/sns-v050/bin/gh-cred /tmp/sns-v050/bin/fj-cred
```

**2. The operator sinks** — their terminal, their session:

```console
$ sns sink forgejo FORGEJO_TOKEN /tmp/sns-v050/forgejo_token
wrote FORGEJO_TOKEN (40 bytes) → /tmp/sns-v050/forgejo_token (0600)
$ sns sink forgejo GITHUB_TOKEN /tmp/sns-v050/github_token
wrote GITHUB_TOKEN (40 bytes) → /tmp/sns-v050/github_token (0600)
```

If the destination is disk-backed, `statfs` makes sink say so — on a box
where `/tmp` is tmpfs the warning is quiet. The warning is the design
working, not noise to route around.

**3. The agent probes, then pushes.** The probe reads permissions, never
values, and takes its header from a file: a shell `$(cat …)` inside
`-H "…"` would expand the token into curl's argv, where a `ps` snapshot
reads it for the life of the call (`curl -H @file` needs curl ≥ 7.55; the
header file lands at the umask's default mode — the `0700` staging
directory is what guards it, and it dies with the staging directory):

```sh
printf 'Authorization: token %s\n' "$(cat /tmp/sns-v050/forgejo_token)" \
  > /tmp/sns-v050/forgejo-api-header
curl -sS -H @/tmp/sns-v050/forgejo-api-header \
  https://git.artlu.xyz/api/v1/repos/artlu99/sns_secrets_cli | jq .permissions.push
```

Branch and tag are the release's own — branch `release-v<ver>` cut at the
release commit, tag `v<ver>`, the shape CONTRIBUTING.md fixes — so the
pushes need no placeholders:

```sh
git -c credential.helper=/tmp/sns-v050/bin/fj-cred \
  push https://git.artlu.xyz/artlu99/sns_secrets_cli.git main release-v0.5.0 v0.5.0
git -c credential.helper=/tmp/sns-v050/bin/gh-cred \
  push https://github.com/artlu99/sns_secrets_cli.git main release-v0.5.0 v0.5.0
```

Auth rides git's credential protocol, not the URL: the token moves from
helper stdout to git over a pipe, so even a failed push's error output
carries no credential. A rejected push is information, not improvisation —
an authentication failure means a stale, wrong-scoped, or truncated token
file: stop, burn, and report back to the operator. A non-fast-forward or
protected-branch refusal is the operator's call; an agent-side `--force` is
never.

**4. The agent verifies and burns.** `git ls-remote` against both HTTPS
endpoints with the same helpers, then `rm -rf /tmp/sns-v050` and confirm it
is gone. The vault is the only durable copy this ceremony leaves behind —
everything else it burned.

## Why this shape

- **One durable copy: the vault.** The staging files are the only copies the
  ceremony creates outside the vault; they live minutes and are
  memory-backed when the staging directory landed on tmpfs — SECURITY.md's
  swap caveat carries the other half of that sentence.
- **Nothing transcript-shaped ever sees the value.** No chat paste, no
  prompt card — chat lands in transcripts you neither control nor can burn;
  the staging dir is burned. Both sides can audit the flow from the
  transcript alone: each sees the same sink line — key name, byte count,
  path, mode — no value either way.
- **Credentials never sit in argv, env, remote URLs, or shell history.** The
  helpers read the files at git's request; the API header rides a file, not
  the command line.
- **The same ceremony covers any agent-needs-a-secret flow** — API calls,
  release attachment, deploy hooks: files, not chat. A card flow was
  considered and rejected: the operator chose to hold the value-exit — the
  responsibility is the feature, not an accident.
