# RECAP — sns: original design, the Rust rewrite, and every fix in between

**Date:** 2026-11-14

**Commits this document describes** — recover context later with `git show
<hash>` (short hashes, main branch):

| hash | what it is |
|---|---|
| `1267771` | v0.2.0 — the TypeScript CLI baseline (original design) |
| `a790632` | Rust rewrite foundation: kdf, 004 items, session crypto, chacha20 cache, api client |
| `85b275b` | Rust hardening: lenient deserialization, redacting Debug, DELETE identity headers |
| `1e0a09c` | Rust review swing 1: nine correctness fixes after the sync engine |
| `9d045f8` | Rust rewrite feature-complete: all eleven commands, compiled-binary e2e |
| `e28ffee` | Rust refactor and clean: browse dispatch fix, helper dedup, doctor flatten, lazy/point-query reads |
| `afe691e` | Rust review swing 2: six fixes from the full code review (incl. the lock wedge) |
| `d315bdc` | Chrome extension v1: popup + dashboard over the CLI's crypto core |
| `0aab8f4` | extension v0.1.1: the offscreen clipboard-clear schedule fixed |
| `a4bb545` | extension v0.1.2: auto-lock |
| `f30a6fd` | extension v0.1.3: UI glow-up; the cycle-safe flattenTagTree (same cycle theme as sns list) |
| `251fccc` `2c46a1c` | extension v0.1.4–v0.1.5: light mode; whole-body copy removed from the web |
| `4c57ecc` | extension v0.1.6: prose panel trims blank lines |
| `203381b` | TypeScript: hold the sync lock with flock (the design replacement) |
| `0c3cc22` | Rust: lock ported to flock(2), matching the TS fix |

*One repository, three surfaces: a TypeScript CLI (`src/`, Bun), a
browser extension (`extension/`, WXT/Chrome MV3), and a Rust CLI (`rs/`). This
document tells how they relate, what broke along the way, and — for every fix —
whether the root cause was a genuine bug, an oversight, or a defensible design
choice.*

---

## 1. The project

`sns` is a Standard Notes reader CLI for secrets: it logs in, syncs an
account, and surfaces **env-style** notes (`KEY=VALUE` lines in note prose)
as a safe terminal workflow — list, search, show a masked inventory, copy
**one value at a time** to a self-clearing clipboard. The one rule every view
enforces: **a value never reaches stdout or a log.** Keys do; values don't.

The arc, in order:

| phase | commit | what |
|---|---|---|
| v0.2.0 | `1267771` | the TypeScript CLI, feature-complete |
| extension | `0aab8f4`…`4c57ecc` | v0.1.1–v0.1.6: dashboard + popup, auto-lock, clipboard clearing, theme |
| Rust rewrite | `a790632`…`9d045f8` | the whole CLI ported to a static ~9 MB binary |
| refactor + reviews | `e28ffee`, `afe691e` | cleanup pass, full code review, six fixes |
| lock convergence | `203381b` (TS), `0c3cc22` (Rust) | both sides land on `flock(2)` |

The Rust rewrite exists for one reason: **distribution**. A Bun-compiled
binary carries a 104 MB runtime floor; the Rust binary is 9.0 MB, static,
and runs anywhere without an interpreter. Everything else about the CLI is
deliberately the same program.

---

## 2. The original design (TypeScript, v0.2.0)

### Deliberate choices — sound then, sound now

- **Crypto bar at dotenvx grade.** Session files are encrypted with ECDH
  (NIST P-256) + HKDF-SHA256 + AES-256-GCM — verified field-by-field against
  dotenvx's own source before the CLI ever shipped a session. Notes decrypt
  via Standard Notes protocol 004 (Argon2id, 64 MiB, XChaCha20-Poly1305).
- **Encrypted cache.** SQLite with the `chacha20` cipher
  (better-sqlite3-multiple-ciphers) — a deliberate exception to the repo's
  Bun rules, because `bun:sqlite` cannot encrypt. Wrong-key detection maps to
  a clean "replace the cache" path, never a crash.
- **The value-proof reading layer.** Snippets are cut only from text where
  every assignment-shaped line was first collapsed to `KEY=[redacted]`; the
  show inventory parses settings, shows keys, withholds values. This is the
  product's core invariant, designed in, not patched in.
- **Clipboard hygiene.** OSC 52 with a tmux wrapper, a detached 30-second
  clearer, and a stale-clear sweep on the next command. (The extension later
  hit its own version of this: offscreen documents don't get extension APIs,
  so the storage-based clear schedule was dead code — fixed in v0.1.1.)
- **Per-key copy on the web.** v0.1.5 removed the extension's
  copy-whole-body button: one click putting every value on the clipboard is
  too dangerous in a browser. The CLI keeps whole-body copy. Deliberate,
  surface-appropriate asymmetry.

### The sync lock — the design that seeds sections 4 and 5

v0.2.0's `sync.lock` was a **content protocol**: `O_EXCL`-create the file,
then best-effort write `pid token` into it. A waiter that lost the create
read the file and decided whether the holder was *stale* — dead pid
(`kill(pid, 0)`), a recycled pid that isn't sns (`/proc/<pid>/cmdline`),
the waiter's own leaked lock, or anything older than 30 minutes — and took
the lock over by unlinking it.

**Classification: a defensible design choice, with two flaws hiding inside.**
The intent was legitimate — a zero-dependency CLI wanting crash recovery and
a way to reclaim a hung sync. But:

1. *(Design flaw)* The token write happens **after** the create and swallows
   failure (`let _ = write(...)`). A crash or full disk between the two
   steps produces a **0-byte lock file** — producible by design, not by
   corruption.
2. *(Oversight)* The stale branch judged an empty file stale, then refused
   to unlink empty content (`if (judged !== "" ...)`) — the two halves of
   the same mechanism disagree about what empty means. So the producible
   file is never removed.
3. *(Bug)* That stale branch `continue`s **before** reaching the wait/timeout
   path. Combined: any command that needs the lock spins at 100% CPU,
   forever, with the "another sns sync is still running" error unreachable.
4. *(Bug)* The takeover guard reads the file twice and compares it to
   itself — `judged = read(); if (judged !== "" && read() === judged)` — so
   the comment's promise ("never unlink a fresh lock a racing waiter just
   created") is not delivered by the code. A racing waiter's fresh lock can
   be unlinked.

These four lived quietly in v0.2.0. The Rust port, whose discipline was
behavior parity, inherited all of them faithfully — which is exactly why the
port found them: the same code, asked to survive tests and review, had to be
understood line by line first.

---

## 3. The Rust rewrite

### Method — parity, proven with external oracles

Every crypto layer was pinned byte-for-byte against something that was not
the port itself: the published SN 004 test vector, libsodium payloads
generated by Bun scripts, a `node:crypto` known-answer test for the session
composition, and a **cache written by the TypeScript implementation** that
the Rust binary opens (and vice versa). The TS source stayed the executable
spec throughout: when Rust and TS disagreed, either the test failed or the
review had something to point at. That discipline is what turns "it feels
fine" into findings with receipts.

The port also swallowed real build constraints without changing behavior:
`jiff` instead of `chrono` (chrono's timezone probe links CoreFoundation,
which zig's macOS cross-headers can't provide) and reqwest pinned to 0.12
with bundled webpki roots (0.13 hard-depends on the macOS platform
verifier). All four targets cross-compile through cargo-zigbuild: 9.0 MB
musl static, ~10 MB macOS ×2, 13.7 MB Windows.

### What the port got wrong on its own

Parity discipline cuts both ways — the port introduced its own bugs, each
caught by a test or a review against the TS spec:

| bug | where it came from | classification |
|---|---|---|
| **Browse's action menu never dispatched** — the TS `select` separates `value` from `label`; the port merged them into one string and matched lowercase values against capitalized options. All four arms were dead; **every pick, including Quit and Back, fell through to Copy.** | port (mechanism flattened) | **Bug, port-introduced** — live user-visible |
| Tag-forest tie-break compared uuids where TS compares **titles** through `titleOf` | port (misread the comparator) | **Bug, port-introduced** |
| Schema applied **after** migrations, so a fresh cache had no `sync_state` table to ALTER | port (reordered a load-bearing sequence) | **Bug, port-introduced** |
| Snippet window indexed by **byte offset treated as char index** — multi-byte text pushed the window off the end (TS's UTF-16 index has its own latent drift, but doesn't collapse this way) | port (unit error) | **Bug, port-introduced** |
| Sync-page items went through a **strict deserialization gate** the TS never had (TS keeps raw items; the engine decides). Lenient helpers covered some fields; three could still error — and the drop point silently discarded failures | port (invented strictness, then hardened it only partially) | **Oversight** — regression against TS tolerance, half-fixed once already |
| Session files written then chmod'd (TS opens with `mode: 0o600` **at creation**) | port (std convenience over the TS's explicit mode) | **Oversight** — a readable window the TS never had |

### The hardening timeline

**Swing 0 — `85b275b`, hardening the API layer while porting it.** Lenient
bool deserialization (the server sends `0/1`, `"0"`, real booleans),
`SessionSecrets`' Debug redacting tokens and the db key, logout's DELETE
carrying the same identity headers as POST, tolerant field lookup across
key spellings. Most of this is *beyond* the TS, which tolerates by being
loose everywhere — the Rust typed layer has to choose its lenience
explicitly, and got it partly wrong the first time.

**Swing 1 — `1e0a09c`, nine fixes from the first code review.** The notable
ones, with classification: silent sync-page item drops at the parse seam
(**bug**, the same family as the snippet-table row above — fixed once here,
completed in swing 2); a deferred note letting the sync token advance past
undecryptable data (**bug**, port-introduced; the TS lets the failure
propagate for exactly this reason); a panic path on malformed stored session
keys (**bug**; typed error now); an Argon2 `"inf"` iterations value wedging
the KDF (**oversight** in parameter validation); `??` null-fallthrough gaps
in API field parsing (**bug** — TS's `??` has no Rust equivalent and the
port translated some by hand).

**Feature complete — `9d045f8`.** All eleven commands, the compiled-binary
e2e test, 110 tests, four targets.

**Refactor and clean — `e28ffee`.** A four-angle quality review (reuse,
simplification, efficiency, altitude) applied behavior-preservingly: the
browse dispatch bug above surfaced *here* and was fixed toward the TS spec;
triplicated helpers folded; doctor flattened into per-check functions with
one session load instead of three; list/search stream lazily and parse each
note's content once; show/copy hit the primary key instead of scanning the
table; the two `#[allow]` silencers the crate's own rules forbade were
removed.

**Swing 2 — `afe691e`, six fixes from the full code review.** The lock wedge
and the self-comparing guard (both **inherited TS bugs** — see §2), the
completed lenient-item parsing (**oversight**, closed), 0600-at-creation
(**port oversight**, closed), the char-indexed snippet window (**port bug**,
closed), and search writing through the EPIPE-safe path instead of panicking
on a broken pipe (**inconsistency** — the safe writer existed for the other
commands; search predated it). Every fix carries a regression test; the
session-file mode is now pinned in the compiled-binary e2e.

### What was never a bug (checked and deliberately kept)

- `locale_cmp` approximates JS `localeCompare` (case-folded, then code
  points) — documented approximation, exact ICU collation not worth a
  dependency for tag titles.
- Browse uses numbered prompts, not a TUI — matches the "intermediately
  beautiful" UX bar the project set.
- doctor's scrub probe spawns `sh` (not `bun -e`) — the probe tests the
  environment, not the runtime.
- `.env` holds only non-secret config (`SN_EMAIL`, `SN_API_URL`) and stays
  plaintext by design; every secret-bearing file is encrypted or 0600.

---

## 4. The TypeScript rewrite of the lock (`203381b`)

After the six Rust fixes repaired the content-protocol lock *within* its
design, the TypeScript side fixed the same wedge **by replacing the design**:
`sync.lock` became a dumb sentinel and mutual exclusion moved to
`flock(2)` — the kernel holds the lock and drops it when the holder's
process exits.

- A crash cannot stick: there is nothing to take over, so the pid/token
  protocol, the stale machinery, and the token registry are deleted.
- The 0-byte file is not merely tolerated — the file's bytes are declared
  "not part of the protocol" and never read.
- The release path can no longer delete a successor's lock, because the
  kernel arbitrates: the whole race class vanishes structurally.
- The cost is Bun FFI: ~80 lines of `dlopen`/errno plumbing because
  TypeScript has no std `flock`. And one behavior trade: a **hung-but-alive**
  holder is never reclaimed — every waiter fails until a human kills it
  (the old design's 30-minute takeover is gone by design: "a live holder is
  never taken over").

**Classification: the deeper fix.** It targets the mechanism rather than its
defects — which is why it needs no equivalent of our repair tests: the
machinery those bugs lived in no longer exists.

---

## 5. Convergence — the Rust side adopts flock (`0c3cc22`)

The Rust lock was ported to the same design: open the sentinel at 0600,
`flock(LOCK_EX|LOCK_NB)` with the same 200 ms / timeout poll, `LOCK_UN` on
release. Where the TS needed 80 lines of FFI, Rust needed one `unsafe` call
— `libc` was already a dependency. The module came out 47 lines lighter than
the repaired version, with the takeover subsystem deleted outright.

The two tests now pin semantics instead of repairs: a holder **excludes** a
contender (two descriptors of one process contend exactly as two processes
would) and release permits re-acquire; a leftover sentinel — empty or full
of dead-pid content from the old scheme — cannot block acquisition.

The honest divergence kept from the Rust side: non-flock platforms fall back
to an exclusive-create sentinel whose timeout error names the manual fix —
functional, degraded, and stated in the error rather than silent.

**Interop note:** content-protocol (TS v0.2.0) and flock builds do not
mutually exclude each other — a v0.2.0 binary will judge a flock holder's
empty sentinel stale and take it over. TS v0.2.0 ↔ Rust v0.2.0-era were
compatible with each other; flock ↔ flock (current TS ↔ current Rust) are
compatible. A v0.2.0 TS binary alongside either current build is the one
unsupported mixing.

---

## 6. Where things stand

- **Rust CLI:** all eleven commands, 115 tests (92 unit + 22 notes + 1
  compiled-binary e2e, plus the TS-written cache fixture test), clippy
  silent, four targets: 9.0 MB musl static, ~10 MB macOS ×2, 13.7 MB Windows.
- **TypeScript CLI:** v0.2.0 plus the flock lock fix.
- **Extension:** v0.1.6.

### Known gaps — open, documented, not bugs

- **Live API untested.** Login/sync have only ever run against canned
  transports and a real-socket mock. The first real `sns login` is the
  moment of truth.
- The `Zeroizing<String>` wrap for the db key is a flagged follow-up
  (mechanical, serde-less ripple through every construction site).
- Release binaries are unsigned; the Rust CLI is not yet in the README's
  install docs; the release tooling built for v0.2.0 was reverted and would
  need re-creation for Rust artifacts.
- `locale_cmp` and the non-flock lock fallback are approximations by
  declaration (§3).

### The one-paragraph moral

The original design was good where its invariants were *designed in*
(value-proof views, crypto bar) and fragile where it relied on best-effort
bookkeeping (the lock's create-then-write, the parse seams). The port
inherited the fragile parts faithfully — which made them visible — and
introduced its own share of bugs, mostly where a TS mechanism was flattened
to fit Rust's types. Two review swings fixed defects inside designs; the
refactor pass and the flock rewrite then showed the better move: when every
bug lives in one subsystem, the fix is deleting the subsystem, not the
bug list.
