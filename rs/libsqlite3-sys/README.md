# Vendored libsqlite3-sys (patched)

libsqlite3-sys 0.40.0, vendored and patched so the cache keeps its chacha20
at-rest encryption:

1. `sqlite3/sqlite3.c` and `sqlite3/sqlite3.h` are replaced with the **SQLite3
   Multiple Ciphers 2.6.1 amalgamation** (SQLite 3.54.0, taken from
   `sqlite3mc-src` 206.1.0 on crates.io) — the upstream of
   `better-sqlite3-multiple-ciphers`, which the TypeScript implementation
   uses. Same pragmas, same chacha20 defaults, same cache files (verified
   bidirectionally in `src/db.rs` tests).
2. Local patch: the entropy block's `#include <sys/syscall.h>` is guarded to
   `__linux__` only — the call site already is, but the unconditional include
   breaks builds against zig's minimal macOS headers (a real macOS SDK has
   the header). Proposed upstream.

The amalgamation is hand-copied, so crates.io checksums never covered it —
the integrity reference is local instead:

- `sqlite3/sqlite3.sha256` pins the SHA-256 of the **patched** `sqlite3.c`
  and `sqlite3.h` this directory builds (the pristine upstream bytes differ
  by the syscall.h patch above, so no upstream hash matches this tree).
- Verify drift before an upgrade or after touching anything here:
  `sha256sum -c sqlite3/sqlite3.sha256` from `rs/libsqlite3-sys/sqlite3/`.
- On an intentional upgrade: replace the amalgamation, re-apply the
  syscall.h patch, re-run the cross-format tests (`cargo test`, then the
  bun-side open of a Rust-written cache per `src/db.rs`'s test comment), and
  regenerate the `.sha256` file. A hash mismatch on an *unintentional* build
  means the file drifted — stop and diff before compiling it into every
  cache the Rust binary writes.

`sqlcipher/` and `bindgen-bindings/` were pruned: unused without the
`bundled-sqlcipher`/`buildtime_bindgen` features, which this project never
enables. Do not enable them here.
