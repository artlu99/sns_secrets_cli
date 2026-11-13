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

`sqlcipher/` and `bindgen-bindings/` were pruned: unused without the
`bundled-sqlcipher`/`buildtime_bindgen` features, which this project never
enables. Do not enable them here.
