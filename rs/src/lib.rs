//! sns: Standard Notes reader CLI — Rust rewrite.
//!
//! The TypeScript implementation under `../src` is the executable spec: every
//! ported module pins byte-exact parity with golden vectors taken from the
//! corresponding `*.test.ts` file (and, where published, from the Standard
//! Notes specification itself).

pub mod db;
pub mod http;
pub mod kdf;
pub mod proto004;
pub mod session;
pub mod sn_api;
