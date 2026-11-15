//! sns: Standard Notes reader CLI — portable Rust port.
//!
//! The TypeScript implementation under `../src` is the tip of the spear and
//! the executable spec. This crate stays mostly caught up for distribution
//! (small static binary). Every ported module pins byte-exact parity with
//! golden vectors taken from the corresponding `*.test.ts` file (and, where
//! published, from the Standard Notes specification itself). Do not ship
//! Rust-only product behavior — land it in TypeScript first.

#[cfg(not(unix))]
compile_error!("sns supports Linux and macOS only; Windows support is deferred");

pub mod clipboard;
pub mod commands;
pub mod db;
pub mod env;
pub mod errors;
pub mod http;
pub mod keychain;
pub mod kdf;
pub mod lock;
pub mod note_env;
pub mod notes;
pub mod pager;
pub mod paths;
pub mod prompt;
pub mod proto004;
pub mod session;
pub mod session_file;
pub mod sn_api;
pub mod sync_engine;
pub mod time;
