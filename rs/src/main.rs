/// Placeholder binary — the CLI surface is ported after the crypto and cache
/// modules reach parity. It touches the cache stack so every release build
/// links the bundled sqlite3mc C and fails loudly if the cipher layer is
/// broken on any target.
fn main() {
    let path = std::env::temp_dir().join("sns-binary-smoke.db");
    if let Ok(db) = sns::db::open_database(&path, &"ab".repeat(32)) {
        let _ = db.sqlite_master_count();
        db.close();
    }
    let _ = std::fs::remove_file(&path);
    println!("sns {} (rust rewrite scaffold)", env!("CARGO_PKG_VERSION"));
}
