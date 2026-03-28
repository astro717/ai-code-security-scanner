// clean.rs — Rust fixture with safe implementations.
// Used by rust-fixtures.vitest.ts to verify the Rust scanner does NOT fire false positives.

use std::collections::HashMap;
use std::env;

fn main() {
    // Safe: no unsafe blocks or pointer dereferences
    let mut scores: HashMap<&str, i32> = HashMap::new();
    scores.insert("Alice", 100);
    scores.insert("Bob", 95);

    // Safe: secrets loaded from environment variables
    let api_key = env::var("API_KEY").unwrap_or_default();
    let password = env::var("DB_PASSWORD").unwrap_or_default();

    // Safe: cryptographically secure random via ring or rand::rngs::OsRng
    // (no rand::random() for secrets)
    let session_id = format!("{}-{}", api_key.len(), password.len());

    // Safe: SHA-256 for hashing
    // use sha2::{Sha256, Digest};
    // let mut hasher = Sha256::new();
    // hasher.update(b"hello");
    // let result = hasher.finalize();

    // Safe: running a static command string (not user-controlled)
    // std::process::Command::new("ls").arg("-la").output().unwrap();

    // Safe: parse structured data
    let data: serde_json::Value = serde_json::json!({"key": "value"});

    println!("{} {:?}", session_id, data);
}
