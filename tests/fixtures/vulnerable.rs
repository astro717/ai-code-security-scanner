// vulnerable.rs — Rust fixture with intentional security vulnerabilities.
// Used by rust-fixtures.vitest.ts to verify the Rust scanner detects all covered types.

use std::process::Command;
use std::fs;

fn main() {
    // BUFFER_OVERFLOW: raw pointer dereference inside unsafe block (multi-line)
    let value: i32 = 42;
    let ptr: *const i32 = &value;
    unsafe {
        let x = *ptr;
        println!("{}", x);
    }

    // BUFFER_OVERFLOW: mem::transmute usage
    let y: u64 = std::mem::transmute(value);
    println!("{}", y);

    // BUFFER_OVERFLOW: mem::forget
    let s = String::from("hello");
    std::mem::forget(s);

    // SECRET_HARDCODED: hardcoded API key
    let api_key = "sk_live_FAKE_TEST_FIXTURE_NOT_REAL";

    // SECRET_HARDCODED: hardcoded token assignment
    let token = "secret_token_abc123456789xyz";

    // INSECURE_RANDOM: rand::random() for non-crypto use
    let session_id: u64 = rand::random();

    // WEAK_CRYPTO: MD5 usage via md5 crate
    use md5::compute;
    let _digest = md5::compute(b"hello world this is a test");

    // COMMAND_INJECTION: user-controlled variable passed to Command::new
    let user_cmd = "ls";
    let _output = Command::new(user_cmd).output().unwrap();

    // PATH_TRAVERSAL: fs::read_to_string with user-supplied path variable
    let user_path = "/etc/passwd";
    let _contents = fs::read_to_string(user_path).unwrap_or_default();

    // UNSAFE_DESERIALIZATION: serde_json on raw user input
    let body = r#"{"key":"value"}"#;
    let _data: serde_json::Value = serde_json::from_str(body).unwrap();

    println!("{} {} {}", api_key, token, session_id);
}
