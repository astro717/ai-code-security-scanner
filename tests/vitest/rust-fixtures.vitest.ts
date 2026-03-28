/**
 * Fixture-based unit tests for the Rust language scanner.
 *
 * Each test provides a code snippet (inline fixture) and asserts that
 * the scanner either fires the expected finding type or stays silent.
 */

import { describe, it, expect } from 'vitest';
import { parseRustCode, scanRust } from '../../src/scanner/rust-parser';

// Helper: scan inline snippet, return array of finding types
function scan(code: string): string[] {
  return scanRust(parseRustCode(code, 'test.rs')).map((f) => f.type);
}

// Helper: scan inline snippet, return all findings (for metadata checks)
function scanFull(code: string) {
  return scanRust(parseRustCode(code, 'test.rs'));
}

// ── BUFFER_OVERFLOW ────────────────────────────────────────────────────────────

describe('BUFFER_OVERFLOW', () => {
  it('fires on unsafe block with raw pointer dereference', () => {
    const code = `
unsafe {
  let x = *ptr;
}`;
    expect(scan(code)).toContain('BUFFER_OVERFLOW');
  });

  it('fires on mem::transmute', () => {
    const code = `let y: u64 = std::mem::transmute(x);`;
    expect(scan(code)).toContain('BUFFER_OVERFLOW');
  });

  it('fires on std::ptr::copy_nonoverlapping', () => {
    const code = `std::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), len);`;
    expect(scan(code)).toContain('BUFFER_OVERFLOW');
  });

  it('fires on mem::forget', () => {
    const code = `mem::forget(value);`;
    expect(scan(code)).toContain('BUFFER_OVERFLOW');
  });

  it('does NOT fire on safe Rust code', () => {
    const code = `let v: Vec<u8> = vec![0; 16];`;
    expect(scan(code)).not.toContain('BUFFER_OVERFLOW');
  });
});

// ── COMMAND_INJECTION ─────────────────────────────────────────────────────────

describe('COMMAND_INJECTION', () => {
  it('fires when Command::new receives a variable', () => {
    const code = `let output = Command::new(user_cmd).output().unwrap();`;
    expect(scan(code)).toContain('COMMAND_INJECTION');
  });

  it('fires when .arg() receives user input variable', () => {
    const code = `cmd.arg(user_input);`;
    expect(scan(code)).toContain('COMMAND_INJECTION');
  });

  it('does NOT fire on Command::new with literal string', () => {
    const code = `let output = Command::new("ls").arg("-la").output().unwrap();`;
    expect(scan(code)).not.toContain('COMMAND_INJECTION');
  });
});

// ── WEAK_CRYPTO ───────────────────────────────────────────────────────────────

describe('WEAK_CRYPTO', () => {
  it('fires on md5::compute', () => {
    const code = `let digest = md5::compute(b"hello");`;
    expect(scan(code)).toContain('WEAK_CRYPTO');
  });

  it('fires on sha1::Sha1', () => {
    const code = `use sha1::Sha1;`;
    expect(scan(code)).toContain('WEAK_CRYPTO');
  });

  it('does NOT fire on sha2::Sha256', () => {
    const code = `use sha2::{Sha256, Digest};`;
    expect(scan(code)).not.toContain('WEAK_CRYPTO');
  });
});

// ── INSECURE_RANDOM ───────────────────────────────────────────────────────────

describe('INSECURE_RANDOM', () => {
  it('fires on rand::random', () => {
    const code = `let token: u64 = rand::random();`;
    expect(scan(code)).toContain('INSECURE_RANDOM');
  });

  it('fires on thread_rng()', () => {
    const code = `let mut rng = thread_rng();`;
    expect(scan(code)).toContain('INSECURE_RANDOM');
  });
});

// ── PATH_TRAVERSAL ────────────────────────────────────────────────────────────

describe('PATH_TRAVERSAL', () => {
  it('fires on fs::read_to_string with variable', () => {
    const code = `let content = fs::read_to_string(user_path)?;`;
    expect(scan(code)).toContain('PATH_TRAVERSAL');
  });

  it('fires on fs::File::open with variable', () => {
    const code = `let f = fs::File::open(input_path)?;`;
    expect(scan(code)).toContain('PATH_TRAVERSAL');
  });
});

// ── SECRET_HARDCODED ──────────────────────────────────────────────────────────

describe('SECRET_HARDCODED', () => {
  it('fires on hardcoded api_key', () => {
    const code = `let api_key = "sk_live_abcdef1234567890abcdef1234";`;
    expect(scan(code)).toContain('SECRET_HARDCODED');
  });

  it('fires on hardcoded password', () => {
    const code = `let password: &str = "mysecretpassword123";`;
    expect(scan(code)).toContain('SECRET_HARDCODED');
  });
});

// ── UNSAFE_DESERIALIZATION ────────────────────────────────────────────────────

describe('UNSAFE_DESERIALIZATION', () => {
  it('fires on serde_json::from_str with body variable', () => {
    const code = `let data: Value = serde_json::from_str(body)?;`;
    expect(scan(code)).toContain('UNSAFE_DESERIALIZATION');
  });

  it('fires on serde_json::from_slice with request variable', () => {
    const code = `let v: Config = serde_json::from_slice(request.body())?;`;
    expect(scan(code)).toContain('UNSAFE_DESERIALIZATION');
  });
});

// ── FORMAT_STRING ─────────────────────────────────────────────────────────────

describe('FORMAT_STRING', () => {
  it('fires on format! with variable format string', () => {
    const code = `let s = format!(user_format, name);`;
    expect(scan(code)).toContain('FORMAT_STRING');
  });

  it('does NOT fire on format! with literal string', () => {
    const code = `let s = format!("Hello, {}!", name);`;
    expect(scan(code)).not.toContain('FORMAT_STRING');
  });
});

// ── INSECURE_ASSERT ───────────────────────────────────────────────────────────

describe('INSECURE_ASSERT', () => {
  it('fires on debug_assert! with is_authorized check', () => {
    const code = `debug_assert!(is_authorized(user));`;
    expect(scan(code)).toContain('INSECURE_ASSERT');
  });

  it('does NOT fire on assert! with is_authorized check', () => {
    const code = `assert!(is_authorized(user));`;
    expect(scan(code)).not.toContain('INSECURE_ASSERT');
  });
});

// ── Metadata accuracy ─────────────────────────────────────────────────────────

describe('Finding metadata', () => {
  it('sets file path correctly', () => {
    const result = scanRust(parseRustCode('mem::forget(v);', '/project/src/main.rs'));
    expect(result[0]?.file).toBe('/project/src/main.rs');
  });

  it('sets line number correctly', () => {
    const code = `\n\nlet y = std::mem::transmute(x);`;
    const findings = scanFull(code);
    const f = findings.find((f) => f.type === 'BUFFER_OVERFLOW');
    expect(f?.line).toBe(3);
  });

  it('sets snippet to trimmed line content', () => {
    const code = `  let digest = md5::compute(b"hello");`;
    const findings = scanFull(code);
    const f = findings.find((f) => f.type === 'WEAK_CRYPTO');
    expect(f?.snippet).toMatch(/md5::compute/);
  });

  it('does NOT scan comment lines', () => {
    const code = `// let y: u64 = std::mem::transmute(x);`;
    expect(scan(code)).not.toContain('BUFFER_OVERFLOW');
  });

  it('confidence is a number between 0 and 1 when set', () => {
    const findings = scanFull('let y: u64 = std::mem::transmute(x);');
    const f = findings.find((f) => f.type === 'BUFFER_OVERFLOW');
    if (f && 'confidence' in f && f.confidence !== undefined) {
      expect(f.confidence).toBeGreaterThan(0);
      expect(f.confidence).toBeLessThanOrEqual(1);
    }
  });
});
