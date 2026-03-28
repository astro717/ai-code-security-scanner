/**
 * Rust language support for the AI Code Security Scanner.
 *
 * This module implements a regex-based scan pass for Rust source files.
 * It targets memory-safety and security patterns that Rust's compiler cannot
 * catch because they are semantically valid but logically unsafe.
 *
 * Covered vulnerability classes:
 *   - BUFFER_OVERFLOW (unsafe pointer arithmetic, raw pointer dereferences)
 *   - COMMAND_INJECTION (std::process::Command with user-controlled args)
 *   - WEAK_CRYPTO (use of deprecated md5 / sha1 crates)
 *   - INSECURE_RANDOM (rand::random / thread_rng used in security context)
 *   - PATH_TRAVERSAL (std::fs with unvalidated user input paths)
 *   - SECRET_HARDCODED (hardcoded API keys / passwords in string literals)
 *   - UNSAFE_DESERIALIZATION (serde_json::from_str on raw user input)
 *   - FORMAT_STRING (format!/println! with non-literal format strings)
 *   - INSECURE_ASSERT (debug_assert! used for security invariants)
 */

import * as fs from 'fs';
import type { Finding } from './reporter';

export interface RustParseResult {
  language: 'rust';
  code: string;
  lines: string[];
  filePath: string;
}

export function parseRustFile(filePath: string): RustParseResult {
  const code = fs.readFileSync(filePath, 'utf-8');
  return parseRustCode(code, filePath);
}

export function parseRustCode(code: string, filePath = 'input.rs'): RustParseResult {
  return { language: 'rust', code, lines: code.split('\n'), filePath };
}

// ── Pattern-based detectors ───────────────────────────────────────────────────

interface RustPattern {
  type: string;
  severity: Finding['severity'];
  pattern: RegExp;
  message: string;
  confidence?: number;
}

const RUST_PATTERNS: RustPattern[] = [
  // unsafe blocks with raw pointer dereferences (single-line form: unsafe { let x = *ptr; })
  {
    type: 'BUFFER_OVERFLOW',
    severity: 'high',
    pattern: /unsafe\s*\{[^}]*\*\s*(?:mut\s+)?\w+/,
    message:
      'Raw pointer dereference inside unsafe block. Ensure pointer arithmetic ' +
      'and bounds are validated to prevent out-of-bounds memory access.',
    confidence: 0.85,
  },
  // Raw pointer dereference as a statement (catches multi-line unsafe blocks)
  {
    type: 'BUFFER_OVERFLOW',
    severity: 'high',
    pattern: /(?:let\s+\w+\s*=\s*\*\s*\w+|=\s*\*\s*(?:mut\s+)?\w+\b)/,
    message:
      'Raw pointer dereference detected. Inside an unsafe block this can cause ' +
      'out-of-bounds memory access if the pointer is not properly validated.',
    confidence: 0.80,
  },
  // ptr::copy / ptr::write — unsafe buffer operations
  {
    type: 'BUFFER_OVERFLOW',
    severity: 'high',
    pattern: /std::ptr::(?:copy|write|read)\s*(?:_nonoverlapping)?\s*\(/,
    message:
      'std::ptr::copy/write/read used — verify source/destination sizes are ' +
      'correct to prevent buffer overflow or undefined behaviour.',
    confidence: 0.90,
  },
  // std::mem::transmute — type punning, common UB vector
  {
    type: 'BUFFER_OVERFLOW',
    severity: 'high',
    pattern: /(?:std::mem::transmute|mem::transmute)\s*(?:<[^>]*>)?\s*\(/,
    message:
      'mem::transmute used — this bypasses Rust\'s type system entirely. ' +
      'Ensure source and destination types have identical memory layouts.',
    confidence: 0.95,
  },
  // mem::forget — can cause resource leaks or safety invariant violations
  {
    type: 'BUFFER_OVERFLOW',
    severity: 'medium',
    pattern: /(?:std::mem::forget|mem::forget)\s*\(/,
    message:
      'mem::forget called — this leaks the value without running its destructor. ' +
      'Ensure no safety invariants depend on the destructor running.',
    confidence: 0.80,
  },
  // std::process::Command with user-controlled arguments
  {
    type: 'COMMAND_INJECTION',
    severity: 'critical',
    pattern: /Command::new\s*\(\s*(?!\"[a-zA-Z_\-\/\.]+\")(?:\w+|format!)/,
    message:
      'std::process::Command::new() called with a non-literal value. If the value ' +
      'originates from user input, this enables arbitrary command injection.',
    confidence: 0.90,
  },
  {
    type: 'COMMAND_INJECTION',
    severity: 'high',
    pattern: /\.arg\s*\(\s*(?:&?)?(?:user_|input|request|param|query|body|args\[)/,
    message:
      'Command argument may be user-controlled. Validate and sanitise all ' +
      'arguments passed to external process commands.',
    confidence: 0.85,
  },
  // Weak cryptography — md5/sha1 crates
  {
    type: 'WEAK_CRYPTO',
    severity: 'medium',
    pattern: /(?:use\s+)?(?:md5|sha1)::(?:Md5|Sha1|compute|digest)/,
    message:
      'MD5 or SHA-1 used for hashing. These algorithms are cryptographically broken; ' +
      'use SHA-256 or SHA-3 via the sha2 or sha3 crates instead.',
    confidence: 0.95,
  },
  // Weak random — rand::random or thread_rng in security context
  {
    type: 'INSECURE_RANDOM',
    severity: 'medium',
    pattern: /(?:rand::random|thread_rng\(\)|SmallRng|StdRng::seed_from_u64\s*\(\s*\d)/,
    message:
      'rand::random / thread_rng used in a context that may require cryptographic ' +
      'randomness. Use rand::rngs::OsRng or the getrandom crate for secrets, tokens, or IVs.',
    confidence: 0.75,
  },
  // Path traversal — fs operations with variable paths
  {
    type: 'PATH_TRAVERSAL',
    severity: 'high',
    pattern: /fs::(?:read|write|remove_file|read_to_string|File::open|File::create)\s*\(\s*(?!Path::new\s*\(")/,
    message:
      'std::fs call with a potentially unvalidated path. If the path includes ' +
      'user-controlled segments, canonicalize and prefix-check against an allowed base.',
    confidence: 0.80,
  },
  // Hardcoded API keys / passwords
  {
    type: 'SECRET_HARDCODED',
    severity: 'high',
    pattern: /(?:api_key|api_secret|password|secret|token|private_key)\s*(?::[^=\n]{0,30})?=\s*"[A-Za-z0-9+\/=_\-!@#$%^&*]{10,}"/,
    message:
      'Possible hardcoded secret in string literal. Move secrets to environment ' +
      'variables or a secrets manager (e.g. std::env::var, HashiCorp Vault).',
    confidence: 0.90,
  },
  // Unsafe deserialization via serde_json on raw user input
  {
    type: 'UNSAFE_DESERIALIZATION',
    severity: 'high',
    pattern: /serde_json::from_(?:str|slice|reader)\s*\(\s*(?:&?)?(?:body|input|user|request|payload|raw|data)/,
    message:
      'serde_json::from_str/from_slice called on a potentially user-controlled value. ' +
      'Validate the JSON schema or enforce size/depth limits before deserializing.',
    confidence: 0.85,
  },
  // Non-literal format string — Rust macros with variable format strings
  {
    type: 'FORMAT_STRING',
    severity: 'medium',
    pattern: /(?:format|println|eprintln|write|writeln)!\s*\(\s*(?!["'])[a-zA-Z_]\w*\s*[,)]/,
    message:
      'Non-literal format string passed to a format macro. If the format string is ' +
      'user-controlled this is a format-string vulnerability risk. Use a literal format string.',
    confidence: 0.80,
  },
  // debug_assert used as security check
  {
    type: 'INSECURE_ASSERT',
    severity: 'medium',
    pattern: /debug_assert!\s*\(\s*(?:is_auth|has_permission|is_admin|is_valid|is_authorized)/,
    message:
      'debug_assert! used for a security-relevant check. debug_assert! is compiled ' +
      'out in release builds — use assert! or an explicit runtime check instead.',
    confidence: 0.90,
  },
];

/**
 * Scan a parsed Rust file and return a list of security findings.
 */
export function scanRust(parsed: RustParseResult): Finding[] {
  const findings: Finding[] = [];

  for (let i = 0; i < parsed.lines.length; i++) {
    const line = parsed.lines[i]!;
    // Skip comment lines
    if (/^\s*\/\//.test(line)) continue;

    for (const p of RUST_PATTERNS) {
      if (p.pattern.test(line)) {
        const column = line.search(p.pattern);
        const finding: Finding = {
          type: p.type,
          severity: p.severity,
          line: i + 1,
          column: column < 0 ? 0 : column,
          snippet: line.trim().slice(0, 120),
          message: p.message,
          file: parsed.filePath,
          ...(p.confidence !== undefined ? { confidence: p.confidence } : {}),
        };
        findings.push(finding);
      }
    }
  }

  return findings;
}
