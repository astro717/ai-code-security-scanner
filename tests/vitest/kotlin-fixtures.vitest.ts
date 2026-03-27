/**
 * Unit tests for kotlin-parser.ts — exercises all detector patterns using
 * inline code strings so no fixture files are required.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import { parseKotlinCode, scanKotlin } from '../../src/scanner/kotlin-parser';

// ── Helper ────────────────────────────────────────────────────────────────────

function scan(code: string, filePath = 'input.kt') {
  return scanKotlin(parseKotlinCode(code, filePath));
}

// ── SECRET_HARDCODED ──────────────────────────────────────────────────────────

describe('kotlin-parser — SECRET_HARDCODED', () => {
  test('detects hardcoded API key assigned to val', () => {
    const code = `val apiKey = "sk-abc123secrettoken"`;
    const findings = scan(code);
    const hits = findings.filter((f) => f.type === 'SECRET_HARDCODED');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].severity).toBe('high');
    expect(hits[0].line).toBe(1);
  });

  test('detects hardcoded password in const val', () => {
    const code = `const val password = "hunter2secret"`;
    const findings = scan(code);
    const hits = findings.filter((f) => f.type === 'SECRET_HARDCODED');
    expect(hits.length).toBeGreaterThan(0);
  });

  test('detects hardcoded token variable', () => {
    const code = `var secretToken = "eyJhbGciOiJIUzI1NiJ9.payload"`;
    const findings = scan(code);
    expect(findings.some((f) => f.type === 'SECRET_HARDCODED')).toBe(true);
  });

  test('does not flag short literals unlikely to be secrets', () => {
    // 3-char string is below the 4-char minimum in the pattern
    const code = `val label = "ok"`;
    const findings = scan(code);
    expect(findings.filter((f) => f.type === 'SECRET_HARDCODED')).toHaveLength(0);
  });
});

// ── INSECURE_RANDOM ───────────────────────────────────────────────────────────

describe('kotlin-parser — INSECURE_RANDOM', () => {
  test('detects java.util.Random() constructor call', () => {
    const code = `val rng = java.util.Random()`;
    const findings = scan(code);
    const hits = findings.filter((f) => f.type === 'INSECURE_RANDOM');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].severity).toBe('medium');
  });

  test('detects bare Random() constructor call', () => {
    const code = `val r = Random()`;
    const findings = scan(code);
    expect(findings.some((f) => f.type === 'INSECURE_RANDOM')).toBe(true);
  });

  test('does not flag SecureRandom', () => {
    const code = `val sr = java.security.SecureRandom()`;
    const findings = scan(code);
    expect(findings.filter((f) => f.type === 'INSECURE_RANDOM')).toHaveLength(0);
  });
});

// ── WEAK_CRYPTO ───────────────────────────────────────────────────────────────

describe('kotlin-parser — WEAK_CRYPTO', () => {
  test('detects MessageDigest.getInstance("MD5")', () => {
    const code = `val md = MessageDigest.getInstance("MD5")`;
    const findings = scan(code);
    const hits = findings.filter((f) => f.type === 'WEAK_CRYPTO');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].severity).toBe('high');
  });

  test('detects MessageDigest.getInstance("SHA-1")', () => {
    const code = `val md = MessageDigest.getInstance("SHA-1")`;
    const findings = scan(code);
    expect(findings.some((f) => f.type === 'WEAK_CRYPTO')).toBe(true);
  });

  test('does not flag MessageDigest.getInstance("SHA-256")', () => {
    const code = `val md = MessageDigest.getInstance("SHA-256")`;
    const findings = scan(code);
    expect(findings.filter((f) => f.type === 'WEAK_CRYPTO')).toHaveLength(0);
  });
});

// ── INSECURE_SHARED_PREFS ─────────────────────────────────────────────────────

describe('kotlin-parser — INSECURE_SHARED_PREFS', () => {
  test('detects putString storing a password key', () => {
    const code = `prefs.edit().putString("password", userPass).apply()`;
    const findings = scan(code);
    const hits = findings.filter((f) => f.type === 'INSECURE_SHARED_PREFS');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].severity).toBe('medium');
  });

  test('detects putString storing a token key', () => {
    const code = `prefs.edit().putString("token", authToken).apply()`;
    const findings = scan(code);
    expect(findings.some((f) => f.type === 'INSECURE_SHARED_PREFS')).toBe(true);
  });

  test('does not flag putString with non-sensitive key names', () => {
    const code = `prefs.edit().putString("username_display", name).apply()`;
    const findings = scan(code);
    expect(findings.filter((f) => f.type === 'INSECURE_SHARED_PREFS')).toHaveLength(0);
  });
});

// ── WEBVIEW_LOAD_URL ──────────────────────────────────────────────────────────

describe('kotlin-parser — WEBVIEW_LOAD_URL', () => {
  test('detects loadUrl with intent-derived URL', () => {
    const code = `webView.loadUrl(intent.getStringExtra("url"))`;
    const findings = scan(code);
    const hits = findings.filter((f) => f.type === 'WEBVIEW_LOAD_URL');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].severity).toBe('high');
  });

  test('detects loadUrl with request parameter variable', () => {
    const code = `webView.loadUrl(request.getParameter("target"))`;
    const findings = scan(code);
    expect(findings.some((f) => f.type === 'WEBVIEW_LOAD_URL')).toBe(true);
  });
});

// ── COMMAND_INJECTION ─────────────────────────────────────────────────────────

describe('kotlin-parser — SQL_INJECTION (via rawQuery)', () => {
  test('detects rawQuery with string concatenation', () => {
    const code = `db.rawQuery("SELECT * FROM users WHERE id = " + userId, null)`;
    const findings = scan(code);
    const hits = findings.filter((f) => f.type === 'SQL_INJECTION');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].severity).toBe('critical');
  });

  test('detects rawQuery with string interpolation', () => {
    const code = 'db.rawQuery("SELECT * FROM orders WHERE id = ${orderId}", null)';
    const findings = scan(code);
    expect(findings.some((f) => f.type === 'SQL_INJECTION')).toBe(true);
  });

  test('does not flag rawQuery with parameterised args placeholder', () => {
    const code = `db.rawQuery("SELECT * FROM users WHERE id = ?", arrayOf(userId))`;
    const findings = scan(code);
    expect(findings.filter((f) => f.type === 'SQL_INJECTION')).toHaveLength(0);
  });
});

// ── General finding shape ─────────────────────────────────────────────────────

describe('kotlin-parser — finding shape', () => {
  test('every finding has a line number, severity, message, and file', () => {
    const code = [
      `val apiKey = "sk-secretkey12345"`,
      `val rng = java.util.Random()`,
      `val md = MessageDigest.getInstance("MD5")`,
    ].join('\n');
    const findings = scan(code, 'test.kt');
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(typeof f.line).toBe('number');
      expect(f.line).toBeGreaterThan(0);
      expect(['critical', 'high', 'medium', 'low']).toContain(f.severity);
      expect(typeof f.message).toBe('string');
      expect(f.message.length).toBeGreaterThan(0);
      expect(f.file).toBe('test.kt');
    }
  });

  test('pure comment lines are not flagged', () => {
    const code = `// val password = "secretvalue"`;
    const findings = scan(code);
    expect(findings.filter((f) => f.type === 'SECRET_HARDCODED')).toHaveLength(0);
  });
});
