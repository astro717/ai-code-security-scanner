/**
 * Unit tests for kotlin-parser.ts — exercises all finding types detected by
 * the Kotlin/Android security scanner using fixture strings.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import { parseKotlinCode, scanKotlin } from '../../src/scanner/kotlin-parser';

// ── Helper ────────────────────────────────────────────────────────────────────

function scanCode(code: string, fileName = 'input.kt') {
  const result = parseKotlinCode(code, fileName);
  return scanKotlin(result);
}

function findingTypes(code: string, fileName?: string): string[] {
  return scanCode(code, fileName).map((f) => f.type);
}

// ── SECRET_HARDCODED ─────────────────────────────────────────────────────────

describe('kotlin-parser — SECRET_HARDCODED', () => {
  test('detects hardcoded API key', () => {
    const code = 'val apiKey = "sk-abc1234567890abcdef"';
    expect(findingTypes(code)).toContain('SECRET_HARDCODED');
  });

  test('detects hardcoded password', () => {
    const code = 'val password = "SuperSecret123"';
    expect(findingTypes(code)).toContain('SECRET_HARDCODED');
  });

  test('detects hardcoded token', () => {
    const code = 'const val accessToken = "Bearer eyJhbGciOiJIUzI1NiJ9"';
    expect(findingTypes(code)).toContain('SECRET_HARDCODED');
  });

  test('detects hardcoded private_key', () => {
    const code = 'val privateKey = "-----BEGIN RSA PRIVATE KEY-----"';
    expect(findingTypes(code)).toContain('SECRET_HARDCODED');
  });

  test('does NOT flag short placeholder strings', () => {
    // Less than 4 chars in the value — below the pattern threshold
    const code = 'val apiKey = "abc"';
    expect(findingTypes(code)).not.toContain('SECRET_HARDCODED');
  });

  test('does NOT flag comment lines', () => {
    const code = '// val password = "SuperSecret123"';
    expect(findingTypes(code)).not.toContain('SECRET_HARDCODED');
  });
});

// ── INSECURE_RANDOM ──────────────────────────────────────────────────────────

describe('kotlin-parser — INSECURE_RANDOM', () => {
  test('detects java.util.Random()', () => {
    const code = 'val rng = java.util.Random()';
    expect(findingTypes(code)).toContain('INSECURE_RANDOM');
  });

  test('detects Random() constructor usage', () => {
    const code = 'val r = Random()';
    expect(findingTypes(code)).toContain('INSECURE_RANDOM');
  });

  test('finding has medium severity', () => {
    const code = 'val r = Random()';
    const findings = scanCode(code);
    const match = findings.find((f) => f.type === 'INSECURE_RANDOM');
    expect(match?.severity).toBe('medium');
  });
});

// ── WEAK_CRYPTO ──────────────────────────────────────────────────────────────

describe('kotlin-parser — WEAK_CRYPTO', () => {
  test('detects MD5 MessageDigest', () => {
    const code = 'val md = MessageDigest.getInstance("MD5")';
    expect(findingTypes(code)).toContain('WEAK_CRYPTO');
  });

  test('detects SHA-1 MessageDigest', () => {
    const code = 'val sha = MessageDigest.getInstance("SHA-1")';
    expect(findingTypes(code)).toContain('WEAK_CRYPTO');
  });

  test('detects SHA1 (no hyphen) MessageDigest', () => {
    const code = 'val sha = MessageDigest.getInstance("SHA1")';
    expect(findingTypes(code)).toContain('WEAK_CRYPTO');
  });

  test('does NOT flag SHA-256', () => {
    const code = 'val sha = MessageDigest.getInstance("SHA-256")';
    expect(findingTypes(code)).not.toContain('WEAK_CRYPTO');
  });

  test('finding has high severity', () => {
    const code = 'val md = MessageDigest.getInstance("MD5")';
    const findings = scanCode(code);
    const match = findings.find((f) => f.type === 'WEAK_CRYPTO');
    expect(match?.severity).toBe('high');
  });
});

// ── INSECURE_SHARED_PREFS ────────────────────────────────────────────────────

describe('kotlin-parser — INSECURE_SHARED_PREFS', () => {
  test('detects putString storing a password key', () => {
    const code = 'prefs.edit().putString("password", value).apply()';
    expect(findingTypes(code)).toContain('INSECURE_SHARED_PREFS');
  });

  test('detects putString storing a token key', () => {
    const code = 'prefs.edit().putString("authToken", userToken).apply()';
    expect(findingTypes(code)).toContain('INSECURE_SHARED_PREFS');
  });

  test('detects putString storing a secret key', () => {
    const code = 'prefs.edit().putString("userSecret", secretValue).commit()';
    expect(findingTypes(code)).toContain('INSECURE_SHARED_PREFS');
  });

  test('does NOT flag putString for non-sensitive keys', () => {
    const code = 'prefs.edit().putString("username", name).apply()';
    expect(findingTypes(code)).not.toContain('INSECURE_SHARED_PREFS');
  });

  test('finding has medium severity', () => {
    const code = 'prefs.edit().putString("password", val).apply()';
    const findings = scanCode(code);
    const match = findings.find((f) => f.type === 'INSECURE_SHARED_PREFS');
    expect(match?.severity).toBe('medium');
  });
});

// ── WEBVIEW_LOAD_URL ─────────────────────────────────────────────────────────

describe('kotlin-parser — WEBVIEW_LOAD_URL', () => {
  test('detects loadUrl with url variable', () => {
    const code = 'webView.loadUrl(url)';
    expect(findingTypes(code)).toContain('WEBVIEW_LOAD_URL');
  });

  test('detects loadUrl with intent-derived input', () => {
    const code = 'webView.loadUrl(intent.getStringExtra("url"))';
    expect(findingTypes(code)).toContain('WEBVIEW_LOAD_URL');
  });

  test('detects loadUrl with request parameter', () => {
    const code = 'webView.loadUrl(request.getParameter("target"))';
    expect(findingTypes(code)).toContain('WEBVIEW_LOAD_URL');
  });

  test('finding has high severity', () => {
    const code = 'webView.loadUrl(url)';
    const findings = scanCode(code);
    const match = findings.find((f) => f.type === 'WEBVIEW_LOAD_URL');
    expect(match?.severity).toBe('high');
  });
});

// ── SQL_INJECTION (Kotlin via rawQuery / execSQL) ───────────────────────────

describe('kotlin-parser — SQL_INJECTION', () => {
  test('detects rawQuery with Kotlin string interpolation', () => {
    // The regex matches when the query string contains ${...} interpolation
    const code = 'db.rawQuery("SELECT * FROM users WHERE id = ${userId}", null)';
    expect(findingTypes(code)).toContain('SQL_INJECTION');
  });

  test('detects rawQuery where first argument is a variable (not a literal)', () => {
    // Pattern also matches rawQuery(variableName, ...) — non-literal first arg
    const code = 'db.rawQuery(queryStr, null)';
    expect(findingTypes(code)).toContain('SQL_INJECTION');
  });

  test('finding has critical severity', () => {
    const code = 'db.rawQuery("DELETE FROM users WHERE id = ${id}", null)';
    const findings = scanCode(code);
    const match = findings.find((f) => f.type === 'SQL_INJECTION');
    expect(match?.severity).toBe('critical');
  });
});

// ── General scanner behavior ─────────────────────────────────────────────────

describe('kotlin-parser — general behavior', () => {
  test('returns empty array for clean code', () => {
    const code = `
      fun add(a: Int, b: Int): Int = a + b
      val result = add(1, 2)
    `;
    expect(scanCode(code)).toHaveLength(0);
  });

  test('each finding includes line number, snippet, and message', () => {
    const code = 'val password = "SuperSecretPassword"';
    const findings = scanCode(code);
    expect(findings.length).toBeGreaterThan(0);
    const finding = findings[0]!;
    expect(finding.line).toBe(1);
    expect(typeof finding.message).toBe('string');
    expect(finding.message.length).toBeGreaterThan(0);
    expect(typeof finding.snippet).toBe('string');
  });

  test('filePath is preserved in finding.file', () => {
    const code = 'val apiKey = "sk-verylongapikey123456"';
    const result = parseKotlinCode(code, '/app/src/MainActivity.kt');
    const findings = scanKotlin(result);
    expect(findings[0]?.file).toBe('/app/src/MainActivity.kt');
  });

  test('multi-line code detects findings on correct lines', () => {
    const code = [
      'fun setup() {',
      '  val rng = Random()',
      '  val name = "Alice"',
      '}',
    ].join('\n');
    const findings = scanCode(code);
    const randomFinding = findings.find((f) => f.type === 'INSECURE_RANDOM');
    expect(randomFinding?.line).toBe(2);
  });

  test('pure comment lines are skipped', () => {
    const code = [
      '// val password = "DoNotStore"',
      '* val apiKey = "sk-abc1234567890abcdef"',
    ].join('\n');
    expect(findingTypes(code)).not.toContain('SECRET_HARDCODED');
  });
});
