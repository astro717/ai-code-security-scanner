/**
 * Unit tests for the Kotlin parser (kotlin-parser.ts).
 *
 * Exercises all finding types emitted by the Kotlin scanner using inline
 * fixture strings. No fixture files required — each test creates a minimal
 * code snippet that should trigger exactly the finding under test.
 *
 * Finding types covered:
 *   SECRET_HARDCODED       — hardcoded API keys / tokens in Kotlin source
 *   INSECURE_RANDOM        — java.util.Random for security-sensitive values
 *   WEAK_CRYPTO            — MD5 / SHA-1 via MessageDigest
 *   INSECURE_SHARED_PREFS  — SharedPreferences storing sensitive data unencrypted
 *   WEBVIEW_LOAD_URL       — WebView.loadUrl with user-controlled URL
 *   SQL_INJECTION          — rawQuery / execSQL with string concatenation
 *   PATH_TRAVERSAL         — File() constructor with user-controlled path
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import { parseKotlinCode, scanKotlin } from '../../src/scanner/kotlin-parser';

// ── Helper ────────────────────────────────────────────────────────────────────

function scan(code: string) {
  return scanKotlin(parseKotlinCode(code, 'test.kt'));
}

function findingsOfType(code: string, type: string) {
  return scan(code).filter((f) => f.type === type);
}

// ── SECRET_HARDCODED ──────────────────────────────────────────────────────────

describe('Kotlin scanner — SECRET_HARDCODED', () => {
  test('detects hardcoded API key assigned to val', () => {
    const code = 'val apiKey = "sk-secret-1234567890abcdef"';
    expect(findingsOfType(code, 'SECRET_HARDCODED').length).toBeGreaterThan(0);
  });

  test('detects hardcoded token assigned to var', () => {
    const code = 'var authToken = "Bearer eyJhbGciOiJIUzI1NiJ9"';
    expect(findingsOfType(code, 'SECRET_HARDCODED').length).toBeGreaterThan(0);
  });

  test('detects hardcoded password constant', () => {
    const code = 'const val PASSWORD = "supersecretpassword123"';
    expect(findingsOfType(code, 'SECRET_HARDCODED').length).toBeGreaterThan(0);
  });

  test('does NOT flag unrelated string assignments', () => {
    const code = 'val message = "Hello, World!"';
    expect(findingsOfType(code, 'SECRET_HARDCODED').length).toBe(0);
  });

  test('finding has high severity', () => {
    const hits = findingsOfType('val apiKey = "sk-secret-abc123xyz"', 'SECRET_HARDCODED');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0]!.severity).toBe('high');
  });
});

// ── INSECURE_RANDOM ───────────────────────────────────────────────────────────

describe('Kotlin scanner — INSECURE_RANDOM', () => {
  test('detects java.util.Random() instantiation', () => {
    const code = 'val rng = java.util.Random()';
    expect(findingsOfType(code, 'INSECURE_RANDOM').length).toBeGreaterThan(0);
  });

  test('detects Random() without package prefix', () => {
    const code = 'val rand = Random()';
    expect(findingsOfType(code, 'INSECURE_RANDOM').length).toBeGreaterThan(0);
  });

  test('does NOT flag SecureRandom()', () => {
    const code = 'val rng = SecureRandom()';
    expect(findingsOfType(code, 'INSECURE_RANDOM').length).toBe(0);
  });

  test('finding has medium severity', () => {
    const hits = findingsOfType('val r = Random()', 'INSECURE_RANDOM');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0]!.severity).toBe('medium');
  });
});

// ── WEAK_CRYPTO ───────────────────────────────────────────────────────────────

describe('Kotlin scanner — WEAK_CRYPTO', () => {
  test('detects MessageDigest.getInstance("MD5")', () => {
    const code = 'val md = MessageDigest.getInstance("MD5")';
    expect(findingsOfType(code, 'WEAK_CRYPTO').length).toBeGreaterThan(0);
  });

  test('detects MessageDigest.getInstance("SHA-1")', () => {
    const code = 'val md = MessageDigest.getInstance("SHA-1")';
    expect(findingsOfType(code, 'WEAK_CRYPTO').length).toBeGreaterThan(0);
  });

  test('detects MessageDigest.getInstance("SHA1") (no dash)', () => {
    const code = 'val md = MessageDigest.getInstance("SHA1")';
    expect(findingsOfType(code, 'WEAK_CRYPTO').length).toBeGreaterThan(0);
  });

  test('does NOT flag MessageDigest.getInstance("SHA-256")', () => {
    const code = 'val md = MessageDigest.getInstance("SHA-256")';
    expect(findingsOfType(code, 'WEAK_CRYPTO').length).toBe(0);
  });

  test('finding has high severity', () => {
    const hits = findingsOfType('MessageDigest.getInstance("MD5")', 'WEAK_CRYPTO');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0]!.severity).toBe('high');
  });
});

// ── INSECURE_SHARED_PREFS ─────────────────────────────────────────────────────

describe('Kotlin scanner — INSECURE_SHARED_PREFS', () => {
  test('detects putString storing auth_token', () => {
    const code = 'prefs.edit().putString("auth_token", token).apply()';
    expect(findingsOfType(code, 'INSECURE_SHARED_PREFS').length).toBeGreaterThan(0);
  });

  test('detects putString storing password', () => {
    const code = 'prefs.edit().putString("user_password", pwd).apply()';
    expect(findingsOfType(code, 'INSECURE_SHARED_PREFS').length).toBeGreaterThan(0);
  });

  test('detects putString storing api_key', () => {
    const code = 'sharedPrefs.edit().putString("api_key", key).commit()';
    expect(findingsOfType(code, 'INSECURE_SHARED_PREFS').length).toBeGreaterThan(0);
  });

  test('does NOT flag putString with a non-sensitive key', () => {
    const code = 'prefs.edit().putString("username_display", name).apply()';
    expect(findingsOfType(code, 'INSECURE_SHARED_PREFS').length).toBe(0);
  });

  test('finding has medium severity', () => {
    const hits = findingsOfType('prefs.edit().putString("auth_token", t).apply()', 'INSECURE_SHARED_PREFS');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0]!.severity).toBe('medium');
  });
});

// ── WEBVIEW_LOAD_URL ──────────────────────────────────────────────────────────

describe('Kotlin scanner — WEBVIEW_LOAD_URL', () => {
  test('detects loadUrl with intent-based URL', () => {
    const code = 'webView.loadUrl(intent.getStringExtra("url"))';
    expect(findingsOfType(code, 'WEBVIEW_LOAD_URL').length).toBeGreaterThan(0);
  });

  test('detects loadUrl with uri variable', () => {
    const code = 'webView.loadUrl(uri)';
    expect(findingsOfType(code, 'WEBVIEW_LOAD_URL').length).toBeGreaterThan(0);
  });

  test('detects loadUrl with user input variable', () => {
    const code = 'webView.loadUrl(userInput)';
    expect(findingsOfType(code, 'WEBVIEW_LOAD_URL').length).toBeGreaterThan(0);
  });

  test('does NOT flag loadUrl with a hardcoded https:// URL', () => {
    const code = 'webView.loadUrl("https://example.com/page")';
    expect(findingsOfType(code, 'WEBVIEW_LOAD_URL').length).toBe(0);
  });

  test('finding has high severity', () => {
    const hits = findingsOfType('webView.loadUrl(url)', 'WEBVIEW_LOAD_URL');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0]!.severity).toBe('high');
  });
});

// ── SQL_INJECTION ─────────────────────────────────────────────────────────────

describe('Kotlin scanner — SQL_INJECTION', () => {
  test('detects rawQuery with string concatenation', () => {
    const code = 'db.rawQuery("SELECT * FROM users WHERE id = " + userId, null)';
    expect(findingsOfType(code, 'SQL_INJECTION').length).toBeGreaterThan(0);
  });

  test('detects execSQL with string interpolation', () => {
    const code = 'db.execSQL("DELETE FROM users WHERE id = ${userId}")';
    expect(findingsOfType(code, 'SQL_INJECTION').length).toBeGreaterThan(0);
  });

  test('does NOT flag rawQuery with a plain string literal', () => {
    const code = 'db.rawQuery("SELECT * FROM users", null)';
    expect(findingsOfType(code, 'SQL_INJECTION').length).toBe(0);
  });

  test('finding has critical severity', () => {
    const hits = findingsOfType('db.rawQuery("SELECT * FROM t WHERE id = " + id, null)', 'SQL_INJECTION');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0]!.severity).toBe('critical');
  });
});

// ── PATH_TRAVERSAL ────────────────────────────────────────────────────────────

describe('Kotlin scanner — PATH_TRAVERSAL', () => {
  test('detects File() with intent parameter', () => {
    const code = 'val file = File(intent.getStringExtra("path"))';
    expect(findingsOfType(code, 'PATH_TRAVERSAL').length).toBeGreaterThan(0);
  });

  test('detects File() with path variable', () => {
    const code = 'val f = File(path)';
    expect(findingsOfType(code, 'PATH_TRAVERSAL').length).toBeGreaterThan(0);
  });

  test('detects File() with args array access', () => {
    const code = 'val file = File(args[0])';
    expect(findingsOfType(code, 'PATH_TRAVERSAL').length).toBeGreaterThan(0);
  });

  test('finding has high severity', () => {
    const hits = findingsOfType('val f = File(path)', 'PATH_TRAVERSAL');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0]!.severity).toBe('high');
  });
});

// ── Common finding shape ──────────────────────────────────────────────────────

describe('Kotlin scanner — finding shape', () => {
  test('every finding has required fields: type, severity, line, column, message, file', () => {
    const code = [
      'val apiKey = "sk-secret-1234567890abcdef"',
      'val rng = Random()',
      'val md = MessageDigest.getInstance("MD5")',
    ].join('\n');

    const findings = scan(code);
    expect(findings.length).toBeGreaterThan(0);

    const validSeverities = new Set(['critical', 'high', 'medium', 'low']);
    for (const f of findings) {
      expect(typeof f.type).toBe('string');
      expect(f.type.length).toBeGreaterThan(0);
      expect(typeof f.severity).toBe('string');
      expect(validSeverities.has(f.severity)).toBe(true);
      expect(typeof f.line).toBe('number');
      expect(f.line).toBeGreaterThan(0);
      expect(typeof f.column).toBe('number');
      expect(typeof f.message).toBe('string');
      expect(f.message.length).toBeGreaterThan(0);
    }
  });

  test('line numbers are 1-indexed and match the fixture line', () => {
    const code = [
      'package com.example',
      '',
      'val apiKey = "sk-secret-1234567890abcdef"', // line 3
    ].join('\n');

    const hits = findingsOfType(code, 'SECRET_HARDCODED');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0]!.line).toBe(3);
  });

  test('clean Kotlin code returns zero findings', () => {
    const code = `
package com.example

import java.security.SecureRandom
import java.security.MessageDigest

class SafeService {
    fun hash(data: String): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(data.toByteArray())
    }
    fun token(): ByteArray {
        val b = ByteArray(32)
        SecureRandom().nextBytes(b)
        return b
    }
}
`.trim();

    expect(scan(code).length).toBe(0);
  });
});
