/**
 * Tests for kotlin-parser.ts — both fixture-file-based and inline.
 *
 * Fixture tests (Part 1) verify end-to-end coverage via parseKotlinFile(),
 * mirroring the pattern used by ruby-fixtures.vitest.ts.
 *
 * Inline tests (Part 2) verify individual detector patterns in isolation.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import path from 'path';
import { parseKotlinFile, parseKotlinCode, scanKotlin } from '../../src/scanner/kotlin-parser';

const FIXTURES = path.join(__dirname, '..', 'fixtures');

// ── Part 1 — Fixture-file-based tests ────────────────────────────────────────

describe('Kotlin scanner — fixture files', () => {
  test('vulnerable.kt produces expected findings', () => {
    const parsed = parseKotlinFile(path.join(FIXTURES, 'vulnerable.kt'));
    const findings = scanKotlin(parsed);

    expect(findings.length).toBeGreaterThan(0);

    const types = new Set(findings.map((f) => f.type));

    expect(types.has('SECRET_HARDCODED')).toBe(true);
    expect(types.has('INSECURE_RANDOM')).toBe(true);
    expect(types.has('WEAK_CRYPTO')).toBe(true);
    expect(types.has('SQL_INJECTION')).toBe(true);
    expect(types.has('PATH_TRAVERSAL')).toBe(true);
    expect(types.has('INSECURE_SHARED_PREFS')).toBe(true);
    expect(types.has('PERFORMANCE_N_PLUS_ONE')).toBe(true);
  });

  test('clean.kt produces zero findings', () => {
    const parsed = parseKotlinFile(path.join(FIXTURES, 'clean.kt'));
    const findings = scanKotlin(parsed);

    expect(findings.length).toBe(0);
  });

  test('findings from vulnerable.kt include the correct file path', () => {
    const filePath = path.join(FIXTURES, 'vulnerable.kt');
    const parsed = parseKotlinFile(filePath);
    const findings = scanKotlin(parsed);

    for (const f of findings) {
      expect(f.file).toBe(filePath);
    }
  });

  test('findings from vulnerable.kt have valid severity levels', () => {
    const parsed = parseKotlinFile(path.join(FIXTURES, 'vulnerable.kt'));
    const findings = scanKotlin(parsed);

    const validSeverities = new Set(['critical', 'high', 'medium', 'low']);
    for (const f of findings) {
      expect(validSeverities.has(f.severity)).toBe(true);
    }
  });

  test('SQL_INJECTION findings are critical', () => {
    const parsed = parseKotlinFile(path.join(FIXTURES, 'vulnerable.kt'));
    const findings = scanKotlin(parsed);

    const sqlFindings = findings.filter((f) => f.type === 'SQL_INJECTION');
    expect(sqlFindings.length).toBeGreaterThan(0);
    for (const f of sqlFindings) {
      expect(f.severity).toBe('critical');
    }
  });
});

// ── Helper ────────────────────────────────────────────────────────────────────

// ── Part 2 — Inline detector tests ───────────────────────────────────────────

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

// ── N+1 stateful detector ─────────────────────────────────────────────────────

describe('kotlin-parser — PERFORMANCE_N_PLUS_ONE (stateful)', () => {
  test('detects repository.findById inside for loop', () => {
    const code = `
for (item in items) {
  val user = userRepository.findById(item.userId)
  process(user)
}
`;
    const findings = scan(code);
    expect(findings.filter((f) => f.type === 'PERFORMANCE_N_PLUS_ONE').length).toBeGreaterThan(0);
  });

  test('detects JPA entityManager.find inside forEach', () => {
    const code = `
ids.forEach { id ->
  val entity = entityManager.find(Order::class.java, id)
  results.add(entity)
}
`;
    const findings = scan(code);
    expect(findings.filter((f) => f.type === 'PERFORMANCE_N_PLUS_ONE').length).toBeGreaterThan(0);
  });

  test('does not flag repository call outside a loop', () => {
    const code = `
val ids = items.map { it.id }
val users = userRepository.findAllById(ids)
`;
    const findings = scan(code);
    expect(findings.filter((f) => f.type === 'PERFORMANCE_N_PLUS_ONE')).toHaveLength(0);
  });

  test('N+1 finding has correct confidence value', () => {
    const code = `
for (item in items) {
  val order = orderRepository.findById(item.id)
}
`;
    const findings = scan(code).filter((f) => f.type === 'PERFORMANCE_N_PLUS_ONE');
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.confidence).toBeDefined();
      expect(f.confidence).toBeGreaterThan(0);
    }
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
