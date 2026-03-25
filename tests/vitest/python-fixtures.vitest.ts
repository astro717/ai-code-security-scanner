/**
 * Python scanner integration tests using fixture files.
 *
 * Tests that:
 *  - tests/fixtures/vulnerable.py triggers findings for known vulnerability patterns
 *  - tests/fixtures/clean.py produces zero findings
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import path from 'path';
import { parsePythonFile, scanPython } from '../../src/scanner/python-parser';

const FIXTURES_DIR = path.join(__dirname, '..', 'fixtures');

describe('Python scanner — vulnerable.py fixture', () => {
  const result = parsePythonFile(path.join(FIXTURES_DIR, 'vulnerable.py'));
  const findings = scanPython(result);
  const types = new Set(findings.map((f) => f.type));

  // ── Broad smoke tests ───────────────────────────────────────────────────────

  test('produces at least one finding', () => {
    expect(findings.length).toBeGreaterThan(0);
  });

  test('every finding has a line number, severity, and message', () => {
    for (const f of findings) {
      expect(typeof f.line).toBe('number');
      expect(f.line).toBeGreaterThan(0);
      expect(['critical', 'high', 'medium', 'low']).toContain(f.severity);
      expect(typeof f.message).toBe('string');
      expect(f.message.length).toBeGreaterThan(0);
    }
  });

  // ── Per-type individual tests ────────────────────────────────────────────────
  // Each test targets a specific vulnerability type, checks it is detected at
  // least once, and asserts the expected severity. Line numbers are also checked
  // to catch regressions where the detector fires on the wrong location.

  test('SQL_INJECTION — detects execute() with string concatenation (line 16)', () => {
    const hits = findings.filter((f) => f.type === 'SQL_INJECTION');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].severity).toBe('critical');
    expect(hits[0].line).toBe(16);
  });

  test('COMMAND_INJECTION — detects os.system() with variable argument (line 21)', () => {
    const hits = findings.filter((f) => f.type === 'COMMAND_INJECTION');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].severity).toBe('critical');
    expect(hits[0].line).toBe(21);
  });

  test('EVAL_INJECTION — detects eval() with dynamic argument (line 25)', () => {
    const hits = findings.filter((f) => f.type === 'EVAL_INJECTION');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].severity).toBe('critical');
    expect(hits[0].line).toBe(25);
  });

  test('UNSAFE_DESERIALIZATION — detects pickle.loads() (line 29)', () => {
    const hits = findings.filter((f) => f.type === 'UNSAFE_DESERIALIZATION');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].severity).toBe('critical');
    expect(hits[0].line).toBe(29);
  });

  test('WEAK_CRYPTO — detects hashlib.md5() (line 33)', () => {
    const hits = findings.filter((f) => f.type === 'WEAK_CRYPTO');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].severity).toBe('high');
    expect(hits[0].line).toBe(33);
  });

  test('PATH_TRAVERSAL — detects open() with path concatenation (line 37)', () => {
    const hits = findings.filter((f) => f.type === 'PATH_TRAVERSAL');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].severity).toBe('high');
    expect(hits[0].line).toBe(37);
  });

  test('SSRF — detects requests.get() with variable URL (line 42)', () => {
    const hits = findings.filter((f) => f.type === 'SSRF');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].severity).toBe('high');
    expect(hits[0].line).toBe(42);
  });

  test('SECRET — detects hardcoded api_key assignment (line 46)', () => {
    const hits = findings.filter((f) => f.type === 'SECRET');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].severity).toBe('high');
    expect(hits[0].line).toBe(46);
  });
});

describe('Python scanner — clean.py fixture', () => {
  const result = parsePythonFile(path.join(FIXTURES_DIR, 'clean.py'));
  const findings = scanPython(result);

  test('produces zero findings', () => {
    if (findings.length > 0) {
      const detail = findings.map((f) => `  line ${f.line}: [${f.type}] ${f.message}`).join('\n');
      throw new Error(`Expected 0 findings in clean.py but got ${findings.length}:\n${detail}`);
    }
    expect(findings.length).toBe(0);
  });
});
