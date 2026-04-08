/**
 * Go scanner integration tests using fixture files.
 *
 * Tests that:
 *  - tests/fixtures/vulnerable.go triggers findings for known vulnerability patterns
 *  - tests/fixtures/clean.go produces zero findings
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import path from 'path';
import { parseGoFile, scanGo } from '../../src/scanner/go-parser';

const FIXTURES_DIR = path.join(__dirname, '..', 'fixtures');

describe('Go scanner — vulnerable.go fixture', () => {
  const result = parseGoFile(path.join(FIXTURES_DIR, 'vulnerable.go'));
  const findings = scanGo(result);
  const types = new Set(findings.map((f) => f.type));

  test('produces at least one finding', () => {
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects SQL_INJECTION', () => {
    expect(types.has('SQL_INJECTION')).toBe(true);
  });

  test('detects COMMAND_INJECTION_GO', () => {
    expect(types.has('COMMAND_INJECTION_GO')).toBe(true);
  });

  test('detects SSRF', () => {
    expect(types.has('SSRF')).toBe(true);
  });

  test('detects SECRET_HARDCODED', () => {
    expect(types.has('SECRET_HARDCODED')).toBe(true);
  });

  test('detects WEAK_CRYPTO', () => {
    expect(types.has('WEAK_CRYPTO')).toBe(true);
  });

  test('detects PATH_TRAVERSAL', () => {
    expect(types.has('PATH_TRAVERSAL')).toBe(true);
  });

  test('detects INSECURE_RANDOM', () => {
    expect(types.has('INSECURE_RANDOM')).toBe(true);
  });

  test('detects EVAL_INJECTION (template injection)', () => {
    expect(types.has('EVAL_INJECTION')).toBe(true);
  });

  test('detects OPEN_REDIRECT', () => {
    expect(types.has('OPEN_REDIRECT')).toBe(true);
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
});

describe('Go scanner — clean.go fixture', () => {
  const result = parseGoFile(path.join(FIXTURES_DIR, 'clean.go'));
  const findings = scanGo(result);

  test('produces zero findings', () => {
    if (findings.length > 0) {
      const detail = findings.map((f) => `  line ${f.line}: [${f.type}] ${f.message}`).join('\n');
      throw new Error(`Expected 0 findings in clean.go but got ${findings.length}:\n${detail}`);
    }
    expect(findings.length).toBe(0);
  });
});
