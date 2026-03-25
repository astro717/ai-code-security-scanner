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

  test('produces at least one finding', () => {
    expect(findings.length).toBeGreaterThan(0);
  });

  test('detects SQL_INJECTION', () => {
    expect(types.has('SQL_INJECTION')).toBe(true);
  });

  test('detects COMMAND_INJECTION', () => {
    expect(types.has('COMMAND_INJECTION')).toBe(true);
  });

  test('detects EVAL_INJECTION', () => {
    expect(types.has('EVAL_INJECTION')).toBe(true);
  });

  test('detects UNSAFE_DESERIALIZATION', () => {
    expect(types.has('UNSAFE_DESERIALIZATION')).toBe(true);
  });

  test('detects WEAK_CRYPTO', () => {
    expect(types.has('WEAK_CRYPTO')).toBe(true);
  });

  test('detects PATH_TRAVERSAL', () => {
    expect(types.has('PATH_TRAVERSAL')).toBe(true);
  });

  test('detects SSRF', () => {
    expect(types.has('SSRF')).toBe(true);
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
