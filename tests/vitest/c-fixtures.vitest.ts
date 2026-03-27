/**
 * Fixture-based tests for the C/C++ scanner (c-parser.ts).
 *
 * Verifies that vulnerable.c triggers expected finding types and clean.c
 * produces zero findings.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import path from 'path';
import { parseCFile, scanC } from '../../src/scanner/c-parser';

const FIXTURES = path.join(__dirname, '..', 'fixtures');

describe('C/C++ scanner — fixture files', () => {
  test('vulnerable.c produces expected findings', () => {
    const parsed = parseCFile(path.join(FIXTURES, 'vulnerable.c'));
    const findings = scanC(parsed);

    expect(findings.length).toBeGreaterThan(0);

    const types = new Set(findings.map((f) => f.type));

    // Expected vulnerability classes in vulnerable.c
    expect(types.has('BUFFER_OVERFLOW')).toBe(true);
    expect(types.has('FORMAT_STRING')).toBe(true);
    expect(types.has('SECRET_HARDCODED')).toBe(true);
    expect(types.has('INSECURE_RANDOM')).toBe(true);
    expect(types.has('WEAK_CRYPTO')).toBe(true);
    expect(types.has('COMMAND_INJECTION_C')).toBe(true);
  });

  test('clean.c produces zero findings', () => {
    const parsed = parseCFile(path.join(FIXTURES, 'clean.c'));
    const findings = scanC(parsed);

    expect(findings.length).toBe(0);
  });

  test('findings include correct file path', () => {
    const filePath = path.join(FIXTURES, 'vulnerable.c');
    const parsed = parseCFile(filePath);
    const findings = scanC(parsed);

    for (const f of findings) {
      expect(f.file).toBe(filePath);
    }
  });

  test('buffer overflow findings have correct severity', () => {
    const parsed = parseCFile(path.join(FIXTURES, 'vulnerable.c'));
    const findings = scanC(parsed);

    const bufferFindings = findings.filter((f) => f.type === 'BUFFER_OVERFLOW');
    expect(bufferFindings.length).toBeGreaterThan(0);

    // gets() should be critical, others should be high
    const getsFindings = bufferFindings.filter((f) => f.snippet.includes('gets'));
    for (const f of getsFindings) {
      expect(f.severity).toBe('critical');
    }
  });
});
