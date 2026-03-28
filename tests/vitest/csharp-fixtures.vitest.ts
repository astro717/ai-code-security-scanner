/**
 * Fixture-based tests for the C# scanner (csharp-parser.ts).
 *
 * Verifies that vulnerable.cs triggers expected finding types and clean.cs
 * produces zero findings.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import path from 'path';
import { parseCSharpFile, scanCSharp } from '../../src/scanner/csharp-parser';

const FIXTURES = path.join(__dirname, '..', 'fixtures');

describe('C# scanner — fixture files', () => {
  test('vulnerable.cs produces expected findings', () => {
    const parsed = parseCSharpFile(path.join(FIXTURES, 'vulnerable.cs'));
    const findings = scanCSharp(parsed);

    expect(findings.length).toBeGreaterThan(0);

    const types = new Set(findings.map((f) => f.type));

    // Expected vulnerability classes in vulnerable.cs
    expect(types.has('SQL_INJECTION_CS')).toBe(true);
    expect(types.has('COMMAND_INJECTION_CS')).toBe(true);
    expect(types.has('SECRET_HARDCODED')).toBe(true);
    expect(types.has('WEAK_CRYPTO')).toBe(true);
    expect(types.has('INSECURE_RANDOM')).toBe(true);
    expect(types.has('UNSAFE_DESERIALIZATION')).toBe(true);
  });

  test('clean.cs produces zero findings', () => {
    const parsed = parseCSharpFile(path.join(FIXTURES, 'clean.cs'));
    const findings = scanCSharp(parsed);

    expect(findings.length).toBe(0);
  });

  test('findings include correct file path', () => {
    const filePath = path.join(FIXTURES, 'vulnerable.cs');
    const parsed = parseCSharpFile(filePath);
    const findings = scanCSharp(parsed);

    for (const f of findings) {
      expect(f.file).toBe(filePath);
    }
  });

  test('findings have valid severity levels', () => {
    const parsed = parseCSharpFile(path.join(FIXTURES, 'vulnerable.cs'));
    const findings = scanCSharp(parsed);

    const validSeverities = new Set(['critical', 'high', 'medium', 'low']);
    for (const f of findings) {
      expect(validSeverities.has(f.severity)).toBe(true);
    }
  });
});
