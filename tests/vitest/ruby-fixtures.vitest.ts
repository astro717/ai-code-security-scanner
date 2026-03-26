/**
 * Fixture-based tests for the Ruby scanner (ruby-parser.ts).
 *
 * Verifies that vulnerable.rb triggers expected finding types and clean.rb
 * produces zero findings.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import path from 'path';
import { parseRubyFile, scanRuby } from '../../src/scanner/ruby-parser';

const FIXTURES = path.join(__dirname, '..', 'fixtures');

describe('Ruby scanner — fixture files', () => {
  test('vulnerable.rb produces expected findings', () => {
    const parsed = parseRubyFile(path.join(FIXTURES, 'vulnerable.rb'));
    const findings = scanRuby(parsed);

    expect(findings.length).toBeGreaterThan(0);

    const types = new Set(findings.map((f) => f.type));

    // Expected vulnerability classes in vulnerable.rb
    expect(types.has('SQL_INJECTION')).toBe(true);
    expect(types.has('COMMAND_INJECTION')).toBe(true);
    expect(types.has('SECRET_HARDCODED')).toBe(true);
    expect(types.has('MASS_ASSIGNMENT')).toBe(true);
    expect(types.has('WEAK_CRYPTO')).toBe(true);
    expect(types.has('EVAL_INJECTION')).toBe(true);
  });

  test('clean.rb produces zero findings', () => {
    const parsed = parseRubyFile(path.join(FIXTURES, 'clean.rb'));
    const findings = scanRuby(parsed);

    expect(findings.length).toBe(0);
  });

  test('findings include correct file path', () => {
    const filePath = path.join(FIXTURES, 'vulnerable.rb');
    const parsed = parseRubyFile(filePath);
    const findings = scanRuby(parsed);

    for (const f of findings) {
      expect(f.file).toBe(filePath);
    }
  });

  test('findings have valid severity levels', () => {
    const parsed = parseRubyFile(path.join(FIXTURES, 'vulnerable.rb'));
    const findings = scanRuby(parsed);

    const validSeverities = new Set(['critical', 'high', 'medium', 'low']);
    for (const f of findings) {
      expect(validSeverities.has(f.severity)).toBe(true);
    }
  });

  test('SQL injection findings are critical', () => {
    const parsed = parseRubyFile(path.join(FIXTURES, 'vulnerable.rb'));
    const findings = scanRuby(parsed);

    const sqlFindings = findings.filter((f) => f.type === 'SQL_INJECTION');
    expect(sqlFindings.length).toBeGreaterThan(0);
    for (const f of sqlFindings) {
      expect(f.severity).toBe('critical');
    }
  });
});
