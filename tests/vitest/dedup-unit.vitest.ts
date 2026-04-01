/**
 * Unit tests for deduplicateFindings() in src/scanner/reporter.ts.
 *
 * Verifies:
 *   - A line matching 2 patterns of the same type only produces 1 finding
 *   - The finding with the highest confidence is kept
 *   - Different types on the same line are NOT collapsed
 *   - Relative order is preserved
 *
 * Run with: npm run test:vitest
 */

import { describe, it, expect } from 'vitest';
import { deduplicateFindings } from '../../src/scanner/reporter';
import type { Finding } from '../../src/scanner/reporter';

function makeFinding(overrides: Partial<Finding>): Finding {
  return {
    type: 'SQL_INJECTION',
    severity: 'high',
    message: 'test finding',
    line: 1,
    column: 0,
    snippet: '',
    file: 'test.ts',
    confidence: 0.8,
    ...overrides,
  };
}

describe('deduplicateFindings — same type on same line', () => {
  it('collapses two findings of the same type on the same line into one', () => {
    const findings = [
      makeFinding({ type: 'SQL_INJECTION', line: 10, confidence: 0.7 }),
      makeFinding({ type: 'SQL_INJECTION', line: 10, confidence: 0.9 }),
    ];

    const result = deduplicateFindings(findings);
    expect(result).toHaveLength(1);
  });

  it('keeps the finding with the highest confidence', () => {
    const low = makeFinding({ type: 'SQL_INJECTION', line: 5, confidence: 0.5 });
    const high = makeFinding({ type: 'SQL_INJECTION', line: 5, confidence: 0.95 });

    // Low first
    const result1 = deduplicateFindings([low, high]);
    expect(result1).toHaveLength(1);
    expect(result1[0]!.confidence).toBe(0.95);

    // High first
    const result2 = deduplicateFindings([high, low]);
    expect(result2).toHaveLength(1);
    expect(result2[0]!.confidence).toBe(0.95);
  });

  it('keeps the first when confidence is equal', () => {
    const first = makeFinding({ type: 'XSS', line: 3, confidence: 0.8, message: 'first' });
    const second = makeFinding({ type: 'XSS', line: 3, confidence: 0.8, message: 'second' });

    const result = deduplicateFindings([first, second]);
    expect(result).toHaveLength(1);
    expect(result[0]!.message).toBe('first');
  });
});

describe('deduplicateFindings — different types on same line', () => {
  it('does NOT collapse findings of different types on the same line', () => {
    const findings = [
      makeFinding({ type: 'SQL_INJECTION', line: 7, confidence: 0.9 }),
      makeFinding({ type: 'XSS', line: 7, confidence: 0.85 }),
    ];

    const result = deduplicateFindings(findings);
    expect(result).toHaveLength(2);
    expect(result.map((f) => f.type).sort()).toEqual(['SQL_INJECTION', 'XSS']);
  });

  it('handles three different types on the same line independently', () => {
    const findings = [
      makeFinding({ type: 'SQL_INJECTION', line: 1, confidence: 0.9 }),
      makeFinding({ type: 'XSS', line: 1, confidence: 0.85 }),
      makeFinding({ type: 'COMMAND_INJECTION', line: 1, confidence: 0.7 }),
    ];

    const result = deduplicateFindings(findings);
    expect(result).toHaveLength(3);
  });
});

describe('deduplicateFindings — no duplicates', () => {
  it('returns all findings when none are duplicates', () => {
    const findings = [
      makeFinding({ type: 'SQL_INJECTION', line: 1 }),
      makeFinding({ type: 'SQL_INJECTION', line: 2 }),
      makeFinding({ type: 'XSS', line: 1 }),
    ];

    const result = deduplicateFindings(findings);
    expect(result).toHaveLength(3);
  });

  it('returns empty array for empty input', () => {
    expect(deduplicateFindings([])).toEqual([]);
  });
});

describe('deduplicateFindings — order preservation', () => {
  it('preserves the relative order of surviving findings', () => {
    const findings = [
      makeFinding({ type: 'XSS', line: 5, confidence: 0.9 }),
      makeFinding({ type: 'SQL_INJECTION', line: 3, confidence: 0.8 }),
      makeFinding({ type: 'COMMAND_INJECTION', line: 1, confidence: 0.7 }),
      // Duplicate of first SQL_INJECTION on line 3 with lower confidence
      makeFinding({ type: 'SQL_INJECTION', line: 3, confidence: 0.6 }),
    ];

    const result = deduplicateFindings(findings);
    expect(result).toHaveLength(3);
    // Order: XSS(5), SQL(3), CMD(1) — original relative order preserved
    const types = result.map((f) => f.type);
    expect(types).toEqual(['XSS', 'SQL_INJECTION', 'COMMAND_INJECTION']);
  });
});

describe('deduplicateFindings — different files', () => {
  it('does NOT collapse findings of the same type on the same line in different files', () => {
    const findings = [
      makeFinding({ type: 'SQL_INJECTION', line: 10, file: 'a.ts', confidence: 0.9 }),
      makeFinding({ type: 'SQL_INJECTION', line: 10, file: 'b.ts', confidence: 0.9 }),
    ];

    const result = deduplicateFindings(findings);
    expect(result).toHaveLength(2);
  });
});
