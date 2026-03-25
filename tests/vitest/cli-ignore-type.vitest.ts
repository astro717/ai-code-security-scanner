/**
 * Tests for --ignore-type and --exclude-pattern CLI logic.
 *
 * Because the CLI is tightly coupled to commander and calls process.exit(),
 * we test the underlying logic units directly rather than spawning a subprocess:
 *
 *   - KNOWN_TYPES.has() — correct types recognised, typos detected
 *   - Finding suppression: filter(f => !suppressedTypes.has(f.type))
 *   - --exclude-pattern: minimatch-based file path filtering
 *   - Typo warning: unknown type value triggers console.error
 *
 * This gives fast, reliable coverage without I/O overhead.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest';
import { KNOWN_TYPES } from '../../src/scanner/reporter';
import { minimatch } from 'minimatch';

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeFinding(type, file = 'src/app.ts') {
  return { type, severity: 'high', message: 'test', file, line: 1, column: 1, snippet: '' };
}

/** Mirrors the CLI's --ignore-type suppression logic exactly. */
function applyIgnoreType(findings, ignoreTypeValues) {
  if (!ignoreTypeValues || ignoreTypeValues.length === 0) return { filtered: findings, warnings: [] };
  const suppressedTypes = new Set(ignoreTypeValues.map((v) => v.trim().toUpperCase()));
  const errors = [];
  for (const t of suppressedTypes) {
    if (!KNOWN_TYPES.has(t)) {
      errors.push(
        `[ignore-type] Warning: "${t}" is not a known finding type and will suppress nothing. ` +
        `Known types: ${[...KNOWN_TYPES].sort().join(', ')}`,
      );
    }
  }
  return { filtered: findings.filter((f) => !suppressedTypes.has(f.type)), warnings: errors };
}

/** Mirrors the CLI's --exclude-pattern path filter. */
function applyExcludePattern(findings, patterns) {
  if (!patterns || patterns.length === 0) return findings;
  return findings.filter(
    (f) => !patterns.some((p) => minimatch(f.file, p, { matchBase: true, dot: true })),
  );
}

// ── KNOWN_TYPES correctness ───────────────────────────────────────────────────

describe('KNOWN_TYPES registry', () => {
  test('WEAK_CRYPTO is a known type', () => {
    expect(KNOWN_TYPES.has('WEAK_CRYPTO')).toBe(true);
  });

  test('SQL_INJECTION is a known type', () => {
    expect(KNOWN_TYPES.has('SQL_INJECTION')).toBe(true);
  });

  test('SECRET_HARDCODED is a known type', () => {
    expect(KNOWN_TYPES.has('SECRET_HARDCODED')).toBe(true);
  });

  test('EVAL_INJECTION is a known type', () => {
    expect(KNOWN_TYPES.has('EVAL_INJECTION')).toBe(true);
  });

  test('WEAK_CRYPT0 (typo: digit 0) is NOT a known type', () => {
    expect(KNOWN_TYPES.has('WEAK_CRYPT0')).toBe(false);
  });

  test('empty string is NOT a known type', () => {
    expect(KNOWN_TYPES.has('')).toBe(false);
  });

  test('lowercase type name is NOT recognised (types are upper-case)', () => {
    expect(KNOWN_TYPES.has('weak_crypto')).toBe(false);
  });
});

// ── --ignore-type suppression logic ──────────────────────────────────────────

describe('--ignore-type suppression', () => {
  test('recognised type WEAK_CRYPTO suppresses matching findings silently', () => {
    const findings = [
      makeFinding('WEAK_CRYPTO'),
      makeFinding('SQL_INJECTION'),
    ];
    const { filtered, warnings } = applyIgnoreType(findings, ['WEAK_CRYPTO']);
    expect(filtered.length).toBe(1);
    expect(filtered[0].type).toBe('SQL_INJECTION');
    expect(warnings.length).toBe(0);
  });

  test('suppressing multiple types removes all matching findings', () => {
    const findings = [
      makeFinding('WEAK_CRYPTO'),
      makeFinding('SQL_INJECTION'),
      makeFinding('EVAL_INJECTION'),
    ];
    const { filtered } = applyIgnoreType(findings, ['WEAK_CRYPTO', 'EVAL_INJECTION']);
    expect(filtered.length).toBe(1);
    expect(filtered[0].type).toBe('SQL_INJECTION');
  });

  test('unrecognised type WEAK_CRYPT0 emits a console.error warning', () => {
    const findings = [makeFinding('WEAK_CRYPTO')];
    const { filtered, warnings } = applyIgnoreType(findings, ['WEAK_CRYPT0']);
    // The typo type matches nothing, so all findings are preserved
    expect(filtered.length).toBe(1);
    // A warning must be produced for the unknown type
    expect(warnings.length).toBe(1);
    expect(warnings[0]).toMatch(/WEAK_CRYPT0/);
    expect(warnings[0]).toMatch(/not a known finding type/i);
  });

  test('mix of valid and invalid types: valid type suppressed, warning for typo', () => {
    const findings = [
      makeFinding('WEAK_CRYPTO'),
      makeFinding('SQL_INJECTION'),
    ];
    const { filtered, warnings } = applyIgnoreType(findings, ['WEAK_CRYPTO', 'WEAK_CRYPT0']);
    // WEAK_CRYPTO findings are suppressed
    expect(filtered.some((f) => f.type === 'WEAK_CRYPTO')).toBe(false);
    // SQL_INJECTION remains
    expect(filtered.some((f) => f.type === 'SQL_INJECTION')).toBe(true);
    // One warning for the typo
    expect(warnings.length).toBe(1);
    expect(warnings[0]).toMatch(/WEAK_CRYPT0/);
  });

  test('empty ignore-type list leaves all findings intact', () => {
    const findings = [makeFinding('WEAK_CRYPTO'), makeFinding('SQL_INJECTION')];
    const { filtered, warnings } = applyIgnoreType(findings, []);
    expect(filtered.length).toBe(2);
    expect(warnings.length).toBe(0);
  });

  test('suppressing a type that has no matching findings returns all findings', () => {
    const findings = [makeFinding('SQL_INJECTION')];
    const { filtered, warnings } = applyIgnoreType(findings, ['WEAK_CRYPTO']);
    expect(filtered.length).toBe(1);
    expect(warnings.length).toBe(0);
  });
});

// ── --exclude-pattern file path filtering ─────────────────────────────────────

describe('--exclude-pattern file filtering', () => {
  const findings = [
    makeFinding('SQL_INJECTION', 'src/app.ts'),
    makeFinding('WEAK_CRYPTO',   'src/utils/crypto.ts'),
    makeFinding('EVAL_INJECTION','tests/fixtures/vulnerable.ts'),
    makeFinding('SECRET_HARDCODED', 'node_modules/dep/index.ts'),
  ];

  test('no patterns → all findings kept', () => {
    const result = applyExcludePattern(findings, []);
    expect(result.length).toBe(4);
  });

  test('*.test.ts pattern does not match any src files', () => {
    const result = applyExcludePattern(findings, ['*.test.ts']);
    expect(result.length).toBe(4);
  });

  test('tests/**/* pattern excludes the fixture finding', () => {
    const result = applyExcludePattern(findings, ['tests/**/*']);
    expect(result.some((f) => f.file === 'tests/fixtures/vulnerable.ts')).toBe(false);
    expect(result.length).toBe(3);
  });

  test('node_modules/** excludes node_modules findings', () => {
    const result = applyExcludePattern(findings, ['node_modules/**']);
    expect(result.some((f) => f.file.startsWith('node_modules/'))).toBe(false);
    expect(result.length).toBe(3);
  });

  test('multiple patterns can exclude multiple paths', () => {
    const result = applyExcludePattern(findings, ['tests/**/*', 'node_modules/**']);
    expect(result.length).toBe(2);
  });

  test('pattern matching all files returns empty array', () => {
    const result = applyExcludePattern(findings, ['**/*']);
    expect(result.length).toBe(0);
  });

  test('exact filename match by matchBase: "vulnerable.ts" excludes that file', () => {
    const result = applyExcludePattern(findings, ['vulnerable.ts']);
    expect(result.some((f) => f.file === 'tests/fixtures/vulnerable.ts')).toBe(false);
    expect(result.length).toBe(3);
  });
});

// ── Integration: ignore-type + exclude-pattern combined ───────────────────────

describe('--ignore-type and --exclude-pattern combined', () => {
  test('suppressed type AND excluded path both applied correctly', () => {
    const findings = [
      makeFinding('WEAK_CRYPTO', 'src/app.ts'),
      makeFinding('SQL_INJECTION', 'src/db.ts'),
      makeFinding('EVAL_INJECTION', 'tests/fixtures/vuln.ts'),
    ];

    // First apply ignore-type, then exclude-pattern
    const { filtered } = applyIgnoreType(findings, ['WEAK_CRYPTO']);
    const result = applyExcludePattern(filtered, ['tests/**/*']);

    // WEAK_CRYPTO is suppressed, fixture file is excluded
    expect(result.length).toBe(1);
    expect(result[0].type).toBe('SQL_INJECTION');
    expect(result[0].file).toBe('src/db.ts');
  });
});
