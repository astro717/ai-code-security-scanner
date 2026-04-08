/**
 * Tests for --ignore-type with C#-specific finding types.
 *
 * Covers:
 *   - SQL_INJECTION_CS is a known type and can be suppressed
 *   - PATH_TRAVERSAL_CS is a known type and can be suppressed
 *   - Suppressing SQL_INJECTION_CS does not suppress SQL_INJECTION for other languages
 *   - Suppressing PATH_TRAVERSAL_CS does not suppress PATH_TRAVERSAL
 *   - --exclude-pattern can filter .cs files entirely
 *   - Typo SQL_INJECTION_C# (invalid) triggers an unknown-type warning
 */

import { describe, test, expect } from 'vitest';
import { KNOWN_TYPES } from '../../src/scanner/reporter';
import { minimatch } from 'minimatch';

// ── Helpers (mirror CLI logic exactly) ────────────────────────────────────────

function makeFinding(
  type: string,
  file = 'src/App.cs',
  severity: 'critical' | 'high' | 'medium' | 'low' = 'high',
) {
  return { type, severity, message: 'test', file, line: 1, column: 1, snippet: '' };
}

function applyIgnoreType(
  findings: ReturnType<typeof makeFinding>[],
  ignoreTypeValues: string[],
): { filtered: ReturnType<typeof makeFinding>[]; warnings: string[] } {
  if (!ignoreTypeValues || ignoreTypeValues.length === 0) {
    return { filtered: findings, warnings: [] };
  }
  const suppressedTypes = new Set(ignoreTypeValues.map((v) => v.trim().toUpperCase()));
  const warnings: string[] = [];
  for (const t of suppressedTypes) {
    if (!KNOWN_TYPES.has(t)) {
      warnings.push(
        `[ignore-type] Warning: "${t}" is not a known finding type and will suppress nothing. ` +
        `Known types: ${[...KNOWN_TYPES].sort().join(', ')}`,
      );
    }
  }
  return {
    filtered: findings.filter((f) => !suppressedTypes.has(f.type)),
    warnings,
  };
}

function applyExcludePattern(
  findings: ReturnType<typeof makeFinding>[],
  patterns: string[],
): ReturnType<typeof makeFinding>[] {
  if (!patterns || patterns.length === 0) return findings;
  return findings.filter(
    (f) => !patterns.some((p) => minimatch(f.file, p, { matchBase: true, dot: true })),
  );
}

// ── KNOWN_TYPES — C# types ────────────────────────────────────────────────────

describe('KNOWN_TYPES — C# specific types', () => {
  test('SQL_INJECTION_CS is registered', () => {
    expect(KNOWN_TYPES.has('SQL_INJECTION_CS')).toBe(true);
  });

  test('PATH_TRAVERSAL_CS is registered', () => {
    expect(KNOWN_TYPES.has('PATH_TRAVERSAL_CS')).toBe(true);
  });

  test('COMMAND_INJECTION_CS is registered', () => {
    expect(KNOWN_TYPES.has('COMMAND_INJECTION_CS')).toBe(true);
  });
});

// ── Suppression — SQL_INJECTION_CS ────────────────────────────────────────────

describe('--ignore-type SQL_INJECTION_CS', () => {
  const findings = [
    makeFinding('SQL_INJECTION_CS', 'src/Repo.cs'),
    makeFinding('SQL_INJECTION', 'src/app.py'),
    makeFinding('PATH_TRAVERSAL_CS', 'src/FileController.cs'),
  ];

  test('removes SQL_INJECTION_CS findings', () => {
    const { filtered } = applyIgnoreType(findings, ['SQL_INJECTION_CS']);
    expect(filtered.some((f) => f.type === 'SQL_INJECTION_CS')).toBe(false);
  });

  test('does NOT remove SQL_INJECTION (other language)', () => {
    const { filtered } = applyIgnoreType(findings, ['SQL_INJECTION_CS']);
    expect(filtered.some((f) => f.type === 'SQL_INJECTION')).toBe(true);
  });

  test('does NOT remove PATH_TRAVERSAL_CS', () => {
    const { filtered } = applyIgnoreType(findings, ['SQL_INJECTION_CS']);
    expect(filtered.some((f) => f.type === 'PATH_TRAVERSAL_CS')).toBe(true);
  });

  test('produces no warnings for a known type', () => {
    const { warnings } = applyIgnoreType(findings, ['SQL_INJECTION_CS']);
    expect(warnings).toHaveLength(0);
  });
});

// ── Suppression — PATH_TRAVERSAL_CS ──────────────────────────────────────────

describe('--ignore-type PATH_TRAVERSAL_CS', () => {
  const findings = [
    makeFinding('PATH_TRAVERSAL_CS', 'src/Upload.cs'),
    makeFinding('PATH_TRAVERSAL', 'src/handler.rb'),
    makeFinding('SQL_INJECTION_CS', 'src/DbUtil.cs'),
  ];

  test('removes PATH_TRAVERSAL_CS findings', () => {
    const { filtered } = applyIgnoreType(findings, ['PATH_TRAVERSAL_CS']);
    expect(filtered.some((f) => f.type === 'PATH_TRAVERSAL_CS')).toBe(false);
  });

  test('does NOT remove PATH_TRAVERSAL (other language)', () => {
    const { filtered } = applyIgnoreType(findings, ['PATH_TRAVERSAL_CS']);
    expect(filtered.some((f) => f.type === 'PATH_TRAVERSAL')).toBe(true);
  });

  test('does NOT remove SQL_INJECTION_CS', () => {
    const { filtered } = applyIgnoreType(findings, ['PATH_TRAVERSAL_CS']);
    expect(filtered.some((f) => f.type === 'SQL_INJECTION_CS')).toBe(true);
  });
});

// ── Multi-type suppression ────────────────────────────────────────────────────

describe('--ignore-type SQL_INJECTION_CS,PATH_TRAVERSAL_CS', () => {
  const findings = [
    makeFinding('SQL_INJECTION_CS', 'src/Repo.cs'),
    makeFinding('PATH_TRAVERSAL_CS', 'src/Upload.cs'),
    makeFinding('COMMAND_INJECTION_CS', 'src/Exec.cs'),
    makeFinding('SQL_INJECTION', 'src/app.py'),
  ];

  test('removes both C# types', () => {
    const { filtered } = applyIgnoreType(findings, ['SQL_INJECTION_CS', 'PATH_TRAVERSAL_CS']);
    expect(filtered.some((f) => f.type === 'SQL_INJECTION_CS')).toBe(false);
    expect(filtered.some((f) => f.type === 'PATH_TRAVERSAL_CS')).toBe(false);
  });

  test('retains COMMAND_INJECTION_CS', () => {
    const { filtered } = applyIgnoreType(findings, ['SQL_INJECTION_CS', 'PATH_TRAVERSAL_CS']);
    expect(filtered.some((f) => f.type === 'COMMAND_INJECTION_CS')).toBe(true);
  });

  test('retains SQL_INJECTION from other language', () => {
    const { filtered } = applyIgnoreType(findings, ['SQL_INJECTION_CS', 'PATH_TRAVERSAL_CS']);
    expect(filtered.some((f) => f.type === 'SQL_INJECTION')).toBe(true);
  });
});

// ── Unknown / typo type warning ───────────────────────────────────────────────

describe('--ignore-type with invalid C# type identifier', () => {
  const findings = [makeFinding('SQL_INJECTION_CS', 'src/Repo.cs')];

  test('SQL_INJECTION_C# produces an unknown-type warning', () => {
    // The CLI normalises to uppercase; '#' makes it an invalid type
    const { warnings } = applyIgnoreType(findings, ['SQL_INJECTION_C#']);
    expect(warnings.length).toBeGreaterThan(0);
    expect(warnings[0]).toContain('SQL_INJECTION_C#');
    expect(warnings[0]).toContain('not a known finding type');
  });

  test('SQLI_CS (typo) produces a warning', () => {
    const { warnings } = applyIgnoreType(findings, ['SQLI_CS']);
    expect(warnings.length).toBeGreaterThan(0);
    expect(warnings[0]).toContain('SQLI_CS');
  });

  test('SQL_INJECTION_CS (correct) produces no warning despite typo neighbour', () => {
    const { warnings } = applyIgnoreType(findings, ['SQL_INJECTION_CS', 'SQLI_CS']);
    // Only SQLI_CS should produce a warning — SQL_INJECTION_CS should not.
    // The SQLI_CS warning body includes the full known-types list which contains
    // SQL_INJECTION_CS, so we must check that NO warning specifically identifies
    // SQL_INJECTION_CS as the unknown type (i.e. it starts with "SQL_INJECTION_CS").
    expect(warnings.some((w) => w.includes('"SQL_INJECTION_CS" is not a known'))).toBe(false);
    expect(warnings.some((w) => w.includes('SQLI_CS'))).toBe(true);
  });
});

// ── --exclude-pattern .cs files ───────────────────────────────────────────────

describe('--exclude-pattern for .cs files', () => {
  const findings = [
    makeFinding('SQL_INJECTION_CS', 'src/Repo.cs'),
    makeFinding('PATH_TRAVERSAL_CS', 'src/Upload.cs'),
    makeFinding('SQL_INJECTION', 'src/app.py'),
    makeFinding('XSS', 'src/frontend.ts'),
  ];

  test('excludes .cs files entirely', () => {
    const filtered = applyExcludePattern(findings, ['**/*.cs']);
    expect(filtered.every((f) => !f.file.endsWith('.cs'))).toBe(true);
  });

  test('retains non-.cs findings after exclude', () => {
    const filtered = applyExcludePattern(findings, ['**/*.cs']);
    expect(filtered.some((f) => f.type === 'SQL_INJECTION')).toBe(true);
    expect(filtered.some((f) => f.type === 'XSS')).toBe(true);
  });

  test('path pattern src/Repo.cs excludes only that file', () => {
    const filtered = applyExcludePattern(findings, ['src/Repo.cs']);
    expect(filtered.some((f) => f.file === 'src/Repo.cs')).toBe(false);
    expect(filtered.some((f) => f.file === 'src/Upload.cs')).toBe(true);
  });
});

// ── Case-insensitive normalisation ────────────────────────────────────────────

describe('case-insensitive --ignore-type', () => {
  const findings = [makeFinding('SQL_INJECTION_CS', 'src/Repo.cs')];

  test('sql_injection_cs (lowercase) suppresses SQL_INJECTION_CS', () => {
    const { filtered } = applyIgnoreType(findings, ['sql_injection_cs']);
    expect(filtered).toHaveLength(0);
  });

  test('Sql_Injection_Cs (mixed case) suppresses SQL_INJECTION_CS', () => {
    const { filtered } = applyIgnoreType(findings, ['Sql_Injection_Cs']);
    expect(filtered).toHaveLength(0);
  });
});
