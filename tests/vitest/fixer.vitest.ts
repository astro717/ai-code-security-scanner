/**
 * Unit tests for the auto-remediation fixer module (--fix flag).
 */

import { describe, test, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { applyFixes, isFixable } from '../../src/scanner/fixer';
import type { Finding } from '../../src/scanner/reporter';

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<Finding> & { type: string; line: number }): Finding {
  return {
    severity: 'medium',
    column: 0,
    message: 'test finding',
    ...overrides,
  };
}

function writeTempFile(name: string, content: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fixer-test-'));
  const filePath = path.join(dir, name);
  fs.writeFileSync(filePath, content, 'utf-8');
  return filePath;
}

// ── isFixable ─────────────────────────────────────────────────────────────────

describe('isFixable', () => {
  test('returns true for INSECURE_RANDOM', () => {
    expect(isFixable('INSECURE_RANDOM')).toBe(true);
  });

  test('returns true for EVAL_INJECTION', () => {
    expect(isFixable('EVAL_INJECTION')).toBe(true);
  });

  test('returns false for SQL_INJECTION', () => {
    expect(isFixable('SQL_INJECTION')).toBe(false);
  });

  test('returns false for unknown types', () => {
    expect(isFixable('NONEXISTENT_TYPE')).toBe(false);
  });
});

// ── INSECURE_RANDOM fixes ─────────────────────────────────────────────────────

describe('applyFixes — INSECURE_RANDOM', () => {
  test('replaces Math.random() with crypto.randomBytes on the flagged line', () => {
    const code = [
      'const token = Math.random();',
      'console.log(token);',
    ].join('\n');
    const filePath = writeTempFile('insecure.ts', code);
    const finding = makeFinding({ type: 'INSECURE_RANDOM', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results).toHaveLength(1);
    expect(results[0]!.applied).toBe(true);

    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain('crypto.randomBytes(32)');
    expect(updated).not.toContain('Math.random()');
    // Line 2 untouched
    expect(updated).toContain('console.log(token)');
  });

  test('dry-run mode does NOT write the file', () => {
    const code = 'const token = Math.random();\n';
    const filePath = writeTempFile('insecure-dry.ts', code);
    const finding = makeFinding({ type: 'INSECURE_RANDOM', line: 1, file: filePath });

    const results = applyFixes([finding], true);
    expect(results[0]!.applied).toBe(true);

    // File should remain unchanged
    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain('Math.random()');
  });

  test('returns applied=false when Math.random() is not on the flagged line', () => {
    const code = 'const x = 42;\n';
    const filePath = writeTempFile('no-random.ts', code);
    const finding = makeFinding({ type: 'INSECURE_RANDOM', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(false);
  });
});

// ── EVAL_INJECTION fixes ──────────────────────────────────────────────────────

describe('applyFixes — EVAL_INJECTION', () => {
  test('replaces eval(variable) with JSON.parse(variable)', () => {
    const code = 'const data = eval(userInput);\n';
    const filePath = writeTempFile('eval.ts', code);
    const finding = makeFinding({ type: 'EVAL_INJECTION', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(true);

    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain('JSON.parse(userInput)');
    expect(updated).not.toContain('eval(');
  });

  test('does NOT replace eval with a string literal argument', () => {
    const code = "const r = eval('1+1');\n";
    const filePath = writeTempFile('eval-literal.ts', code);
    const finding = makeFinding({ type: 'EVAL_INJECTION', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    // Should NOT be applied — literal eval is not a dynamic injection
    expect(results[0]!.applied).toBe(false);
  });
});

// ── Non-JS/TS files ───────────────────────────────────────────────────────────

describe('applyFixes — unsupported file types', () => {
  test('returns applied=false for .py files', () => {
    const filePath = writeTempFile('script.py', 'x = eval(input())\n');
    const finding = makeFinding({ type: 'EVAL_INJECTION', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(false);
    expect(results[0]!.description).toMatch(/not supported/i);
  });
});

// ── Missing files ─────────────────────────────────────────────────────────────

describe('applyFixes — edge cases', () => {
  test('returns applied=false for a non-existent file path', () => {
    const finding = makeFinding({ type: 'INSECURE_RANDOM', line: 1, file: '/tmp/does-not-exist-xyz.ts' });
    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(false);
  });

  test('skips findings without a file property', () => {
    const finding = makeFinding({ type: 'INSECURE_RANDOM', line: 1 });
    const results = applyFixes([finding], false);
    expect(results).toHaveLength(0);
  });

  test('no-op findings list returns empty results', () => {
    const results = applyFixes([], false);
    expect(results).toHaveLength(0);
  });
});
