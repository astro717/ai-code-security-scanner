/**
 * Unit tests for the auto-remediation fixer module (--fix flag).
 */

import { describe, test, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { applyFixes, isFixable, buildUnifiedDiff } from '../../src/scanner/fixer';
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

  test('returns true for WEAK_CRYPTO', () => {
    expect(isFixable('WEAK_CRYPTO')).toBe(true);
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

// ── WEAK_CRYPTO fixes ────────────────────────────────────────────────────────

describe('applyFixes — WEAK_CRYPTO', () => {
  test('replaces createHash(\'md5\') with createHash(\'sha256\')', () => {
    const code = "const hash = crypto.createHash('md5').update(data).digest('hex');\n";
    const filePath = writeTempFile('weak-md5.ts', code);
    const finding = makeFinding({ type: 'WEAK_CRYPTO', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(true);

    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain("createHash('sha256')");
    expect(updated).not.toContain("createHash('md5')");
  });

  test('replaces createHash(\'sha1\') with createHash(\'sha256\')', () => {
    const code = "const h = crypto.createHash('sha1').digest();\n";
    const filePath = writeTempFile('weak-sha1.ts', code);
    const finding = makeFinding({ type: 'WEAK_CRYPTO', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(true);

    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain("createHash('sha256')");
    expect(updated).not.toContain("createHash('sha1')");
  });

  test('dry-run mode does NOT write the file', () => {
    const code = "const hash = crypto.createHash('md5').update(data).digest('hex');\n";
    const filePath = writeTempFile('weak-dry.ts', code);
    const finding = makeFinding({ type: 'WEAK_CRYPTO', line: 1, file: filePath });

    const results = applyFixes([finding], true);
    expect(results[0]!.applied).toBe(true);

    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain("createHash('md5')");
  });

  test("replaces createHash('md4') with createHash('sha256')", () => {
    const code = "const h = crypto.createHash('md4').digest('hex');\n";
    const filePath = writeTempFile('weak-md4.ts', code);
    const finding = makeFinding({ type: 'WEAK_CRYPTO', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(true);

    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain("createHash('sha256')");
    expect(updated).not.toContain("createHash('md4')");
  });

  test("replaces createHash('sha-1') with createHash('sha256')", () => {
    const code = "const h = crypto.createHash('sha-1').digest();\n";
    const filePath = writeTempFile('weak-sha-1.ts', code);
    const finding = makeFinding({ type: 'WEAK_CRYPTO', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(true);

    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain("createHash('sha256')");
    expect(updated).not.toContain("createHash('sha-1')");
  });

  test('handles double-quoted algorithm strings', () => {
    const code = 'const h = crypto.createHash("md5").digest("hex");\n';
    const filePath = writeTempFile('weak-dquote.ts', code);
    const finding = makeFinding({ type: 'WEAK_CRYPTO', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(true);

    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain("createHash('sha256')");
  });
});

// ── XSS fixes ────────────────────────────────────────────────────────────────

describe('applyFixes — XSS', () => {
  test('replaces .innerHTML = with .textContent =', () => {
    const code = 'element.innerHTML = userInput;\n';
    const filePath = writeTempFile('xss.ts', code);
    const finding = makeFinding({ type: 'XSS', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(true);

    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain('.textContent =');
    expect(updated).not.toContain('.innerHTML =');
  });

  test('returns applied=false when innerHTML is not on the line', () => {
    const code = 'element.textContent = safe;\n';
    const filePath = writeTempFile('no-xss.ts', code);
    const finding = makeFinding({ type: 'XSS', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(false);
  });
});

// ── JWT_NONE_ALGORITHM fixes ─────────────────────────────────────────────────

describe('applyFixes — JWT_NONE_ALGORITHM', () => {
  test("inserts { algorithms: ['HS256'] } when jwt.verify has no 3rd argument", () => {
    const code = "const payload = jwt.verify(token, secret);\n";
    const filePath = writeTempFile('jwt-no-opts.ts', code);
    const finding = makeFinding({ type: 'JWT_NONE_ALGORITHM', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(true);

    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain("{ algorithms: ['HS256'] }");
  });

  test("replaces algorithms: ['none'] with algorithms: ['HS256']", () => {
    const code = "const p = jwt.verify(token, secret, { algorithms: ['none'] });\n";
    const filePath = writeTempFile('jwt-none-alg.ts', code);
    const finding = makeFinding({ type: 'JWT_NONE_ALGORITHM', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(true);

    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain("algorithms: ['HS256']");
    expect(updated).not.toContain("algorithms: ['none']");
  });

  test('isFixable returns true for JWT_NONE_ALGORITHM', () => {
    expect(isFixable('JWT_NONE_ALGORITHM')).toBe(true);
  });

  test('dry-run does NOT write the file', () => {
    const code = "const p = jwt.verify(token, secret, { algorithms: ['none'] });\n";
    const filePath = writeTempFile('jwt-dry.ts', code);
    const finding = makeFinding({ type: 'JWT_NONE_ALGORITHM', line: 1, file: filePath });

    const results = applyFixes([finding], true);
    expect(results[0]!.applied).toBe(true);

    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain("algorithms: ['none']");
  });
});

// ── INSECURE_RANDOM crypto import insertion ──────────────────────────────────

describe('applyFixes — INSECURE_RANDOM crypto import', () => {
  test('inserts crypto import when missing after fixing INSECURE_RANDOM', () => {
    const code = 'const token = Math.random();\nconsole.log(token);\n';
    const filePath = writeTempFile('no-import.ts', code);
    const finding = makeFinding({ type: 'INSECURE_RANDOM', line: 1, file: filePath });

    applyFixes([finding], false);

    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain("import crypto from 'crypto'");
    expect(updated).toContain('crypto.randomBytes(32)');
  });

  test('does NOT insert crypto import when already present', () => {
    const code = "import crypto from 'crypto';\nconst token = Math.random();\n";
    const filePath = writeTempFile('has-import.ts', code);
    const finding = makeFinding({ type: 'INSECURE_RANDOM', line: 2, file: filePath });

    applyFixes([finding], false);

    const updated = fs.readFileSync(filePath, 'utf-8');
    const importCount = (updated.match(/import crypto/g) || []).length;
    expect(importCount).toBe(1);
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

// ── JWT_DECODE_NO_VERIFY fixes ────────────────────────────────────────────────

describe('isFixable — JWT_DECODE_NO_VERIFY', () => {
  test('returns true for JWT_DECODE_NO_VERIFY', () => {
    expect(isFixable('JWT_DECODE_NO_VERIFY')).toBe(true);
  });
});

describe('applyFixes — JWT_DECODE_NO_VERIFY', () => {
  test('replaces jwt.decode(token) with jwt.verify using process.env.JWT_SECRET', () => {
    const code = 'const payload = jwt.decode(token);\n';
    const filePath = writeTempFile('jwt-decode.ts', code);
    const finding = makeFinding({ type: 'JWT_DECODE_NO_VERIFY', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results).toHaveLength(1);
    expect(results[0]!.applied).toBe(true);

    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain('jwt.verify(');
    expect(updated).toContain('process.env.JWT_SECRET');
    expect(updated).toContain("algorithms: ['HS256']");
    expect(updated).not.toContain('jwt.decode(');
  });

  test('dry-run does NOT write the file', () => {
    const code = 'const payload = jwt.decode(token);\n';
    const filePath = writeTempFile('jwt-decode-dry.ts', code);
    const finding = makeFinding({ type: 'JWT_DECODE_NO_VERIFY', line: 1, file: filePath });

    const results = applyFixes([finding], true);
    expect(results[0]!.applied).toBe(true);

    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain('jwt.decode(');
  });

  test('returns applied=false when jwt.decode is not on the flagged line', () => {
    const code = 'const x = someOtherCall(token);\n';
    const filePath = writeTempFile('jwt-no-decode.ts', code);
    const finding = makeFinding({ type: 'JWT_DECODE_NO_VERIFY', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(false);
  });

  test('replaces jwt.decode with spaces in the call expression', () => {
    const code = 'const p = jwt.decode( token );\n';
    const filePath = writeTempFile('jwt-decode-spaces.ts', code);
    const finding = makeFinding({ type: 'JWT_DECODE_NO_VERIFY', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(true);

    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain('jwt.verify(');
  });
});

// ── buildUnifiedDiff ──────────────────────────────────────────────────────────

describe('buildUnifiedDiff', () => {
  test('produces --- a/ and +++ b/ headers for an applied fix', () => {
    const code = 'const token = Math.random();\nconsole.log(token);\n';
    const filePath = writeTempFile('diff-test.ts', code);
    const finding = makeFinding({ type: 'INSECURE_RANDOM', line: 1, file: filePath });

    const results = applyFixes([finding], true);
    const diff = buildUnifiedDiff(results);

    expect(diff).toContain(`--- a/${filePath}`);
    expect(diff).toContain(`+++ b/${filePath}`);
  });

  test('produces @@ hunk markers', () => {
    const code = 'const token = Math.random();\nconsole.log(token);\n';
    const filePath = writeTempFile('diff-hunk.ts', code);
    const finding = makeFinding({ type: 'INSECURE_RANDOM', line: 1, file: filePath });

    const results = applyFixes([finding], true);
    const diff = buildUnifiedDiff(results);

    expect(diff).toMatch(/^@@.+@@/m);
  });

  test('excludes non-applied fix results from the diff', () => {
    const code = 'const x = 42;\n';
    const filePath = writeTempFile('diff-no-apply.ts', code);
    const finding = makeFinding({ type: 'INSECURE_RANDOM', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(false);

    const diff = buildUnifiedDiff(results);
    expect(diff).toBe('');
  });

  test('includes 3 context lines before and after the changed line', () => {
    const code = 'line1\nline2\nline3\nconst token = Math.random();\nline5\nline6\nline7\n';
    const filePath = writeTempFile('diff-context.ts', code);
    const finding = makeFinding({ type: 'INSECURE_RANDOM', line: 4, file: filePath });

    const results = applyFixes([finding], true);
    const diff = buildUnifiedDiff(results);

    expect(diff).toContain(' line1');
    expect(diff).toContain(' line2');
    expect(diff).toContain(' line3');
    expect(diff).toContain(' line5');
    expect(diff).toContain(' line6');
    expect(diff).toContain(' line7');
    expect(diff).toContain('-const token = Math.random();');
    expect(diff).toContain('+const token = crypto.randomBytes(32)');
  });

  test('returns empty string when results array is empty', () => {
    const diff = buildUnifiedDiff([]);
    expect(diff).toBe('');
  });
});
