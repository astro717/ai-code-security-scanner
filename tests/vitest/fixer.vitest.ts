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

  test('returns true for SQL_INJECTION', () => {
    expect(isFixable('SQL_INJECTION')).toBe(true);
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
  test('returns applied=true for .py files with EVAL_INJECTION', () => {
    const filePath = writeTempFile('script.py', 'x = eval(input())\n');
    const finding = makeFinding({ type: 'EVAL_INJECTION', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(true);
  });
});

// ── Kotlin and Ruby extension guard ──────────────────────────────────────────

describe('applyFixes — .kt and .rb extension support', () => {
  test('processes (does not skip) a finding in a .kt file', () => {
    // INSECURE_RANDOM — replace Math.random() equivalent; the file is processed
    // because .kt is now in FIXABLE_EXTENSIONS.
    const code = 'val token = Math.random()\n';
    const filePath = writeTempFile('utils.kt', code);
    const finding = makeFinding({ type: 'INSECURE_RANDOM', line: 1, file: filePath });

    // applyFixes should attempt the fix (not return an empty array due to extension guard)
    const results = applyFixes([finding], false);
    expect(results).toHaveLength(1);
  });

  test('processes (does not skip) a finding in a .kts file', () => {
    const code = 'val token = Math.random()\n';
    const filePath = writeTempFile('build.kts', code);
    const finding = makeFinding({ type: 'INSECURE_RANDOM', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results).toHaveLength(1);
  });

  test('processes (does not skip) a finding in a .rb file', () => {
    const code = "token = rand\n";
    const filePath = writeTempFile('util.rb', code);
    const finding = makeFinding({ type: 'INSECURE_RANDOM', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results).toHaveLength(1);
  });

  test('returns applied=false for an unsupported extension such as .go', () => {
    const code = 'token := rand.Float64()\n';
    const filePath = writeTempFile('util.go', code);
    const finding = makeFinding({ type: 'INSECURE_RANDOM', line: 1, file: filePath });

    // .go is not in FIXABLE_EXTENSIONS — applyFixes returns a result with applied=false
    const results = applyFixes([finding], false);
    expect(results).toHaveLength(1);
    expect(results[0]!.applied).toBe(false);
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

// ── LDAP_INJECTION fixes ──────────────────────────────────────────────────────

describe('applyFixes — LDAP_INJECTION', () => {
  test('isFixable returns true for LDAP_INJECTION', () => {
    expect(isFixable('LDAP_INJECTION')).toBe(true);
  });

  test('returns applied=false (note-only rule — language-specific escaping required)', () => {
    const code = 'String query = "(&(uid=" + userId + "))";\n';
    const filePath = writeTempFile('ldap.ts', code);
    const finding = makeFinding({ type: 'LDAP_INJECTION', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(false);
    expect(results[0]!.description).toMatch(/LDAP/i);
  });
});

// ── XML_INJECTION fixes ───────────────────────────────────────────────────────

describe('applyFixes — XML_INJECTION', () => {
  test('isFixable returns true for XML_INJECTION', () => {
    expect(isFixable('XML_INJECTION')).toBe(true);
  });

  test('returns applied=false (note-only rule — import swap required)', () => {
    const code = 'import xml.etree.ElementTree as ET\n';
    const filePath = writeTempFile('xml.ts', code);
    const finding = makeFinding({ type: 'XML_INJECTION', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(false);
    expect(results[0]!.description).toMatch(/defusedxml|external entities/i);
  });
});

// ── INSECURE_ASSERT fixes ─────────────────────────────────────────────────────

describe('applyFixes — INSECURE_ASSERT', () => {
  test('isFixable returns true for INSECURE_ASSERT', () => {
    expect(isFixable('INSECURE_ASSERT')).toBe(true);
  });

  test('replaces Python assert line with if/raise', () => {
    const code = '    assert user.is_admin, "Not admin"\n';
    const filePath = writeTempFile('assert.ts', code);
    const finding = makeFinding({ type: 'INSECURE_ASSERT', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(true);

    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain('if not (');
    expect(updated).toContain('raise ValueError(');
    expect(updated).not.toContain('assert user.is_admin');
  });

  test('dry-run does NOT write the file', () => {
    const code = '    assert user.is_admin, "Not admin"\n';
    const filePath = writeTempFile('assert-dry.ts', code);
    const finding = makeFinding({ type: 'INSECURE_ASSERT', line: 1, file: filePath });

    const results = applyFixes([finding], true);
    expect(results[0]!.applied).toBe(true);

    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain('assert user.is_admin');
  });
});

// ── INSECURE_BINDING fixes ────────────────────────────────────────────────────

describe('applyFixes — INSECURE_BINDING', () => {
  test('isFixable returns true for INSECURE_BINDING', () => {
    expect(isFixable('INSECURE_BINDING')).toBe(true);
  });

  test("replaces '0.0.0.0' with '127.0.0.1' on the flagged line", () => {
    const code = "app.run(host='0.0.0.0', port=5000)\n";
    const filePath = writeTempFile('binding.ts', code);
    const finding = makeFinding({ type: 'INSECURE_BINDING', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(true);

    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain("'127.0.0.1'");
    expect(updated).not.toContain("'0.0.0.0'");
  });

  test('returns applied=false when 0.0.0.0 is not present on the line', () => {
    const code = "app.run(host='localhost', port=5000)\n";
    const filePath = writeTempFile('binding-safe.ts', code);
    const finding = makeFinding({ type: 'INSECURE_BINDING', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(false);
  });
});

// ── MASS_ASSIGNMENT fixes ─────────────────────────────────────────────────────

describe('applyFixes — MASS_ASSIGNMENT', () => {
  test('isFixable returns true for MASS_ASSIGNMENT', () => {
    expect(isFixable('MASS_ASSIGNMENT')).toBe(true);
  });

  test('returns applied=false (note-only rule — manual parameter specification required)', () => {
    const code = 'params.permit(:all)\n';
    const filePath = writeTempFile('mass.ts', code);
    const finding = makeFinding({ type: 'MASS_ASSIGNMENT', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(false);
    expect(results[0]!.description).toMatch(/permit\(:all\)|specify allowed/i);
  });
});

// ── PATH_TRAVERSAL fixes ──────────────────────────────────────────────────────

describe('isFixable — PATH_TRAVERSAL', () => {
  test('returns true for PATH_TRAVERSAL', () => {
    expect(isFixable('PATH_TRAVERSAL')).toBe(true);
  });
});

describe('applyFixes — PATH_TRAVERSAL', () => {
  test('wraps fs.readFile first argument with path.normalize()', () => {
    const code = "const data = fs.readFile(userInput, 'utf-8');\n";
    const filePath = writeTempFile('traversal.ts', code);
    const finding = makeFinding({ type: 'PATH_TRAVERSAL', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(true);

    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain('path.normalize(userInput)');
    expect(updated).not.toMatch(/fs\.readFile\s*\(\s*userInput\s*,/);
  });

  test('wraps fs.readFileSync first argument with path.normalize()', () => {
    const code = 'const content = fs.readFileSync(filePath);\n';
    const filePath = writeTempFile('traversal-sync.ts', code);
    const finding = makeFinding({ type: 'PATH_TRAVERSAL', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(true);

    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain('path.normalize(filePath)');
  });

  test('wraps path.join() call with path.normalize()', () => {
    const code = 'const full = path.join(baseDir, userInput);\n';
    const filePath = writeTempFile('traversal-join.ts', code);
    const finding = makeFinding({ type: 'PATH_TRAVERSAL', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(true);

    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain('path.normalize(path.join(');
  });

  test('dry-run does NOT write the file', () => {
    const code = "const data = fs.readFile(userInput, 'utf-8');\n";
    const filePath = writeTempFile('traversal-dry.ts', code);
    const finding = makeFinding({ type: 'PATH_TRAVERSAL', line: 1, file: filePath });

    const results = applyFixes([finding], true);
    expect(results[0]!.applied).toBe(true);

    // File must remain unchanged in dry-run
    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain('fs.readFile(userInput');
    expect(updated).not.toContain('path.normalize');
  });

  test('does NOT double-wrap if path.normalize already present', () => {
    const code = 'const data = fs.readFile(path.normalize(userInput));\n';
    const filePath = writeTempFile('traversal-already-fixed.ts', code);
    const finding = makeFinding({ type: 'PATH_TRAVERSAL', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    // Should not apply — already has path.normalize
    expect(results[0]!.applied).toBe(false);
  });

  test('does NOT fix string literal path arguments', () => {
    const code = "const data = fs.readFile('/etc/passwd');\n";
    const filePath = writeTempFile('traversal-literal.ts', code);
    const finding = makeFinding({ type: 'PATH_TRAVERSAL', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    // String literals are not dynamic — the fix should not apply
    expect(results[0]!.applied).toBe(false);
  });

  test('returns applied=false for .cs files (C# requires manual fix)', () => {
    const code = 'File.ReadAllText(userPath);\n';
    const filePath = writeTempFile('traversal.cs', code);
    const finding = makeFinding({ type: 'PATH_TRAVERSAL', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(false);
  });

  test('returns applied=false for .py files (Python normpath is note-only)', () => {
    const code = "open(user_path, 'r')\n";
    const filePath = writeTempFile('traversal.py', code);
    const finding = makeFinding({ type: 'PATH_TRAVERSAL', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results[0]!.applied).toBe(false);
  });
});

// ── .kt and .rb extension guard ───────────────────────────────────────────────

describe('applyFixes — .kt and .rb files are processed (not skipped)', () => {
  test('processes INSECURE_RANDOM finding in a .kt file', () => {
    const code = 'val token = Math.random();\n';
    const filePath = writeTempFile('insecure.kt', code);
    const finding = makeFinding({ type: 'INSECURE_RANDOM', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results).toHaveLength(1);
    expect(results[0]!.applied).toBe(true);

    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain('crypto.randomBytes(32)');
    expect(updated).not.toContain('Math.random()');
  });

  test('processes WEAK_CRYPTO finding in a .rb file', () => {
    const code = "h = crypto.createHash('md5').digest('hex');\n";
    const filePath = writeTempFile('weak.rb', code);
    const finding = makeFinding({ type: 'WEAK_CRYPTO', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results).toHaveLength(1);
    expect(results[0]!.applied).toBe(true);

    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain("createHash('sha256')");
    expect(updated).not.toContain("createHash('md5')");
  });

  test('processes EVAL_INJECTION finding in a .kts file', () => {
    const code = 'val data = eval(userInput);\n';
    const filePath = writeTempFile('script.kts', code);
    const finding = makeFinding({ type: 'EVAL_INJECTION', line: 1, file: filePath });

    const results = applyFixes([finding], false);
    expect(results).toHaveLength(1);
    expect(results[0]!.applied).toBe(true);

    const updated = fs.readFileSync(filePath, 'utf-8');
    expect(updated).toContain('JSON.parse(userInput)');
    expect(updated).not.toContain('eval(');
  });
});
