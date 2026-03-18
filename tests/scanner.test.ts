/**
 * Scanner test suite — run with: npx ts-node tests/scanner.test.ts
 *
 * Verifies that each detector:
 *   1) Produces ≥1 finding of the expected type on tests/fixtures/vulnerable.ts
 *   2) Produces 0 findings on tests/fixtures/clean.ts (no false positives)
 */

import * as path from 'path';
import * as fs from 'fs';
import { parseFile, parseCode } from '../src/scanner/parser';
import { detectSecrets } from '../src/scanner/detectors/secrets';
import { detectSQLInjection } from '../src/scanner/detectors/sql';
import { detectShellInjection } from '../src/scanner/detectors/shell';
import { detectEval } from '../src/scanner/detectors/eval';
import { detectXSS } from '../src/scanner/detectors/xss';
import { detectPathTraversal } from '../src/scanner/detectors/pathTraversal';
import { detectPrototypePollution } from '../src/scanner/detectors/prototypePollution';
import { detectInsecureRandom } from '../src/scanner/detectors/insecureRandom';
import { detectSSRF } from '../src/scanner/detectors/ssrf';
import { detectJWTSecrets } from '../src/scanner/detectors/jwt';
import { detectCommandInjection } from '../src/scanner/detectors/commandInjection';
import { detectOpenRedirect } from '../src/scanner/detectors/openRedirect';
import { Finding } from '../src/scanner/reporter';

// ─── Tiny test runner ─────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;

function test(name: string, fn: () => void): void {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`  ✗ ${name}`);
    console.error(`    ${msg}`);
    failed++;
  }
}

function expect(value: unknown) {
  return {
    toBeGreaterThanOrEqual(n: number) {
      if (typeof value !== 'number' || value < n) {
        throw new Error(`Expected ${value} to be ≥ ${n}`);
      }
    },
    toBe(expected: unknown) {
      if (value !== expected) {
        throw new Error(`Expected ${value} to be ${expected}`);
      }
    },
    toContain(type: string) {
      if (!Array.isArray(value)) throw new Error('Expected an array');
      const types = (value as Finding[]).map((f) => f.type);
      if (!types.includes(type)) {
        throw new Error(`Expected findings to contain type "${type}", got: [${types.join(', ')}]`);
      }
    },
  };
}

// ─── Setup ────────────────────────────────────────────────────────────────────

const FIXTURES_DIR = path.join(__dirname, 'fixtures');
const vulnerablePath = path.join(FIXTURES_DIR, 'vulnerable.ts');
const cleanPath = path.join(FIXTURES_DIR, 'clean.ts');

if (!fs.existsSync(vulnerablePath)) {
  console.error(`Missing fixture: ${vulnerablePath}`);
  process.exit(1);
}
if (!fs.existsSync(cleanPath)) {
  console.error(`Missing fixture: ${cleanPath}`);
  process.exit(1);
}

const vulnerableParsed = parseFile(vulnerablePath);
const cleanParsed = parseFile(cleanPath);

// ─── Tests: vulnerable.ts ─────────────────────────────────────────────────────

console.log('\nvulnerable.ts — should produce findings:');

test('detectSecrets: ≥1 SECRET_HARDCODED finding', () => {
  const findings = detectSecrets(vulnerableParsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('SECRET_HARDCODED');
});

test('detectSQLInjection: ≥1 SQL_INJECTION finding', () => {
  const findings = detectSQLInjection(vulnerableParsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('SQL_INJECTION');
});

test('detectShellInjection: ≥1 SHELL_INJECTION finding', () => {
  const findings = detectShellInjection(vulnerableParsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('SHELL_INJECTION');
});

test('detectEval: ≥1 EVAL_INJECTION finding', () => {
  const findings = detectEval(vulnerableParsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('EVAL_INJECTION');
});

test('detectXSS: ≥1 XSS finding', () => {
  const findings = detectXSS(vulnerableParsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('XSS');
});

test('detectPathTraversal: ≥1 PATH_TRAVERSAL finding', () => {
  const findings = detectPathTraversal(vulnerableParsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('PATH_TRAVERSAL');
});

test('detectPrototypePollution: ≥1 PROTOTYPE_POLLUTION finding', () => {
  const findings = detectPrototypePollution(vulnerableParsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('PROTOTYPE_POLLUTION');
});

test('detectInsecureRandom: ≥1 INSECURE_RANDOM finding', () => {
  const findings = detectInsecureRandom(vulnerableParsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('INSECURE_RANDOM');
});

test('detectSSRF: ≥1 SSRF finding', () => {
  const findings = detectSSRF(vulnerableParsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('SSRF');
});

test('detectCommandInjection: ≥1 COMMAND_INJECTION finding', () => {
  const findings = detectCommandInjection(vulnerableParsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('COMMAND_INJECTION');
test('detectJWTSecrets: ≥1 JWT_HARDCODED_SECRET or JWT_WEAK_SECRET finding', () => {
  const findings = detectJWTSecrets(vulnerableParsed);
  const types = findings.map((f) => f.type);
  if (!types.includes('JWT_HARDCODED_SECRET') && !types.includes('JWT_WEAK_SECRET')) {
    throw new Error(`Expected JWT_HARDCODED_SECRET or JWT_WEAK_SECRET, got: [${types.join(', ')}]`);
  }
});

// ─── Tests: clean.ts — zero false positives ───────────────────────────────────

console.log('\nclean.ts — should produce 0 findings (no false positives):');

test('detectSecrets: 0 findings on clean code', () => {
  const findings = detectSecrets(cleanParsed);
  expect(findings.length).toBe(0);
});

test('detectSQLInjection: 0 findings on clean code', () => {
  const findings = detectSQLInjection(cleanParsed);
  expect(findings.length).toBe(0);
});

test('detectShellInjection: 0 findings on clean code', () => {
  const findings = detectShellInjection(cleanParsed);
  expect(findings.length).toBe(0);
});

test('detectEval: 0 findings on clean code', () => {
  const findings = detectEval(cleanParsed);
  expect(findings.length).toBe(0);
});

test('detectXSS: 0 findings on clean code', () => {
  const findings = detectXSS(cleanParsed);
  expect(findings.length).toBe(0);
});

test('detectPathTraversal: 0 findings on clean code', () => {
  const findings = detectPathTraversal(cleanParsed);
  expect(findings.length).toBe(0);
});

test('detectPrototypePollution: 0 findings on clean code', () => {
  const findings = detectPrototypePollution(cleanParsed);
  expect(findings.length).toBe(0);
});

test('detectInsecureRandom: 0 findings on clean code', () => {
  const findings = detectInsecureRandom(cleanParsed);
  expect(findings.length).toBe(0);
});

test('detectSSRF: 0 findings on clean code', () => {
  const findings = detectSSRF(cleanParsed);
  expect(findings.length).toBe(0);
});

test('detectCommandInjection: 0 findings on clean code', () => {
  const findings = detectCommandInjection(cleanParsed);
test('detectJWTSecrets: 0 findings on clean code', () => {
  const findings = detectJWTSecrets(cleanParsed);
  expect(findings.length).toBe(0);
});

// ─── Tests: parseCode() for server usage ─────────────────────────────────────

console.log('\nparseCode() — server inline parsing:');

test('parseCode parses a snippet with a hardcoded secret', () => {
  const code = `const apiKey = 'sk-proj-abc123xyz456';`;
  const parsed = parseCode(code);
  const findings = detectSecrets(parsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('SECRET_HARDCODED');
});

test('parseCode parses a snippet with eval injection', () => {
  const code = `eval(userInput);`;
  const parsed = parseCode(code);
  const findings = detectEval(parsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('EVAL_INJECTION');
});

test('parseCode parses a snippet with insecure random (INSECURE_RANDOM)', () => {
  const code = `const resetToken = Math.random().toString(36).slice(2);`;
  const parsed = parseCode(code);
  const findings = detectInsecureRandom(parsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('INSECURE_RANDOM');
});

test('parseCode parses a snippet with SSRF via dynamic fetch URL', () => {
  const code = `const data = await fetch(userProvidedUrl);`;
  const parsed = parseCode(code);
  const findings = detectSSRF(parsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('SSRF');
});

test('parseCode detects hardcoded JWT secret in jwt.sign() call (JWT_HARDCODED_SECRET)', () => {
  const code = `const token = jwt.sign({ userId: 123 }, 'my-super-secret-key-that-is-long-enough-here');`;
  const parsed = parseCode(code);
  const findings = detectJWTSecrets(parsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('JWT_HARDCODED_SECRET');
});

test('parseCode detects short JWT secret (< 32 chars) as JWT_WEAK_SECRET', () => {
  const code = `jwt.sign(payload, 'weak');`;
  const parsed = parseCode(code);
  const findings = detectJWTSecrets(parsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('JWT_WEAK_SECRET');
});

test('parseCode: no JWT findings when secret comes from env variable', () => {
  const code = `jwt.sign(payload, process.env.JWT_SECRET);`;
  const parsed = parseCode(code);
  const findings = detectJWTSecrets(parsed);
  expect(findings.length).toBe(0);
});

test('parseCode detects command injection via spawn with dynamic command', () => {
  const code = `spawn(userCommand, ['--flag']);`;
  const parsed = parseCode(code);
  const findings = detectCommandInjection(parsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('COMMAND_INJECTION');
});

test('parseCode detects command injection via spawnSync with template literal command', () => {
  const code = "spawnSync(`${req.body.tool}`, ['-r', file]);";
  const parsed = parseCode(code);
  const findings = detectCommandInjection(parsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('COMMAND_INJECTION');
});

test('parseCode: no COMMAND_INJECTION when spawn uses hardcoded command string', () => {
  const code = `spawn('convert', [inputFile, '-resize', '800x600', outputFile]);`;
  const parsed = parseCode(code);
  const findings = detectCommandInjection(parsed);
  expect(findings.length).toBe(0);
test('parseCode detects PROTOTYPE_POLLUTION via Object.assign with dynamic source', () => {
  const code = `Object.assign(target, userPayload);`;
  const findings = detectPrototypePollution(parsed);
  expect(findings).toContain('PROTOTYPE_POLLUTION');
test('parseCode detects PROTOTYPE_POLLUTION via __proto__ assignment', () => {
  const code = `(obj as any).__proto__ = attackerPayload;`;
  const findings = detectPrototypePollution(parsed);
  expect(findings).toContain('PROTOTYPE_POLLUTION');
test('parseCode detects INSECURE_RANDOM via Math.random() for token generation', () => {
  const code = `const sessionToken = Math.random().toString(36).slice(2);`;
  const findings = detectInsecureRandom(parsed);
  expect(findings).toContain('INSECURE_RANDOM');
test('parseCode detects OPEN_REDIRECT when res.redirect() receives dynamic URL', () => {
  const code = `res.redirect(req.query.next);`;
  const findings = detectOpenRedirect(parsed);
  expect(findings).toContain('OPEN_REDIRECT');
test('parseCode: no OPEN_REDIRECT finding when res.redirect() uses a static string', () => {
  const code = `res.redirect('/dashboard');`;
  const findings = detectOpenRedirect(parsed);
});

// ─── Integration: scan-repo detector coverage ─────────────────────────────────

console.log('\nscan-repo integration — all detector types registered:');

test('all detector types fire on a multi-vuln snippet (simulating scan-repo file)', () => {
  // A single snippet containing one vulnerability of each type
  const code = [
    `const apiKey = 'sk-proj-abc123xyz456def789ghi012jkl345mno678pqr901stu';`,
    `const q = db.query('SELECT * FROM users WHERE id = ' + userId);`,
    `exec(userInput);`,
    `eval(userCmd);`,
    `el.innerHTML = userHtml;`,
    `fs.readFileSync(userPath);`,
    `Object.assign(target, userPayload);`,
    `const resetToken = Math.random().toString(36).slice(2);`,
    `res.redirect(req.query.next);`,
    `await fetch(userUrl);`,
    `jwt.sign({ id: 1 }, 'short');`,
    `spawn(userTool, ['--help']);`,
  ].join('\n');

  const parsed = parseCode(code);

  const allFindings = [
    ...detectSecrets(parsed),
    ...detectSQLInjection(parsed),
    ...detectShellInjection(parsed),
    ...detectEval(parsed),
    ...detectXSS(parsed),
    ...detectPathTraversal(parsed),
    ...detectPrototypePollution(parsed),
    ...detectInsecureRandom(parsed),
    ...detectSSRF(parsed),
    ...detectJWTSecrets(parsed),
    ...detectCommandInjection(parsed),
  ];

  const types = new Set(allFindings.map((f) => f.type));

  const expected = [
    'SECRET_HARDCODED',
    'SQL_INJECTION',
    'SHELL_INJECTION',
    'EVAL_INJECTION',
    'XSS',
    'PATH_TRAVERSAL',
    'PROTOTYPE_POLLUTION',
    'INSECURE_RANDOM',
    'SSRF',
    'JWT_WEAK_SECRET',
    'COMMAND_INJECTION',
  ];

  for (const t of expected) {
    if (!types.has(t)) {
      throw new Error(`Missing detector type in scan-repo pipeline: ${t}. Got: [${[...types].join(', ')}]`);
    }
  }
});

// ─── Summary ──────────────────────────────────────────────────────────────────

console.log(`\n${'─'.repeat(50)}`);
const total = passed + failed;
if (failed === 0) {
  console.log(`✓ All ${total} tests passed\n`);
} else {
  console.log(`${passed}/${total} tests passed, ${failed} failed\n`);
  process.exit(1);
}
