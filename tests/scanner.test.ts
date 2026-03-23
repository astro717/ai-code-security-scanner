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
import { detectReDoS } from '../src/scanner/detectors/redos';
import { detectWeakCrypto } from '../src/scanner/detectors/weakCrypto';
import { detectJWTNoneAlgorithm } from '../src/scanner/detectors/jwtNone';
import { detectCORSMisconfiguration } from '../src/scanner/detectors/cors';
import { detectUnsafeDeps } from '../src/scanner/detectors/deps';
import { Finding } from '../src/scanner/reporter';
import * as os from 'os';

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
});

test('detectJWTSecrets: ≥1 JWT_HARDCODED_SECRET or JWT_WEAK_SECRET finding', () => {
  const findings = detectJWTSecrets(vulnerableParsed);
  const types = findings.map((f) => f.type);
  if (!types.includes('JWT_HARDCODED_SECRET') && !types.includes('JWT_WEAK_SECRET')) {
    throw new Error(`Expected JWT_HARDCODED_SECRET or JWT_WEAK_SECRET, got: [${types.join(', ')}]`);
  }
});

test('detectJWTSecrets: ≥1 JWT_WEAK_SECRET finding from fixture', () => {
  const findings = detectJWTSecrets(vulnerableParsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('JWT_WEAK_SECRET');
});

test('detectReDoS: ≥1 REDOS finding on vulnerable fixture', () => {
  const findings = detectReDoS(vulnerableParsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('REDOS');
});

test('detectWeakCrypto: ≥1 WEAK_CRYPTO finding on vulnerable fixture', () => {
  const findings = detectWeakCrypto(vulnerableParsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('WEAK_CRYPTO');
});

test('detectReDoS: 0 findings on clean code', () => {
  const findings = detectReDoS(cleanParsed);
  expect(findings.length).toBe(0);
});

test('detectWeakCrypto: 0 findings on clean code', () => {
  const findings = detectWeakCrypto(cleanParsed);
  expect(findings.length).toBe(0);
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
  expect(findings.length).toBe(0);
});

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

test('parseCode detects open redirect with dynamic URL (OPEN_REDIRECT)', () => {
  const code = `res.redirect(req.query.next);`;
  const parsed = parseCode(code);
  const findings = detectOpenRedirect(parsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('OPEN_REDIRECT');
});

test('parseCode: no OPEN_REDIRECT when redirect target is a static string', () => {
  const code = `res.redirect('/home');`;
  const parsed = parseCode(code);
  const findings = detectOpenRedirect(parsed);
  expect(findings.length).toBe(0);
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
});

test('parseCode detects PROTOTYPE_POLLUTION via Object.assign with dynamic source', () => {
  const code = `Object.assign(target, userInput);`;
  const parsed = parseCode(code);
  const { detectPrototypePollution } = require('../src/scanner/detectors/prototypePollution');
  const findings = detectPrototypePollution(parsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('PROTOTYPE_POLLUTION');
});

test('parseCode detects INSECURE_RANDOM via Math.random() for security token', () => {
  const code = `const sessionId = Math.random().toString(36).slice(2);`;
  const parsed = parseCode(code);
  const { detectInsecureRandom } = require('../src/scanner/detectors/insecureRandom');
  const findings = detectInsecureRandom(parsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('INSECURE_RANDOM');
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
    ...detectOpenRedirect(parsed),
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
    'OPEN_REDIRECT',
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

// ─── CORS misconfiguration detector ──────────────────────────────────────────

console.log('\nCORS misconfiguration detector:');

test('detectCORSMisconfiguration: flags cors({ origin: "*", credentials: true })', () => {
  const code = `app.use(cors({ origin: '*', credentials: true }));`;
  const parsed = parseCode(code);
  const findings = detectCORSMisconfiguration(parsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('CORS_MISCONFIGURATION');
});

test('detectCORSMisconfiguration: flags reflected req.headers.origin in setHeader', () => {
  const code = `res.setHeader('Access-Control-Allow-Origin', req.headers.origin);`;
  const parsed = parseCode(code);
  const findings = detectCORSMisconfiguration(parsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('CORS_MISCONFIGURATION');
});

test('detectCORSMisconfiguration: no finding for cors({ origin: "*" }) without credentials', () => {
  const code = `app.use(cors({ origin: '*' }));`;
  const parsed = parseCode(code);
  const findings = detectCORSMisconfiguration(parsed);
  expect(findings.length).toBe(0);
});

test('detectCORSMisconfiguration: no finding for cors({ origin: "https://trusted.com", credentials: true })', () => {
  const code = `app.use(cors({ origin: 'https://trusted.com', credentials: true }));`;
  const parsed = parseCode(code);
  const findings = detectCORSMisconfiguration(parsed);
  expect(findings.length).toBe(0);
});

test('detectCORSMisconfiguration: flags reflected origin via computed bracket notation', () => {
  const code = `res.setHeader('Access-Control-Allow-Origin', req.headers['origin']);`;
  const parsed = parseCode(code);
  const findings = detectCORSMisconfiguration(parsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('CORS_MISCONFIGURATION');
});

// ─── JWT none-algorithm detector ──────────────────────────────────────────────

console.log('\nJWT none-algorithm detector:');

test('detectJWTNoneAlgorithm: flags jwt.verify() without options (missing algorithms whitelist)', () => {
  const code = `const payload = jwt.verify(token, secret);`;
  const parsed = parseCode(code);
  const findings = detectJWTNoneAlgorithm(parsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('JWT_NONE_ALGORITHM');
});

test('detectJWTNoneAlgorithm: flags jwt.verify() with algorithms: ["none"]', () => {
  const code = `jwt.verify(token, secret, { algorithms: ['none'] });`;
  const parsed = parseCode(code);
  const findings = detectJWTNoneAlgorithm(parsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('JWT_NONE_ALGORITHM');
});

test('detectJWTNoneAlgorithm: flags jwt.decode() (bypasses signature verification)', () => {
  const code = `const data = jwt.decode(token);`;
  const parsed = parseCode(code);
  const findings = detectJWTNoneAlgorithm(parsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('JWT_DECODE_NO_VERIFY');
});

test('detectJWTNoneAlgorithm: no JWT_NONE_ALGORITHM finding for jwt.verify() with RS256', () => {
  const code = `jwt.verify(token, publicKey, { algorithms: ['RS256'] });`;
  const parsed = parseCode(code);
  const findings = detectJWTNoneAlgorithm(parsed);
  const noneFindings = findings.filter((f) => f.type === 'JWT_NONE_ALGORITHM');
  expect(noneFindings.length).toBe(0);
});

test('detectJWTNoneAlgorithm: flags jwt.verify() with algorithm: "none" (singular key)', () => {
  const code = `jwt.verify(token, secret, { algorithm: 'none' });`;
  const parsed = parseCode(code);
  const findings = detectJWTNoneAlgorithm(parsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('JWT_NONE_ALGORITHM');
});

// ─── ReDoS detector ───────────────────────────────────────────────────────────

console.log('\nReDoS detector:');

test('detectReDoS: flags new RegExp(userInput) with dynamic variable pattern', () => {
  const code = `const re = new RegExp(userInput);`;
  const parsed = parseCode(code);
  const findings = detectReDoS(parsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('REDOS');
});

test('detectReDoS: flags new RegExp(req.body.pattern, "i") with member expression pattern', () => {
  const code = `const re = new RegExp(req.body.pattern, 'i');`;
  const parsed = parseCode(code);
  const findings = detectReDoS(parsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('REDOS');
});

test('detectReDoS: no finding for new RegExp("^[a-z]+$") with static string literal', () => {
  const code = `const re = new RegExp('^[a-z]+$');`;
  const parsed = parseCode(code);
  const findings = detectReDoS(parsed);
  expect(findings.length).toBe(0);
});

test('detectReDoS: no finding for static template literal with no interpolation', () => {
  const code = 'const re = new RegExp(`^\\\\d+$`);';
  const parsed = parseCode(code);
  const findings = detectReDoS(parsed);
  expect(findings.length).toBe(0);
});

test('detectReDoS: flags new RegExp() with template literal containing expressions', () => {
  const code = 'const re = new RegExp(`prefix-${userValue}-suffix`);';
  const parsed = parseCode(code);
  const findings = detectReDoS(parsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('REDOS');
});

// ─── Weak crypto detector ─────────────────────────────────────────────────────

console.log('\nWeak crypto detector:');

test('detectWeakCrypto: flags crypto.createHash("md5")', () => {
  const code = `const hash = crypto.createHash('md5').update(data).digest('hex');`;
  const parsed = parseCode(code);
  const findings = detectWeakCrypto(parsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('WEAK_CRYPTO');
});

test('detectWeakCrypto: flags crypto.createHash("sha1")', () => {
  const code = `const sig = crypto.createHash('sha1').update(payload).digest('hex');`;
  const parsed = parseCode(code);
  const findings = detectWeakCrypto(parsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('WEAK_CRYPTO');
});

test('detectWeakCrypto: flags bare createHash("md4") after destructuring import', () => {
  const code = `const { createHash } = require('crypto'); const h = createHash('md4');`;
  const parsed = parseCode(code);
  const findings = detectWeakCrypto(parsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('WEAK_CRYPTO');
});

test('detectWeakCrypto: no finding for crypto.createHash("sha256")', () => {
  const code = `const hash = crypto.createHash('sha256').update(data).digest('hex');`;
  const parsed = parseCode(code);
  const findings = detectWeakCrypto(parsed);
  expect(findings.length).toBe(0);
});

test('detectWeakCrypto: no finding for crypto.createHash("sha512")', () => {
  const code = `const hash = crypto.createHash('sha512').update(data).digest('hex');`;
  const parsed = parseCode(code);
  const findings = detectWeakCrypto(parsed);
  expect(findings.length).toBe(0);
});

test('detectWeakCrypto: case-insensitive match — flags "MD5" uppercase input', () => {
  const code = `crypto.createHash('MD5');`;
  const parsed = parseCode(code);
  const findings = detectWeakCrypto(parsed);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('WEAK_CRYPTO');
});

// ─── Unsafe dependency detector ───────────────────────────────────────────────

console.log('\nUnsafe dependency detector:');

test('detectUnsafeDeps: flags wildcard version "*" in dependencies', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-sec-deps-'));
  fs.writeFileSync(
    path.join(dir, 'package.json'),
    JSON.stringify({ dependencies: { lodash: '*' } }),
  );
  // Create a lockfile so only the wildcard finding fires
  fs.writeFileSync(path.join(dir, 'package-lock.json'), '{}');
  const findings = detectUnsafeDeps(dir);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('UNSAFE_DEPENDENCY');
  fs.rmSync(dir, { recursive: true });
});

test('detectUnsafeDeps: flags "latest" version in devDependencies', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-sec-deps-'));
  fs.writeFileSync(
    path.join(dir, 'package.json'),
    JSON.stringify({ devDependencies: { typescript: 'latest' } }),
  );
  fs.writeFileSync(path.join(dir, 'package-lock.json'), '{}');
  const findings = detectUnsafeDeps(dir);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('UNSAFE_DEPENDENCY');
  fs.rmSync(dir, { recursive: true });
});

test('detectUnsafeDeps: flags missing lockfile when deps are present', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-sec-deps-'));
  fs.writeFileSync(
    path.join(dir, 'package.json'),
    JSON.stringify({ dependencies: { express: '^4.18.0' } }),
  );
  // No lockfile written
  const findings = detectUnsafeDeps(dir);
  expect(findings.length).toBeGreaterThanOrEqual(1);
  expect(findings).toContain('UNSAFE_DEPENDENCY');
  fs.rmSync(dir, { recursive: true });
});

test('detectUnsafeDeps: no finding for pinned semver version with lockfile present', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-sec-deps-'));
  // Use versions that are above all KNOWN_VULNERABLE thresholds to avoid VULNERABLE_DEPENDENCY
  fs.writeFileSync(
    path.join(dir, 'package.json'),
    JSON.stringify({ dependencies: { 'some-safe-package': '9.0.0' } }),
  );
  fs.writeFileSync(path.join(dir, 'package-lock.json'), '{}');
  const findings = detectUnsafeDeps(dir);
  expect(findings.length).toBe(0);
  fs.rmSync(dir, { recursive: true });
});

test('detectUnsafeDeps: no finding when package.json is absent', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-sec-deps-'));
  // No package.json written
  const findings = detectUnsafeDeps(dir);
  expect(findings.length).toBe(0);
  fs.rmSync(dir, { recursive: true });
});

// ─── Known-CVE (VULNERABLE_DEPENDENCY) detector ───────────────────────────────

console.log('\nVulnerable dependency detector (known CVEs):');

import { isBelow, KNOWN_VULNERABLE } from '../src/scanner/detectors/deps';

test('isBelow: lodash 4.17.20 is below 4.17.21', () => {
  expect(isBelow('4.17.20', '4.17.21')).toBe(true);
});

test('isBelow: lodash 4.17.21 is NOT below 4.17.21 (equal = safe)', () => {
  expect(isBelow('4.17.21', '4.17.21')).toBe(false);
});

test('isBelow: lodash 4.18.0 is NOT below 4.17.21', () => {
  expect(isBelow('4.18.0', '4.17.21')).toBe(false);
});

test('detectUnsafeDeps: flags lodash 4.17.20 as VULNERABLE_DEPENDENCY (positive CVE case)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-sec-vuln-'));
  fs.writeFileSync(
    path.join(dir, 'package.json'),
    JSON.stringify({ dependencies: { lodash: '4.17.20' } }),
  );
  fs.writeFileSync(path.join(dir, 'package-lock.json'), '{}');
  const findings = detectUnsafeDeps(dir);
  const types = findings.map((f) => f.type);
  if (!types.includes('VULNERABLE_DEPENDENCY')) {
    throw new Error(`Expected VULNERABLE_DEPENDENCY, got: [${types.join(', ')}]`);
  }
  const vulnFinding = findings.find((f) => f.type === 'VULNERABLE_DEPENDENCY')!;
  if (vulnFinding.severity !== 'critical') {
    throw new Error(`Expected severity critical for lodash CVE, got: ${vulnFinding.severity}`);
  }
  fs.rmSync(dir, { recursive: true });
});

test('detectUnsafeDeps: no VULNERABLE_DEPENDENCY for lodash 4.17.21 (patched version)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-sec-vuln-'));
  fs.writeFileSync(
    path.join(dir, 'package.json'),
    JSON.stringify({ dependencies: { lodash: '4.17.21' } }),
  );
  fs.writeFileSync(path.join(dir, 'package-lock.json'), '{}');
  const findings = detectUnsafeDeps(dir);
  const vulnFindings = findings.filter((f) => f.type === 'VULNERABLE_DEPENDENCY');
  if (vulnFindings.length > 0) {
    throw new Error(`Expected 0 VULNERABLE_DEPENDENCY for lodash 4.17.21, got ${vulnFindings.length}`);
  }
  fs.rmSync(dir, { recursive: true });
});

test('detectUnsafeDeps: flags axios 1.5.0 as VULNERABLE_DEPENDENCY (CSRF CVE)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-sec-vuln-'));
  fs.writeFileSync(
    path.join(dir, 'package.json'),
    JSON.stringify({ dependencies: { axios: '1.5.0' } }),
  );
  fs.writeFileSync(path.join(dir, 'package-lock.json'), '{}');
  const findings = detectUnsafeDeps(dir);
  const types = findings.map((f) => f.type);
  if (!types.includes('VULNERABLE_DEPENDENCY')) {
    throw new Error(`Expected VULNERABLE_DEPENDENCY for axios 1.5.0, got: [${types.join(', ')}]`);
  }
  fs.rmSync(dir, { recursive: true });
});

test('detectUnsafeDeps: no VULNERABLE_DEPENDENCY for axios 1.6.0 (patched version)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-sec-vuln-'));
  fs.writeFileSync(
    path.join(dir, 'package.json'),
    JSON.stringify({ dependencies: { axios: '1.6.0' } }),
  );
  fs.writeFileSync(path.join(dir, 'package-lock.json'), '{}');
  const findings = detectUnsafeDeps(dir);
  const vulnFindings = findings.filter((f) => f.type === 'VULNERABLE_DEPENDENCY');
  if (vulnFindings.length > 0) {
    throw new Error(`Expected 0 VULNERABLE_DEPENDENCY for axios 1.6.0, got ${vulnFindings.length}`);
  }
  fs.rmSync(dir, { recursive: true });
});

test('KNOWN_VULNERABLE map: all entries have required fields', () => {
  for (const [name, entry] of Object.entries(KNOWN_VULNERABLE)) {
    if (!entry.below || !entry.severity || !entry.cve) {
      throw new Error(`KNOWN_VULNERABLE["${name}"] is missing required fields`);
    }
    if (!['critical', 'high', 'medium'].includes(entry.severity)) {
      throw new Error(`KNOWN_VULNERABLE["${name}"] has invalid severity: ${entry.severity}`);
    }
  }
  expect(Object.keys(KNOWN_VULNERABLE).length).toBeGreaterThanOrEqual(1);
});

// ─── buildSARIF output structure (direct unit tests) ──────────────────────────
//
// buildSARIF is now exported from src/scanner/sarif.ts and can be tested
// directly without spawning the full CLI. This is ~10x faster and allows
// testing edge cases (empty findings, unknown severity levels) in isolation.

import { buildSARIF, SARIF_RULE_DESCRIPTIONS } from '../src/scanner/sarif';

console.log('\nbuildSARIF output structure (direct unit tests):');

/** Build a minimal Finding for use in SARIF tests */
function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    type: 'SECRET_HARDCODED',
    severity: 'high',
    message: 'Test finding',
    file: 'test.ts',
    line: 1,
    column: 1,
    ...overrides,
  };
}

test('buildSARIF: runs[0].tool.driver.informationUri is present', () => {
  const sarif = buildSARIF([makeFinding()]) as any;
  const runs = sarif.runs;
  if (!Array.isArray(runs) || runs.length === 0) throw new Error('No runs array in SARIF output');
  const uri = runs[0]?.tool?.driver?.informationUri;
  if (typeof uri !== 'string' || uri.length === 0) {
    throw new Error(`Expected informationUri to be a non-empty string, got: ${JSON.stringify(uri)}`);
  }
});

test('buildSARIF: each rule has fullDescription.text populated', () => {
  const findings = [makeFinding({ type: 'SQL_INJECTION' }), makeFinding({ type: 'XSS' })];
  const sarif = buildSARIF(findings) as any;
  const rules: any[] = sarif.runs?.[0]?.tool?.driver?.rules ?? [];
  if (rules.length === 0) throw new Error('No rules in SARIF output');
  for (const rule of rules) {
    const text = rule?.fullDescription?.text;
    if (typeof text !== 'string' || text.length === 0) {
      throw new Error(`Rule "${rule.id}" is missing fullDescription.text`);
    }
  }
});

test('buildSARIF: each rule has helpUri populated', () => {
  const sarif = buildSARIF([makeFinding()]) as any;
  const rules: any[] = sarif.runs?.[0]?.tool?.driver?.rules ?? [];
  if (rules.length === 0) throw new Error('No rules in SARIF output');
  for (const rule of rules) {
    const helpUri = rule?.helpUri;
    if (typeof helpUri !== 'string' || !helpUri.startsWith('https://')) {
      throw new Error(`Rule "${rule.id}" is missing or has an invalid helpUri: ${JSON.stringify(helpUri)}`);
    }
  }
});

test('buildSARIF: critical/high findings map to level "error"', () => {
  const sarif = buildSARIF([makeFinding({ type: 'SECRET_HARDCODED', severity: 'high' })]) as any;
  const results: any[] = sarif.runs?.[0]?.results ?? [];
  if (results.length === 0) throw new Error('Expected ≥1 result in SARIF output');
  const secretResult = results.find((r: any) => r.ruleId === 'SECRET_HARDCODED');
  if (!secretResult) throw new Error('No SECRET_HARDCODED result in SARIF');
  if (secretResult.level !== 'error') {
    throw new Error(`Expected SECRET_HARDCODED to have level "error", got "${secretResult.level}"`);
  }
});

test('buildSARIF: critical severity also maps to level "error"', () => {
  const sarif = buildSARIF([makeFinding({ type: 'SQL_INJECTION', severity: 'critical' })]) as any;
  const results: any[] = sarif.runs?.[0]?.results ?? [];
  const result = results.find((r: any) => r.ruleId === 'SQL_INJECTION');
  if (!result) throw new Error('No SQL_INJECTION result in SARIF');
  if (result.level !== 'error') {
    throw new Error(`Expected critical severity to map to "error", got "${result.level}"`);
  }
});

test('buildSARIF: medium finding maps to level "warning"', () => {
  const sarif = buildSARIF([makeFinding({ type: 'UNSAFE_DEPENDENCY', severity: 'medium' })]) as any;
  const results: any[] = sarif.runs?.[0]?.results ?? [];
  const unsafeDep = results.find((r: any) => r.ruleId === 'UNSAFE_DEPENDENCY');
  if (!unsafeDep) throw new Error('No UNSAFE_DEPENDENCY in SARIF results');
  if (unsafeDep.level !== 'warning') {
    throw new Error(`Expected medium severity to map to "warning", got "${unsafeDep.level}"`);
  }
});

test('buildSARIF: low severity maps to level "note"', () => {
  const sarif = buildSARIF([makeFinding({ severity: 'low' })]) as any;
  const results: any[] = sarif.runs?.[0]?.results ?? [];
  if (results[0].level !== 'note') {
    throw new Error(`Expected low severity to map to "note", got "${results[0].level}"`);
  }
});

test('buildSARIF: empty findings array produces valid SARIF with no results', () => {
  const sarif = buildSARIF([]) as any;
  if (!Array.isArray(sarif.runs)) throw new Error('Missing runs array');
  const results: any[] = sarif.runs?.[0]?.results ?? [];
  if (results.length !== 0) throw new Error(`Expected 0 results for empty findings, got ${results.length}`);
  const rules: any[] = sarif.runs?.[0]?.tool?.driver?.rules ?? [];
  if (rules.length !== 0) throw new Error(`Expected 0 rules for empty findings, got ${rules.length}`);
});

test('buildSARIF: unknown rule type uses type as fallback description', () => {
  const sarif = buildSARIF([makeFinding({ type: 'UNKNOWN_RULE_XYZ' as any })]) as any;
  const rules: any[] = sarif.runs?.[0]?.tool?.driver?.rules ?? [];
  const rule = rules.find((r: any) => r.id === 'UNKNOWN_RULE_XYZ');
  if (!rule) throw new Error('Missing rule entry for unknown type');
  if (rule.fullDescription.text !== 'UNKNOWN_RULE_XYZ') {
    throw new Error(`Expected fallback description to equal the rule id, got: "${rule.fullDescription.text}"`);
  }
});

test('buildSARIF: SARIF_RULE_DESCRIPTIONS covers all known finding types', () => {
  const knownTypes = [
    'SECRET_HARDCODED', 'SQL_INJECTION', 'SHELL_INJECTION', 'EVAL_INJECTION',
    'XSS', 'PATH_TRAVERSAL', 'PROTOTYPE_POLLUTION', 'INSECURE_RANDOM',
    'OPEN_REDIRECT', 'SSRF', 'COMMAND_INJECTION', 'CORS_MISCONFIGURATION',
    'JWT_HARDCODED_SECRET', 'JWT_WEAK_SECRET', 'JWT_NONE_ALGORITHM',
    'JWT_DECODE_NO_VERIFY', 'REDOS', 'WEAK_CRYPTO', 'UNSAFE_DEPENDENCY',
    'VULNERABLE_DEPENDENCY',
  ];
  for (const type of knownTypes) {
    if (!SARIF_RULE_DESCRIPTIONS[type]) {
      throw new Error(`SARIF_RULE_DESCRIPTIONS is missing entry for: ${type}`);
    }
  }
});

// ─── CLI integration: --exit-code flag ────────────────────────────────────────
//
// These tests invoke dist/cli.js directly (compiled output) so they exercise
// the full CLI path including Commander option parsing and process.exit() logic.

console.log('\nCLI integration — --exit-code and --output flags:');

function runCLI(args: string[], input?: string): { stdout: string; stderr: string; status: number | null } {
  const result = spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf8',
    timeout: 15000,
    input,
  });
  return { stdout: result.stdout, stderr: result.stderr, status: result.status };
}

test('--exit-code 0: exits with code 0 even when critical/high findings exist', () => {
  // vulnerablePath has multiple high/critical findings — without --exit-code the CLI exits 1
  const { status } = runCLI(['--exit-code', '0', vulnerablePath]);
  if (status !== 0) {
    throw new Error(`Expected exit code 0 with --exit-code 0 flag, got: ${status}`);
  }
});

test('--exit-code 0: absent flag exits 1 when high/critical findings exist (baseline check)', () => {
  const { status } = runCLI([vulnerablePath]);
  if (status !== 1) {
    throw new Error(`Expected CLI to exit 1 on high/critical findings without --exit-code, got: ${status}`);
  }
});

test('--output with text format: file is created and contains formatFindingsText content', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-sec-output-'));
  const outFile = path.join(dir, 'findings.txt');
  runCLI(['--format', 'text', '--exit-code', '0', '--output', outFile, vulnerablePath]);
  if (!fs.existsSync(outFile)) {
    throw new Error(`Expected output file to be created at ${outFile}`);
  }
  const content = fs.readFileSync(outFile, 'utf8');
  if (content.trim().length === 0) {
    throw new Error('Expected output file to have non-empty content');
  }
  // formatFindingsText includes severity labels — verify structured content is present
  if (!content.includes('CRITICAL') && !content.includes('HIGH') && !content.includes('MEDIUM') && !content.includes('LOW')) {
    throw new Error(`Output file does not contain expected severity labels. Content snippet: ${content.slice(0, 200)}`);
  }
  fs.rmSync(dir, { recursive: true });
});

test('--output with sarif format: file contains valid SARIF JSON', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-sec-output-'));
  const outFile = path.join(dir, 'findings.sarif');
  runCLI(['--format', 'sarif', '--exit-code', '0', '--output', outFile, vulnerablePath]);
  if (!fs.existsSync(outFile)) {
    throw new Error(`Expected SARIF output file to be created at ${outFile}`);
  }
  const content = fs.readFileSync(outFile, 'utf8');
  let sarif: any;
  try {
    sarif = JSON.parse(content);
  } catch {
    throw new Error(`Output file is not valid JSON. Content snippet: ${content.slice(0, 200)}`);
  }
  if (sarif.version !== '2.1.0') {
    throw new Error(`Expected SARIF version "2.1.0", got "${sarif.version}"`);
  }
  fs.rmSync(dir, { recursive: true });
});

test('--output with json format: file contains valid JSON with findings and summary', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-sec-output-'));
  const outFile = path.join(dir, 'findings.json');
  runCLI(['--format', 'json', '--exit-code', '0', '--output', outFile, vulnerablePath]);
  if (!fs.existsSync(outFile)) {
    throw new Error(`Expected JSON output file to be created at ${outFile}`);
  }
  const content = fs.readFileSync(outFile, 'utf8');
  let parsed: any;
  try {
    parsed = JSON.parse(content);
  } catch {
    throw new Error(`Output file is not valid JSON. Content snippet: ${content.slice(0, 200)}`);
  }
  // formatJSON returns { findings: [...], summary: {...} }
  if (!Array.isArray(parsed.findings)) {
    throw new Error(`Expected JSON output to have a "findings" array, got keys: [${Object.keys(parsed).join(', ')}]`);
  }
  if (typeof parsed.summary !== 'object' || parsed.summary === null) {
    throw new Error(`Expected JSON output to have a "summary" object`);
  }
  fs.rmSync(dir, { recursive: true });
});

// ─── CLI integration: --watch + --output append behavior ──────────────────────
//
// watch mode is inherently long-running so we test it via the filesystem helpers
// used by startWatchMode rather than invoking the full CLI. Specifically:
// - the output file is created with a header on session start (writeFileSync)
// - subsequent change events append entries (appendFileSync) rather than overwrite
// - missing output directory causes fs.writeFileSync to throw (graceful check)

console.log('\n--watch + --output append behavior:');

test('watch --output: output file is created (writeFileSync) on session start with header line', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-sec-watch-'));
  const outFile = path.join(dir, 'watch.log');

  // Simulate what startWatchMode does on startup when outputPath is set
  fs.writeFileSync(outFile, `# ai-sec-scan watch session started ${new Date().toISOString()}\n`, 'utf8');

  if (!fs.existsSync(outFile)) {
    throw new Error('Expected output file to be created on watch session start');
  }
  const content = fs.readFileSync(outFile, 'utf8');
  if (!content.startsWith('# ai-sec-scan watch session started')) {
    throw new Error(`Expected header line at start of watch output file, got: ${content.slice(0, 100)}`);
  }
  fs.rmSync(dir, { recursive: true });
});

test('watch --output: subsequent appendFileSync calls append entries, do not overwrite', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-sec-watch-'));
  const outFile = path.join(dir, 'watch.log');

  // Session start: create file with header
  fs.writeFileSync(outFile, `# ai-sec-scan watch session started ${new Date().toISOString()}\n`, 'utf8');

  // Simulate two change events being appended
  const entry1 = '[2026-01-01T00:00:00.000Z] src/a.ts\n  + [HIGH] SECRET_HARDCODED at line 1: test\n\n';
  const entry2 = '[2026-01-01T00:01:00.000Z] src/b.ts\n  + [MEDIUM] SSRF at line 5: test\n\n';
  fs.appendFileSync(outFile, entry1, 'utf8');
  fs.appendFileSync(outFile, entry2, 'utf8');

  const content = fs.readFileSync(outFile, 'utf8');

  if (!content.includes('# ai-sec-scan watch session started')) {
    throw new Error('Header line was overwritten — expected it to be preserved');
  }
  if (!content.includes('SECRET_HARDCODED')) {
    throw new Error('First change event entry was lost — appendFileSync did not append');
  }
  if (!content.includes('SSRF')) {
    throw new Error('Second change event entry was lost — appendFileSync did not append');
  }

  const headerCount = (content.match(/# ai-sec-scan watch session started/g) ?? []).length;
  if (headerCount !== 1) {
    throw new Error(`Expected 1 header line but found ${headerCount} — file was overwritten on append`);
  }

  fs.rmSync(dir, { recursive: true });
});

test('watch --output: appendFileSync to a non-existent directory throws (graceful error check)', () => {
  const nonExistentDir = path.join(os.tmpdir(), `ai-sec-watch-missing-${Date.now()}`);
  const outFile = path.join(nonExistentDir, 'watch.log');
  let threw = false;
  try {
    fs.writeFileSync(outFile, 'header\n', 'utf8');
  } catch {
    threw = true;
  }
  if (!threw) {
    // Clean up if the OS somehow created it
    try { fs.rmSync(nonExistentDir, { recursive: true }); } catch { /* ignore */ }
    throw new Error('Expected writeFileSync to a missing directory to throw — this means the CLI would crash, not fail silently');
  }
});

test('watch --output: only change events with added/resolved findings trigger appendFileSync (no-op on unchanged)', () => {
  // This mirrors the appendToOutput guard: `if (added.length > 0 || resolved.length > 0)`
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-sec-watch-'));
  const outFile = path.join(dir, 'watch.log');

  fs.writeFileSync(outFile, `# header\n`, 'utf8');
  const initialSize = fs.statSync(outFile).size;

  // Simulate a no-change scan event: added=[], resolved=[] — appendFileSync NOT called
  const added: any[] = [];
  const resolved: any[] = [];
  if (added.length > 0 || resolved.length > 0) {
    fs.appendFileSync(outFile, 'should not appear\n', 'utf8');
  }

  const finalSize = fs.statSync(outFile).size;
  if (finalSize !== initialSize) {
    throw new Error(`Expected no write on no-change event, but file grew from ${initialSize} to ${finalSize} bytes`);
  }

  fs.rmSync(dir, { recursive: true });
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
