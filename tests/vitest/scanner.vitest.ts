/**
 * Vitest-native test suite for the AI Code Security Scanner.
 *
 * This file mirrors the key tests from tests/scanner.test.ts using the
 * vitest API so that `npm run test:coverage` produces real coverage data
 * (v8 provider, no ts-node intermediary). The existing custom-runner file
 * continues to serve as the primary integration test suite run via `npm test`.
 */

import { describe, test, expect } from 'vitest';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

import { parseFile, parseCode } from '../../src/scanner/parser';
import { detectSecrets } from '../../src/scanner/detectors/secrets';
import { detectSQLInjection } from '../../src/scanner/detectors/sql';
import { detectShellInjection } from '../../src/scanner/detectors/shell';
import { detectEval } from '../../src/scanner/detectors/eval';
import { detectXSS } from '../../src/scanner/detectors/xss';
import { detectPathTraversal } from '../../src/scanner/detectors/pathTraversal';
import { detectPrototypePollution } from '../../src/scanner/detectors/prototypePollution';
import { detectInsecureRandom } from '../../src/scanner/detectors/insecureRandom';
import { detectSSRF } from '../../src/scanner/detectors/ssrf';
import { detectJWTSecrets } from '../../src/scanner/detectors/jwt';
import { detectCommandInjection } from '../../src/scanner/detectors/commandInjection';
import { detectOpenRedirect } from '../../src/scanner/detectors/openRedirect';
import { detectReDoS } from '../../src/scanner/detectors/redos';
import { detectWeakCrypto } from '../../src/scanner/detectors/weakCrypto';
import { detectJWTNoneAlgorithm } from '../../src/scanner/detectors/jwtNone';
import { detectCORSMisconfiguration } from '../../src/scanner/detectors/cors';
import { buildSARIF, SARIF_RULE_DESCRIPTIONS } from '../../src/scanner/sarif';
import { buildHTMLReport } from '../../src/scanner/htmlReport';
import type { Finding } from '../../src/scanner/reporter';

// ── Fixtures ──────────────────────────────────────────────────────────────────

const FIXTURES_DIR = path.join(__dirname, '..', 'fixtures');
const vulnerablePath = path.join(FIXTURES_DIR, 'vulnerable.ts');
const cleanPath = path.join(FIXTURES_DIR, 'clean.ts');

const vulnerableParsed = parseFile(vulnerablePath);
const cleanParsed = parseFile(cleanPath);

// ── Helper ────────────────────────────────────────────────────────────────────

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

// ── Detectors: vulnerable fixture should produce findings ─────────────────────

describe('Detectors — vulnerable.ts produces findings', () => {
  test('detectSecrets: ≥1 SECRET_HARDCODED finding', () => {
    const findings = detectSecrets(vulnerableParsed);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.map((f) => f.type)).toContain('SECRET_HARDCODED');
  });

  test('detectSQLInjection: ≥1 SQL_INJECTION finding', () => {
    const findings = detectSQLInjection(vulnerableParsed);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.map((f) => f.type)).toContain('SQL_INJECTION');
  });

  test('detectShellInjection: ≥1 SHELL_INJECTION finding', () => {
    const findings = detectShellInjection(vulnerableParsed);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.map((f) => f.type)).toContain('SHELL_INJECTION');
  });

  test('detectEval: ≥1 EVAL_INJECTION finding', () => {
    const findings = detectEval(vulnerableParsed);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.map((f) => f.type)).toContain('EVAL_INJECTION');
  });

  test('detectXSS: ≥1 XSS finding', () => {
    const findings = detectXSS(vulnerableParsed);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.map((f) => f.type)).toContain('XSS');
  });

  test('detectPathTraversal: ≥1 PATH_TRAVERSAL finding', () => {
    const findings = detectPathTraversal(vulnerableParsed);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.map((f) => f.type)).toContain('PATH_TRAVERSAL');
  });

  test('detectPrototypePollution: ≥1 PROTOTYPE_POLLUTION finding', () => {
    const findings = detectPrototypePollution(vulnerableParsed);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.map((f) => f.type)).toContain('PROTOTYPE_POLLUTION');
  });

  test('detectInsecureRandom: ≥1 INSECURE_RANDOM finding', () => {
    const findings = detectInsecureRandom(vulnerableParsed);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.map((f) => f.type)).toContain('INSECURE_RANDOM');
  });

  test('detectSSRF: ≥1 SSRF finding', () => {
    const findings = detectSSRF(vulnerableParsed);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.map((f) => f.type)).toContain('SSRF');
  });

  test('detectJWTSecrets: ≥1 JWT finding', () => {
    const findings = detectJWTSecrets(vulnerableParsed);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  test('detectCommandInjection: ≥1 COMMAND_INJECTION finding', () => {
    const findings = detectCommandInjection(vulnerableParsed);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.map((f) => f.type)).toContain('COMMAND_INJECTION');
  });

  test('detectOpenRedirect: ≥1 OPEN_REDIRECT finding', () => {
    const findings = detectOpenRedirect(vulnerableParsed);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.map((f) => f.type)).toContain('OPEN_REDIRECT');
  });

  test('detectReDoS: ≥1 REDOS finding', () => {
    const findings = detectReDoS(vulnerableParsed);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.map((f) => f.type)).toContain('REDOS');
  });

  test('detectWeakCrypto: ≥1 WEAK_CRYPTO finding', () => {
    const findings = detectWeakCrypto(vulnerableParsed);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.map((f) => f.type)).toContain('WEAK_CRYPTO');
  });

  test('detectCORSMisconfiguration: ≥1 CORS_MISCONFIGURATION finding', () => {
    // CORS detector requires the specific wildcard-credentials pattern;
    // use a targeted snippet rather than the generic vulnerable fixture.
    const parsed = parseCode(`app.use(cors({ origin: '*', credentials: true }));`);
    const findings = detectCORSMisconfiguration(parsed);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.map((f) => f.type)).toContain('CORS_MISCONFIGURATION');
  });
});

// ── Detectors: clean fixture should produce zero findings ─────────────────────

describe('Detectors — clean.ts produces no false positives', () => {
  test('detectSecrets: 0 findings on clean.ts', () => {
    // clean.ts contains patterns that could cause false positives if the
    // SENSITIVE_VAR_NAMES regex or SECRET_VALUE_PATTERNS ever regress:
    //   - a variable named "secret" assigned from process.env.APP_SECRET
    //   - a jwt.verify() call with process.env.JWT_SECRET
    // Both must produce zero SECRET_HARDCODED findings because the values
    // come from environment variables, not hardcoded literals.
    expect(detectSecrets(cleanParsed).length).toBe(0);
  });

  test('detectSecrets: env-var secret assignment does not trigger SECRET_HARDCODED', () => {
    // Regression guard: "secret = process.env.APP_SECRET" is safe — the value
    // is read at runtime from the environment, not hardcoded in source.
    const parsed = parseCode(`const secret = process.env.APP_SECRET;`);
    expect(detectSecrets(parsed).length).toBe(0);
  });

  test('detectSecrets: jwt.verify with env-var key does not trigger SECRET_HARDCODED', () => {
    // Regression guard: jwt.verify with a process.env key is safe. If the
    // SECRET_VALUE_PATTERNS ever match "process.env.*" this test catches it.
    const parsed = parseCode(
      `import jwt from 'jsonwebtoken'; jwt.verify(token, process.env.JWT_SECRET ?? '', { algorithms: ['RS256'] });`,
    );
    expect(detectSecrets(parsed).length).toBe(0);
  });

  test('detectSQLInjection: 0 findings on clean.ts', () => {
    expect(detectSQLInjection(cleanParsed).length).toBe(0);
  });

  test('detectXSS: 0 findings on clean.ts', () => {
    expect(detectXSS(cleanParsed).length).toBe(0);
  });

  test('detectCommandInjection: 0 findings on clean.ts (static spawn commands are safe)', () => {
    // clean.ts uses _spawn('convert', [...]) and _spawnSync('ls', [...]) — both
    // have fully hardcoded command strings. The detector must not flag these.
    expect(detectCommandInjection(cleanParsed).length).toBe(0);
  });

  test('detectWeakCrypto: 0 findings on clean.ts (sha256 is safe)', () => {
    // clean.ts uses crypto.createHash('sha256') — a strong algorithm.
    // The detector must not flag sha256 or any other non-weak algorithm.
    expect(detectWeakCrypto(cleanParsed).length).toBe(0);
  });

  test('detectShellInjection: 0 findings on clean.ts (no exec/execSync with dynamic arg)', () => {
    // clean.ts only uses execFile (not exec/execSync) and spawn/spawnSync with
    // static command strings. Neither pattern should trigger SHELL_INJECTION.
    expect(detectShellInjection(cleanParsed).length).toBe(0);
  });

  test('detectPathTraversal: 0 findings on clean.ts (all paths are static)', () => {
    // clean.ts only calls path.join and fs.readFileSync with string literals —
    // no dynamic user-supplied path arguments. Zero findings expected.
    expect(detectPathTraversal(cleanParsed).length).toBe(0);
  });
});

// ── commandInjection: targeted positive + negative unit tests ─────────────────

describe('detectCommandInjection — positive and negative cases', () => {
  test('flags spawn() with a variable as the command (dynamic command)', () => {
    const parsed = parseCode(`spawn(userCmd, ['arg1']);`);
    const findings = detectCommandInjection(parsed);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.map((f) => f.type)).toContain('COMMAND_INJECTION');
  });

  test('flags spawnSync() with a template literal containing an expression', () => {
    const parsed = parseCode('spawnSync(`${req.body.tool}`, []);');
    const findings = detectCommandInjection(parsed);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.map((f) => f.type)).toContain('COMMAND_INJECTION');
  });

  test('does NOT flag spawn() with a static string literal command', () => {
    const parsed = parseCode(`spawn('ls', ['-la', userPath]);`);
    expect(detectCommandInjection(parsed).length).toBe(0);
  });

  test('does NOT flag spawnSync() with a static template literal (no expressions)', () => {
    const parsed = parseCode('spawnSync(`convert`, [input, output]);');
    expect(detectCommandInjection(parsed).length).toBe(0);
  });
});

// ── weakCrypto: targeted positive + negative unit tests ───────────────────────

describe('detectWeakCrypto — positive and negative cases', () => {
  test('flags createHash("md5") as WEAK_CRYPTO', () => {
    const parsed = parseCode(`import crypto from 'crypto'; crypto.createHash('md5').update(data).digest('hex');`);
    const findings = detectWeakCrypto(parsed);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.map((f) => f.type)).toContain('WEAK_CRYPTO');
  });

  test('flags createHash("sha1") as WEAK_CRYPTO', () => {
    const parsed = parseCode(`createHash('sha1').update(token).digest('hex');`);
    const findings = detectWeakCrypto(parsed);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.map((f) => f.type)).toContain('WEAK_CRYPTO');
  });

  test('does NOT flag createHash("sha256") — strong algorithm', () => {
    const parsed = parseCode(`crypto.createHash('sha256').update(data).digest('hex');`);
    expect(detectWeakCrypto(parsed).length).toBe(0);
  });

  test('does NOT flag createHash("sha3-256") — strong algorithm', () => {
    const parsed = parseCode(`createHash('sha3-256').update(data).digest('hex');`);
    expect(detectWeakCrypto(parsed).length).toBe(0);
  });
});

// ── shellInjection: targeted positive + negative unit tests ───────────────────

describe('detectShellInjection — positive and negative cases', () => {
  test('flags exec() with a variable as the command', () => {
    const parsed = parseCode(`exec(userInput);`);
    const findings = detectShellInjection(parsed);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.map((f) => f.type)).toContain('SHELL_INJECTION');
  });

  test('flags execSync() with a template literal containing an expression', () => {
    const parsed = parseCode('execSync(`rm -rf ${req.body.path}`);');
    const findings = detectShellInjection(parsed);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.map((f) => f.type)).toContain('SHELL_INJECTION');
  });

  test('does NOT flag exec() with a static string literal', () => {
    const parsed = parseCode(`exec('ls -la');`);
    expect(detectShellInjection(parsed).length).toBe(0);
  });

  test('does NOT flag spawn() — spawn is NOT a shell-invoking function', () => {
    // spawn() does not invoke a shell; it is handled by commandInjection.ts.
    // Ensuring shell.ts does not produce duplicate SHELL_INJECTION findings.
    const parsed = parseCode(`spawn(userCmd, ['arg']);`);
    const findings = detectShellInjection(parsed);
    expect(findings.map((f) => f.type)).not.toContain('SHELL_INJECTION');
  });

  test('does NOT flag spawnSync() — spawnSync is NOT a shell-invoking function', () => {
    const parsed = parseCode(`spawnSync(cmd, ['-r', file]);`);
    const findings = detectShellInjection(parsed);
    expect(findings.map((f) => f.type)).not.toContain('SHELL_INJECTION');
  });
});

// ── pathTraversal: targeted positive + negative unit tests ────────────────────

describe('detectPathTraversal — positive and negative cases', () => {
  test('flags fs.readFileSync() with a dynamic path argument', () => {
    const parsed = parseCode(`import * as fs from 'fs'; fs.readFileSync(req.params.file);`);
    const findings = detectPathTraversal(parsed);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.map((f) => f.type)).toContain('PATH_TRAVERSAL');
  });

  test('flags path.join() with a dynamic argument', () => {
    const parsed = parseCode(`import * as path from 'path'; path.join('/uploads', req.body.name);`);
    const findings = detectPathTraversal(parsed);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.map((f) => f.type)).toContain('PATH_TRAVERSAL');
  });

  test('flags path.resolve() with a dynamic argument', () => {
    const parsed = parseCode(`import * as path from 'path'; path.resolve('/base', userPath);`);
    const findings = detectPathTraversal(parsed);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.map((f) => f.type)).toContain('PATH_TRAVERSAL');
  });

  test('does NOT flag fs.readFileSync() with a static string literal path', () => {
    const parsed = parseCode(`import * as fs from 'fs'; fs.readFileSync('/etc/config.json', 'utf8');`);
    expect(detectPathTraversal(parsed).length).toBe(0);
  });

  test('does NOT flag path.join() with all static string arguments', () => {
    const parsed = parseCode(`import * as path from 'path'; path.join('/var', 'app', 'data.json');`);
    expect(detectPathTraversal(parsed).length).toBe(0);
  });
});

// ── buildSARIF: direct unit tests ─────────────────────────────────────────────

describe('buildSARIF — output structure', () => {
  test('runs[0].tool.driver.informationUri is present', () => {
    const sarif = buildSARIF([makeFinding()]) as any;
    const uri = sarif.runs?.[0]?.tool?.driver?.informationUri;
    expect(typeof uri).toBe('string');
    expect(uri.length).toBeGreaterThanOrEqual(1);
  });

  test('each rule has fullDescription.text populated', () => {
    const findings = [
      makeFinding({ type: 'SQL_INJECTION' }),
      makeFinding({ type: 'XSS' }),
    ];
    const sarif = buildSARIF(findings) as any;
    const rules: any[] = sarif.runs?.[0]?.tool?.driver?.rules ?? [];
    expect(rules.length).toBeGreaterThanOrEqual(1);
    for (const rule of rules) {
      expect(typeof rule.fullDescription?.text).toBe('string');
      expect(rule.fullDescription.text.length).toBeGreaterThanOrEqual(1);
    }
  });

  test('each rule has a valid helpUri', () => {
    const sarif = buildSARIF([makeFinding()]) as any;
    const rules: any[] = sarif.runs?.[0]?.tool?.driver?.rules ?? [];
    for (const rule of rules) {
      expect(rule.helpUri).toMatch(/^https:\/\//);
    }
  });

  test('critical/high findings map to level "error"', () => {
    const sarif = buildSARIF([makeFinding({ severity: 'high' })]) as any;
    const result = sarif.runs?.[0]?.results?.[0];
    expect(result?.level).toBe('error');
  });

  test('critical severity also maps to level "error"', () => {
    const sarif = buildSARIF([makeFinding({ severity: 'critical' })]) as any;
    expect(sarif.runs?.[0]?.results?.[0]?.level).toBe('error');
  });

  test('medium severity maps to level "warning"', () => {
    const sarif = buildSARIF([makeFinding({ severity: 'medium' })]) as any;
    expect(sarif.runs?.[0]?.results?.[0]?.level).toBe('warning');
  });

  test('low severity maps to level "note"', () => {
    const sarif = buildSARIF([makeFinding({ severity: 'low' })]) as any;
    expect(sarif.runs?.[0]?.results?.[0]?.level).toBe('note');
  });

  test('empty findings array produces valid SARIF with zero results', () => {
    const sarif = buildSARIF([]) as any;
    expect(Array.isArray(sarif.runs)).toBe(true);
    expect(sarif.runs?.[0]?.results?.length).toBe(0);
    expect(sarif.runs?.[0]?.tool?.driver?.rules?.length).toBe(0);
  });

  test('unknown rule type uses the type id as fallback description', () => {
    const sarif = buildSARIF([makeFinding({ type: 'UNKNOWN_RULE_XYZ' as any })]) as any;
    const rule = sarif.runs?.[0]?.tool?.driver?.rules?.[0];
    expect(rule?.fullDescription?.text).toBe('UNKNOWN_RULE_XYZ');
  });

  test('SARIF_RULE_DESCRIPTIONS covers all known finding types', () => {
    const knownTypes = [
      'SECRET_HARDCODED', 'SQL_INJECTION', 'SHELL_INJECTION', 'EVAL_INJECTION',
      'XSS', 'PATH_TRAVERSAL', 'PROTOTYPE_POLLUTION', 'INSECURE_RANDOM',
      'OPEN_REDIRECT', 'SSRF', 'COMMAND_INJECTION', 'CORS_MISCONFIGURATION',
      'JWT_HARDCODED_SECRET', 'JWT_WEAK_SECRET', 'JWT_NONE_ALGORITHM',
      'JWT_DECODE_NO_VERIFY', 'REDOS', 'WEAK_CRYPTO', 'UNSAFE_DEPENDENCY',
      'VULNERABLE_DEPENDENCY',
    ];
    for (const type of knownTypes) {
      expect(SARIF_RULE_DESCRIPTIONS[type], `Missing description for ${type}`).toBeTruthy();
    }
  });
});

// ── buildHTMLReport — unit tests ──────────────────────────────────────────────

describe('buildHTMLReport — output structure', () => {
  test('returns a string starting with <!DOCTYPE html>', () => {
    const html = buildHTMLReport([], '/some/root');
    expect(typeof html).toBe('string');
    expect(html.trimStart().startsWith('<!DOCTYPE html>')).toBe(true);
  });

  test('empty findings renders no-findings state and no file cards', () => {
    const html = buildHTMLReport([], '/some/root');
    expect(html).toContain('No findings');
    expect(html).not.toContain('class="finding"');
  });

  test('findings appear in output grouped under their file path', () => {
    const findings: Finding[] = [
      makeFinding({ file: '/root/src/foo.ts', message: 'Hardcoded password', severity: 'high' }),
      makeFinding({ file: '/root/src/foo.ts', message: 'SQL concat', type: 'SQL_INJECTION', severity: 'critical' }),
      makeFinding({ file: '/root/src/bar.ts', message: 'Eval call', type: 'EVAL_INJECTION', severity: 'medium' }),
    ];
    const html = buildHTMLReport(findings, '/root');
    // All three messages must appear
    expect(html).toContain('Hardcoded password');
    expect(html).toContain('SQL concat');
    expect(html).toContain('Eval call');
    // Relative paths are rendered (scan root stripped)
    expect(html).toContain('src/foo.ts');
    expect(html).toContain('src/bar.ts');
  });

  test('severity badges are rendered for each severity level', () => {
    const findings: Finding[] = [
      makeFinding({ severity: 'critical', message: 'crit finding' }),
      makeFinding({ severity: 'high',     message: 'high finding' }),
      makeFinding({ severity: 'medium',   message: 'med finding' }),
      makeFinding({ severity: 'low',      message: 'low finding' }),
    ];
    const html = buildHTMLReport(findings, '/root');
    // Each severity label must appear at least once as an uppercased badge
    expect(html).toContain('critical');
    expect(html).toContain('high');
    expect(html).toContain('medium');
    expect(html).toContain('low');
  });

  test('summary bar counts are correct', () => {
    const findings: Finding[] = [
      makeFinding({ severity: 'high' }),
      makeFinding({ severity: 'high' }),
      makeFinding({ severity: 'medium' }),
    ];
    const html = buildHTMLReport(findings, '/root');
    // Summary bar should mention the count 2 for high and 1 for medium
    expect(html).toContain('>2<');
    expect(html).toContain('>1<');
  });

  test('total findings count appears in the report header', () => {
    const findings: Finding[] = [makeFinding(), makeFinding(), makeFinding()];
    const html = buildHTMLReport(findings, '/root');
    expect(html).toContain('Total findings: <strong>3</strong>');
  });

  test('generatedAt timestamp appears in the report', () => {
    const ts = '2026-01-15T12:00:00.000Z';
    const html = buildHTMLReport([], '/root', ts);
    expect(html).toContain(ts);
  });

  test('escapeHtml prevents XSS via malicious finding messages', () => {
    const malicious = '<script>alert("xss")</script>';
    const findings: Finding[] = [
      makeFinding({ message: malicious, file: 'evil.ts' }),
    ];
    const html = buildHTMLReport(findings, '/root');
    // Raw script tag must NOT appear
    expect(html).not.toContain('<script>alert("xss")</script>');
    // Escaped version must appear instead
    expect(html).toContain('&lt;script&gt;');
  });

  test('escapeHtml prevents XSS in file path', () => {
    const findings: Finding[] = [
      makeFinding({ file: '/root/<evil>.ts', message: 'test finding' }),
    ];
    const html = buildHTMLReport(findings, '/root');
    expect(html).not.toContain('<evil>');
    expect(html).toContain('&lt;evil&gt;');
  });

  test('scan root is stripped from file paths in output', () => {
    const findings: Finding[] = [
      makeFinding({ file: '/project/src/auth.ts' }),
    ];
    const html = buildHTMLReport(findings, '/project');
    expect(html).toContain('src/auth.ts');
    // Absolute path should not appear verbatim as a leading path
    expect(html).not.toContain('/project/src/auth.ts');
  });
});
