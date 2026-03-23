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
    expect(detectSecrets(cleanParsed).length).toBe(0);
  });

  test('detectSQLInjection: 0 findings on clean.ts', () => {
    expect(detectSQLInjection(cleanParsed).length).toBe(0);
  });

  test('detectXSS: 0 findings on clean.ts', () => {
    expect(detectXSS(cleanParsed).length).toBe(0);
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
