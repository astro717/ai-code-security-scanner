/**
 * Tests verifying that the per-rule severity override and cacheTtlDays config
 * keys are correctly validated by validateConfig (exercised via the CLI with a
 * temp config file so we test the actual validation path).
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execFileSync } from 'child_process';

const CLI_ENTRY = path.resolve(__dirname, '../../dist/cli.js');
const FIXTURE_FILE = path.resolve(__dirname, '../fixtures/vulnerable.js');

function writeTempConfig(dir: string, config: object): string {
  const filePath = path.join(dir, '.ai-sec-scan.json');
  fs.writeFileSync(filePath, JSON.stringify(config), 'utf-8');
  return filePath;
}

/**
 * Runs the CLI with a given config directory. Returns { stdout, stderr, code }.
 * We deliberately scan the fixtures directory so the scan succeeds and the
 * config is loaded — the exit code alone tells us whether config was accepted.
 */
function runCLI(configDir: string, extraArgs: string[] = []): { stdout: string; stderr: string; code: number } {
  try {
    const stdout = execFileSync(
      process.execPath,
      [CLI_ENTRY, FIXTURE_FILE, '--config', path.join(configDir, '.ai-sec-scan.json'), ...extraArgs],
      { encoding: 'utf-8', cwd: configDir },
    );
    return { stdout, stderr: '', code: 0 };
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; status?: number };
    return { stdout: e.stdout ?? '', stderr: e.stderr ?? '', code: e.status ?? 1 };
  }
}

describe('.ai-sec-scan.json — per-rule severity overrides (rules key)', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-sec-rules-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('valid rules object with all severity values is accepted by the schema', () => {
    const configPath = writeTempConfig(tmpDir, {
      rules: {
        SQL_INJECTION: 'critical',
        XSS: 'high',
        INSECURE_RANDOM: 'medium',
        CORS_MISCONFIGURATION: 'low',
      },
    });
    const parsed = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(parsed.rules).toBeDefined();
    expect(parsed.rules.SQL_INJECTION).toBe('critical');
    expect(parsed.rules.XSS).toBe('high');
    expect(parsed.rules.INSECURE_RANDOM).toBe('medium');
    expect(parsed.rules.CORS_MISCONFIGURATION).toBe('low');
  });

  test('rules with invalid severity value produces a validation error in CLI output', () => {
    writeTempConfig(tmpDir, {
      rules: {
        SQL_INJECTION: 'blocker', // invalid — not one of the 4 severities
      },
    });
    const { stderr, code } = runCLI(tmpDir);
    expect(code).not.toBe(0);
    expect(stderr + '').toMatch(/rules\.SQL_INJECTION|invalid|severity/i);
  });

  test('rules as an array (non-object) produces a validation error', () => {
    writeTempConfig(tmpDir, {
      rules: ['SQL_INJECTION', 'XSS'],
    });
    const { stderr, code } = runCLI(tmpDir);
    expect(code).not.toBe(0);
    expect(stderr + '').toMatch(/"rules"|plain object|array/i);
  });

  test('rules as a string (non-object) produces a validation error', () => {
    writeTempConfig(tmpDir, {
      rules: 'SQL_INJECTION:critical',
    });
    const { stderr, code } = runCLI(tmpDir);
    expect(code).not.toBe(0);
    expect(stderr + '').toMatch(/"rules"|plain object/i);
  });

  test('empty rules object is accepted as valid', () => {
    const configPath = writeTempConfig(tmpDir, { rules: {} });
    const parsed = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(parsed.rules).toEqual({});
  });
});

describe('.ai-sec-scan.json — cacheTtlDays config key', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-sec-ttl-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('cacheTtlDays with a positive number is accepted by the schema', () => {
    const configPath = writeTempConfig(tmpDir, { cacheTtlDays: 7 });
    const parsed = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(parsed.cacheTtlDays).toBe(7);
  });

  test('cacheTtlDays with a fractional positive value is accepted', () => {
    const configPath = writeTempConfig(tmpDir, { cacheTtlDays: 0.5 });
    const parsed = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(parsed.cacheTtlDays).toBe(0.5);
  });

  test('cacheTtlDays of 0 produces a validation error (must be positive)', () => {
    writeTempConfig(tmpDir, { cacheTtlDays: 0 });
    const { stderr, code } = runCLI(tmpDir);
    expect(code).not.toBe(0);
    expect(stderr + '').toMatch(/cacheTtlDays|positive/i);
  });

  test('cacheTtlDays of -1 produces a validation error', () => {
    writeTempConfig(tmpDir, { cacheTtlDays: -1 });
    const { stderr, code } = runCLI(tmpDir);
    expect(code).not.toBe(0);
    expect(stderr + '').toMatch(/cacheTtlDays|positive/i);
  });

  test('cacheTtlDays as a string produces a validation error', () => {
    writeTempConfig(tmpDir, { cacheTtlDays: '7' });
    const { stderr, code } = runCLI(tmpDir);
    expect(code).not.toBe(0);
    expect(stderr + '').toMatch(/cacheTtlDays|positive number/i);
  });

  test('unknown config key produces a validation error with suggestion', () => {
    writeTempConfig(tmpDir, { cacheTtlDay: 7 }); // typo — missing 's'
    const { stderr, code } = runCLI(tmpDir);
    expect(code).not.toBe(0);
    expect(stderr + '').toMatch(/cacheTtlDay|Unknown config key/i);
  });
});
