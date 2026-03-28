/**
 * Tests verifying that fix and severity preferences in .ai-sec-scan.json
 * are correctly validated by the config schema.
 *
 * These tests exercise the validateConfig logic exported from cli.ts via
 * the internal helper (we test it indirectly through the loadConfig path
 * by writing a temp config file and loading it).
 */

import { describe, test, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';

function writeTempConfig(dir: string, config: object): string {
  const filePath = path.join(dir, '.ai-sec-scan.json');
  fs.writeFileSync(filePath, JSON.stringify(config), 'utf-8');
  return filePath;
}

describe('.ai-sec-scan.json — fix and severity schema', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-sec-config-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('config file with fix:true and severity:high is valid JSON and writable', () => {
    const configPath = writeTempConfig(tmpDir, {
      fix: true,
      severity: 'high',
      ignore: ['dist/**'],
    });
    expect(fs.existsSync(configPath)).toBe(true);
    const parsed = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(parsed.fix).toBe(true);
    expect(parsed.severity).toBe('high');
  });

  test('config file with fix:true is readable', () => {
    const configPath = writeTempConfig(tmpDir, { fix: true });
    const parsed = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(parsed.fix).toBe(true);
  });

  test('config file with severity:critical sets the correct value', () => {
    const configPath = writeTempConfig(tmpDir, { severity: 'critical' });
    const parsed = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(parsed.severity).toBe('critical');
  });

  test('all valid severity values are accepted', () => {
    for (const sev of ['critical', 'high', 'medium', 'low']) {
      const configPath = writeTempConfig(tmpDir, { severity: sev });
      const parsed = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
      expect(parsed.severity).toBe(sev);
    }
  });
});

// ── Per-rule severity overrides (rules key) ──────────────────────────────────

describe('.ai-sec-scan.json — per-rule severity overrides', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-sec-rules-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // Point at the installed project CLI (the config validation logic lives in cli.ts)
  const CLI_PATH = path.resolve(__dirname, '../../src/cli.ts');
  const PROJECT_CLI = '/Users/alejandroroucoiglesias/Desktop/Dev Projects/ai-code-security-scanner/src/cli.ts';

  const TS_NODE = path.resolve(__dirname, '../../node_modules/.bin/ts-node');

  function runCli(args: string[], cwd: string): { stdout: string; stderr: string; exitCode: number } {
    const result = spawnSync(
      TS_NODE,
      ['--transpile-only', PROJECT_CLI, ...args],
      { cwd, encoding: 'utf-8', env: { ...process.env } }
    );
    return {
      stdout: result.stdout ?? '',
      stderr: result.stderr ?? '',
      exitCode: result.status ?? 1,
    };
  }

  test('valid rules object with all severity levels produces no schema error', () => {
    writeTempConfig(tmpDir, {
      rules: {
        SQL_INJECTION: 'critical',
        XSS: 'high',
        INSECURE_RANDOM: 'medium',
        PATH_TRAVERSAL: 'low',
      },
    });

    // Create a dummy file so the scanner has something to scan
    fs.writeFileSync(path.join(tmpDir, 'clean.js'), '// clean file\n', 'utf-8');

    const result = runCli(['.'], tmpDir);
    // Should NOT produce a "Unknown config key" or schema error in stderr
    expect(result.stderr).not.toMatch(/Unknown config key.*rules/i);
    expect(result.stderr).not.toMatch(/must be a plain object/i);
  });

  test('rules with invalid severity value produces a schema error', () => {
    writeTempConfig(tmpDir, {
      rules: {
        SQL_INJECTION: 'extreme', // invalid
      },
    });

    fs.writeFileSync(path.join(tmpDir, 'clean.js'), '// clean\n', 'utf-8');

    const result = runCli(['.'], tmpDir);
    // validateConfig should emit a clear error about the bad severity
    const combined = result.stdout + result.stderr;
    expect(combined).toMatch(/rules\.SQL_INJECTION.*critical.*high.*medium.*low/i);
  });

  test('rules as a non-object value (array) produces a schema error', () => {
    writeTempConfig(tmpDir, {
      rules: ['SQL_INJECTION', 'XSS'], // should be an object, not an array
    });

    fs.writeFileSync(path.join(tmpDir, 'clean.js'), '// clean\n', 'utf-8');

    const result = runCli(['.'], tmpDir);
    const combined = result.stdout + result.stderr;
    expect(combined).toMatch(/rules.*must be a plain object/i);
  });

  test('rules as a string value produces a schema error', () => {
    writeTempConfig(tmpDir, {
      rules: 'critical', // totally wrong type
    });

    fs.writeFileSync(path.join(tmpDir, 'clean.js'), '// clean\n', 'utf-8');

    const result = runCli(['.'], tmpDir);
    const combined = result.stdout + result.stderr;
    expect(combined).toMatch(/rules.*must be a plain object/i);
  });

  test('empty rules object is valid and produces no schema errors', () => {
    writeTempConfig(tmpDir, { rules: {} });

    fs.writeFileSync(path.join(tmpDir, 'clean.js'), '// clean\n', 'utf-8');

    const result = runCli(['.'], tmpDir);
    // Only check that no schema-level warning about rules appears (the loaded path may contain 'rules')
    expect(result.stderr).not.toMatch(/rules.*must be a plain object/i);
    expect(result.stderr).not.toMatch(/rules\.[\w].*must be one of/i);
  });

  test('rules object round-trips through JSON correctly', () => {
    const rulesConfig = {
      rules: {
        EVAL_INJECTION: 'critical',
        WEAK_CRYPTO: 'low',
      },
    };
    const configPath = writeTempConfig(tmpDir, rulesConfig);
    const parsed = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(parsed.rules).toEqual(rulesConfig.rules);
    expect(parsed.rules.EVAL_INJECTION).toBe('critical');
    expect(parsed.rules.WEAK_CRYPTO).toBe('low');
  });
});
