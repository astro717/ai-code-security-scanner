/**
 * E2E test for CLI scanning of PHP (.php) files.
 *
 * Compiles the TypeScript source, then invokes dist/cli.js against
 * tests/fixtures/vulnerable.php. Asserts that PHP-specific findings
 * (SQL_INJECTION, XSS, COMMAND_INJECTION) are detected in both JSON and text
 * output modes. Also verifies clean.php produces no findings.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, beforeAll } from 'vitest';
import { execSync, spawnSync } from 'child_process';
import path from 'path';
import fs from 'fs';

const PROJECT_ROOT = path.resolve(__dirname, '..', '..');
const DIST_CLI = path.join(PROJECT_ROOT, 'dist', 'cli.js');
const VULNERABLE = path.join(PROJECT_ROOT, 'tests', 'fixtures', 'vulnerable.php');
const CLEAN = path.join(PROJECT_ROOT, 'tests', 'fixtures', 'clean.php');

describe('CLI E2E — PHP scanner', () => {
  beforeAll(() => {
    const cliMtime = fs.existsSync(DIST_CLI) ? fs.statSync(DIST_CLI).mtimeMs : 0;
    const srcMtime = fs.statSync(path.join(PROJECT_ROOT, 'src', 'cli.ts')).mtimeMs;
    if (cliMtime < srcMtime) {
      execSync('npm run build', {
        cwd: PROJECT_ROOT,
        stdio: 'pipe',
        timeout: 120_000,
        maxBuffer: 10 * 1024 * 1024,
      });
    }
  }, 60_000);

  test('dist/cli.js exists after build', () => {
    expect(fs.existsSync(DIST_CLI)).toBe(true);
  });

  test('PHP fixture files exist', () => {
    expect(fs.existsSync(VULNERABLE)).toBe(true);
    expect(fs.existsSync(CLEAN)).toBe(true);
  });

  test('exits with code 1 and emits JSON findings for vulnerable.php', () => {
    const result = spawnSync(
      process.execPath,
      [DIST_CLI, VULNERABLE, '--json'],
      {
        cwd: PROJECT_ROOT,
        encoding: 'utf-8',
        timeout: 30_000,
      },
    );

    // CLI exits 1 when findings are present
    expect(result.status).toBe(1);

    // stdout must be valid JSON
    let output: { findings: Array<{ type: string; severity: string; line: number; message: string }> };
    expect(() => {
      output = JSON.parse(result.stdout);
    }).not.toThrow();

    output = JSON.parse(result.stdout);
    expect(output.findings).toBeDefined();
    expect(Array.isArray(output.findings)).toBe(true);
    expect(output.findings.length).toBeGreaterThanOrEqual(10);

    const types = new Set(output.findings.map((f) => f.type));

    // Must detect core PHP vulnerability types
    expect(types.has('SQL_INJECTION')).toBe(true);
    expect(types.has('XSS')).toBe(true);
    expect(types.has('COMMAND_INJECTION')).toBe(true);
    expect(types.has('PATH_TRAVERSAL')).toBe(true);
    expect(types.has('EVAL_INJECTION')).toBe(true);
    expect(types.has('SECRET_HARDCODED')).toBe(true);
    expect(types.has('INSECURE_RANDOM')).toBe(true);
    expect(types.has('WEAK_CRYPTO')).toBe(true);
  });

  test('SQL_INJECTION findings have correct severity and line numbers', () => {
    const result = spawnSync(
      process.execPath,
      [DIST_CLI, VULNERABLE, '--json'],
      {
        cwd: PROJECT_ROOT,
        encoding: 'utf-8',
        timeout: 30_000,
      },
    );

    const output = JSON.parse(result.stdout);
    const sqlFindings = output.findings.filter((f: { type: string }) => f.type === 'SQL_INJECTION');

    expect(sqlFindings.length).toBeGreaterThanOrEqual(1);
    for (const f of sqlFindings) {
      expect(f.severity).toBe('critical');
      expect(f.line).toBeGreaterThan(0);
      expect(f.message).toBeTruthy();
    }
  });

  test('text output mode includes finding types and severity labels', () => {
    const result = spawnSync(
      process.execPath,
      [DIST_CLI, VULNERABLE],
      {
        cwd: PROJECT_ROOT,
        encoding: 'utf-8',
        timeout: 30_000,
      },
    );

    expect(result.status).toBe(1);

    const output = result.stdout + result.stderr;
    expect(output).toContain('SQL_INJECTION');
    expect(output).toContain('XSS');
    expect(output).toContain('COMMAND_INJECTION');
    // Should show severity labels
    expect(output).toMatch(/CRITICAL|HIGH|MEDIUM/i);
  });

  test('clean.php produces zero findings and exits 0', () => {
    const result = spawnSync(
      process.execPath,
      [DIST_CLI, CLEAN, '--json'],
      {
        cwd: PROJECT_ROOT,
        encoding: 'utf-8',
        timeout: 30_000,
      },
    );

    expect(result.status).toBe(0);

    const output = JSON.parse(result.stdout);
    expect(output.findings).toBeDefined();
    expect(output.findings).toHaveLength(0);
  });

  test('--severity high filters out medium/low findings', () => {
    const result = spawnSync(
      process.execPath,
      [DIST_CLI, VULNERABLE, '--json', '--severity', 'high'],
      {
        cwd: PROJECT_ROOT,
        encoding: 'utf-8',
        timeout: 30_000,
      },
    );

    const output = JSON.parse(result.stdout);
    // All remaining findings should be high or critical
    for (const f of output.findings) {
      expect(['high', 'critical']).toContain(f.severity);
    }
  });
});
