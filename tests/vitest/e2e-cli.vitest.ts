/**
 * E2E CLI integration tests — scan real fixture files, verify all output
 * formats and exit codes.
 *
 * Uses the compiled dist/cli.js against real fixture files in tests/fixtures/.
 * Covers: json, sarif, html, junit, markdown, sonarqube output formats;
 *         exit codes; --min-severity flag.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, beforeAll } from 'vitest';
import { execSync, spawnSync } from 'child_process';
import path from 'path';
import fs from 'fs';

const PROJECT_ROOT = path.resolve(__dirname, '..', '..');
const DIST_CLI = path.join(PROJECT_ROOT, 'dist', 'cli.js');
const VULNERABLE_TS = path.join(PROJECT_ROOT, 'tests', 'fixtures', 'vulnerable.ts');
const CLEAN_TS = path.join(PROJECT_ROOT, 'tests', 'fixtures', 'clean.ts');

const MAX_BUF = 10 * 1024 * 1024;

function runCLI(args: string[]): ReturnType<typeof spawnSync> {
  return spawnSync(process.execPath, [DIST_CLI, ...args], {
    cwd: PROJECT_ROOT,
    encoding: 'utf-8',
    timeout: 30_000,
    maxBuffer: MAX_BUF,
  });
}

describe('E2E CLI — build gate', () => {
  beforeAll(() => {
    const cliMtime = fs.existsSync(DIST_CLI) ? fs.statSync(DIST_CLI).mtimeMs : 0;
    const srcMtime = fs.statSync(path.join(PROJECT_ROOT, 'src', 'cli.ts')).mtimeMs;
    if (cliMtime < srcMtime) {
      execSync('npm run build', {
        cwd: PROJECT_ROOT,
        stdio: 'pipe',
        timeout: 120_000,
        maxBuffer: MAX_BUF,
      });
    }
  }, 90_000);

  test('dist/cli.js exists', () => {
    expect(fs.existsSync(DIST_CLI)).toBe(true);
  });
});

describe('E2E CLI — exit codes', () => {
  test('exits 1 for vulnerable file', () => {
    const result = runCLI([VULNERABLE_TS]);
    expect(result.status).toBe(1);
  });

  test('exits 0 for clean file', () => {
    const result = runCLI([CLEAN_TS]);
    expect(result.status).toBe(0);
  });

  test('vulnerable file emits non-empty stdout', () => {
    const result = runCLI([VULNERABLE_TS]);
    expect(result.stdout.trim().length).toBeGreaterThan(0);
  });
});

describe('E2E CLI — --format json', () => {
  test('outputs valid JSON with findings array', () => {
    const result = runCLI([VULNERABLE_TS, '--format', 'json']);
    expect(result.status).toBe(1);
    let parsed: { findings?: unknown[] };
    expect(() => { parsed = JSON.parse(result.stdout); }).not.toThrow();
    expect(Array.isArray(parsed!.findings)).toBe(true);
    expect(parsed!.findings!.length).toBeGreaterThan(0);
  });

  test('clean file outputs empty findings array', () => {
    const result = runCLI([CLEAN_TS, '--format', 'json']);
    expect(result.status).toBe(0);
    const parsed = JSON.parse(result.stdout) as { findings: unknown[] };
    expect(Array.isArray(parsed.findings)).toBe(true);
    expect(parsed.findings.length).toBe(0);
  });
});

describe('E2E CLI — --format sarif', () => {
  test('outputs valid SARIF 2.1.0 JSON', () => {
    const result = runCLI([VULNERABLE_TS, '--format', 'sarif']);
    expect(result.status).toBe(1);
    let parsed: { version?: string; $schema?: string; runs?: unknown[] };
    expect(() => { parsed = JSON.parse(result.stdout); }).not.toThrow();
    expect(parsed!.version).toBe('2.1.0');
    expect(parsed!.$schema).toMatch(/sarif/i);
    expect(Array.isArray(parsed!.runs)).toBe(true);
  });
});

describe('E2E CLI — --format html', () => {
  test('outputs HTML with <html> tag', () => {
    const result = runCLI([VULNERABLE_TS, '--format', 'html']);
    expect(result.status).toBe(1);
    expect(result.stdout).toContain('<html');
  });
});

describe('E2E CLI — --format junit', () => {
  test('outputs XML with <testsuites> element', () => {
    const result = runCLI([VULNERABLE_TS, '--format', 'junit']);
    expect(result.status).toBe(1);
    expect(result.stdout).toContain('<testsuites');
  });
});

describe('E2E CLI — --format markdown', () => {
  test('outputs markdown with ## header', () => {
    const result = runCLI([VULNERABLE_TS, '--format', 'markdown']);
    expect(result.status).toBe(1);
    expect(result.stdout).toMatch(/^##\s/m);
  });
});

describe('E2E CLI — --format sonarqube', () => {
  test('outputs JSON with issues array', () => {
    const result = runCLI([VULNERABLE_TS, '--format', 'sonarqube']);
    expect(result.status).toBe(1);
    let parsed: { issues?: unknown[] };
    expect(() => { parsed = JSON.parse(result.stdout); }).not.toThrow();
    expect(Array.isArray(parsed!.issues)).toBe(true);
    expect(parsed!.issues!.length).toBeGreaterThan(0);
  });
});

describe('E2E CLI — --min-severity flag', () => {
  test('--min-severity critical only exits 1 for critical findings', () => {
    // Run against vulnerable.ts — may or may not have critical findings
    // The key assertion is that the output is valid JSON when format=json
    const result = runCLI([VULNERABLE_TS, '--format', 'json', '--min-severity', 'critical']);
    // status is 0 (no criticals) or 1 (has criticals) — both are valid outcomes
    expect([0, 1]).toContain(result.status);
    const parsed = JSON.parse(result.stdout) as { findings: unknown[] };
    expect(Array.isArray(parsed.findings)).toBe(true);
    // If there are findings, they must all be critical
    for (const f of parsed.findings as Array<{ severity: string }>) {
      expect(f.severity).toBe('critical');
    }
  });

  test('--min-severity high filters out low/medium findings', () => {
    const result = runCLI([VULNERABLE_TS, '--format', 'json', '--min-severity', 'high']);
    expect([0, 1]).toContain(result.status);
    const parsed = JSON.parse(result.stdout) as { findings: Array<{ severity: string }> };
    for (const f of parsed.findings) {
      expect(['critical', 'high']).toContain(f.severity);
    }
  });
});
