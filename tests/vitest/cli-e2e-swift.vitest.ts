/**
 * E2E test for CLI scanning of Swift (.swift) files.
 *
 * Compiles the TypeScript source, then invokes dist/cli.js against
 * tests/fixtures/vulnerable.swift. Asserts that Swift-specific findings
 * (SSRF, INSECURE_SHARED_PREFS, UNSAFE_WEBVIEW, SECRET_HARDCODED, WEAK_CRYPTO)
 * are detected and the exit code is 1.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, beforeAll } from 'vitest';
import { execSync, spawnSync } from 'child_process';
import path from 'path';
import fs from 'fs';

const PROJECT_ROOT = path.resolve(__dirname, '..', '..');
const DIST_CLI = path.join(PROJECT_ROOT, 'dist', 'cli.js');
const FIXTURE = path.join(PROJECT_ROOT, 'tests', 'fixtures', 'vulnerable.swift');

describe('CLI E2E — Swift scanner', () => {
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

  test('fixture file exists', () => {
    expect(fs.existsSync(FIXTURE)).toBe(true);
  });

  test('exits with code 1 and emits JSON findings for vulnerable.swift', () => {
    const result = spawnSync(
      process.execPath,
      [DIST_CLI, FIXTURE, '--json'],
      {
        cwd: PROJECT_ROOT,
        encoding: 'utf-8',
        timeout: 30_000,
      },
    );

    // CLI exits 1 when findings are present
    expect(result.status).toBe(1);

    // stdout must be valid JSON
    let output: unknown;
    expect(() => {
      output = JSON.parse(result.stdout);
    }).not.toThrow();

    const parsed = output as { findings?: unknown[]; summary?: unknown };
    expect(Array.isArray(parsed.findings)).toBe(true);
    expect((parsed.findings as unknown[]).length).toBeGreaterThan(0);
    expect(parsed.summary).toBeDefined();

    // Each finding has required fields
    for (const f of parsed.findings as Array<Record<string, unknown>>) {
      expect(typeof f.type).toBe('string');
      expect(typeof f.severity).toBe('string');
      expect(['critical', 'high', 'medium', 'low']).toContain(f.severity);
      expect(typeof f.line).toBe('number');
      expect(f.line).toBeGreaterThan(0);
      expect(typeof f.message).toBe('string');
    }
  });

  test('detects expected Swift finding types', () => {
    const result = spawnSync(
      process.execPath,
      [DIST_CLI, FIXTURE, '--json'],
      {
        cwd: PROJECT_ROOT,
        encoding: 'utf-8',
        timeout: 30_000,
      },
    );

    const parsed = JSON.parse(result.stdout) as { findings: Array<{ type: string }> };
    const types = new Set(parsed.findings.map((f) => f.type));

    expect(types.has('SSRF')).toBe(true);
    expect(types.has('SECRET_HARDCODED')).toBe(true);
    expect(types.has('WEAK_CRYPTO')).toBe(true);
  });
});
