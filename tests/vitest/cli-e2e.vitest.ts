/**
 * E2E test for the full CLI scan pipeline.
 *
 * Compiles the TypeScript source via `npm run build`, then invokes the
 * compiled `dist/cli.js` as a child process against the
 * tests/fixtures/vulnerable.ts fixture. Asserts that:
 *   - the process exits with code 1 (findings found)
 *   - stdout is valid JSON
 *   - the JSON contains a non-empty `findings` array
 *   - at least one finding has the expected shape (type, severity, line, message)
 *
 * This test is deliberately coarse — it validates the end-to-end build and
 * scan pipeline rather than individual detector logic (covered by unit tests).
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, beforeAll } from 'vitest';
import { execSync, spawnSync } from 'child_process';
import path from 'path';
import fs from 'fs';

const PROJECT_ROOT = path.resolve(__dirname, '..', '..');
const DIST_CLI = path.join(PROJECT_ROOT, 'dist', 'cli.js');
const FIXTURE = path.join(PROJECT_ROOT, 'tests', 'fixtures', 'vulnerable.ts');

describe('CLI E2E — full scan pipeline', () => {
  // Ensure the project is built before running the child process.
  // If dist/cli.js already exists and is newer than the source, skip rebuild
  // to keep the test suite fast in development.
  beforeAll(() => {
    const cliMtime = fs.existsSync(DIST_CLI) ? fs.statSync(DIST_CLI).mtimeMs : 0;
    const srcMtime = fs.statSync(path.join(PROJECT_ROOT, 'src', 'cli.ts')).mtimeMs;
    if (cliMtime < srcMtime) {
      execSync('npm run build', {
        cwd: PROJECT_ROOT,
        stdio: 'pipe',
        timeout: 120_000,         // 2 min cap — prevent hanging tsc from blocking CI indefinitely
        maxBuffer: 10 * 1024 * 1024, // 10 MB — avoid truncation on verbose tsc output
      });
    }
  }, 60_000);

  test('dist/cli.js exists after build', () => {
    expect(fs.existsSync(DIST_CLI)).toBe(true);
  });

  test('exits with code 1 and emits JSON findings for vulnerable.ts', () => {
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

    // Top-level shape: { findings: [...], summary: {...} }
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

  test('exits with code 0 and empty findings for clean.ts', () => {
    const cleanFixture = path.join(PROJECT_ROOT, 'tests', 'fixtures', 'clean.ts');
    const result = spawnSync(
      process.execPath,
      [DIST_CLI, cleanFixture, '--json'],
      {
        cwd: PROJECT_ROOT,
        encoding: 'utf-8',
        timeout: 30_000,
      },
    );

    expect(result.status).toBe(0);

    let output: unknown;
    expect(() => {
      output = JSON.parse(result.stdout);
    }).not.toThrow();

    const parsed = output as { findings?: unknown[] };
    expect(Array.isArray(parsed.findings)).toBe(true);
    expect((parsed.findings as unknown[]).length).toBe(0);
  });
});
