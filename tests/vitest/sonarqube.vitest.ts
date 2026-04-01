/**
 * E2E integration test for the --format=sonarqube CLI flag.
 *
 * Runs the compiled CLI against the vulnerable.ts fixture with --format=sonarqube
 * and asserts the output is valid SonarQube Generic Issue Import JSON:
 *   { issues: [ { engineId, ruleId, severity, type, primaryLocation } ] }
 *
 * Reference: https://docs.sonarqube.org/latest/analysis/generic-issue/
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

describe('CLI --format=sonarqube', () => {
  // Ensure a built dist/cli.js is available before tests run.
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

  test('dist/cli.js exists', () => {
    expect(fs.existsSync(DIST_CLI)).toBe(true);
  });

  test('exits with code 1 and emits non-empty stdout for vulnerable.ts', () => {
    const result = spawnSync(
      process.execPath,
      [DIST_CLI, FIXTURE, '--format=sonarqube'],
      { cwd: PROJECT_ROOT, encoding: 'utf-8', timeout: 30_000, maxBuffer: 10 * 1024 * 1024 },
    );
    expect(result.status).toBe(1);
    expect(result.stdout.trim().length).toBeGreaterThan(0);
  });

  test('output is valid JSON', () => {
    const result = spawnSync(
      process.execPath,
      [DIST_CLI, FIXTURE, '--format=sonarqube'],
      { cwd: PROJECT_ROOT, encoding: 'utf-8', timeout: 30_000, maxBuffer: 10 * 1024 * 1024 },
    );
    expect(() => JSON.parse(result.stdout)).not.toThrow();
  });

  test('top-level structure has an "issues" array', () => {
    const result = spawnSync(
      process.execPath,
      [DIST_CLI, FIXTURE, '--format=sonarqube'],
      { cwd: PROJECT_ROOT, encoding: 'utf-8', timeout: 30_000, maxBuffer: 10 * 1024 * 1024 },
    );
    const parsed = JSON.parse(result.stdout) as { issues?: unknown[] };
    expect(Array.isArray(parsed.issues)).toBe(true);
    expect((parsed.issues as unknown[]).length).toBeGreaterThan(0);
  });

  test('each issue has required SonarQube Generic Issue Import fields', () => {
    const result = spawnSync(
      process.execPath,
      [DIST_CLI, FIXTURE, '--format=sonarqube'],
      { cwd: PROJECT_ROOT, encoding: 'utf-8', timeout: 30_000, maxBuffer: 10 * 1024 * 1024 },
    );
    const parsed = JSON.parse(result.stdout) as {
      issues: Array<{
        engineId: string;
        ruleId: string;
        severity: string;
        type: string;
        primaryLocation: {
          message: string;
          filePath: string;
          textRange: { startLine: number };
        };
      }>;
    };

    for (const issue of parsed.issues) {
      // Required Generic Issue Import fields
      expect(typeof issue.engineId).toBe('string');
      expect(issue.engineId.length).toBeGreaterThan(0);

      expect(typeof issue.ruleId).toBe('string');
      expect(issue.ruleId.length).toBeGreaterThan(0);

      expect(typeof issue.severity).toBe('string');
      expect(['BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO']).toContain(issue.severity);

      expect(typeof issue.type).toBe('string');
      expect(issue.type).toBe('VULNERABILITY');

      // Primary location
      expect(typeof issue.primaryLocation).toBe('object');
      expect(typeof issue.primaryLocation.message).toBe('string');
      expect(typeof issue.primaryLocation.filePath).toBe('string');
      expect(typeof issue.primaryLocation.textRange).toBe('object');
      expect(typeof issue.primaryLocation.textRange.startLine).toBe('number');
      expect(issue.primaryLocation.textRange.startLine).toBeGreaterThan(0);
    }
  });

  test('engineId is "ai-code-security-scanner" for all issues', () => {
    const result = spawnSync(
      process.execPath,
      [DIST_CLI, FIXTURE, '--format=sonarqube'],
      { cwd: PROJECT_ROOT, encoding: 'utf-8', timeout: 30_000, maxBuffer: 10 * 1024 * 1024 },
    );
    const parsed = JSON.parse(result.stdout) as { issues: Array<{ engineId: string }> };
    for (const issue of parsed.issues) {
      expect(issue.engineId).toBe('ai-code-security-scanner');
    }
  });

  test('severity values map correctly from scanner severities', () => {
    const result = spawnSync(
      process.execPath,
      [DIST_CLI, FIXTURE, '--format=sonarqube'],
      { cwd: PROJECT_ROOT, encoding: 'utf-8', timeout: 30_000, maxBuffer: 10 * 1024 * 1024 },
    );
    const parsed = JSON.parse(result.stdout) as {
      issues: Array<{ severity: string }>;
    };
    // All severities should be valid SonarQube severities
    const validSonarSeverities = new Set(['BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO']);
    for (const issue of parsed.issues) {
      expect(validSonarSeverities.has(issue.severity)).toBe(true);
    }
  });

  test('clean.ts produces empty issues array with exit code 0', () => {
    const cleanFixture = path.join(PROJECT_ROOT, 'tests', 'fixtures', 'clean.ts');
    const result = spawnSync(
      process.execPath,
      [DIST_CLI, cleanFixture, '--format=sonarqube'],
      { cwd: PROJECT_ROOT, encoding: 'utf-8', timeout: 30_000, maxBuffer: 10 * 1024 * 1024 },
    );
    expect(result.status).toBe(0);
    const parsed = JSON.parse(result.stdout) as { issues: unknown[] };
    expect(Array.isArray(parsed.issues)).toBe(true);
    expect(parsed.issues.length).toBe(0);
  });
});
