/**
 * CLI integration test for --format=sonarqube.
 *
 * Verifies that the CLI produces valid SonarQube Generic Issue Import JSON
 * when invoked with --format=sonarqube against a vulnerable fixture.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, beforeAll } from 'vitest';
import { execSync, spawnSync } from 'child_process';
import path from 'path';
import fs from 'fs';
import os from 'os';

const PROJECT_ROOT = '/Users/alejandroroucoiglesias/Desktop/Dev Projects/ai-code-security-scanner';
const DIST_CLI = path.join(PROJECT_ROOT, 'dist', 'cli.js');
const FIXTURE = path.join(PROJECT_ROOT, 'tests', 'fixtures', 'vulnerable.ts');

// SonarQube Generic Issue Import format shape:
// https://docs.sonarsource.com/sonarqube/latest/analyzing-source-code/importing-external-issues/importing-third-party-issues/
interface SonarIssue {
  engineId: string;
  ruleId: string;
  severity: string;
  type: string;
  primaryLocation: {
    message: string;
    filePath: string;
    textRange: {
      startLine: number;
      endLine: number;
      startColumn: number;
      endColumn: number;
    };
  };
}

interface SonarReport {
  issues: SonarIssue[];
}

describe('CLI --format=sonarqube', () => {
  beforeAll(() => {
    // Rebuild only if dist is stale
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

  test('produces valid SonarQube Generic Issue Import JSON', () => {
    const result = spawnSync(
      process.execPath,
      [DIST_CLI, FIXTURE, '--format=sonarqube'],
      {
        cwd: PROJECT_ROOT,
        encoding: 'utf-8',
        timeout: 30_000,
      }
    );

    // The CLI exits 1 when findings are present
    expect(result.status).toBe(1);

    // stdout must be valid JSON
    let report: SonarReport;
    expect(() => {
      report = JSON.parse(result.stdout) as SonarReport;
    }).not.toThrow();

    // Top-level shape: { issues: [...] }
    expect(report!).toHaveProperty('issues');
    expect(Array.isArray(report!.issues)).toBe(true);
    expect(report!.issues.length).toBeGreaterThan(0);
  });

  test('each issue has required SonarQube fields', () => {
    const result = spawnSync(
      process.execPath,
      [DIST_CLI, FIXTURE, '--format=sonarqube'],
      {
        cwd: PROJECT_ROOT,
        encoding: 'utf-8',
        timeout: 30_000,
      }
    );

    const report = JSON.parse(result.stdout) as SonarReport;

    for (const issue of report.issues) {
      // engineId must be present
      expect(typeof issue.engineId).toBe('string');
      expect(issue.engineId.length).toBeGreaterThan(0);

      // ruleId maps to the finding type
      expect(typeof issue.ruleId).toBe('string');
      expect(issue.ruleId.length).toBeGreaterThan(0);

      // severity must be MAJOR, MINOR, or INFO
      expect(['MAJOR', 'MINOR', 'INFO']).toContain(issue.severity);

      // type must be present
      expect(typeof issue.type).toBe('string');

      // primaryLocation must have message, filePath, and textRange
      expect(issue.primaryLocation).toBeDefined();
      expect(typeof issue.primaryLocation.message).toBe('string');
      expect(typeof issue.primaryLocation.filePath).toBe('string');
      expect(issue.primaryLocation.textRange).toBeDefined();
      expect(typeof issue.primaryLocation.textRange.startLine).toBe('number');
      expect(issue.primaryLocation.textRange.startLine).toBeGreaterThan(0);
      expect(typeof issue.primaryLocation.textRange.endLine).toBe('number');
    }
  });

  test('critical/high severity findings map to MAJOR', () => {
    const result = spawnSync(
      process.execPath,
      [DIST_CLI, FIXTURE, '--format=sonarqube'],
      {
        cwd: PROJECT_ROOT,
        encoding: 'utf-8',
        timeout: 30_000,
      }
    );

    const report = JSON.parse(result.stdout) as SonarReport;
    // At least one issue should be MAJOR from the vulnerable fixture
    const majorIssues = report.issues.filter((i) => i.severity === 'MAJOR');
    expect(majorIssues.length).toBeGreaterThan(0);
  });

  test('engineId is always ai-code-security-scanner', () => {
    const result = spawnSync(
      process.execPath,
      [DIST_CLI, FIXTURE, '--format=sonarqube'],
      {
        cwd: PROJECT_ROOT,
        encoding: 'utf-8',
        timeout: 30_000,
      }
    );

    const report = JSON.parse(result.stdout) as SonarReport;
    for (const issue of report.issues) {
      expect(issue.engineId).toBe('ai-code-security-scanner');
    }
  });

  test('no findings produces empty issues array (clean file)', () => {
    // Write a clean temp file
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sonar-clean-'));
    const cleanFile = path.join(tmpDir, 'clean.ts');
    fs.writeFileSync(cleanFile, '// clean file\nconst x = 1;\nexport default x;\n', 'utf-8');

    try {
      const result = spawnSync(
        process.execPath,
        [DIST_CLI, cleanFile, '--format=sonarqube'],
        {
          cwd: PROJECT_ROOT,
          encoding: 'utf-8',
          timeout: 30_000,
        }
      );

      // Exit 0 for no findings
      expect(result.status).toBe(0);
      const report = JSON.parse(result.stdout) as SonarReport;
      expect(report.issues).toHaveLength(0);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
