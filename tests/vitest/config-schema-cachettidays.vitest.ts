/**
 * Tests for cacheTtlDays config key validation.
 *
 * cacheTtlDays was added to AiSecScanConfig and validateConfig this cycle.
 * This file verifies that the config schema correctly accepts valid positive
 * numbers and rejects invalid values (negative, zero, non-number).
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';

const PROJECT_CLI = '/Users/alejandroroucoiglesias/Desktop/Dev Projects/ai-code-security-scanner/src/cli.ts';
const TS_NODE = path.resolve(__dirname, '../../node_modules/.bin/ts-node');

function writeTempConfig(dir: string, config: object): string {
  const filePath = path.join(dir, '.ai-sec-scan.json');
  fs.writeFileSync(filePath, JSON.stringify(config), 'utf-8');
  return filePath;
}

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

describe('.ai-sec-scan.json — cacheTtlDays validation', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-sec-ttl-'));
    // Write a clean file so the scanner always has something to scan
    fs.writeFileSync(path.join(tmpDir, 'clean.js'), '// clean\n', 'utf-8');
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('cacheTtlDays with a positive integer is accepted (no schema error)', () => {
    writeTempConfig(tmpDir, { cacheTtlDays: 7 });
    const result = runCli(['.'], tmpDir);
    expect(result.stderr).not.toMatch(/cacheTtlDays.*must be/i);
    expect(result.stderr).not.toMatch(/schema errors/i);
  });

  test('cacheTtlDays with a positive float is accepted', () => {
    writeTempConfig(tmpDir, { cacheTtlDays: 0.5 });
    const result = runCli(['.'], tmpDir);
    expect(result.stderr).not.toMatch(/cacheTtlDays.*must be/i);
  });

  test('cacheTtlDays: 1 (minimum positive value) is accepted', () => {
    writeTempConfig(tmpDir, { cacheTtlDays: 1 });
    const result = runCli(['.'], tmpDir);
    expect(result.stderr).not.toMatch(/cacheTtlDays.*must be/i);
  });

  test('cacheTtlDays: 30 (typical value) is accepted', () => {
    writeTempConfig(tmpDir, { cacheTtlDays: 30 });
    const result = runCli(['.'], tmpDir);
    expect(result.stderr).not.toMatch(/cacheTtlDays.*must be/i);
  });

  test('cacheTtlDays: 0 (zero) is rejected with a schema error', () => {
    writeTempConfig(tmpDir, { cacheTtlDays: 0 });
    const result = runCli(['.'], tmpDir);
    const combined = result.stdout + result.stderr;
    expect(combined).toMatch(/cacheTtlDays.*must be a positive number/i);
  });

  test('cacheTtlDays: -1 (negative) is rejected with a schema error', () => {
    writeTempConfig(tmpDir, { cacheTtlDays: -1 });
    const result = runCli(['.'], tmpDir);
    const combined = result.stdout + result.stderr;
    expect(combined).toMatch(/cacheTtlDays.*must be a positive number/i);
  });

  test('cacheTtlDays: -100 (large negative) is rejected', () => {
    writeTempConfig(tmpDir, { cacheTtlDays: -100 });
    const result = runCli(['.'], tmpDir);
    const combined = result.stdout + result.stderr;
    expect(combined).toMatch(/cacheTtlDays.*must be a positive number/i);
  });

  test('cacheTtlDays: "7" (string instead of number) is rejected', () => {
    writeTempConfig(tmpDir, { cacheTtlDays: '7' });
    const result = runCli(['.'], tmpDir);
    const combined = result.stdout + result.stderr;
    expect(combined).toMatch(/cacheTtlDays.*must be a positive number/i);
  });

  test('cacheTtlDays: true (boolean) is rejected', () => {
    writeTempConfig(tmpDir, { cacheTtlDays: true });
    const result = runCli(['.'], tmpDir);
    const combined = result.stdout + result.stderr;
    expect(combined).toMatch(/cacheTtlDays.*must be a positive number/i);
  });

  test('cacheTtlDays: null is rejected', () => {
    // JSON.stringify with null keeps the value
    const configPath = path.join(tmpDir, '.ai-sec-scan.json');
    fs.writeFileSync(configPath, '{"cacheTtlDays": null}', 'utf-8');
    const result = runCli(['.'], tmpDir);
    const combined = result.stdout + result.stderr;
    expect(combined).toMatch(/cacheTtlDays.*must be a positive number/i);
  });

  test('cacheTtlDays absent from config causes no errors', () => {
    writeTempConfig(tmpDir, { fix: false });
    const result = runCli(['.'], tmpDir);
    expect(result.stderr).not.toMatch(/cacheTtlDays/i);
    expect(result.stderr).not.toMatch(/schema errors/i);
  });

  test('cacheTtlDays round-trips through JSON correctly', () => {
    const configPath = writeTempConfig(tmpDir, { cacheTtlDays: 14 });
    const parsed = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(parsed.cacheTtlDays).toBe(14);
    expect(typeof parsed.cacheTtlDays).toBe('number');
  });
});
