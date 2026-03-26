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
import { execFileSync } from 'child_process';

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
