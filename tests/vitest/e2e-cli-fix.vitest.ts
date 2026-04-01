/**
 * E2E CLI tests — --fix flag applies auto-fixes to real files.
 *
 * Copies fixture files to a temp directory, runs dist/cli.js --fix on them,
 * verifies the file was modified and the fixed version no longer triggers
 * the same finding type.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, beforeAll, afterEach } from 'vitest';
import { execSync, spawnSync } from 'child_process';
import path from 'path';
import fs from 'fs';
import os from 'os';

const PROJECT_ROOT = path.resolve(__dirname, '..', '..');
const DIST_CLI = path.join(PROJECT_ROOT, 'dist', 'cli.js');
const MAX_BUF = 10 * 1024 * 1024;

let tmpDir = '';

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
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-sec-fix-'));
}, 90_000);

afterEach(() => {
  // Clean up temp files after each test
  if (tmpDir && fs.existsSync(tmpDir)) {
    for (const f of fs.readdirSync(tmpDir)) {
      fs.unlinkSync(path.join(tmpDir, f));
    }
  }
});

function runFix(filePath: string): ReturnType<typeof spawnSync> {
  return spawnSync(process.execPath, [DIST_CLI, filePath, '--fix'], {
    cwd: PROJECT_ROOT,
    encoding: 'utf-8',
    timeout: 30_000,
    maxBuffer: MAX_BUF,
  });
}

function copyFixture(name: string): string {
  const src = path.join(PROJECT_ROOT, 'tests', 'fixtures', name);
  const dest = path.join(tmpDir, name);
  fs.copyFileSync(src, dest);
  return dest;
}

describe('E2E CLI --fix — JS INSECURE_RANDOM', () => {
  test('replaces Math.random() with crypto.randomBytes in a JS-like file', () => {
    // Create a minimal JS file with an INSECURE_RANDOM pattern
    const tmpFile = path.join(tmpDir, 'rand-test.js');
    const originalContent = 'const token = Math.random() * 1e17;\n';
    fs.writeFileSync(tmpFile, originalContent, 'utf-8');

    const originalText = fs.readFileSync(tmpFile, 'utf-8');
    runFix(tmpFile);
    const fixedText = fs.readFileSync(tmpFile, 'utf-8');

    // The file should have been modified
    expect(fixedText).not.toBe(originalText);
    // Math.random should be gone
    expect(fixedText).not.toMatch(/Math\.random\s*\(\s*\)/);
    // crypto replacement should be present
    expect(fixedText).toContain('crypto.randomBytes');
  });
});

describe('E2E CLI --fix — JS XSS innerHTML', () => {
  test('replaces innerHTML with textContent in JS file', () => {
    const tmpFile = path.join(tmpDir, 'xss-test.js');
    const originalContent = "element.innerHTML = userInput;\n";
    fs.writeFileSync(tmpFile, originalContent, 'utf-8');

    const originalText = fs.readFileSync(tmpFile, 'utf-8');
    runFix(tmpFile);
    const fixedText = fs.readFileSync(tmpFile, 'utf-8');

    expect(fixedText).not.toBe(originalText);
    expect(fixedText).not.toMatch(/\.innerHTML\s*=/);
    expect(fixedText).toContain('.textContent =');
  });
});

describe('E2E CLI --fix — fix output summary', () => {
  test('prints fix output to stdout', () => {
    const tmpFile = path.join(tmpDir, 'summary-test.js');
    fs.writeFileSync(tmpFile, 'const x = Math.random();\n', 'utf-8');

    const result = runFix(tmpFile);
    // Should have some output (fix summary or findings)
    expect(result.stdout.length + result.stderr.length).toBeGreaterThan(0);
  });
});

describe('E2E CLI --fix — fixed file no longer triggers finding', () => {
  test('fixed Math.random() line does not trigger INSECURE_RANDOM again', () => {
    const tmpFile = path.join(tmpDir, 'recheck.js');
    fs.writeFileSync(tmpFile, 'const token = Math.random();\n', 'utf-8');

    // Apply fix
    runFix(tmpFile);

    // Re-scan the fixed file with JSON output
    const rescanResult = spawnSync(process.execPath, [DIST_CLI, tmpFile, '--format', 'json'], {
      cwd: PROJECT_ROOT,
      encoding: 'utf-8',
      timeout: 30_000,
      maxBuffer: MAX_BUF,
    });

    // The fixed file should not have INSECURE_RANDOM anymore
    const parsed = JSON.parse(rescanResult.stdout || '{"findings":[]}') as { findings: Array<{ type: string }> };
    const hasInsecureRandom = parsed.findings.some(f => f.type === 'INSECURE_RANDOM');
    expect(hasInsecureRandom).toBe(false);
  });
});
