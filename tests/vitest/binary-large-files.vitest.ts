/**
 * Tests for binary file and large file handling in the scanner.
 *
 * Verifies that the CLI skips binary files and files exceeding the size limit,
 * and that the server rejects oversized /scan payloads with 413.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, beforeAll } from 'vitest';
import { execSync, spawnSync } from 'child_process';
import path from 'path';
import fs from 'fs';
import os from 'os';
import request from 'supertest';
import { app } from '../../src/server';

const PROJECT_ROOT = path.resolve(__dirname, '..', '..');
const DIST_CLI = path.join(PROJECT_ROOT, 'dist', 'cli.js');
const MAX_BUF = 10 * 1024 * 1024;

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

// ── CLI binary file tests ─────────────────────────────────────────────────────

describe('CLI — binary file handling', () => {
  test('skips binary file (null bytes) and exits 0', () => {
    const tmpFile = path.join(os.tmpdir(), `binary-test-${Date.now()}.ts`);
    // Write a buffer with null bytes (simulates binary content)
    const buf = Buffer.alloc(1024);
    buf.fill(0x41); // 'A'
    buf[512] = 0x00; // null byte
    fs.writeFileSync(tmpFile, buf);

    try {
      const result = spawnSync(process.execPath, [DIST_CLI, tmpFile, '--format', 'json'], {
        cwd: PROJECT_ROOT,
        encoding: 'utf-8',
        timeout: 30_000,
        maxBuffer: MAX_BUF,
      });

      // Should exit 0 (no findings — file was skipped)
      expect(result.status).toBe(0);
      // Output should be parseable JSON with empty or zero findings
      if (result.stdout.trim().startsWith('{')) {
        const parsed = JSON.parse(result.stdout) as { findings: unknown[] };
        expect(Array.isArray(parsed.findings)).toBe(true);
      }
    } finally {
      if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile);
    }
  });
});

// ── CLI large file tests ──────────────────────────────────────────────────────

describe('CLI — large file handling', () => {
  test('skips files larger than 2 MB and exits 0', () => {
    const tmpFile = path.join(os.tmpdir(), `large-test-${Date.now()}.ts`);
    // Write > 2 MB of safe text
    const chunk = 'const safe = "hello world";\n'.repeat(5000); // ~140 KB per repeat
    const content = chunk.repeat(16); // ~2.2 MB
    fs.writeFileSync(tmpFile, content, 'utf-8');

    try {
      const result = spawnSync(process.execPath, [DIST_CLI, tmpFile, '--format', 'json'], {
        cwd: PROJECT_ROOT,
        encoding: 'utf-8',
        timeout: 30_000,
        maxBuffer: MAX_BUF,
      });

      // Should exit 0 (file skipped)
      expect(result.status).toBe(0);
      // Stderr should mention the skip
      expect(result.stderr).toMatch(/skip|large|MB/i);
    } finally {
      if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile);
    }
  });
});

// ── Server payload size tests ─────────────────────────────────────────────────

describe('Server — /scan payload size limit', () => {
  test('rejects payloads larger than 500 KB with 413', async () => {
    // Generate > 500 KB of code content
    const oversizedCode = 'const x = "safe";\n'.repeat(30_000); // ~540 KB

    const res = await request(app)
      .post('/scan')
      .send({ code: oversizedCode, filename: 'test.ts' });

    expect(res.status).toBe(413);
    expect(res.body).toHaveProperty('error');
    expect(res.body.error).toMatch(/too large|payload/i);
  });

  test('accepts payloads within the 500 KB limit', async () => {
    const safeCode = 'const x = "hello";\n'.repeat(100); // tiny payload

    const res = await request(app)
      .post('/scan')
      .send({ code: safeCode, filename: 'test.ts' });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('findings');
  });
});
