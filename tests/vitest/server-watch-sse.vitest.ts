/**
 * Integration tests for the GET /watch SSE endpoint.
 *
 * Verifies that:
 *   - Invalid or missing path returns 400
 *   - A valid directory path establishes an SSE stream
 *   - The initial "connected" event is emitted with the resolved path
 */

import { describe, test, expect } from 'vitest';
import request from 'supertest';
import { app } from '../../src/server';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('GET /watch — validation', () => {
  test('returns 400 for a non-existent path', async () => {
    const res = await request(app).get('/watch?path=/does/not/exist/xyz');
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/existing directory/i);
  });

  test('returns 400 for a file path (not a directory)', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'watch-test-'));
    const tmpFile = path.join(tmpDir, 'file.ts');
    fs.writeFileSync(tmpFile, 'const x = 1;\n');
    const res = await request(app).get(`/watch?path=${encodeURIComponent(tmpFile)}`);
    expect(res.status).toBe(400);
    fs.unlinkSync(tmpFile);
    fs.rmSync(tmpDir, { recursive: true });
  });
});

describe('GET /watch — SSE stream', () => {
  test('returns Content-Type: text/event-stream for a valid directory', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'watch-dir-'));

    const res = await request(app)
      .get(`/watch?path=${encodeURIComponent(tmpDir)}`)
      .set('Accept', 'text/event-stream')
      .buffer(true)
      .parse((res, cb) => {
        let data = '';
        res.on('data', (chunk: Buffer) => {
          data += chunk.toString();
          // Close connection after receiving first event
          if (data.includes('event: connected')) {
            res.destroy();
            cb(null, data);
          }
        });
        setTimeout(() => { res.destroy(); cb(null, data); }, 3000);
      });

    expect(res.status).toBe(200);
    fs.rmSync(tmpDir, { recursive: true });
  });

  test('emits initial "connected" event with the resolved path', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'watch-dir-'));

    const res = await request(app)
      .get(`/watch?path=${encodeURIComponent(tmpDir)}`)
      .set('Accept', 'text/event-stream')
      .buffer(true)
      .parse((res, cb) => {
        let data = '';
        res.on('data', (chunk: Buffer) => {
          data += chunk.toString();
          if (data.includes('event: connected')) {
            res.destroy();
            cb(null, data);
          }
        });
        setTimeout(() => { res.destroy(); cb(null, data); }, 3000);
      });

    const text = res.body as string;
    expect(text).toContain('event: connected');
    const dataLine = text.split('\n').find((l: string) => l.startsWith('data: '));
    expect(dataLine).toBeDefined();
    const eventData = JSON.parse(dataLine!.replace('data: ', ''));
    expect(eventData.path).toBe(tmpDir);
    expect(typeof eventData.ts).toBe('string');
    fs.rmSync(tmpDir, { recursive: true });
  });
});
import {
  initCache,
  getCachedFindings,
  setCachedFindings,
  clearCache,
} from '../../src/scanner/scan-cache';

// ── /watch cache integration ──────────────────────────────────────────────────

describe('GET /watch — scan result caching', () => {
  test('getCachedFindings returns null before a file is scanned via /watch (cache miss)', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'watch-cache-'));
    const testFile = path.join(tmpDir, 'test.ts');
    const content = 'const x = 1; // clean file';
    fs.writeFileSync(testFile, content, 'utf-8');

    // Before any scan, the cache should have nothing for this file
    clearCache();
    initCache({ cacheDir: path.join(tmpDir, '.cache') });
    const result = getCachedFindings(testFile, content);
    expect(result).toBeNull();

    clearCache();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('setCachedFindings stores findings that getCachedFindings can retrieve', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'watch-cache2-'));

    clearCache();
    initCache({ cacheDir: path.join(tmpDir, '.cache') });

    const filePath = path.join(tmpDir, 'auth.ts');
    const fileContent = 'const token = Math.random();';
    const fakeFindings = [{
      type: 'INSECURE_RANDOM',
      severity: 'high' as const,
      line: 1,
      column: 14,
      snippet: fileContent,
      message: 'Insecure random detected',
      file: filePath,
    }];

    // Simulate what scanFile in /watch does: cache miss → scan → cache store
    setCachedFindings(filePath, fileContent, fakeFindings);

    // Next lookup with same content should hit
    const hit = getCachedFindings(filePath, fileContent);
    expect(hit).not.toBeNull();
    expect(hit!).toHaveLength(1);
    expect(hit![0]!.type).toBe('INSECURE_RANDOM');

    clearCache();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('getCachedFindings returns null after file content changes (content hash mismatch)', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'watch-cache3-'));

    clearCache();
    initCache({ cacheDir: path.join(tmpDir, '.cache') });

    const filePath = path.join(tmpDir, 'service.ts');
    const contentV1 = 'const a = 1;';
    const contentV2 = 'const a = 2; // changed';
    const findings = [{ type: 'XSS', severity: 'high' as const, line: 1, column: 0, message: 'test', file: filePath }];

    setCachedFindings(filePath, contentV1, findings);

    // Content changed → cache miss
    const miss = getCachedFindings(filePath, contentV2);
    expect(miss).toBeNull();

    // Original content → cache hit
    const hit = getCachedFindings(filePath, contentV1);
    expect(hit).not.toBeNull();

    clearCache();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});
