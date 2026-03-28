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
