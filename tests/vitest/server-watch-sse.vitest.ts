/**
 * Integration tests for the GET /watch SSE endpoint.
 *
 * Verifies that:
 *   - Invalid or missing path returns 400
 *   - A valid directory path establishes an SSE stream
 *   - The initial "connected" event is emitted with the resolved path
 */

import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import net from 'net';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      srv.close((err) => (err ? reject(err) : resolve(port)));
    });
  });
}

/** Make a GET request and return {statusCode, body}. */
function get(port: number, urlPath: string): Promise<{ statusCode: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.get(
      { hostname: '127.0.0.1', port, path: urlPath },
      (res) => {
        let raw = '';
        res.on('data', (chunk: Buffer) => (raw += chunk.toString()));
        res.on('end', () => resolve({ statusCode: res.statusCode ?? 0, body: raw }));
      },
    );
    req.on('error', reject);
  });
}

/** Open an SSE connection and read the first event or timeout. */
function openSSE(port: number, urlPath: string, timeoutMs = 3000): Promise<{ statusCode: number; firstEvent: string }> {
  return new Promise((resolve, reject) => {
    let firstEvent = '';
    let statusCode = 0;
    const timer = setTimeout(() => resolve({ statusCode, firstEvent }), timeoutMs);

    const req = http.get(
      { hostname: '127.0.0.1', port, path: urlPath, headers: { Accept: 'text/event-stream' } },
      (res) => {
        statusCode = res.statusCode ?? 0;
        res.on('data', (chunk: Buffer) => {
          if (!firstEvent) {
            firstEvent = chunk.toString();
            clearTimeout(timer);
            req.destroy();
            resolve({ statusCode, firstEvent });
          }
        });
        res.on('error', () => {});
      },
    );
    req.on('error', () => {});
    setTimeout(() => req.destroy(), timeoutMs + 500);
  });
}

// ── Server lifecycle ──────────────────────────────────────────────────────────

let serverPort: number;
let serverHandle: any = null;

beforeAll(async () => {
  serverPort = await getFreePort();
  delete process.env.SERVER_API_KEY;
  process.env.PORT = String(serverPort);

  try { require('ts-node/register'); } catch { /* already registered */ }
  Object.keys(require.cache ?? {}).forEach((k) => {
    if (k.includes('/src/server')) delete require.cache[k];
  });

  const origLog = console.log;
  const origError = console.error;
  console.log = () => {};
  console.error = () => {};

  const mod = require('../../src/server');
  serverHandle = mod?.default ?? mod?.server ?? null;
  await new Promise((r) => setTimeout(r, 400));

  console.log = origLog;
  console.error = origError;
}, 15_000);

afterAll(() => {
  delete process.env.PORT;
  return new Promise<void>((resolve) => {
    if (serverHandle && typeof serverHandle.close === 'function') {
      serverHandle.close(() => resolve());
    } else {
      resolve();
    }
  });
});

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('GET /watch — validation', () => {
  test('returns 400 for a non-existent path', async () => {
    const res = await get(serverPort, '/watch?path=/does/not/exist/xyz');
    expect(res.statusCode).toBe(400);
    const body = JSON.parse(res.body);
    expect(body.error).toMatch(/existing directory/i);
  });

  test('returns 400 for a file path (not a directory)', async () => {
    const tmpFile = fs.mkdtempSync(path.join(os.tmpdir(), 'watch-test-')) + '/file.ts';
    fs.writeFileSync(tmpFile, 'const x = 1;\n');
    const res = await get(serverPort, `/watch?path=${encodeURIComponent(tmpFile)}`);
    expect(res.statusCode).toBe(400);
    fs.unlinkSync(tmpFile);
  });
});

describe('GET /watch — SSE stream', () => {
  test('returns Content-Type: text/event-stream for a valid directory', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'watch-dir-'));
    const { statusCode, firstEvent } = await openSSE(serverPort, `/watch?path=${encodeURIComponent(tmpDir)}`);
    expect(statusCode).toBe(200);
    fs.rmSync(tmpDir, { recursive: true });
  });

  test('emits initial "connected" event with the resolved path', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'watch-dir-'));
    const { firstEvent } = await openSSE(serverPort, `/watch?path=${encodeURIComponent(tmpDir)}`);

    expect(firstEvent).toContain('event: connected');
    const dataLine = firstEvent.split('\n').find((l) => l.startsWith('data: '));
    expect(dataLine).toBeDefined();
    const data = JSON.parse(dataLine!.replace('data: ', ''));
    expect(data.path).toBe(tmpDir);
    expect(typeof data.ts).toBe('string');
    fs.rmSync(tmpDir, { recursive: true });
  });
});
