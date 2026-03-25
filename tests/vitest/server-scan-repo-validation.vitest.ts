/**
 * Integration tests for /scan-repo input validation.
 *
 * Covers: missing repoUrl (400), invalid URL format (400), unsupported
 * protocol (400), and a happy-path stub that returns 200 with a findings
 * array. The GitHub fetch logic is mocked via vi.mock so tests run fast
 * and fully offline.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, beforeAll, afterAll, vi } from 'vitest';
import http from 'http';
import net from 'net';

// ── Mock GitHub I/O before any server module loads ────────────────────────────
// The /scan-repo handler uses the private githubGet / githubGetText helpers
// internally. We mock the built-in https module so those helpers never make a
// real network call.

vi.mock('https', async (importOriginal) => {
  const actual = await importOriginal<typeof import('https')>();

  // Minimal stub: collect(files) calls githubGet (returns JSON array), then
  // each file's contents are fetched via githubGetText (returns raw code).
  // We intercept https.get to inject canned responses.
  const mockGet = (
    opts: http.RequestOptions | string | URL,
    cb: (res: http.IncomingMessage) => void,
  ) => {
    const url = typeof opts === 'string' ? opts : (opts as http.RequestOptions & { hostname?: string; path?: string });
    const urlStr = typeof url === 'string' ? url : `https://${(url as http.RequestOptions).hostname}${(url as http.RequestOptions).path}`;

    // Contents listing for root dir → one JS file
    const isContentsRoot = urlStr.includes('/contents/?ref=') || urlStr.includes('/contents?ref=');
    const isContentsFile = urlStr.includes('/contents/index.js');

    const body = isContentsRoot
      ? JSON.stringify([
          {
            type: 'file',
            name: 'index.js',
            path: 'index.js',
            size: 100,
            download_url: 'https://raw.example.com/index.js',
            url: 'https://api.github.com/repos/owner/repo/contents/index.js',
          },
        ])
      : isContentsFile
        ? 'const x = 1;'
        : '[]';

    // Simulate a readable stream response
    const { PassThrough } = require('stream');
    const res = new PassThrough() as unknown as http.IncomingMessage;
    (res as unknown as Record<string, unknown>).statusCode = 200;
    (res as unknown as Record<string, unknown>).headers = {};

    const fakeReq = {
      on: (_evt: string, _fn: unknown) => fakeReq,
      write: () => {},
      end: () => {
        setImmediate(() => {
          res.emit('data', body);
          res.emit('end');
        });
      },
    };

    setImmediate(() => {
      cb(res);
      res.emit('data', body);
      res.emit('end');
    });

    return fakeReq;
  };

  return { ...actual, default: { ...actual, get: mockGet, request: mockGet } };
});

// ── Helpers ───────────────────────────────────────────────────────────────────

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

interface ScanRepoResponse {
  statusCode: number;
  body: unknown;
}

function post(port: number, payload: unknown): Promise<ScanRepoResponse> {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(payload);
    const opts: http.RequestOptions = {
      hostname: '127.0.0.1',
      port,
      path: '/scan-repo',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
      },
    };

    const req = http.request(opts, (res) => {
      let raw = '';
      res.on('data', (chunk) => (raw += chunk));
      res.on('end', () => {
        try {
          resolve({ statusCode: res.statusCode ?? 0, body: JSON.parse(raw) });
        } catch {
          resolve({ statusCode: res.statusCode ?? 0, body: raw });
        }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

// ── Server lifecycle ──────────────────────────────────────────────────────────

let serverPort: number;
let serverHandle: http.Server | null = null;

beforeAll(async () => {
  serverPort = await getFreePort();

  delete process.env.SERVER_API_KEY;
  process.env.PORT = String(serverPort);
  process.env.NODE_ENV = 'test';

  const origWarn = console.warn;
  const origLog = console.log;
  console.warn = () => {};
  console.log = () => {};

  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ts-node/register');
  } catch { /* already registered */ }

  // Clear cached module so we get a fresh server on this port
  Object.keys(require.cache ?? {}).forEach((k) => {
    if (k.includes('/src/server')) delete require.cache[k];
  });

  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const mod = require('../../src/server');
  serverHandle = (mod?.default ?? mod?.server ?? null) as http.Server | null;

  await new Promise((r) => setTimeout(r, 400));

  console.warn = origWarn;
  console.log = origLog;

  // Reset rate-limiter hit counters so prior test suites running in the same
  // process (shared module cache) cannot exhaust the /scan-repo budget.
  if (typeof mod?.resetRateLimiters === 'function') {
    await mod.resetRateLimiters();
  }
}, 10_000);

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

// ── /scan-repo input validation tests ────────────────────────────────────────

describe('/scan-repo input validation', () => {
  test('missing repoUrl field returns 400', async () => {
    const res = await post(serverPort, {});
    expect(res.statusCode).toBe(400);
    const body = res.body as { error?: string };
    expect(typeof body.error).toBe('string');
    expect(body.error).toMatch(/repoUrl/i);
  });

  test('repoUrl as null returns 400', async () => {
    const res = await post(serverPort, { repoUrl: null });
    expect(res.statusCode).toBe(400);
    const body = res.body as { error?: string };
    expect(typeof body.error).toBe('string');
    expect(body.error).toMatch(/repoUrl/i);
  });

  test('repoUrl as integer returns 400', async () => {
    const res = await post(serverPort, { repoUrl: 12345 });
    expect(res.statusCode).toBe(400);
    const body = res.body as { error?: string };
    expect(typeof body.error).toBe('string');
    expect(body.error).toMatch(/repoUrl/i);
  });

  test('non-GitHub URL returns 400', async () => {
    const res = await post(serverPort, { repoUrl: 'https://gitlab.com/owner/repo' });
    expect(res.statusCode).toBe(400);
    const body = res.body as { error?: string };
    expect(typeof body.error).toBe('string');
    expect(body.error).toMatch(/github/i);
  });

  test('unsupported protocol (ssh) returns 400', async () => {
    const res = await post(serverPort, { repoUrl: 'git@github.com:owner/repo.git' });
    expect(res.statusCode).toBe(400);
    const body = res.body as { error?: string };
    expect(typeof body.error).toBe('string');
    expect(body.error).toMatch(/github/i);
  });

  test('invalid URL string returns 400', async () => {
    const res = await post(serverPort, { repoUrl: 'not-a-url-at-all' });
    expect(res.statusCode).toBe(400);
    const body = res.body as { error?: string };
    expect(typeof body.error).toBe('string');
    expect(body.error).toMatch(/github/i);
  });

  test('valid GitHub URL returns 200 with findings array', async () => {
    const res = await post(serverPort, {
      repoUrl: 'https://github.com/owner/repo',
      branch: 'main',
    });
    // With the mock returning clean code, we expect 200 and findings array
    expect(res.statusCode).toBe(200);
    const body = res.body as { findings?: unknown[]; filesScanned?: number; summary?: unknown };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(typeof body.filesScanned).toBe('number');
    expect(body.summary).toBeDefined();
  });
});
