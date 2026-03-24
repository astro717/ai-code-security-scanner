/**
 * Integration tests for /scan filename sanitization.
 *
 * Covers the null-byte rejection, path-traversal guard, and path.basename
 * stripping added to the POST /scan endpoint in server.ts.
 *
 * Each test-group spins up a real Express instance on a random port with
 * SERVER_API_KEY unset (open/dev mode) so the auth middleware is bypassed
 * and only the sanitization logic under test is exercised.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import net from 'net';

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

interface ScanResponse {
  statusCode: number;
  body: unknown;
}

function post(port: number, path: string, payload: unknown): Promise<ScanResponse> {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(payload);
    const opts: http.RequestOptions = {
      hostname: '127.0.0.1',
      port,
      path,
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

// Minimal valid TypeScript code used in all /scan calls
const CLEAN_CODE = 'const x: number = 1;';

beforeAll(async () => {
  serverPort = await getFreePort();

  // Dev mode: no SERVER_API_KEY so auth middleware is bypassed
  delete process.env.SERVER_API_KEY;
  process.env.PORT = String(serverPort);

  const origWarn = console.warn;
  const origLog = console.log;
  console.warn = () => {};
  console.log = () => {};

  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('ts-node/register');
  } catch { /* already registered */ }

  // Clear any cached server module to get a fresh instance
  Object.keys(require.cache ?? {}).forEach((k) => {
    if (k.includes('/src/server')) delete require.cache[k];
  });

  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const mod = require('../../src/server');
  serverHandle = (mod?.default ?? mod?.server ?? null) as http.Server | null;

  await new Promise((r) => setTimeout(r, 400));

  console.warn = origWarn;
  console.log = origLog;
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

// ── Malicious filename tests — must all return 400 ────────────────────────────

describe('/scan filename sanitization — malicious inputs rejected with 400', () => {
  test('path traversal: "../../../etc/passwd" returns 400', async () => {
    const res = await post(serverPort, '/scan', {
      code: CLEAN_CODE,
      filename: '../../../etc/passwd',
    });
    expect(res.statusCode).toBe(400);
    const body = res.body as { error?: string };
    expect(typeof body.error).toBe('string');
    expect(body.error).toMatch(/path traversal/i);
  });

  test('path traversal: ".." alone returns 400', async () => {
    const res = await post(serverPort, '/scan', {
      code: CLEAN_CODE,
      filename: '..',
    });
    expect(res.statusCode).toBe(400);
    const body = res.body as { error?: string };
    expect(body.error).toMatch(/path traversal/i);
  });

  test('path traversal: "folder/../secret.ts" returns 400', async () => {
    const res = await post(serverPort, '/scan', {
      code: CLEAN_CODE,
      filename: 'folder/../secret.ts',
    });
    expect(res.statusCode).toBe(400);
    const body = res.body as { error?: string };
    expect(body.error).toMatch(/path traversal/i);
  });

  test('null byte: "file\\0name.ts" returns 400', async () => {
    const res = await post(serverPort, '/scan', {
      code: CLEAN_CODE,
      filename: 'file\0name.ts',
    });
    expect(res.statusCode).toBe(400);
    const body = res.body as { error?: string };
    expect(typeof body.error).toBe('string');
    expect(body.error).toMatch(/null byte/i);
  });

  test('absolute Unix path: "/absolute/path/file.ts" returns 400', async () => {
    const res = await post(serverPort, '/scan', {
      code: CLEAN_CODE,
      filename: '/absolute/path/file.ts',
    });
    expect(res.statusCode).toBe(400);
    const body = res.body as { error?: string };
    expect(body.error).toMatch(/path traversal/i);
  });

  test('absolute Windows-style path: "\\\\server\\share\\file.ts" returns 400', async () => {
    const res = await post(serverPort, '/scan', {
      code: CLEAN_CODE,
      filename: '\\server\\share\\file.ts',
    });
    expect(res.statusCode).toBe(400);
    const body = res.body as { error?: string };
    expect(body.error).toMatch(/path traversal/i);
  });

  test('non-string filename returns 400', async () => {
    const res = await post(serverPort, '/scan', {
      code: CLEAN_CODE,
      filename: 42,
    });
    expect(res.statusCode).toBe(400);
    const body = res.body as { error?: string };
    expect(typeof body.error).toBe('string');
    expect(body.error).toMatch(/filename must be a string/i);
  });
});

// ── Valid filename tests — must return 200 ────────────────────────────────────

describe('/scan filename sanitization — valid filenames accepted with 200', () => {
  test('plain filename "app.ts" returns 200', async () => {
    const res = await post(serverPort, '/scan', {
      code: CLEAN_CODE,
      filename: 'app.ts',
    });
    expect(res.statusCode).toBe(200);
    const body = res.body as { findings?: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
  });

  test('filename with subdirectory stripped by basename: "src/utils.ts" returns 200', async () => {
    // path.basename('src/utils.ts') === 'utils.ts' — no ".." involved, no leading slash
    // The server applies basename AFTER the traversal check — but since "src/utils.ts"
    // does not contain ".." or start with "/" or "\\", it passes the guard and is then
    // basename-stripped to "utils.ts".
    const res = await post(serverPort, '/scan', {
      code: CLEAN_CODE,
      filename: 'src/utils.ts',
    });
    expect(res.statusCode).toBe(200);
    const body = res.body as { findings?: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
  });

  test('omitting filename entirely returns 200 (field is optional)', async () => {
    const res = await post(serverPort, '/scan', {
      code: CLEAN_CODE,
    });
    expect(res.statusCode).toBe(200);
    const body = res.body as { findings?: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
  });

  test('filename with dots in name (not traversal) "my.config.ts" returns 200', async () => {
    const res = await post(serverPort, '/scan', {
      code: CLEAN_CODE,
      filename: 'my.config.ts',
    });
    expect(res.statusCode).toBe(200);
  });
});
