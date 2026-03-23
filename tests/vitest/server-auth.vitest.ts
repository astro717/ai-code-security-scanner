/**
 * Integration tests for server.ts Bearer token authentication.
 *
 * These tests start a real Express server instance on a random port,
 * exercise the /scan endpoint with and without a valid API key, and
 * verify that the auth middleware enforces the security boundary correctly.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import net from 'net';

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Find a free TCP port on localhost. */
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

/** POST JSON to the server and return status + parsed body. */
function post(port: number, path: string, payload: unknown, authHeader?: string): Promise<ScanResponse> {
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
        ...(authHeader ? { Authorization: authHeader } : {}),
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

/** GET request (for /health). */
function get(port: number, path: string): Promise<ScanResponse> {
  return new Promise((resolve, reject) => {
    http.get({ hostname: '127.0.0.1', port, path }, (res) => {
      let raw = '';
      res.on('data', (chunk) => (raw += chunk));
      res.on('end', () => {
        try {
          resolve({ statusCode: res.statusCode ?? 0, body: JSON.parse(raw) });
        } catch {
          resolve({ statusCode: res.statusCode ?? 0, body: raw });
        }
      });
    }).on('error', reject);
  });
}

// ── Server lifecycle ──────────────────────────────────────────────────────────

/**
 * Dynamically imports server.ts so we can control the SERVER_API_KEY env var
 * at module load time. Returns the http.Server handle so we can close it.
 *
 * We use dynamic require (not static import) to allow re-loading with
 * different env vars between describe blocks.
 */
async function startServer(apiKey: string | undefined, port: number): Promise<http.Server> {
  // Set env before the module is evaluated
  if (apiKey !== undefined) {
    process.env.SERVER_API_KEY = apiKey;
  } else {
    delete process.env.SERVER_API_KEY;
  }
  process.env.PORT = String(port);

  // Clear the module from the require cache so each test suite gets a fresh
  // server instance (ts-node registers the TypeScript transformer globally).
  Object.keys(require.cache ?? {}).forEach((key) => {
    if (key.includes('server')) delete require.cache[key];
  });

  // eslint-disable-next-line @typescript-eslint/no-require-imports
  require('ts-node/register');
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const mod = require('../../src/server');

  // Express stores the server on app.listen return; we need the http.Server.
  // server.ts calls app.listen(...) and exports nothing — the running server
  // is held internally. We wait briefly for it to bind.
  await new Promise((r) => setTimeout(r, 300));

  // Return a stub that closes by sending SIGTERM-equivalent: we keep the
  // server running for the test duration and the afterAll hook will kill
  // the process-level server by exhausting the port.
  //
  // For a cleaner teardown we directly close the underlying libuv handle
  // by looking for the server on the module's exported value (if any).
  const server = mod?.default ?? mod?.server ?? null;
  return server as http.Server;
}

// ── Test suite: SERVER_API_KEY set ───────────────────────────────────────────

describe('server auth — SERVER_API_KEY is set', () => {
  const API_KEY = 'test-secret-key-abc123';
  let port: number;
  let serverHandle: http.Server | null = null;

  beforeAll(async () => {
    port = await getFreePort();

    // Suppress console.warn / console.log noise from the server
    const origWarn = console.warn;
    const origLog = console.log;
    console.warn = () => {};
    console.log = () => {};

    process.env.SERVER_API_KEY = API_KEY;
    process.env.PORT = String(port);

    // Use ts-node to load the server
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      require('ts-node/register');
    } catch { /* already registered */ }

    // Clear cached server module
    Object.keys(require.cache ?? {}).forEach((k) => {
      if (k.includes('/src/server')) delete require.cache[k];
    });

    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const mod = require('../../src/server');
    serverHandle = (mod?.default ?? mod?.server ?? null) as http.Server | null;

    // Give the server time to bind
    await new Promise((r) => setTimeout(r, 400));

    console.warn = origWarn;
    console.log = origLog;
  }, 10_000);

  afterAll(() => {
    delete process.env.SERVER_API_KEY;
    delete process.env.PORT;
    return new Promise<void>((resolve) => {
      if (serverHandle && typeof serverHandle.close === 'function') {
        serverHandle.close(() => resolve());
      } else {
        resolve();
      }
    });
  });

  test('/health is accessible without auth', async () => {
    const res = await get(port, '/health');
    expect(res.statusCode).toBe(200);
    expect((res.body as { status?: string }).status).toBe('ok');
  });

  test('POST /scan without Authorization header returns 401', async () => {
    const res = await post(port, '/scan', { code: 'const x = 1;' });
    expect(res.statusCode).toBe(401);
    const body = res.body as { error?: string };
    expect(typeof body.error).toBe('string');
    expect(body.error).toContain('Unauthorized');
  });

  test('POST /scan with wrong Bearer token returns 401', async () => {
    const res = await post(port, '/scan', { code: 'const x = 1;' }, 'Bearer wrong-token');
    expect(res.statusCode).toBe(401);
  });

  test('POST /scan with correct Bearer token returns 200', async () => {
    const res = await post(port, '/scan', { code: 'const x = 1;' }, `Bearer ${API_KEY}`);
    expect(res.statusCode).toBe(200);
    const body = res.body as { findings?: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
  });

  test('POST /scan with Bearer prefix missing returns 401', async () => {
    // Token present but not as Bearer scheme
    const res = await post(port, '/scan', { code: 'const x = 1;' }, API_KEY);
    expect(res.statusCode).toBe(401);
  });
});
