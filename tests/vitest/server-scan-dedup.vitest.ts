/**
 * Integration tests for cross-detector finding deduplication at /scan level.
 *
 * When multiple detectors produce findings for the same (file, line, type),
 * the /scan endpoint must return only one finding per unique key so that
 * severity counts in the summary reflect the actual number of distinct issues.
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

beforeAll(async () => {
  serverPort = await getFreePort();

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

// ── Deduplication tests ───────────────────────────────────────────────────────

describe('/scan cross-detector finding deduplication', () => {
  test('no duplicate (file, line, type) tuples in the findings array', async () => {
    // vulnerable.ts exercises many detectors simultaneously — an ideal candidate
    // for catching cross-detector duplicates in a realistic scan.
    const fs = await import('fs');
    const path = await import('path');
    const fixturePath = path.join(__dirname, '..', 'fixtures', 'vulnerable.ts');
    const code = fs.readFileSync(fixturePath, 'utf8');

    const res = await post(serverPort, '/scan', { code, filename: 'vulnerable.ts' });
    expect(res.statusCode).toBe(200);

    const body = res.body as { findings?: Array<{ file: string; line: number; type: string }> };
    expect(Array.isArray(body.findings)).toBe(true);

    const keys = (body.findings ?? []).map((f) => `${f.file}:${f.line}:${f.type}`);
    const uniqueKeys = new Set(keys);

    expect(keys.length).toBe(uniqueKeys.size);
  });

  test('synthetic duplicate: code that could trigger overlapping detectors returns each type once', async () => {
    // A string literal that looks like a hardcoded AWS secret key — only the
    // secrets detector should fire, and only once.
    const code = `const key = 'AKIAIOSFODNN7EXAMPLE'; // AWS access key`;

    const res = await post(serverPort, '/scan', { code, filename: 'aws.ts' });
    expect(res.statusCode).toBe(200);

    const body = res.body as { findings?: Array<{ type: string; line: number }> };
    const findings = body.findings ?? [];

    const keys = findings.map((f) => `${f.line}:${f.type}`);
    const uniqueKeys = new Set(keys);

    // There must be no duplicate (line, type) pairs
    expect(keys.length).toBe(uniqueKeys.size);
  });

  test('summary total matches the deduplicated findings count', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const fixturePath = path.join(__dirname, '..', 'fixtures', 'vulnerable.ts');
    const code = fs.readFileSync(fixturePath, 'utf8');

    const res = await post(serverPort, '/scan', { code, filename: 'dup-summary.ts' });
    expect(res.statusCode).toBe(200);

    const body = res.body as {
      findings?: unknown[];
      summary?: { total?: number };
    };

    const findingsCount = (body.findings ?? []).length;
    // summary.total must equal the length of the findings array (no hidden dupes)
    expect(body.summary?.total).toBe(findingsCount);
  });

  test('clean code with no findings produces an empty findings array', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const fixturePath = path.join(__dirname, '..', 'fixtures', 'clean.ts');
    const code = fs.readFileSync(fixturePath, 'utf8');

    const res = await post(serverPort, '/scan', { code, filename: 'clean.ts' });
    expect(res.statusCode).toBe(200);

    const body = res.body as { findings?: unknown[]; summary?: { total?: number } };
    expect(body.findings?.length).toBe(0);
    expect(body.summary?.total).toBe(0);
  });
});
