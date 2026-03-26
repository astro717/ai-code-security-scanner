/**
 * Integration tests for C/C++ file scanning via POST /scan.
 *
 * Verifies that submitting C/C++ code with filename ending in .c/.cpp/.h is
 * correctly routed through the C scanner (c-parser.ts) and returns C-specific
 * findings (BUFFER_OVERFLOW, FORMAT_STRING, COMMAND_INJECTION, etc.).
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import net from 'net';

// ── Vulnerable C fixture ──────────��─────────────────────────────────────────

const VULNERABLE_C = `
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Buffer overflow: gets
void read_input() {
    char buf[64];
    gets(buf);
}

// Buffer overflow: strcpy
void copy_name(const char *src) {
    char dest[32];
    strcpy(dest, src);
}

// Format string vulnerability
void log_message(const char *userInput) {
    printf(userInput);
}

// Command injection via system()
void run_cmd(const char *userInput) {
    char cmd[256];
    sprintf(cmd, "ls %s", userInput);
    system(cmd);
}

// Weak crypto: MD5
void hash_data() {
    MD5_CTX ctx;
    MD5_Init(&ctx);
}
`;

const CLEAN_C = `
#include <stdio.h>
#include <string.h>

int add(int a, int b) {
    return a + b;
}

void print_message(const char *msg) {
    printf("%s\\n", msg);
}
`;

// ── Helpers ────────���────────────────────────────���───────────────────────────

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

function post(port: number, urlPath: string, payload: unknown): Promise<ScanResponse> {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(payload);
    const opts: http.RequestOptions = {
      hostname: '127.0.0.1',
      port,
      path: urlPath,
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

// ── Server lifecycle ────────────────────────���───────────────────────────────

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

// ── Tests ──────���───────────────────────────────���────────────────────────────

describe('/scan with C/C++ files', () => {
  test('vulnerable C code returns findings with filename ending in .c', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_C,
      filename: 'vulnerable.c',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<{ type: string; severity: string }> };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBeGreaterThan(0);

    const types = new Set(body.findings.map((f) => f.type));

    // The vulnerable fixture should trigger at least these C-detected types
    expect(types.has('BUFFER_OVERFLOW')).toBe(true);
    expect(types.has('FORMAT_STRING')).toBe(true);
    expect(types.has('WEAK_CRYPTO')).toBe(true);
  });

  test('vulnerable code works with .cpp extension too', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_C,
      filename: 'vulnerable.cpp',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<{ type: string }> };
    expect(body.findings.length).toBeGreaterThan(0);
  });

  test('clean C code returns zero findings', async () => {
    const res = await post(serverPort, '/scan', {
      code: CLEAN_C,
      filename: 'safe.c',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBe(0);
  });

  test('C findings include correct file field', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_C,
      filename: 'main.c',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<{ file: string }> };
    expect(body.findings.length).toBeGreaterThan(0);
    for (const f of body.findings) {
      expect(f.file).toBe('main.c');
    }
  });

  test('response includes summary object', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_C,
      filename: 'test.c',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: unknown[]; summary: { total: number } };
    expect(typeof body.summary).toBe('object');
    expect(body.summary.total).toBeGreaterThan(0);
  });
});
