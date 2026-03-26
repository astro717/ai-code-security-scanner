/**
 * Integration tests for the POST /scan endpoint with aiExplain=true.
 *
 * Stubs https.request so no real Anthropic API calls are made. Verifies:
 *   1. When ANTHROPIC_API_KEY is set and aiExplain=true, findings include
 *      explanation and fixSuggestion fields.
 *   2. When ANTHROPIC_API_KEY is unset and aiExplain=true, findings are
 *      returned without AI fields (graceful degradation).
 *   3. When aiExplain=false, no Anthropic call is made regardless of key.
 */

import { describe, test, expect, beforeAll, afterAll, vi } from 'vitest';
import http from 'http';
import https from 'https';
import net from 'net';
import { EventEmitter } from 'events';

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

function post(
  port: number,
  urlPath: string,
  payload: unknown,
): Promise<{ statusCode: number; body: unknown }> {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(payload);
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: urlPath,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(data),
        },
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk: Buffer) => (raw += chunk.toString()));
        res.on('end', () => {
          try {
            resolve({ statusCode: res.statusCode ?? 0, body: JSON.parse(raw) });
          } catch {
            resolve({ statusCode: res.statusCode ?? 0, body: raw });
          }
        });
      },
    );
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

/** Builds a fake https.request stub that returns a canned Anthropic response. */
function makeAnthropicStub(responseJson: object) {
  return vi.spyOn(https, 'request').mockImplementation((_opts: unknown, callback?: (res: unknown) => void) => {
    // Simulate an IncomingMessage with the JSON payload
    const fakeRes = new EventEmitter() as any;
    fakeRes.statusCode = 200;
    fakeRes.headers = {};
    if (callback) {
      process.nextTick(() => {
        callback(fakeRes);
        fakeRes.emit('data', Buffer.from(JSON.stringify(responseJson)));
        fakeRes.emit('end');
      });
    }
    const fakeReq = new EventEmitter() as any;
    fakeReq.setTimeout = () => fakeReq;
    fakeReq.write = () => {};
    fakeReq.end = () => {};
    fakeReq.destroy = () => {};
    return fakeReq;
  });
}

// ── Vulnerable code that will produce at least one finding ────────────────────

const VULNERABLE_CODE = `
const token = Math.random();
const secret = "hardcoded-api-key-12345678";
`;

// ── Server lifecycle ──────────────────────────────────────────────────────────

let serverPort: number;
let serverHandle: http.Server | null = null;

beforeAll(async () => {
  serverPort = await getFreePort();
  delete process.env.SERVER_API_KEY;
  process.env.PORT = String(serverPort);
  process.env.ANTHROPIC_API_KEY = 'sk-ant-test-key-for-vitest-stub-only';

  try { require('ts-node/register'); } catch { /* already registered */ }
  Object.keys(require.cache ?? {}).forEach((k) => {
    if (k.includes('/src/server')) delete require.cache[k];
  });

  const origLog = console.log;
  const origWarn = console.warn;
  const origError = console.error;
  console.log = () => {};
  console.warn = () => {};
  console.error = () => {};

  const mod = require('../../src/server');
  serverHandle = (mod?.default ?? mod?.server ?? null) as http.Server | null;
  await new Promise((r) => setTimeout(r, 300));

  console.log = origLog;
  console.warn = origWarn;
  console.error = origError;
}, 15_000);

afterAll(() => {
  delete process.env.ANTHROPIC_API_KEY;
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

describe('POST /scan — aiExplain=true with stubbed Anthropic', () => {
  test('returns explanation and fixSuggestion fields when aiExplain=true', async () => {
    const anthropicResponse = {
      content: [
        {
          text: JSON.stringify({
            explanation: 'Math.random() is not cryptographically secure and predictable.',
            fixSuggestion: "const token = require('crypto').randomBytes(32).toString('hex');",
          }),
        },
      ],
    };

    const stub = makeAnthropicStub(anthropicResponse);

    try {
      const { statusCode, body } = await post(serverPort, '/scan', {
        code: VULNERABLE_CODE,
        filename: 'test.ts',
        aiExplain: true,
      });

      expect(statusCode).toBe(200);
      const { findings } = body as { findings: Array<Record<string, unknown>> };
      expect(Array.isArray(findings)).toBe(true);
      expect(findings.length).toBeGreaterThan(0);

      // At least one finding should have AI fields
      const withAI = findings.filter((f) => f.explanation !== undefined || f.fixSuggestion !== undefined);
      expect(withAI.length).toBeGreaterThan(0);
      expect(typeof withAI[0]!.explanation).toBe('string');
      expect(typeof withAI[0]!.fixSuggestion).toBe('string');
    } finally {
      stub.mockRestore();
    }
  });

  test('Anthropic stub is called when aiExplain=true', async () => {
    const anthropicResponse = {
      content: [{ text: JSON.stringify({ explanation: 'Test explanation.', fixSuggestion: 'crypto.randomBytes()' }) }],
    };
    const stub = makeAnthropicStub(anthropicResponse);

    try {
      await post(serverPort, '/scan', {
        code: VULNERABLE_CODE,
        filename: 'test.ts',
        aiExplain: true,
      });
      expect(stub).toHaveBeenCalled();
    } finally {
      stub.mockRestore();
    }
  });

  test('Anthropic stub is NOT called when aiExplain=false', async () => {
    const stub = vi.spyOn(https, 'request');

    try {
      const { statusCode, body } = await post(serverPort, '/scan', {
        code: VULNERABLE_CODE,
        filename: 'test.ts',
        aiExplain: false,
      });
      expect(statusCode).toBe(200);
      // https.request should not have been called for Anthropic
      expect(stub).not.toHaveBeenCalled();
      const { findings } = body as { findings: Array<Record<string, unknown>> };
      expect(Array.isArray(findings)).toBe(true);
    } finally {
      stub.mockRestore();
    }
  });
});

describe('POST /scan — aiExplain=true without ANTHROPIC_API_KEY', () => {
  test('returns findings without AI fields when key is missing', async () => {
    const savedKey = process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;

    try {
      const { statusCode, body } = await post(serverPort, '/scan', {
        code: VULNERABLE_CODE,
        filename: 'test.ts',
        aiExplain: true,
      });

      expect(statusCode).toBe(200);
      const { findings } = body as { findings: Array<Record<string, unknown>> };
      expect(Array.isArray(findings)).toBe(true);
      // Without an API key, enrichment is skipped — no AI fields expected
      for (const f of findings) {
        expect(f.explanation).toBeUndefined();
      }
    } finally {
      if (savedKey) process.env.ANTHROPIC_API_KEY = savedKey;
    }
  });
});
