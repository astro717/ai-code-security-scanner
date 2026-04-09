/**
 * Integration tests for webhook delivery via the POST /scan endpoint.
 *
 * Tests verify:
 *   1. HMAC-SHA256 signature header (X-Scanner-Signature) is set correctly
 *      when webhookSecret is provided.
 *   2. Non-2xx responses trigger retry — verified by counting received requests.
 *   3. Payload body delivered to the webhook matches the scan findings.
 *
 * A local HTTP server (not HTTPS) is used because:
 *   - The webhook code branches on protocol: https → use https module, else http.
 *   - Using plain http avoids TLS cert setup in tests.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import * as http from 'http';
import * as crypto from 'crypto';
import * as net from 'net';
import request from 'supertest';
import { app } from '../../src/server';

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Find a random available port. */
function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address() as net.AddressInfo;
      srv.close((err) => (err ? reject(err) : resolve(addr.port)));
    });
  });
}

/** A simple HTTP server that records every incoming request. */
interface RecordedRequest {
  headers: http.IncomingHttpHeaders;
  body: string;
}

interface TestServer {
  url: string;
  requests: RecordedRequest[];
  /** Override the status code sent back on the NEXT request (defaults to 200). */
  nextStatusCode: number;
  close: () => Promise<void>;
}

async function startRecordingServer(): Promise<TestServer> {
  const port = await getFreePort();
  const requests: RecordedRequest[] = [];
  let nextStatusCode = 200;

  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      requests.push({ headers: req.headers, body });
      res.writeHead(nextStatusCode);
      res.end();
      // Reset to 200 after the first non-200 response so subsequent retries can succeed
      if (nextStatusCode !== 200) nextStatusCode = 200;
    });
  });

  await new Promise<void>((resolve) => server.listen(port, '127.0.0.1', resolve));

  return {
    url: `http://127.0.0.1:${port}/webhook`,
    requests,
    get nextStatusCode() { return nextStatusCode; },
    set nextStatusCode(v: number) { nextStatusCode = v; },
    close: () => new Promise<void>((resolve, reject) =>
      server.close((err) => (err ? reject(err) : resolve())),
    ),
  };
}

/** Minimal code that is guaranteed to produce at least one finding. */
const SCAN_CODE = `const apiKey = "sk-1234567890abcdef1234567890abcdef";`;

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('Webhook delivery — HMAC signature', () => {
  let srv: TestServer;

  beforeAll(async () => { srv = await startRecordingServer(); });
  afterAll(async () => { await srv.close(); });

  test('X-Scanner-Signature header is present and valid when webhookSecret is provided', async () => {
    const secret = 'super-secret-key';

    // Trigger a scan with a webhookUrl and webhookSecret
    const scanRes = await request(app)
      .post('/scan')
      .send({
        code: SCAN_CODE,
        filename: 'test.ts',
        webhookUrl: srv.url,
        webhookSecret: secret,
      });

    // The /scan endpoint returns 200 synchronously; the webhook is fire-and-forget.
    expect(scanRes.status).toBe(200);

    // Wait up to 3 s for the webhook to arrive
    const deadline = Date.now() + 3_000;
    while (srv.requests.length === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 50));
    }

    expect(srv.requests.length).toBeGreaterThanOrEqual(1);

    const received = srv.requests[0]!;
    const sigHeader = received.headers['x-scanner-signature'];
    expect(typeof sigHeader).toBe('string');
    expect((sigHeader as string).startsWith('sha256=')).toBe(true);

    // Verify the signature against the body
    const expectedSig = 'sha256=' + crypto
      .createHmac('sha256', secret)
      .update(received.body)
      .digest('hex');

    expect(sigHeader).toBe(expectedSig);
  }, 10_000);

  test('X-Scanner-Signature is absent when no webhookSecret is provided', async () => {
    srv.requests.length = 0; // reset

    await request(app)
      .post('/scan')
      .send({
        code: SCAN_CODE,
        filename: 'test.ts',
        webhookUrl: srv.url,
        // no webhookSecret
      });

    const deadline = Date.now() + 3_000;
    while (srv.requests.length === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 50));
    }

    expect(srv.requests.length).toBeGreaterThanOrEqual(1);
    expect(srv.requests[0]!.headers['x-scanner-signature']).toBeUndefined();
  }, 10_000);
});

describe('Webhook delivery — payload body', () => {
  let srv: TestServer;

  beforeAll(async () => { srv = await startRecordingServer(); });
  afterAll(async () => { await srv.close(); });

  test('webhook body is valid JSON containing findings array', async () => {
    await request(app)
      .post('/scan')
      .send({
        code: SCAN_CODE,
        filename: 'test.ts',
        webhookUrl: srv.url,
      });

    const deadline = Date.now() + 3_000;
    while (srv.requests.length === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 50));
    }

    expect(srv.requests.length).toBeGreaterThanOrEqual(1);

    const rawBody = srv.requests[0]!.body;
    let parsed: any;
    expect(() => { parsed = JSON.parse(rawBody); }).not.toThrow();

    // The payload must contain a findings array
    expect(Array.isArray(parsed.findings)).toBe(true);
    expect(parsed.findings.length).toBeGreaterThan(0);

    // Each finding must have at minimum a type and a severity
    for (const f of parsed.findings) {
      expect(typeof f.type).toBe('string');
      expect(typeof f.severity).toBe('string');
    }
  }, 10_000);

  test('payload body matches the findings returned by the /scan endpoint', async () => {
    srv.requests.length = 0;

    // Run the scan and capture the HTTP response
    const scanRes = await request(app)
      .post('/scan')
      .send({ code: SCAN_CODE, filename: 'test.ts', webhookUrl: srv.url });

    const deadline = Date.now() + 3_000;
    while (srv.requests.length === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 50));
    }

    const webhookPayload = JSON.parse(srv.requests[0]!.body);

    // The findings count in the webhook must match the API response
    expect(webhookPayload.findings.length).toBe(scanRes.body.findings.length);
  }, 10_000);
});

describe('Webhook delivery — retry on non-2xx', () => {
  let srv: TestServer;

  beforeAll(async () => { srv = await startRecordingServer(); });
  afterAll(async () => { await srv.close(); });

  test('server retries after a 500 response (at least 2 requests received)', async () => {
    srv.requests.length = 0;
    // First response will be 500; the recording server resets to 200 after that
    srv.nextStatusCode = 500;

    await request(app)
      .post('/scan')
      .send({ code: SCAN_CODE, filename: 'test.ts', webhookUrl: srv.url });

    // WEBHOOK_BACKOFF_BASE_MS is 1000ms; wait up to 4 s for at least 2 attempts
    const deadline = Date.now() + 4_000;
    while (srv.requests.length < 2 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 100));
    }

    expect(srv.requests.length).toBeGreaterThanOrEqual(2);
  }, 10_000);
});
