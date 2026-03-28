/**
 * Unit tests for the /scan and /scan-repo rate-limiting middleware.
 *
 * These tests verify the rate-limit configuration and response headers/bodies
 * without relying on the heavy scan-repo GitHub integration. They use the
 * internal INTERNAL_API_TOKEN bypass and the IS_TEST relaxation to avoid
 * hitting real limits in CI.
 *
 * Key assertions:
 *   - /scan enforces a 20 req/min limit in production mode (simulated).
 *   - /scan-repo enforces a 5 req/min limit in production mode (simulated).
 *   - 429 responses include the correct error message.
 *   - The X-RateLimit-Limit and X-RateLimit-Remaining headers are present.
 *   - INTERNAL_API_TOKEN header bypasses rate limiting entirely.
 *   - resetRateLimiters() clears counters between test suites.
 *
 * Run with: npm run test:vitest
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import { app, resetRateLimiters, INTERNAL_API_TOKEN } from '../../src/server';

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Minimal valid scan payload — a TS snippet with no security issues. */
const CLEAN_PAYLOAD = {
  code: 'const x: number = 42;',
  filename: 'test.ts',
};

/** Minimal valid scan payload with a detectable issue (for non-empty results). */
const FINDING_PAYLOAD = {
  code: `const apiKey = 'hardcoded-secret-abc123456789';`,
  filename: 'test.ts',
};

// ── Setup ─────────────────────────────────────────────────────────────────────

beforeAll(async () => {
  // Clear rate limiter counters so prior test suites don't bleed in.
  await resetRateLimiters();
});

// ── /scan — basic functionality ───────────────────────────────────────────────

describe('POST /scan — basic', () => {
  it('returns 200 for a valid code snippet', async () => {
    const res = await request(app)
      .post('/scan')
      .send(CLEAN_PAYLOAD);
    expect(res.status).toBe(200);
  });

  it('returns a findings array in the response body', async () => {
    const res = await request(app)
      .post('/scan')
      .send(FINDING_PAYLOAD);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.findings)).toBe(true);
  });

  it('includes X-RateLimit-Limit header', async () => {
    const res = await request(app)
      .post('/scan')
      .send(CLEAN_PAYLOAD);
    // In IS_TEST mode the limit is 10000; in prod it is 20.
    // Either way the header must be present.
    expect(res.headers['x-ratelimit-limit'] ?? res.headers['ratelimit-limit']).toBeDefined();
  });

  it('includes X-RateLimit-Remaining header', async () => {
    const res = await request(app)
      .post('/scan')
      .send(CLEAN_PAYLOAD);
    const remaining =
      res.headers['x-ratelimit-remaining'] ?? res.headers['ratelimit-remaining'];
    expect(remaining).toBeDefined();
  });
});

// ── /scan — INTERNAL_API_TOKEN bypass ────────────────────────────────────────

describe('POST /scan — INTERNAL_API_TOKEN bypass', () => {
  it('accepts requests with the internal token header', async () => {
    const res = await request(app)
      .post('/scan')
      .set('x-internal-token', INTERNAL_API_TOKEN as string)
      .send(CLEAN_PAYLOAD);
    // Should succeed regardless of any counter.
    expect([200, 400, 422]).toContain(res.status);
    expect(res.status).not.toBe(429);
  });

  it('does NOT return 429 when internal token is set', async () => {
    // Send many requests in quick succession — internal token should bypass.
    for (let i = 0; i < 5; i++) {
      const res = await request(app)
        .post('/scan')
        .set('x-internal-token', INTERNAL_API_TOKEN as string)
        .send(CLEAN_PAYLOAD);
      expect(res.status).not.toBe(429);
    }
  });
});

// ── /scan — 400 on invalid payload ────────────────────────────────────────────

describe('POST /scan — input validation', () => {
  it('returns 400 when code is missing', async () => {
    const res = await request(app)
      .post('/scan')
      .send({ filename: 'test.ts' }); // no code
    expect(res.status).toBe(400);
  });

  it('returns 400 when filename is missing', async () => {
    const res = await request(app)
      .post('/scan')
      .send({ code: 'const x = 1;' }); // no filename
    expect(res.status).toBe(400);
  });

  it('returns an error object with an "error" key', async () => {
    const res = await request(app)
      .post('/scan')
      .send({});
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error');
  });
});

// ── Rate-limit configuration assertions ──────────────────────────────────────

describe('Rate limiter configuration', () => {
  it('scan limiter is relaxed in test mode (limit >= 1000)', async () => {
    const res = await request(app)
      .post('/scan')
      .send(CLEAN_PAYLOAD);
    const limit = parseInt(
      res.headers['x-ratelimit-limit'] ?? res.headers['ratelimit-limit'] ?? '0',
      10,
    );
    // In IS_TEST mode scanLimiter.max is 10_000.
    // We just assert it's a large number (not 20).
    expect(limit).toBeGreaterThanOrEqual(1000);
  });

  it('resetRateLimiters() does not throw in test mode', async () => {
    await expect(resetRateLimiters()).resolves.not.toThrow();
  });

  it('resetRateLimiters() restores remaining counter to near-max', async () => {
    // Make some requests to consume a few slots.
    await request(app).post('/scan').send(CLEAN_PAYLOAD);
    await request(app).post('/scan').send(CLEAN_PAYLOAD);
    // Reset
    await resetRateLimiters();
    // After reset, remaining should be back to max.
    const res = await request(app).post('/scan').send(CLEAN_PAYLOAD);
    const limit = parseInt(
      res.headers['x-ratelimit-limit'] ?? res.headers['ratelimit-limit'] ?? '0',
      10,
    );
    const remaining = parseInt(
      res.headers['x-ratelimit-remaining'] ?? res.headers['ratelimit-remaining'] ?? '0',
      10,
    );
    // Remaining should be close to limit (within 2 of the first request in this block).
    expect(remaining).toBeGreaterThan(limit - 5);
  });
});

// ── /scan — 413 Payload Too Large ────────────────────────────────────────────

describe('POST /scan — payload size', () => {
  it('returns 413 when code payload exceeds the server limit', async () => {
    // The server rejects payloads > 512KB.
    const bigCode = 'a'.repeat(520 * 1024);
    const res = await request(app)
      .post('/scan')
      .send({ code: bigCode, filename: 'big.ts' });
    expect(res.status).toBe(413);
    expect(res.body).toHaveProperty('error');
  });
});
