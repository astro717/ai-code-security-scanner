/**
 * Integration tests for server.ts Bearer token authentication.
 *
 * These tests use supertest(app) to exercise the /scan endpoint with and
 * without a valid API key, verifying that the auth middleware enforces the
 * security boundary correctly.
 *
 * Note: SERVER_API_KEY must be set BEFORE the server module is imported.
 * Since vitest loads all imports statically, we test with the env var set
 * at process level and verify the middleware behavior.
 *
 * Run with: SERVER_API_KEY=test-secret-key-abc123 npm run test:vitest -- server-auth
 */

import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';

const API_KEY = 'test-secret-key-abc123';

// Set the env var before importing the server module
beforeAll(() => {
  process.env.SERVER_API_KEY = API_KEY;
});

afterAll(() => {
  delete process.env.SERVER_API_KEY;
});

// ── Test suite: SERVER_API_KEY is set ───────────────────────────────────────────

describe('server auth — SERVER_API_KEY is set', () => {
  test('/health is accessible without auth', async () => {
    // Dynamic import so SERVER_API_KEY is set before module loads
    const { app } = await import('../../src/server');
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
  });

  test('POST /scan without Authorization header returns 401', async () => {
    const { app } = await import('../../src/server');
    const res = await request(app)
      .post('/scan')
      .send({ code: 'const x = 1;', filename: 'test.ts' });
    expect(res.status).toBe(401);
    const body = res.body as { error?: string };
    expect(typeof body.error).toBe('string');
    expect(body.error).toContain('Unauthorized');
  });

  test('POST /scan with wrong Bearer token returns 401', async () => {
    const { app } = await import('../../src/server');
    const res = await request(app)
      .post('/scan')
      .send({ code: 'const x = 1;', filename: 'test.ts' })
      .set('Authorization', 'Bearer wrong-token');
    expect(res.status).toBe(401);
  });

  test('POST /scan with correct Bearer token returns 200', async () => {
    const { app } = await import('../../src/server');
    const res = await request(app)
      .post('/scan')
      .send({ code: 'const x = 1;', filename: 'test.ts' })
      .set('Authorization', `Bearer ${API_KEY}`);
    expect(res.status).toBe(200);
    const body = res.body as { findings?: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
  });

  test('POST /scan with Bearer prefix missing returns 401', async () => {
    const { app } = await import('../../src/server');
    const res = await request(app)
      .post('/scan')
      .send({ code: 'const x = 1;', filename: 'test.ts' })
      .set('Authorization', API_KEY);
    expect(res.status).toBe(401);
  });
});
