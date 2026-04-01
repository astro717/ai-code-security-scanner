/**
 * Input validation tests for /scan and /fix endpoints.
 *
 * Covers: Content-Type validation (415), missing/invalid fields (400),
 *         filename sanitization, ignoreTypes validation, webhookUrl validation.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import request from 'supertest';
import { app } from '../../src/server';

// ── /scan Content-Type validation ─────────────────────────────────────────────

describe('POST /scan — Content-Type validation', () => {
  test('returns 415 when Content-Type is text/plain', async () => {
    const res = await request(app)
      .post('/scan')
      .set('Content-Type', 'text/plain')
      .send('const x = 1;');
    expect(res.status).toBe(415);
    expect(res.body.error).toMatch(/content.type|unsupported/i);
  });

  test('returns 415 when Content-Type is missing', async () => {
    const res = await request(app)
      .post('/scan')
      .send(Buffer.from('raw data'));
    expect(res.status).toBe(415);
  });

  test('accepts requests with Content-Type: application/json', async () => {
    const res = await request(app)
      .post('/scan')
      .set('Content-Type', 'application/json')
      .send({ code: 'const x = 1;', filename: 'test.ts' });
    expect([200, 408]).toContain(res.status); // 200 on success, 408 on timeout
  });
});

// ── /fix Content-Type validation ─────────────────────────────────────────────

describe('POST /fix — Content-Type validation', () => {
  test('returns 415 when Content-Type is text/plain', async () => {
    const res = await request(app)
      .post('/fix')
      .set('Content-Type', 'text/plain')
      .send('const x = 1;');
    expect(res.status).toBe(415);
    expect(res.body.error).toMatch(/content.type|unsupported/i);
  });
});

// ── /scan field validation ─────────────────────────────────────────────────────

describe('POST /scan — field validation', () => {
  test('returns 400 when code is missing', async () => {
    const res = await request(app)
      .post('/scan')
      .send({ filename: 'test.ts' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/code/i);
  });

  test('returns 400 when code is not a string', async () => {
    const res = await request(app)
      .post('/scan')
      .send({ code: 123, filename: 'test.ts' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/code/i);
  });

  test('returns 400 when filename is not a string', async () => {
    const res = await request(app)
      .post('/scan')
      .send({ code: 'const x = 1;', filename: 123 });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/filename/i);
  });

  test('returns 400 when filename contains path traversal', async () => {
    const res = await request(app)
      .post('/scan')
      .send({ code: 'const x = 1;', filename: '../../etc/passwd' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/filename|traversal/i);
  });

  test('returns 400 when filename is an absolute path', async () => {
    const res = await request(app)
      .post('/scan')
      .send({ code: 'const x = 1;', filename: '/etc/passwd' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/filename|traversal/i);
  });

  test('returns 400 when ignoreTypes is not an array', async () => {
    const res = await request(app)
      .post('/scan')
      .send({ code: 'const x = 1;', filename: 'test.ts', ignoreTypes: 'SQL_INJECTION' });
    expect(res.status).toBe(400);
  });

  test('returns 400 when webhookUrl is not https', async () => {
    const res = await request(app)
      .post('/scan')
      .send({ code: 'const x = 1;', filename: 'test.ts', webhookUrl: 'http://evil.com/hook' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/https|webhook/i);
  });

  test('returns 400 when webhookUrl is not a valid URL', async () => {
    const res = await request(app)
      .post('/scan')
      .send({ code: 'const x = 1;', filename: 'test.ts', webhookUrl: 'not-a-url' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/webhook/i);
  });

  test('accepts valid https webhookUrl', async () => {
    const res = await request(app)
      .post('/scan')
      .send({ code: 'const x = 1;', filename: 'test.ts', webhookUrl: 'https://example.com/hook' });
    // Should not be 400 for this field specifically (may fail for other reasons like webhook delivery)
    expect(res.status).not.toBe(400);
  });
});

// ── /scan sanitize filename ───────────────────────────────────────────────────

describe('POST /scan — filename sanitization', () => {
  test('accepts a simple basename filename', async () => {
    const res = await request(app)
      .post('/scan')
      .send({ code: 'const x = 1;', filename: 'app.ts' });
    expect([200, 408]).toContain(res.status);
  });

  test('returns 400 for filename with null byte', async () => {
    const res = await request(app)
      .post('/scan')
      .send({ code: 'const x = 1;', filename: 'test\x00.ts' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/filename|null/i);
  });
});
