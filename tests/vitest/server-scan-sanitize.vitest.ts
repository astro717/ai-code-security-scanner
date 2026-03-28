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

import { describe, test, expect } from 'vitest';
import request from 'supertest';
import { app } from '../../src/server';

// Minimal valid TypeScript code used in all /scan calls
const CLEAN_CODE = 'const x: number = 1;';

// ── Malicious filename tests — must all return 400 ────────────────────────────

describe('/scan filename sanitization — malicious inputs rejected with 400', () => {
  test('path traversal: "../../../etc/passwd" returns 400', async () => {
    const res = await request(app).post('/scan').send({
      code: CLEAN_CODE,
      filename: '../../../etc/passwd',
    });
    expect(res.status).toBe(400);
    const body = res.body as { error?: string };
    expect(typeof body.error).toBe('string');
    expect(body.error).toMatch(/path traversal/i);
  });

  test('path traversal: ".." alone returns 400', async () => {
    const res = await request(app).post('/scan').send({
      code: CLEAN_CODE,
      filename: '..',
    });
    expect(res.status).toBe(400);
    const body = res.body as { error?: string };
    expect(body.error).toMatch(/path traversal/i);
  });

  test('path traversal: "folder/../secret.ts" returns 400', async () => {
    const res = await request(app).post('/scan').send({
      code: CLEAN_CODE,
      filename: 'folder/../secret.ts',
    });
    expect(res.status).toBe(400);
    const body = res.body as { error?: string };
    expect(body.error).toMatch(/path traversal/i);
  });

  test('null byte: "file\\0name.ts" returns 400', async () => {
    const res = await request(app).post('/scan').send({
      code: CLEAN_CODE,
      filename: 'file\0name.ts',
    });
    expect(res.status).toBe(400);
    const body = res.body as { error?: string };
    expect(typeof body.error).toBe('string');
    expect(body.error).toMatch(/null byte/i);
  });

  test('absolute Unix path: "/absolute/path/file.ts" returns 400', async () => {
    const res = await request(app).post('/scan').send({
      code: CLEAN_CODE,
      filename: '/absolute/path/file.ts',
    });
    expect(res.status).toBe(400);
    const body = res.body as { error?: string };
    expect(body.error).toMatch(/path traversal/i);
  });

  test('absolute Windows-style path: "\\\\server\\share\\file.ts" returns 400', async () => {
    const res = await request(app).post('/scan').send({
      code: CLEAN_CODE,
      filename: '\\server\\share\\file.ts',
    });
    expect(res.status).toBe(400);
    const body = res.body as { error?: string };
    expect(body.error).toMatch(/path traversal/i);
  });

  test('non-string filename returns 400', async () => {
    const res = await request(app).post('/scan').send({
      code: CLEAN_CODE,
      filename: 42,
    });
    expect(res.status).toBe(400);
    const body = res.body as { error?: string };
    expect(typeof body.error).toBe('string');
    expect(body.error).toMatch(/filename must be a string/i);
  });
});

// ── Valid filename tests — must return 200 ────────────────────────────────────

describe('/scan filename sanitization — valid filenames accepted with 200', () => {
  test('plain filename "app.ts" returns 200', async () => {
    const res = await request(app).post('/scan').send({
      code: CLEAN_CODE,
      filename: 'app.ts',
    });
    expect(res.status).toBe(200);
    const body = res.body as { findings?: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
  });

  test('filename with subdirectory stripped by basename: "src/utils.ts" returns 200', async () => {
    // path.basename('src/utils.ts') === 'utils.ts' — no ".." involved, no leading slash
    // The server applies basename AFTER the traversal check — but since "src/utils.ts"
    // does not contain ".." or start with "/" or "\\", it passes the guard and is then
    // basename-stripped to "utils.ts".
    const res = await request(app).post('/scan').send({
      code: CLEAN_CODE,
      filename: 'src/utils.ts',
    });
    expect(res.status).toBe(200);
    const body = res.body as { findings?: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
  });

  test('omitting filename entirely returns 200 (field is optional)', async () => {
    const res = await request(app).post('/scan').send({
      code: CLEAN_CODE,
    });
    expect(res.status).toBe(200);
    const body = res.body as { findings?: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
  });

  test('filename with dots in name (not traversal) "my.config.ts" returns 200', async () => {
    const res = await request(app).post('/scan').send({
      code: CLEAN_CODE,
      filename: 'my.config.ts',
    });
    expect(res.status).toBe(200);
  });
});
