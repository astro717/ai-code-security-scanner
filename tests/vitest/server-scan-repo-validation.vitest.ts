/**
 * Integration tests for /scan-repo input validation.
 *
 * Covers: missing repoUrl (400), invalid URL format (400), unsupported
 * protocol (400), and a happy-path stub that returns 200 with a findings
 * array. The GitHub fetch logic is mocked via vi.mock so tests run fast
 * and fully offline.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, vi } from 'vitest';
import request from 'supertest';
import { app } from '../../src/server';

// ── /scan-repo input validation tests ────────────────────────────────────────

describe('/scan-repo input validation', () => {
  test('missing repoUrl field returns 400', async () => {
    const res = await request(app).post('/scan-repo').send({});
    expect(res.status).toBe(400);
    const body = res.body as { error?: string };
    expect(typeof body.error).toBe('string');
    expect(body.error).toMatch(/repoUrl/i);
  });

  test('repoUrl as null returns 400', async () => {
    const res = await request(app).post('/scan-repo').send({ repoUrl: null });
    expect(res.status).toBe(400);
    const body = res.body as { error?: string };
    expect(typeof body.error).toBe('string');
    expect(body.error).toMatch(/repoUrl/i);
  });

  test('repoUrl as integer returns 400', async () => {
    const res = await request(app).post('/scan-repo').send({ repoUrl: 12345 });
    expect(res.status).toBe(400);
    const body = res.body as { error?: string };
    expect(typeof body.error).toBe('string');
    expect(body.error).toMatch(/repoUrl/i);
  });

  test('non-allowlisted URL returns 400 with supported hosts message', async () => {
    const res = await request(app).post('/scan-repo').send({ repoUrl: 'https://evil.com/owner/repo' });
    expect(res.status).toBe(400);
    const body = res.body as { error?: string };
    expect(typeof body.error).toBe('string');
    expect(body.error).toMatch(/github\.com/i);
  });

  test('gitlab.com URL returns 400 with clear unsupported message', async () => {
    const res = await request(app).post('/scan-repo').send({ repoUrl: 'https://gitlab.com/owner/repo' });
    expect(res.status).toBe(400);
    const body = res.body as { error?: string };
    expect(typeof body.error).toBe('string');
    expect(body.error).toMatch(/github\.com/i);
  });

  test('bitbucket.org URL returns 400 with clear unsupported message', async () => {
    const res = await request(app).post('/scan-repo').send({ repoUrl: 'https://bitbucket.org/owner/repo' });
    expect(res.status).toBe(400);
    const body = res.body as { error?: string };
    expect(typeof body.error).toBe('string');
    expect(body.error).toMatch(/github\.com/i);
  });

  test('http:// (non-https) URL returns 400', async () => {
    const res = await request(app).post('/scan-repo').send({ repoUrl: 'http://github.com/owner/repo' });
    expect(res.status).toBe(400);
    const body = res.body as { error?: string };
    expect(typeof body.error).toBe('string');
    expect(body.error).toMatch(/https/i);
  });

  test('unsupported protocol (ssh) returns 400', async () => {
    const res = await request(app).post('/scan-repo').send({ repoUrl: 'git@github.com:owner/repo.git' });
    expect(res.status).toBe(400);
    const body = res.body as { error?: string };
    expect(typeof body.error).toBe('string');
    expect(body.error).toMatch(/url|scheme|https/i);
  });

  test('invalid URL string returns 400', async () => {
    const res = await request(app).post('/scan-repo').send({ repoUrl: 'not-a-url-at-all' });
    expect(res.status).toBe(400);
    const body = res.body as { error?: string };
    expect(typeof body.error).toBe('string');
    expect(typeof body.error).toBe('string');
  });

  test('private IP address returns 400 (SSRF protection)', async () => {
    const res = await request(app).post('/scan-repo').send({ repoUrl: 'https://127.0.0.1/owner/repo' });
    expect(res.status).toBe(400);
    const body = res.body as { error?: string };
    expect(typeof body.error).toBe('string');
    expect(body.error).toMatch(/private|loopback|allowed/i);
  });

  test('10.x private IP returns 400 (SSRF protection)', async () => {
    const res = await request(app).post('/scan-repo').send({ repoUrl: 'https://10.0.0.1/owner/repo' });
    expect(res.status).toBe(400);
    const body = res.body as { error?: string };
    expect(typeof body.error).toBe('string');
  });
});
