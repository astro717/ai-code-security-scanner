/**
 * Integration tests for CSRF detection via POST /scan.
 *
 * Verifies that submitting Express.js code without CSRF middleware triggers
 * CSRF findings, while code with csurf/csrf-csrf middleware returns clean.
 *
 * Run with: npm run test:vitest
 */

import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { app } from '../../src/server';

// ── Vulnerable Express app (no CSRF protection) ─────────────────────────────

const VULNERABLE_EXPRESS = `
const express = require('express');
const app = express();

app.get('/', (req, res) => {
  res.send('Home');
});

app.post('/login', (req, res) => {
  // No CSRF protection on POST route
  res.json({ success: true });
});

app.put('/profile', (req, res) => {
  // No CSRF protection on PUT route
  res.json({ updated: true });
});

app.delete('/account', (req, res) => {
  // No CSRF protection on DELETE route
  res.json({ deleted: true });
});

app.listen(3000);
`;

// ── Clean Express app (with csurf middleware) ────────────────────────────────

const CLEAN_EXPRESS_CSURF = `
const express = require('express');
const csurf = require('csurf');
const app = express();

const csrfProtection = csurf({ cookie: true });

app.get('/', (req, res) => {
  res.send('Home');
});

app.post('/login', csrfProtection, (req, res) => {
  res.json({ success: true });
});

app.put('/profile', csrfProtection, (req, res) => {
  res.json({ updated: true });
});

app.listen(3000);
`;

// ── Clean Express app (with csrf-csrf) ───────────────────────────────────────

const CLEAN_EXPRESS_CSRF_CSRF = `
import express from 'express';
import { doubleCsrf } from 'csrf-csrf';

const app = express();

const { doubleCsrfProtection } = doubleCsrf({ getSecret: () => 'secret' });
app.use(doubleCsrfProtection);

app.post('/transfer', (req, res) => {
  res.json({ ok: true });
});

app.listen(3000);
`;

// ── Non-Express code (should not trigger CSRF) ──────────────────────────────

const NON_EXPRESS_CODE = `
const http = require('http');
const server = http.createServer((req, res) => {
  res.writeHead(200);
  res.end('hello');
});
server.listen(3000);
`;

describe('POST /scan — CSRF detection', () => {
  it('should detect CSRF on Express POST/PUT/DELETE routes without csrf middleware', async () => {
    const res = await request(app)
      .post('/scan')
      .send({ code: VULNERABLE_EXPRESS, filename: 'app.js' });

    expect(res.status).toBe(200);
    const findings = res.body.findings;
    const csrfFindings = findings.filter((f: { type: string }) => f.type === 'CSRF');

    // Should find CSRF issues on POST, PUT, and DELETE routes
    expect(csrfFindings.length).toBeGreaterThanOrEqual(3);

    // Verify severity and message quality
    for (const f of csrfFindings) {
      expect(f.severity).toBe('high');
      expect(f.message).toContain('CSRF');
    }
  });

  it('should NOT detect CSRF when csurf middleware is imported', async () => {
    const res = await request(app)
      .post('/scan')
      .send({ code: CLEAN_EXPRESS_CSURF, filename: 'app.js' });

    expect(res.status).toBe(200);
    const csrfFindings = res.body.findings.filter((f: { type: string }) => f.type === 'CSRF');
    expect(csrfFindings).toHaveLength(0);
  });

  it('should NOT detect CSRF when csrf-csrf middleware is imported', async () => {
    const res = await request(app)
      .post('/scan')
      .send({ code: CLEAN_EXPRESS_CSRF_CSRF, filename: 'app.ts' });

    expect(res.status).toBe(200);
    const csrfFindings = res.body.findings.filter((f: { type: string }) => f.type === 'CSRF');
    expect(csrfFindings).toHaveLength(0);
  });

  it('should NOT trigger CSRF on non-Express code', async () => {
    const res = await request(app)
      .post('/scan')
      .send({ code: NON_EXPRESS_CODE, filename: 'server.js' });

    expect(res.status).toBe(200);
    const csrfFindings = res.body.findings.filter((f: { type: string }) => f.type === 'CSRF');
    expect(csrfFindings).toHaveLength(0);
  });

  it('should include line numbers and snippets in CSRF findings', async () => {
    const res = await request(app)
      .post('/scan')
      .send({ code: VULNERABLE_EXPRESS, filename: 'app.js' });

    expect(res.status).toBe(200);
    const csrfFindings = res.body.findings.filter((f: { type: string }) => f.type === 'CSRF');

    for (const f of csrfFindings) {
      expect(f.line).toBeGreaterThan(0);
      expect(f.snippet).toBeDefined();
      expect(f.snippet.length).toBeGreaterThan(0);
    }
  });
});
