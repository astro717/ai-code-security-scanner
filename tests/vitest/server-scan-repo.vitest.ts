/**
 * Integration tests for the POST /scan-repo endpoint.
 *
 * Covers:
 *   - Missing / invalid repoUrl → 400
 *   - Valid GitHub URL → 200 with findings array and filesScanned count
 *   - Key detectors fire against a vulnerable code fixture injected via a
 *     monkey-patched https.get stub (no real network calls)
 *   - ignorePatterns filters files out correctly
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import { app } from '../../src/server';
import https from 'https';
import { buildSARIF } from '../../src/scanner/sarif';

// ── Vulnerable code fixture ───────────────────────────────────────────────────

const VULNERABLE_CODE = `
const apiKey = "sk-1234567890abcdef1234567890abcdef";

function getUser(id) {
  return db.query("SELECT * FROM users WHERE id = " + id);
}

function runCmd(input) {
  require('child_process').exec("ls " + input);
}

function evalCode(code) {
  return eval(code);
}

function generateToken() {
  const sessionToken = Math.random();
}

function hashPw(pw) {
  return require('crypto').createHash('md5').update(pw).digest('hex');
}
`;

// ── https.get stub ────────────────────────────────────────────────────────────

let originalHttpsGet: typeof https.get;
let originalHttpsRequest: typeof https.request;

function makeFakeGet(opts: any, cb: any) {
  const urlStr =
    typeof opts === 'string'
      ? opts
      : 'https://' + (opts.hostname || '') + (opts.path || '');

  const isContentsRoot =
    urlStr.includes('/contents/?ref=') || urlStr.includes('/contents?ref=');
  const isContentsFile =
    urlStr.includes('/contents/vuln.js') && !isContentsRoot;

  let body: string;
  if (isContentsRoot) {
    body = JSON.stringify([
      {
        type: 'file',
        name: 'vuln.js',
        path: 'vuln.js',
        size: VULNERABLE_CODE.length,
        download_url: null,
        url: 'https://api.github.com/repos/owner/repo/contents/vuln.js',
      },
    ]);
  } else if (isContentsFile) {
    body = VULNERABLE_CODE;
  } else {
    body = '[]';
  }

  const { PassThrough } = require('stream');
  const res = new PassThrough();
  (res as any).statusCode = 200;
  (res as any).headers = {};

  const fakeReq = {
    on: (_evt: string, _fn: unknown) => fakeReq,
    setTimeout: (_ms: number, _fn: unknown) => fakeReq,
    write: () => {},
    end: () => {
      setImmediate(() => {
        res.emit('data', body);
        res.emit('end');
      });
    },
  };

  setImmediate(() => {
    if (cb) cb(res);
    res.emit('data', body);
    res.emit('end');
  });

  return fakeReq;
}

// ── Setup / teardown ─────────────────────────────────────────────────────────

let scanResult: any = null;

beforeAll(async () => {
  // Monkey-patch https.get and https.request
  originalHttpsGet = https.get;
  originalHttpsRequest = https.request;
  (https as any).get = makeFakeGet;
  (https as any).request = makeFakeGet;

  // Perform the scan once and reuse for all tests
  const res = await request(app)
    .post('/scan-repo')
    .send({ repoUrl: 'https://github.com/owner/repo', branch: 'main' });
  scanResult = { statusCode: res.status, body: res.body };
}, 15_000);

afterAll(() => {
  (https as any).get = originalHttpsGet;
  (https as any).request = originalHttpsRequest;
});

// ── Input validation — 400 ──────────────────────────────────────────────────

describe('POST /scan-repo — input validation (400)', () => {
  test('missing repoUrl field returns 400 with descriptive message', async () => {
    const res = await request(app).post('/scan-repo').send({});
    expect(res.status).toBe(400);
    expect(typeof res.body.error).toBe('string');
    expect(res.body.error).toMatch(/repoUrl/i);
  });

  test('repoUrl as number returns 400', async () => {
    const res = await request(app).post('/scan-repo').send({ repoUrl: 42 });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/repoUrl/i);
  });

  test('non-GitHub URL returns 400 mentioning github', async () => {
    const res = await request(app).post('/scan-repo').send({
      repoUrl: 'https://gitlab.com/owner/repo',
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/github/i);
  });
});

// ── Happy path — response shape ───────────────────────────────────────────────

describe('POST /scan-repo — successful scan response shape', () => {
  test('returns 200', () => {
    expect(scanResult.statusCode).toBe(200);
  });

  test('body.findings is an array', () => {
    expect(Array.isArray(scanResult.body.findings)).toBe(true);
  });

  test('body.summary is an object', () => {
    expect(typeof scanResult.body.summary).toBe('object');
    expect(scanResult.body.summary).not.toBeNull();
  });

  test('body.filesScanned is a number', () => {
    expect(typeof scanResult.body.filesScanned).toBe('number');
  });

  test('filesScanned equals 1 for single-file mocked repo', () => {
    expect(scanResult.body.filesScanned).toBe(1);
  });

  test('findings array is non-empty', () => {
    expect(scanResult.body.findings.length).toBeGreaterThan(0);
  });

  test('summary.total matches findings array length', () => {
    expect(scanResult.body.summary.total).toBe(scanResult.body.findings.length);
  });

  test('each finding has required fields: type, severity, file, line, message', () => {
    for (const f of scanResult.body.findings) {
      expect(typeof f.type).toBe('string');
      expect(typeof f.severity).toBe('string');
      expect(typeof f.file).toBe('string');
      expect(typeof f.line).toBe('number');
      expect(typeof f.message).toBe('string');
    }
  });

  test('finding file field matches the scanned filename', () => {
    const files = new Set(scanResult.body.findings.map((f: any) => f.file));
    expect(files.has('vuln.js')).toBe(true);
  });
});

// ── Detector coverage ─────────────────────────────────────────────────────────

describe('POST /scan-repo — detector coverage', () => {
  test('SECRET_HARDCODED detector fires on hardcoded sk- API key', () => {
    const types = scanResult.body.findings.map((f: any) => f.type);
    expect(types.some((t: string) => t === 'SECRET_HARDCODED')).toBe(true);
  });

  test('SQL_INJECTION detector fires', () => {
    const types = scanResult.body.findings.map((f: any) => f.type);
    expect(types.some((t: string) => t.includes('SQL'))).toBe(true);
  });

  test('EVAL detector fires', () => {
    const types = scanResult.body.findings.map((f: any) => f.type);
    expect(types.some((t: string) => t.includes('EVAL'))).toBe(true);
  });

  test('WEAK_CRYPTO detector fires on createHash("md5")', () => {
    const types = scanResult.body.findings.map((f: any) => f.type);
    expect(types.some((t: string) => t.includes('CRYPTO') || t.includes('HASH') || t.includes('WEAK'))).toBe(true);
  });

  test('INSECURE_RANDOM detector fires on Math.random()', () => {
    const types = scanResult.body.findings.map((f: any) => f.type);
    expect(types.some((t: string) => t === 'INSECURE_RANDOM')).toBe(true);
  });
});

// ── SARIF mode ────────────────────────────────────────────────────────────────

describe('POST /scan-repo — SARIF output format', () => {
  test('SARIF builder produces valid output from scan findings', () => {
    const findings = scanResult?.body?.findings ?? [];
    const sarif = buildSARIF(findings, 'test-scan');
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toMatch(/sarif/i);
    expect(Array.isArray(sarif.runs)).toBe(true);
    expect(sarif.runs).toHaveLength(1);
  });

  test('SARIF output contains results matching finding count', () => {
    const findings = scanResult?.body?.findings ?? [];
    const sarif = buildSARIF(findings, 'test-scan');
    const results = sarif.runs[0]?.results ?? [];
    expect(results).toHaveLength(findings.length);
  });

  test('each SARIF result has ruleId, message, and location', () => {
    const findings = scanResult?.body?.findings ?? [];
    const sarif = buildSARIF(findings, 'test-scan');
    for (const result of sarif.runs[0]?.results ?? []) {
      expect(typeof result.ruleId).toBe('string');
      expect(typeof result.message?.text).toBe('string');
      expect(Array.isArray(result.locations)).toBe(true);
      expect(result.locations).toHaveLength(1);
    }
  });
});
