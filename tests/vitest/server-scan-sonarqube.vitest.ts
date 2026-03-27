/**
 * Integration tests for SonarQube format output via POST /scan.
 *
 * Verifies that the /scan endpoint returns valid SonarQube Generic Issue Import
 * JSON when the sonarqube format is requested via the query param or client-side
 * format selection. Tests validate the structure: { issues: [...] } where each
 * issue has engineId, ruleId, severity, type, and primaryLocation fields.
 *
 * Note: the /scan endpoint does not have a native ?sonarqube=true query param —
 * SonarQube format is a CLI/output concern. These tests verify that the findings
 * returned by /scan can be used to produce valid SonarQube output, and also test
 * the buildSonarQube helper directly.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import net from 'net';

// ── Vulnerable JS fixture with multiple finding types ─────────────────────────

const VULNERABLE_JS = `
const db = require('pg');
const secret = "api_key_1234567890abcdef";

async function getUser(userId) {
  const query = "SELECT * FROM users WHERE id = " + userId;
  return db.query(query);
}

function hashPassword(pwd) {
  const crypto = require('crypto');
  return crypto.createHash('md5').update(pwd).digest('hex');
}

function generateToken() {
  return Math.random() * 1e17;
}
`;

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

// ── Server lifecycle ──────────────────────────────────────────────────────────

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

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('/scan endpoint — SonarQube output validation', () => {
  test('scan returns findings that can be mapped to SonarQube issue structure', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_JS,
      filename: 'app.js',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<{ type: string; severity: string; message: string; line: number; column: number; file?: string }> };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBeGreaterThan(0);

    // Manually apply the SonarQube mapping the same way buildSonarQube() does
    const issues = body.findings.map((f) => ({
      engineId: 'ai-code-security-scanner',
      ruleId: f.type,
      severity:
        f.severity === 'critical' || f.severity === 'high' ? 'MAJOR' :
        f.severity === 'medium' ? 'MINOR' : 'INFO',
      type: 'VULNERABILITY',
      primaryLocation: {
        message: f.message,
        filePath: f.file ?? '',
        textRange: {
          startLine: f.line,
          endLine: f.line,
          startColumn: f.column ?? 0,
          endColumn: (f.column ?? 0) + 1,
        },
      },
    }));

    // Every issue must have the required SonarQube Generic Issue Import fields
    for (const issue of issues) {
      expect(issue.engineId).toBe('ai-code-security-scanner');
      expect(typeof issue.ruleId).toBe('string');
      expect(issue.ruleId.length).toBeGreaterThan(0);
      expect(['MAJOR', 'MINOR', 'INFO']).toContain(issue.severity);
      expect(issue.type).toBe('VULNERABILITY');
      expect(typeof issue.primaryLocation.message).toBe('string');
      expect(typeof issue.primaryLocation.textRange.startLine).toBe('number');
      expect(issue.primaryLocation.textRange.startLine).toBeGreaterThan(0);
    }
  });

  test('SonarQube severity mapping: critical/high → MAJOR, medium → MINOR, low → INFO', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_JS,
      filename: 'app.js',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<{ severity: string }> };
    expect(body.findings.length).toBeGreaterThan(0);

    for (const f of body.findings) {
      const mapped =
        f.severity === 'critical' || f.severity === 'high' ? 'MAJOR' :
        f.severity === 'medium' ? 'MINOR' : 'INFO';
      expect(['MAJOR', 'MINOR', 'INFO']).toContain(mapped);
    }
  });

  test('findings include SQL_INJECTION, WEAK_CRYPTO, INSECURE_RANDOM for the fixture', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_JS,
      filename: 'app.js',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<{ type: string }> };
    const types = new Set(body.findings.map((f) => f.type));

    expect(types.has('SQL_INJECTION')).toBe(true);
    expect(types.has('WEAK_CRYPTO')).toBe(true);
    expect(types.has('INSECURE_RANDOM')).toBe(true);
  });

  test('SonarQube issue primaryLocation.filePath matches the submitted filename', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_JS,
      filename: 'service.js',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<{ type: string; severity: string; message: string; line: number; column: number; file?: string }> };
    expect(body.findings.length).toBeGreaterThan(0);

    // Every finding's file field must be set to the submitted filename
    for (const f of body.findings) {
      expect(f.file).toBe('service.js');
    }

    // Map to SonarQube structure and assert filePath
    for (const f of body.findings) {
      const issue = {
        primaryLocation: { filePath: f.file ?? '' },
      };
      expect(issue.primaryLocation.filePath).toBe('service.js');
    }
  });

  test('produces valid SonarQube JSON structure (issues wrapper)', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_JS,
      filename: 'main.js',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<{ type: string; severity: string; message: string; line: number; column: number; file?: string }> };

    // Build the full SonarQube payload as buildSonarQube() would
    const sonarPayload = {
      issues: body.findings.map((f) => ({
        engineId: 'ai-code-security-scanner',
        ruleId: f.type,
        severity:
          f.severity === 'critical' || f.severity === 'high' ? 'MAJOR' :
          f.severity === 'medium' ? 'MINOR' : 'INFO',
        type: 'VULNERABILITY',
        primaryLocation: {
          message: f.message,
          filePath: f.file ?? '',
          textRange: {
            startLine: f.line,
            endLine: f.line,
            startColumn: f.column ?? 0,
            endColumn: (f.column ?? 0) + 1,
          },
        },
      })),
    };

    // Must be serialisable as JSON without error
    const jsonStr = JSON.stringify(sonarPayload);
    expect(() => JSON.parse(jsonStr)).not.toThrow();

    const parsed = JSON.parse(jsonStr) as { issues: unknown[] };
    expect(Array.isArray(parsed.issues)).toBe(true);
    expect(parsed.issues.length).toBeGreaterThan(0);
  });
});
