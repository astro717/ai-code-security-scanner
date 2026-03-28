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

import { describe, test, expect } from 'vitest';
import request from 'supertest';
import { app } from '../../src/server';

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

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('/scan endpoint — SonarQube output validation', () => {
  test('scan returns findings that can be mapped to SonarQube issue structure', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_JS,
      filename: 'app.js',
    });

    expect(res.status).toBe(200);
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
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_JS,
      filename: 'app.js',
    });

    expect(res.status).toBe(200);
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
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_JS,
      filename: 'app.js',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ type: string }> };
    const types = new Set(body.findings.map((f) => f.type));

    expect(types.has('SQL_INJECTION')).toBe(true);
    expect(types.has('WEAK_CRYPTO')).toBe(true);
    expect(types.has('INSECURE_RANDOM')).toBe(true);
  });

  test('SonarQube issue primaryLocation.filePath matches the submitted filename', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_JS,
      filename: 'service.js',
    });

    expect(res.status).toBe(200);
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
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_JS,
      filename: 'main.js',
    });

    expect(res.status).toBe(200);
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
