/**
 * Integration tests for the ignoreTypes field on POST /scan.
 *
 * The ignoreTypes array lets callers suppress specific finding types from the
 * response, mirroring the CLI --ignore-type flag. These tests assert:
 *   1. ignoreTypes filters out matching findings from the response.
 *   2. Non-string elements in the array are silently skipped (graceful degradation).
 *   3. An empty ignoreTypes array has no effect on findings.
 *   4. All-caps normalisation works: lowercase input matches uppercase type names.
 *   5. Multiple types can be suppressed in a single request.
 *   6. Summary counts reflect the filtered (not raw) finding set.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import request from 'supertest';
import { app } from '../../src/server';

// ── Code fixtures ─────────────────────────────────────────────────────────────

/** Code that reliably triggers SECRET_HARDCODED and WEAK_CRYPTO findings. */
const CODE_WITH_SECRET_AND_WEAK_CRYPTO = `
const apiKey = 'sk-proj-abc123xyz456def789ghi012jkl345mno678pqr901stu';
import crypto from 'crypto';
const hash = crypto.createHash('md5').update(data).digest('hex');
`;

/** Code that reliably triggers SQL_INJECTION. */
const CODE_WITH_SQL_INJECTION = `
function getUser(email: string, db: any) {
  return db.query('SELECT * FROM users WHERE email = ' + email);
}
`;

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('/scan ignoreTypes filtering', () => {
  test('ignoreTypes filters matching findings from the response', async () => {
    // First confirm the code DOES produce SECRET_HARDCODED without ignoreTypes
    const baseRes = await request(app).post('/scan').send({
      code: CODE_WITH_SECRET_AND_WEAK_CRYPTO,
      filename: 'secrets.ts',
    });
    expect(baseRes.statusCode).toBe(200);
    const baseBody = baseRes.body as { findings?: Array<{ type: string }> };
    const hasSecret = (baseBody.findings ?? []).some((f) => f.type === 'SECRET_HARDCODED');
    expect(hasSecret).toBe(true);

    // Now suppress SECRET_HARDCODED — it must not appear in the filtered response
    const filteredRes = await request(app).post('/scan').send({
      code: CODE_WITH_SECRET_AND_WEAK_CRYPTO,
      filename: 'secrets.ts',
      ignoreTypes: ['SECRET_HARDCODED'],
    });
    expect(filteredRes.statusCode).toBe(200);
    const filteredBody = filteredRes.body as { findings?: Array<{ type: string }> };
    const stillHasSecret = (filteredBody.findings ?? []).some((f) => f.type === 'SECRET_HARDCODED');
    expect(stillHasSecret).toBe(false);
  });

  test('non-string elements in ignoreTypes are silently skipped', async () => {
    // A mix of valid strings and non-string values — the endpoint must not error
    // and must still apply the valid string suppression.
    const res = await request(app).post('/scan').send({
      code: CODE_WITH_SQL_INJECTION,
      filename: 'sql.ts',
      ignoreTypes: [42, null, true, 'SQL_INJECTION', { type: 'EVIL' }],
    });
    expect(res.status).toBe(200);
    const body = res.body as { findings?: Array<{ type: string }> };
    // SQL_INJECTION must be suppressed (the valid string entry)
    const hasSql = (body.findings ?? []).some((f) => f.type === 'SQL_INJECTION');
    expect(hasSql).toBe(false);
  });

  test('empty ignoreTypes array has no effect on findings', async () => {
    const baseRes = await request(app).post('/scan').send({
      code: CODE_WITH_SQL_INJECTION,
      filename: 'sql-base.ts',
    });
    const filteredRes = await request(app).post('/scan').send({
      code: CODE_WITH_SQL_INJECTION,
      filename: 'sql-empty-ignore.ts',
      ignoreTypes: [],
    });

    expect(baseRes.statusCode).toBe(200);
    expect(filteredRes.statusCode).toBe(200);

    const baseBody = baseRes.body as { findings?: unknown[] };
    const filteredBody = filteredRes.body as { findings?: unknown[] };

    // Findings count must be identical when ignoreTypes is empty
    expect((filteredBody.findings ?? []).length).toBe((baseBody.findings ?? []).length);
  });

  test('case-insensitive: lowercase ignoreTypes matches uppercase type names', async () => {
    // The implementation uppercases entries before comparing — test lowercase input
    const res = await request(app).post('/scan').send({
      code: CODE_WITH_SQL_INJECTION,
      filename: 'sql-lower.ts',
      ignoreTypes: ['sql_injection'],
    });
    expect(res.status).toBe(200);
    const body = res.body as { findings?: Array<{ type: string }> };
    const hasSql = (body.findings ?? []).some((f) => f.type === 'SQL_INJECTION');
    expect(hasSql).toBe(false);
  });

  test('multiple types can be suppressed in a single request', async () => {
    // Suppress both SECRET_HARDCODED and WEAK_CRYPTO simultaneously
    const res = await request(app).post('/scan').send({
      code: CODE_WITH_SECRET_AND_WEAK_CRYPTO,
      filename: 'multi-suppress.ts',
      ignoreTypes: ['SECRET_HARDCODED', 'WEAK_CRYPTO'],
    });
    expect(res.status).toBe(200);
    const body = res.body as { findings?: Array<{ type: string }> };
    const findings = body.findings ?? [];
    const hasSecret = findings.some((f) => f.type === 'SECRET_HARDCODED');
    const hasWeakCrypto = findings.some((f) => f.type === 'WEAK_CRYPTO');
    expect(hasSecret).toBe(false);
    expect(hasWeakCrypto).toBe(false);
  });

  test('summary counts reflect the filtered finding set, not the raw count', async () => {
    // Baseline: scan without filter to get raw summary.total
    const baseRes = await request(app).post('/scan').send({
      code: CODE_WITH_SECRET_AND_WEAK_CRYPTO,
      filename: 'summary-base.ts',
    });
    expect(baseRes.statusCode).toBe(200);
    const baseBody = baseRes.body as { findings?: unknown[]; summary?: { total?: number } };
    const rawTotal = baseBody.summary?.total ?? 0;

    // Filtered: suppress SECRET_HARDCODED
    const filteredRes = await request(app).post('/scan').send({
      code: CODE_WITH_SECRET_AND_WEAK_CRYPTO,
      filename: 'summary-filtered.ts',
      ignoreTypes: ['SECRET_HARDCODED'],
    });
    expect(filteredRes.statusCode).toBe(200);
    const filteredBody = filteredRes.body as {
      findings?: unknown[];
      summary?: { total?: number };
    };

    const filteredCount = (filteredBody.findings ?? []).length;
    // summary.total must equal the filtered findings array length
    expect(filteredBody.summary?.total).toBe(filteredCount);
    // And the filtered total must be strictly less than the raw total
    // (we know SECRET_HARDCODED is present in the raw output)
    expect(filteredCount).toBeLessThan(rawTotal);
  });

  test('rejects unknown ignoreTypes with 400 and lists valid types', async () => {
    const res = await request(app).post('/scan').send({
      code: CODE_WITH_SQL_INJECTION,
      filename: 'unknown-type.ts',
      ignoreTypes: ['TOTALLY_FAKE_TYPE'],
    });
    expect(res.status).toBe(400);
    const body = res.body as { error?: string };
    expect(body.error).toContain('Unknown ignoreTypes');
    expect(body.error).toContain('TOTALLY_FAKE_TYPE');
  });

  test('rejects a mix of valid and unknown ignoreTypes with 400', async () => {
    const res = await request(app).post('/scan').send({
      code: CODE_WITH_SQL_INJECTION,
      filename: 'mixed-type.ts',
      ignoreTypes: ['SQL_INJECTION', 'NOT_A_REAL_TYPE'],
    });
    expect(res.status).toBe(400);
    const body = res.body as { error?: string };
    expect(body.error).toContain('NOT_A_REAL_TYPE');
  });
});
