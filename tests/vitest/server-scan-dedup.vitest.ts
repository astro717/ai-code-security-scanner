/**
 * Integration tests for cross-detector finding deduplication at /scan level.
 *
 * When multiple detectors produce findings for the same (file, line, type),
 * the /scan endpoint must return only one finding per unique key so that
 * severity counts in the summary reflect the actual number of distinct issues.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import request from 'supertest';
import { app } from '../../src/server';

// ── Deduplication tests ───────────────────────────────────────────────────────

describe('/scan cross-detector finding deduplication', () => {
  test('no duplicate (file, line, type) tuples in the findings array', async () => {
    // vulnerable.ts exercises many detectors simultaneously — an ideal candidate
    // for catching cross-detector duplicates in a realistic scan.
    const fs = await import('fs');
    const path = await import('path');
    const fixturePath = path.join(__dirname, '..', 'fixtures', 'vulnerable.ts');
    const code = fs.readFileSync(fixturePath, 'utf8');

    const res = await request(app).post('/scan').send({ code, filename: 'vulnerable.ts' });
    expect(res.status).toBe(200);

    const body = res.body as { findings?: Array<{ file: string; line: number; type: string }> };
    expect(Array.isArray(body.findings)).toBe(true);

    const keys = (body.findings ?? []).map((f) => `${f.file}:${f.line}:${f.type}`);
    const uniqueKeys = new Set(keys);

    expect(keys.length).toBe(uniqueKeys.size);
  });

  test('synthetic duplicate: code that could trigger overlapping detectors returns each type once', async () => {
    // A string literal that looks like a hardcoded AWS secret key — only the
    // secrets detector should fire, and only once.
    const code = `const key = 'AKIAIOSFODNN7EXAMPLE'; // AWS access key`;

    const res = await request(app).post('/scan').send({ code, filename: 'aws.ts' });
    expect(res.status).toBe(200);

    const body = res.body as { findings?: Array<{ type: string; line: number }> };
    const findings = body.findings ?? [];

    const keys = findings.map((f) => `${f.line}:${f.type}`);
    const uniqueKeys = new Set(keys);

    // There must be no duplicate (line, type) pairs
    expect(keys.length).toBe(uniqueKeys.size);
  });

  test('summary total matches the deduplicated findings count', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const fixturePath = path.join(__dirname, '..', 'fixtures', 'vulnerable.ts');
    const code = fs.readFileSync(fixturePath, 'utf8');

    const res = await request(app).post('/scan').send({ code, filename: 'dup-summary.ts' });
    expect(res.status).toBe(200);

    const body = res.body as {
      findings?: unknown[];
      summary?: { total?: number };
    };

    const findingsCount = (body.findings ?? []).length;
    // summary.total must equal the length of the findings array (no hidden dupes)
    expect(body.summary?.total).toBe(findingsCount);
  });

  test('clean code with no findings produces an empty findings array', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const fixturePath = path.join(__dirname, '..', 'fixtures', 'clean.ts');
    const code = fs.readFileSync(fixturePath, 'utf8');

    const res = await request(app).post('/scan').send({ code, filename: 'clean.ts' });
    expect(res.status).toBe(200);

    const body = res.body as { findings?: unknown[]; summary?: { total?: number } };
    expect(body.findings?.length).toBe(0);
    expect(body.summary?.total).toBe(0);
  });
});
