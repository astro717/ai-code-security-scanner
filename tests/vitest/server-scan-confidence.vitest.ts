/**
 * Integration tests for minConfidence filtering on POST /scan.
 *
 * Verifies that the minConfidence query parameter and body field correctly
 * filter out findings below the specified confidence threshold.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import request from 'supertest';
import { app } from '../../src/server';

// Ruby code that produces findings with mixed confidence levels.
// SQL injection via .where interpolation has confidence 0.95.
// html_safe without params context has no explicit confidence (defaults to 1.0).
// rand() usage has no explicit confidence.
const MIXED_CONFIDENCE_CODE = `
class UsersController < ApplicationController
  def search
    User.where("name LIKE '%\#{params[:q]}%'")
  end

  def generate_token
    rand(1000000).to_s
  end
end
`;

describe('POST /scan — minConfidence filtering', () => {
  test('default behavior returns all findings (no minConfidence)', async () => {
    const res = await request(app)
      .post('/scan')
      .send({ code: MIXED_CONFIDENCE_CODE, filename: 'app.rb' });

    expect(res.status).toBe(200);
    expect(res.body.findings.length).toBeGreaterThan(0);
  });

  test('minConfidence=0.9 filters low-confidence findings', async () => {
    const res = await request(app)
      .post('/scan')
      .send({
        code: MIXED_CONFIDENCE_CODE,
        filename: 'app.rb',
        minConfidence: 0.9,
      });

    expect(res.status).toBe(200);
    // All remaining findings should have confidence >= 0.9 (or no confidence field = default 1.0)
    for (const f of res.body.findings) {
      const conf = f.confidence ?? 1.0;
      expect(conf).toBeGreaterThanOrEqual(0.9);
    }
  });

  test('minConfidence=1.0 keeps only findings with full confidence', async () => {
    const res = await request(app)
      .post('/scan')
      .send({
        code: MIXED_CONFIDENCE_CODE,
        filename: 'app.rb',
        minConfidence: 1.0,
      });

    expect(res.status).toBe(200);
    for (const f of res.body.findings) {
      const conf = f.confidence ?? 1.0;
      expect(conf).toBeGreaterThanOrEqual(1.0);
    }
  });

  test('findings without confidence field pass through (treated as 1.0)', async () => {
    // JavaScript code where findings typically have no confidence field
    const jsCode = `const cmd = "rm -rf " + userInput; eval(cmd);`;
    const res = await request(app)
      .post('/scan')
      .send({ code: jsCode, filename: 'test.js', minConfidence: 0.5 });

    expect(res.status).toBe(200);
    // Findings without confidence should still be present
    expect(res.body.findings.length).toBeGreaterThan(0);
  });

  test('invalid minConfidence returns 400', async () => {
    const res = await request(app)
      .post('/scan')
      .send({
        code: 'const x = 1;',
        filename: 'test.js',
        minConfidence: 2.0,
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('minConfidence');
  });

  test('negative minConfidence returns 400', async () => {
    const res = await request(app)
      .post('/scan')
      .send({
        code: 'const x = 1;',
        filename: 'test.js',
        minConfidence: -0.5,
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('minConfidence');
  });

  test('minConfidence via query parameter works', async () => {
    const res = await request(app)
      .post('/scan?minConfidence=0.9')
      .send({ code: MIXED_CONFIDENCE_CODE, filename: 'app.rb' });

    expect(res.status).toBe(200);
    for (const f of res.body.findings) {
      const conf = f.confidence ?? 1.0;
      expect(conf).toBeGreaterThanOrEqual(0.9);
    }
  });
});
