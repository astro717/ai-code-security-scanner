/**
 * Integration tests for Ruby file scanning via POST /scan.
 *
 * Verifies that submitting Ruby code with filename ending in .rb is correctly
 * routed through the Ruby scanner (ruby-parser.ts) and returns Ruby-specific
 * findings (SQL_INJECTION, COMMAND_INJECTION, MASS_ASSIGNMENT, etc.).
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import request from 'supertest';
import { app } from '../../src/server';

// ── Vulnerable Ruby fixture ─────────────────────────────────────────────────

const VULNERABLE_RUBY = `
require 'digest'

class UsersController < ApplicationController
  # SQL injection via string interpolation
  def search
    query = params[:q]
    User.where("name LIKE '%#{query}%'")
  end

  # Command injection via backtick execution
  def ping
    host = params[:host]
    result = \`ping -c 1 #{host}\`
    render plain: result
  end

  # Mass assignment via permit all
  def create
    user = User.new(params.require(:user).permit!)
    user.save
  end

  # Weak crypto: MD5
  def hash_password(password)
    Digest::MD5.hexdigest(password)
  end

  # Eval injection
  def calculate
    expression = params[:expr]
    eval(expression)
  end

  # Open redirect
  def login
    redirect_to params[:return_url]
  end

  # Hardcoded secret
  API_KEY = "sk-proj-abc123xyz456def789ghi012jkl345mno678pqr901stu"
end
`;

const CLEAN_RUBY = `
class SafeService
  def initialize(name)
    @name = name
  end

  def greeting
    "Hello, #{@name}"
  end
end
`;

// ── Tests ───────────────────────────────────────────────────────────────────

describe('/scan with Ruby files', () => {
  test('vulnerable Ruby code returns findings with filename ending in .rb', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_RUBY,
      filename: 'users_controller.rb',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ type: string; severity: string }> };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBeGreaterThan(0);

    const types = new Set(body.findings.map((f) => f.type));

    // The vulnerable fixture should trigger at least these Ruby-detected types
    expect(types.has('SQL_INJECTION')).toBe(true);
    expect(types.has('COMMAND_INJECTION')).toBe(true);
    expect(types.has('WEAK_CRYPTO')).toBe(true);
  });

  test('clean Ruby code returns zero findings', async () => {
    const res = await request(app).post('/scan').send({
      code: CLEAN_RUBY,
      filename: 'safe_service.rb',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBe(0);
  });

  test('Ruby findings include correct file field', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_RUBY,
      filename: 'app.rb',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ file: string }> };
    expect(body.findings.length).toBeGreaterThan(0);
    for (const f of body.findings) {
      expect(f.file).toBe('app.rb');
    }
  });

  test('response includes summary object', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_RUBY,
      filename: 'test.rb',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: unknown[]; summary: { total: number } };
    expect(typeof body.summary).toBe('object');
    expect(body.summary.total).toBeGreaterThan(0);
  });
});
