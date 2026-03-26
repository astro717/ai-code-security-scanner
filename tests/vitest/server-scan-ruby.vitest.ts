/**
 * Integration tests for Ruby file scanning via POST /scan.
 *
 * Verifies that submitting Ruby code with filename ending in .rb is correctly
 * routed through the Ruby scanner (ruby-parser.ts) and returns Ruby-specific
 * findings (SQL_INJECTION, COMMAND_INJECTION, MASS_ASSIGNMENT, etc.).
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import net from 'net';

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

// ── Helpers ─────────────────────────────────────────────────────────────────

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

// ── Server lifecycle ────────────────────────────────────────────────────────

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

// ── Tests ───────────────────────────────────────────────────────────────────

describe('/scan with Ruby files', () => {
  test('vulnerable Ruby code returns findings with filename ending in .rb', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_RUBY,
      filename: 'users_controller.rb',
    });

    expect(res.statusCode).toBe(200);
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
    const res = await post(serverPort, '/scan', {
      code: CLEAN_RUBY,
      filename: 'safe_service.rb',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBe(0);
  });

  test('Ruby findings include correct file field', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_RUBY,
      filename: 'app.rb',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<{ file: string }> };
    expect(body.findings.length).toBeGreaterThan(0);
    for (const f of body.findings) {
      expect(f.file).toBe('app.rb');
    }
  });

  test('response includes summary object', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_RUBY,
      filename: 'test.rb',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: unknown[]; summary: { total: number } };
    expect(typeof body.summary).toBe('object');
    expect(body.summary.total).toBeGreaterThan(0);
  });
});
