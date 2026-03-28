/**
 * Integration tests for Python file scanning via POST /scan.
 *
 * Verifies that submitting Python code with filename ending in .py is correctly
 * routed through the Python scanner (python-parser.ts) and returns Python-specific
 * findings.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import net from 'net';

// ── Vulnerable Python fixture ────────────────────────────────────────────────
const VULNERABLE_PYTHON = `
import os
import subprocess
import hashlib
import pickle
import sqlite3

# SQL injection via string formatting
def get_user(conn, user_id):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()

# Command injection via os.system
def run_command(user_input):
    os.system("echo " + user_input)

# Shell injection via subprocess with shell=True
def run_shell(cmd):
    subprocess.call(cmd, shell=True)

# Weak crypto: MD5
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# Unsafe deserialization via pickle
def load_data(data):
    return pickle.loads(data)

# Hardcoded secret
API_KEY = "sk-secret-1234567890abcdef"

# Insecure assert for security check
def check_admin(user):
    assert user.is_admin, "Not admin"
`;

// Clean Python code — no findings expected
const CLEAN_PYTHON = `
import hashlib
import secrets

class SafeService:
    def __init__(self, name):
        self.name = name

    def get_name(self):
        return self.name

    def hash_data(self, data):
        return hashlib.sha256(data.encode()).hexdigest()

    def generate_token(self):
        return secrets.token_hex(32)
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

describe('/scan with Python files', () => {
  test('vulnerable Python code returns findings with filename ending in .py', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_PYTHON,
      filename: 'vulnerable.py',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<{ type: string; severity: string }> };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBeGreaterThan(0);

    const types = new Set(body.findings.map((f) => f.type));

    expect(types.has('SQL_INJECTION')).toBe(true);
    expect(types.has('COMMAND_INJECTION')).toBe(true);
    expect(types.has('WEAK_CRYPTO')).toBe(true);
    expect(types.has('UNSAFE_DESERIALIZATION')).toBe(true);
    expect(types.has('SECRET_HARDCODED')).toBe(true);
  });

  test('clean Python code returns zero findings', async () => {
    const res = await post(serverPort, '/scan', {
      code: CLEAN_PYTHON,
      filename: 'safe.py',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBe(0);
  });

  test('Python findings include correct file field', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_PYTHON,
      filename: 'app.py',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<{ file: string }> };
    expect(body.findings.length).toBeGreaterThan(0);
    for (const f of body.findings) {
      expect(f.file).toBe('app.py');
    }
  });

  test('response includes summary object', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_PYTHON,
      filename: 'test.py',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: unknown[]; summary: { total: number } };
    expect(typeof body.summary).toBe('object');
    expect(body.summary.total).toBeGreaterThan(0);
  });
});

// ── SSTI detection test ───────────────────────────────────────────────────────

const SSTI_PYTHON = `
from flask import render_template_string, request

def render_page():
    template = request.args.get('template', '')
    return render_template_string(template)
`;

describe('/scan with Python — SSTI detection', () => {
  test('render_template_string() call is detected as SSTI with high severity', async () => {
    const res = await post(serverPort, '/scan', {
      code: SSTI_PYTHON,
      filename: 'views.py',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<{ type: string; severity: string }> };
    expect(Array.isArray(body.findings)).toBe(true);

    const types = new Set(body.findings.map((f) => f.type));
    expect(types.has('SSTI')).toBe(true);

    const ssti = body.findings.find((f) => f.type === 'SSTI');
    expect(ssti).toBeDefined();
    expect(ssti!.severity).toBe('high');
  });
});
