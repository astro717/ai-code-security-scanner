/**
 * Integration tests for Rust file scanning via POST /scan.
 *
 * Verifies that submitting Rust code with filename ending in .rs is correctly
 * routed through the Rust scanner (rust-parser.ts) and returns Rust-specific
 * findings (BUFFER_OVERFLOW, COMMAND_INJECTION, WEAK_CRYPTO, SECRET_HARDCODED,
 * INSECURE_RANDOM).
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import net from 'net';

// ── Vulnerable Rust fixture ───────────────────────────────────────────────────
// Triggers: BUFFER_OVERFLOW, COMMAND_INJECTION, WEAK_CRYPTO, SECRET_HARDCODED, INSECURE_RANDOM

const VULNERABLE_RUST = `
use std::process::Command;

// Hardcoded API key — should be read from env
let api_key = "sk_live_abcdef1234567890abcdef1234";

// Insecure random for session token generation
let token: u64 = rand::random();

// Weak crypto — MD5 should not be used
let digest = md5::compute(b"hello");

// Buffer overflow risk — unsafe raw pointer dereference
unsafe {
    let x = *ptr;
}

// Command injection — passing user-controlled variable to Command::new
let output = Command::new(user_cmd).output().unwrap();
`;

// Clean Rust code — no findings expected
const CLEAN_RUST = `
use std::collections::HashMap;

fn greet(name: &str) -> String {
    format!("Hello, {}!", name)
}

fn add(a: i32, b: i32) -> i32 {
    a + b
}

fn main() {
    let mut scores: HashMap<&str, i32> = HashMap::new();
    scores.insert("Alice", 100);
    scores.insert("Bob", 95);
    println!("{:?}", scores);
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

describe('/scan with Rust files (.rs)', () => {
  test('vulnerable Rust code returns findings with filename ending in .rs', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_RUST,
      filename: 'vulnerable.rs',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<{ type: string; severity: string; message: string }> };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBeGreaterThan(0);

    const types = new Set(body.findings.map((f) => f.type));

    // The fixture must trigger these Rust-specific finding types
    expect(types.has('BUFFER_OVERFLOW')).toBe(true);
    expect(types.has('COMMAND_INJECTION')).toBe(true);
    expect(types.has('WEAK_CRYPTO')).toBe(true);
    expect(types.has('SECRET_HARDCODED')).toBe(true);
    expect(types.has('INSECURE_RANDOM')).toBe(true);
  });

  test('clean Rust code returns zero findings', async () => {
    const res = await post(serverPort, '/scan', {
      code: CLEAN_RUST,
      filename: 'safe_lib.rs',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBe(0);
  });

  test('findings include correct filename in file field', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_RUST,
      filename: 'main.rs',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<{ file: string }> };
    expect(body.findings.length).toBeGreaterThan(0);
    for (const f of body.findings) {
      expect(f.file).toBe('main.rs');
    }
  });

  test('response includes summary with correct total count', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_RUST,
      filename: 'vulnerable.rs',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: unknown[]; summary: { total: number } };
    expect(typeof body.summary).toBe('object');
    expect(body.summary.total).toBe(body.findings.length);
    expect(body.summary.total).toBeGreaterThan(0);
  });

  test('all Rust findings have required shape (type, severity, line, message, file)', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_RUST,
      filename: 'vulnerable.rs',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<Record<string, unknown>> };
    for (const f of body.findings) {
      expect(typeof f.type).toBe('string');
      expect(typeof f.severity).toBe('string');
      expect(['critical', 'high', 'medium', 'low']).toContain(f.severity);
      expect(typeof f.line).toBe('number');
      expect(f.line).toBeGreaterThan(0);
      expect(typeof f.message).toBe('string');
      expect(f.message.length).toBeGreaterThan(0);
      expect(f.file).toBe('vulnerable.rs');
    }
  });
});
