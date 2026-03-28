/**
 * Integration tests for Kotlin file scanning via POST /scan.
 *
 * Verifies that submitting Kotlin code with filename ending in .kt is correctly
 * routed through the Kotlin scanner (kotlin-parser.ts) and returns Kotlin-specific
 * findings. This covers the server.ts routing branch for ext === '.kt' || ext === '.kts'.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import net from 'net';

// ── Vulnerable Kotlin fixture ─────────────────────────────────────────────────

const VULNERABLE_KOTLIN = `
package com.example

import android.content.SharedPreferences
import android.webkit.WebView
import java.util.Random
import java.security.MessageDigest

// Hardcoded API key
val API_KEY = "sk-secret-api-key-1234567890abcdef"

// Insecure random for token generation
fun generateToken(): Int {
    val rng = Random()
    return rng.nextInt()
}

// Weak crypto: MD5
fun hashPassword(pwd: String): ByteArray {
    val md = MessageDigest.getInstance("MD5")
    return md.digest(pwd.toByteArray())
}

// Insecure SharedPreferences — storing sensitive data unencrypted
fun saveToken(prefs: SharedPreferences, token: String) {
    prefs.edit().putString("auth_token", token).apply()
}

// SQL injection via rawQuery with string concatenation
fun getUser(db: android.database.sqlite.SQLiteDatabase, userId: String): android.database.Cursor {
    return db.rawQuery("SELECT * FROM users WHERE id = " + userId, null)
}
`;

// Clean Kotlin code — no findings expected
const CLEAN_KOTLIN = `
package com.example

import java.security.MessageDigest
import java.security.SecureRandom

class SafeService {
    fun hashData(data: String): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(data.toByteArray())
    }

    fun generateToken(): String {
        val rng = SecureRandom()
        val bytes = ByteArray(32)
        rng.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
`;

// ── Helpers ──────────────────────────────────────────────────────────────────

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

describe('/scan with Kotlin files (.kt)', () => {
  test('vulnerable Kotlin code returns findings with filename ending in .kt', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_KOTLIN,
      filename: 'MainActivity.kt',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<{ type: string; severity: string }> };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBeGreaterThan(0);

    const types = new Set(body.findings.map((f) => f.type));

    // The fixture contains hardcoded secret, insecure random, and SQL injection
    expect(types.has('SECRET_HARDCODED')).toBe(true);
    expect(types.has('INSECURE_RANDOM')).toBe(true);
    expect(types.has('SQL_INJECTION')).toBe(true);
  });

  test('clean Kotlin code returns zero findings', async () => {
    const res = await post(serverPort, '/scan', {
      code: CLEAN_KOTLIN,
      filename: 'SafeService.kt',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBe(0);
  });

  test('Kotlin findings include correct file field matching submitted filename', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_KOTLIN,
      filename: 'App.kt',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<{ file: string }> };
    expect(body.findings.length).toBeGreaterThan(0);
    for (const f of body.findings) {
      expect(f.file).toBe('App.kt');
    }
  });

  test('response includes summary object with total count', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_KOTLIN,
      filename: 'test.kt',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: unknown[]; summary: { total: number } };
    expect(typeof body.summary).toBe('object');
    expect(body.summary.total).toBeGreaterThan(0);
    expect(body.summary.total).toBe(body.findings.length);
  });

  test('Kotlin routing works for .kts extension too', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_KOTLIN,
      filename: 'build.kts',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
    // .kts should also return findings (uses same kotlin parser)
    expect(body.findings.length).toBeGreaterThan(0);
  });

  test('findings have required shape (type, severity, line, message)', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_KOTLIN,
      filename: 'check.kt',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<Record<string, unknown>> };
    expect(body.findings.length).toBeGreaterThan(0);

    const validSeverities = new Set(['critical', 'high', 'medium', 'low']);
    for (const f of body.findings) {
      expect(typeof f['type']).toBe('string');
      expect(typeof f['severity']).toBe('string');
      expect(validSeverities.has(f['severity'] as string)).toBe(true);
      expect(typeof f['line']).toBe('number');
      expect((f['line'] as number)).toBeGreaterThan(0);
      expect(typeof f['message']).toBe('string');
    }
  });

  test('does NOT return 400 Parse error for valid Kotlin code', async () => {
    // Regression: before the .kt routing fix, /scan returned 400 Parse error
    // for all Kotlin submissions because they fell through to the TS/JS AST parser.
    const res = await post(serverPort, '/scan', {
      code: 'fun main() { println("Hello, World!") }',
      filename: 'hello.kt',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { error?: string };
    expect(body.error).toBeUndefined();
  });

  test('INSECURE_SHARED_PREFS is detected when SharedPreferences stores auth data', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_KOTLIN,
      filename: 'prefs.kt',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<{ type: string }> };
    const types = new Set(body.findings.map((f) => f.type));
    // The fixture has prefs.edit().putString("auth_token", ...) — should flag INSECURE_SHARED_PREFS
    expect(types.has('INSECURE_SHARED_PREFS')).toBe(true);
  });
});
