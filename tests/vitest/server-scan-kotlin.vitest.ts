/**
 * Integration tests for Kotlin file scanning via POST /scan.
 *
 * Verifies that submitting Kotlin code with filename ending in .kt is correctly
 * routed through the Kotlin scanner (kotlin-parser.ts) and returns Kotlin-specific
 * findings (SECRET_HARDCODED, INSECURE_RANDOM, SQL_INJECTION).
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import net from 'net';

// ── Vulnerable Kotlin fixture ─────────────────────────────────────────────────
// Triggers: SECRET_HARDCODED, INSECURE_RANDOM, SQL_INJECTION

const VULNERABLE_KOTLIN = `
package com.example.app

import java.util.Random
import android.database.sqlite.SQLiteDatabase
import java.security.MessageDigest

class VulnerableRepository(private val db: SQLiteDatabase) {

    // Hardcoded API key — should use Android Keystore
    val apiKey = "sk-liveabcdef1234567890secret"

    // Insecure random for generating session tokens
    fun generateSessionId(): Int {
        val rng = Random()
        return rng.nextInt()
    }

    // SQL injection via string concatenation in rawQuery
    fun getOrdersByUser(userId: String): android.database.Cursor {
        return db.rawQuery("SELECT * FROM orders WHERE user_id = " + userId, null)
    }

    // Hardcoded secret token
    val secretToken = "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"
}
`;

// Clean Kotlin code — no findings expected
const CLEAN_KOTLIN = `
package com.example.app

import java.security.SecureRandom
import android.database.sqlite.SQLiteDatabase

class SafeRepository(private val db: SQLiteDatabase) {

    fun generateToken(): ByteArray {
        val sr = SecureRandom()
        val bytes = ByteArray(32)
        sr.nextBytes(bytes)
        return bytes
    }

    fun getUserById(userId: String): android.database.Cursor {
        return db.rawQuery("SELECT * FROM users WHERE id = ?", arrayOf(userId))
    }
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

describe('/scan with Kotlin files (.kt)', () => {
  test('vulnerable Kotlin code returns findings with filename ending in .kt', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_KOTLIN,
      filename: 'VulnerableRepository.kt',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<{ type: string; severity: string; message: string }> };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBeGreaterThan(0);

    const types = new Set(body.findings.map((f) => f.type));

    // The fixture must trigger these Kotlin-specific findings
    expect(types.has('SECRET_HARDCODED')).toBe(true);
    expect(types.has('INSECURE_RANDOM')).toBe(true);
    expect(types.has('SQL_INJECTION')).toBe(true);
  });

  test('clean Kotlin code returns zero findings', async () => {
    const res = await post(serverPort, '/scan', {
      code: CLEAN_KOTLIN,
      filename: 'SafeRepository.kt',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBe(0);
  });

  test('.kts extension is also routed to the Kotlin scanner', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_KOTLIN,
      filename: 'build.kts',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBeGreaterThan(0);
  });

  test('findings include correct filename in file field', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_KOTLIN,
      filename: 'MainActivity.kt',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<{ file: string }> };
    expect(body.findings.length).toBeGreaterThan(0);
    for (const f of body.findings) {
      expect(f.file).toBe('MainActivity.kt');
    }
  });

  test('response includes summary with correct total count', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_KOTLIN,
      filename: 'VulnerableRepository.kt',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: unknown[]; summary: { total: number } };
    expect(typeof body.summary).toBe('object');
    expect(body.summary.total).toBe(body.findings.length);
    expect(body.summary.total).toBeGreaterThan(0);
  });

  test('all Kotlin findings have required shape (type, severity, line, message, file)', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_KOTLIN,
      filename: 'VulnerableRepository.kt',
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
      expect(f.file).toBe('VulnerableRepository.kt');
    }
  });
});
