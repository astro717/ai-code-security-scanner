/**
 * Integration tests for Kotlin file scanning via POST /scan.
 *
 * Verifies that submitting Kotlin code with a .kt filename is correctly routed
 * through kotlin-parser.ts and returns Kotlin-specific findings.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import net from 'net';

// ── Vulnerable Kotlin fixture ─────────────────────────────────────────────────
// Triggers: SECRET_HARDCODED, INSECURE_RANDOM, SQL_INJECTION

const VULNERABLE_KOTLIN = `
import android.database.sqlite.SQLiteDatabase
import java.security.SecureRandom

class VulnerableActivity {
    // Hardcoded secret — SECRET_HARDCODED
    val apiKey = "sk-verylongapikey1234567890abcdef"

    // Insecure random — INSECURE_RANDOM
    fun generateToken(): Int = Random().nextInt()

    // SQL injection via Kotlin string interpolation — SQL_INJECTION
    fun getUser(db: SQLiteDatabase, userId: String) {
        db.rawQuery("SELECT * FROM users WHERE id = \${userId}", null)
    }
}
`;

// Clean Kotlin code — no findings expected
const CLEAN_KOTLIN = `
class SafeActivity {
    private val name: String = "safe"
    fun getName(): String = name
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

// ── Server lifecycle ─────────────────────────────────────────────────────────

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
});

afterAll(() => {
  return new Promise<void>((resolve) => {
    if (serverHandle?.listening) {
      serverHandle.close(() => resolve());
    } else {
      resolve();
    }
  });
});

// ── Tests ────────────────────────────────────────────────────────────────────

describe('POST /scan — Kotlin (.kt)', () => {
  test('returns 200 with findings array', async () => {
    const res = await post(serverPort, '/scan', {
      filename: 'VulnerableActivity.kt',
      code: VULNERABLE_KOTLIN,
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('findings');
    expect(Array.isArray((res.body as { findings: unknown[] }).findings)).toBe(true);
  });

  test('detects SECRET_HARDCODED from hardcoded apiKey', async () => {
    const res = await post(serverPort, '/scan', {
      filename: 'VulnerableActivity.kt',
      code: VULNERABLE_KOTLIN,
    });
    const body = res.body as { findings: Array<{ type: string }> };
    const types = body.findings.map((f) => f.type);
    expect(types).toContain('SECRET_HARDCODED');
  });

  test('detects INSECURE_RANDOM from Random() usage', async () => {
    const code = `
fun generateToken(): Int {
    val rng = Random()
    return rng.nextInt()
}
`;
    const res = await post(serverPort, '/scan', {
      filename: 'Tokens.kt',
      code,
    });
    const body = res.body as { findings: Array<{ type: string }> };
    const types = body.findings.map((f) => f.type);
    expect(types).toContain('INSECURE_RANDOM');
  });

  test('detects SQL_INJECTION from rawQuery with string interpolation', async () => {
    const code = `
fun getUser(db: SQLiteDatabase, userId: String) {
    db.rawQuery("SELECT * FROM users WHERE id = \${userId}", null)
}
`;
    const res = await post(serverPort, '/scan', {
      filename: 'UserRepository.kt',
      code,
    });
    const body = res.body as { findings: Array<{ type: string }> };
    const types = body.findings.map((f) => f.type);
    expect(types).toContain('SQL_INJECTION');
  });

  test('returns no findings for clean Kotlin code', async () => {
    const res = await post(serverPort, '/scan', {
      filename: 'SafeActivity.kt',
      code: CLEAN_KOTLIN,
    });
    const body = res.body as { findings: Array<{ type: string }> };
    expect(body.findings).toHaveLength(0);
  });

  test('finding includes type, severity, line, and message fields', async () => {
    const res = await post(serverPort, '/scan', {
      filename: 'VulnerableActivity.kt',
      code: VULNERABLE_KOTLIN,
    });
    const body = res.body as { findings: Array<Record<string, unknown>> };
    expect(body.findings.length).toBeGreaterThan(0);
    const finding = body.findings[0]!;
    expect(typeof finding.type).toBe('string');
    expect(typeof finding.severity).toBe('string');
    expect(typeof finding.line).toBe('number');
    expect(typeof finding.message).toBe('string');
  });

  test('.kts extension is also handled as Kotlin', async () => {
    const code = `val apiKey = "sk-secretapikey1234567890abcdef"`;
    const res = await post(serverPort, '/scan', {
      filename: 'build.gradle.kts',
      code,
    });
    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<{ type: string }> };
    expect(body.findings.map((f) => f.type)).toContain('SECRET_HARDCODED');
  });
});
