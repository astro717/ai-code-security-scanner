/**
 * Integration tests for C# file scanning via POST /scan.
 *
 * Verifies that submitting C# code with filename ending in .cs is correctly
 * routed through the C# scanner (csharp-parser.ts) and returns C#-specific
 * findings (SQL_INJECTION, COMMAND_INJECTION, WEAK_CRYPTO, etc.).
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import net from 'net';

// ── Vulnerable C# fixture ───────────────────────────────────────────────────

const VULNERABLE_CSHARP = `
using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Security.Cryptography;

public class VulnerableService
{
    // SQL injection via string concatenation
    public void GetUser(SqlConnection conn, string userId)
    {
        var cmd = new SqlCommand("SELECT * FROM users WHERE id = " + userId, conn);
        cmd.ExecuteReader();
    }

    // Command injection via Process.Start
    public void RunCommand(string userInput)
    {
        Process.Start("cmd.exe", "/c " + userInput);
    }

    // Weak crypto: MD5
    public byte[] HashData(string data)
    {
        var md5 = MD5.Create();
        return md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(data));
    }

    // Hardcoded secret
    private string apiKey = "sk-proj-abc123xyz456def789ghi012jkl345mno678pqr901stu";

    // Insecure random
    public int GetToken()
    {
        var rng = new Random();
        return rng.Next();
    }
}
`;

const CLEAN_CSHARP = `
public class SafeService
{
    private readonly string _name;

    public SafeService(string name)
    {
        _name = name;
    }

    public string GetName() => _name;
}
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

describe('/scan with C# files', () => {
  test('vulnerable C# code returns findings with filename ending in .cs', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_CSHARP,
      filename: 'VulnerableService.cs',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<{ type: string; severity: string }> };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBeGreaterThan(0);

    const types = new Set(body.findings.map((f) => f.type));

    // The vulnerable fixture should trigger at least these C#-detected types
    expect(types.has('SQL_INJECTION_CS')).toBe(true);
    expect(types.has('WEAK_CRYPTO')).toBe(true);
  });

  test('clean C# code returns zero findings', async () => {
    const res = await post(serverPort, '/scan', {
      code: CLEAN_CSHARP,
      filename: 'SafeService.cs',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBe(0);
  });

  test('C# findings include correct file field', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_CSHARP,
      filename: 'MyApp.cs',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<{ file: string }> };
    expect(body.findings.length).toBeGreaterThan(0);
    for (const f of body.findings) {
      expect(f.file).toBe('MyApp.cs');
    }
  });

  test('response includes summary object', async () => {
    const res = await post(serverPort, '/scan', {
      code: VULNERABLE_CSHARP,
      filename: 'Test.cs',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: unknown[]; summary: { total: number } };
    expect(typeof body.summary).toBe('object');
    expect(body.summary.total).toBeGreaterThan(0);
  });
});

// ── COMMAND_INJECTION_CS detection test ──────────────────────────────────────

describe('/scan with C# — COMMAND_INJECTION_CS detection', () => {
  test('Process.Start() with user input is detected as COMMAND_INJECTION_CS', async () => {
    const cs_fixture = `
using System.Diagnostics;

public class CommandService
{
    public void RunUserCommand(string userInput)
    {
        Process.Start("cmd.exe", "/c " + userInput);
    }
}
`;
    const res = await post(serverPort, '/scan', {
      code: cs_fixture,
      filename: 'CommandService.cs',
    });

    expect(res.statusCode).toBe(200);
    const body = res.body as { findings: Array<{ type: string; severity: string }> };
    expect(Array.isArray(body.findings)).toBe(true);

    const types = new Set(body.findings.map((f) => f.type));
    expect(types.has('COMMAND_INJECTION_CS')).toBe(true);

    const finding = body.findings.find((f) => f.type === 'COMMAND_INJECTION_CS');
    expect(finding).toBeDefined();
    expect(['high', 'critical']).toContain(finding!.severity);
  });
});
