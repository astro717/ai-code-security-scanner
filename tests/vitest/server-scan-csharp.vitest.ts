/**
 * Integration tests for C# file scanning via POST /scan.
 *
 * Verifies that submitting C# code with filename ending in .cs is correctly
 * routed through the C# scanner (csharp-parser.ts) and returns C#-specific
 * findings (SQL_INJECTION, COMMAND_INJECTION, WEAK_CRYPTO, etc.).
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import request from 'supertest';
import { app } from '../../src/server';

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

// ── Tests ───────────────────────────────────────────────────────────────────

describe('/scan with C# files', () => {
  test('vulnerable C# code returns findings with filename ending in .cs', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_CSHARP,
      filename: 'VulnerableService.cs',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ type: string; severity: string }> };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBeGreaterThan(0);

    const types = new Set(body.findings.map((f) => f.type));

    // The vulnerable fixture should trigger at least these C#-detected types
    expect(types.has('SQL_INJECTION_CS')).toBe(true);
    expect(types.has('WEAK_CRYPTO')).toBe(true);
  });

  test('clean C# code returns zero findings', async () => {
    const res = await request(app).post('/scan').send({
      code: CLEAN_CSHARP,
      filename: 'SafeService.cs',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBe(0);
  });

  test('C# findings include correct file field', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_CSHARP,
      filename: 'MyApp.cs',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ file: string }> };
    expect(body.findings.length).toBeGreaterThan(0);
    for (const f of body.findings) {
      expect(f.file).toBe('MyApp.cs');
    }
  });

  test('response includes summary object', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_CSHARP,
      filename: 'Test.cs',
    });

    expect(res.status).toBe(200);
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
    const res = await request(app).post('/scan').send({
      code: cs_fixture,
      filename: 'CommandService.cs',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ type: string; severity: string }> };
    expect(Array.isArray(body.findings)).toBe(true);

    const types = new Set(body.findings.map((f) => f.type));
    expect(types.has('COMMAND_INJECTION_CS')).toBe(true);

    const finding = body.findings.find((f) => f.type === 'COMMAND_INJECTION_CS');
    expect(finding).toBeDefined();
    expect(['high', 'critical']).toContain(finding!.severity);
  });
});
