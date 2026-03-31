/**
 * Unit tests for C# N+1 stateful detector (brace-depth tracking in foreach/for loops).
 *
 * Covers: foreach containing DbContext.Find, nested braces, and clean code
 * that should NOT trigger PERFORMANCE_N_PLUS_ONE.
 */

import { describe, test, expect } from 'vitest';
import { parseCSharpCode, scanCSharp } from '../../src/scanner/csharp-parser';

function scan(code: string) {
  return scanCSharp(parseCSharpCode(code, 'test.cs'));
}

function n1Findings(code: string) {
  return scan(code).filter((f) => f.type === 'PERFORMANCE_N_PLUS_ONE');
}

// ── foreach with EF Core calls ──────────────────────────────────────────────

describe('C# N+1 stateful detector — foreach loops', () => {
  test('flags context.Find inside foreach', () => {
    const code = `
foreach (var userId in userIds)
{
    var user = context.Users.Find(userId);
    Console.WriteLine(user.Name);
}
`;
    expect(n1Findings(code).length).toBeGreaterThan(0);
  });

  test('flags _context.Where inside foreach', () => {
    const code = `
foreach (var order in orders)
{
    var items = _context.Items.Where(i => i.OrderId == order.Id).ToList();
}
`;
    expect(n1Findings(code).length).toBeGreaterThan(0);
  });

  test('flags FirstOrDefaultAsync inside for loop', () => {
    const code = `
for (int i = 0; i < ids.Length; i++)
{
    var item = _context.Products.FirstOrDefaultAsync(p => p.Id == ids[i]);
}
`;
    expect(n1Findings(code).length).toBeGreaterThan(0);
  });

  test('flags ExecuteReader inside foreach', () => {
    const code = `
foreach (var id in ids)
{
    var reader = cmd.ExecuteReader();
}
`;
    expect(n1Findings(code).length).toBeGreaterThan(0);
  });
});

// ── Clean code — should NOT trigger ─────────────────────────────────────────

describe('C# N+1 stateful detector — negative cases', () => {
  test('does not flag query before foreach', () => {
    const code = `
var users = context.Users.Where(u => u.Active).ToList();
foreach (var user in users)
{
    Console.WriteLine(user.Name);
}
`;
    expect(n1Findings(code).length).toBe(0);
  });

  test('does not flag query after foreach closes', () => {
    const code = `
foreach (var id in ids)
{
    Console.WriteLine(id);
}
var user = context.Users.Find(1);
`;
    expect(n1Findings(code).length).toBe(0);
  });

  test('does not flag non-DB calls inside foreach', () => {
    const code = `
foreach (var item in items)
{
    item.Process();
    Console.WriteLine(item.Name);
}
`;
    expect(n1Findings(code).length).toBe(0);
  });
});

// ── Edge cases with nested braces ───────────────────────────────────────────

describe('C# N+1 stateful detector — nested braces', () => {
  test('handles nested if inside foreach correctly', () => {
    const code = `
foreach (var userId in userIds)
{
    if (userId > 0)
    {
        var user = context.Users.Find(userId);
    }
}
`;
    expect(n1Findings(code).length).toBeGreaterThan(0);
  });

  test('resets state after foreach closes despite nested braces', () => {
    const code = `
foreach (var id in ids)
{
    if (id > 0)
    {
        Console.WriteLine(id);
    }
}
var result = context.Users.Find(1);
`;
    expect(n1Findings(code).length).toBe(0);
  });
});

// ── Finding metadata ────────────────────────────────────────────────────────

describe('C# N+1 finding metadata', () => {
  test('severity is low', () => {
    const code = `
foreach (var id in ids)
{
    var u = context.Users.Find(id);
}
`;
    const findings = n1Findings(code);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.severity).toBe('low');
  });

  test('includes file reference', () => {
    const result = scanCSharp(parseCSharpCode(`
foreach (var id in ids)
{
    var u = _context.Users.Find(id);
}
`, 'Controllers/UserController.cs'));
    const n1 = result.filter((f) => f.type === 'PERFORMANCE_N_PLUS_ONE');
    expect(n1.length).toBeGreaterThan(0);
    expect(n1[0]!.file).toBe('Controllers/UserController.cs');
  });
});
