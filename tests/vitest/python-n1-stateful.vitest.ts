/**
 * Unit tests for Python N+1 stateful detector (indentation-based loop tracking).
 *
 * Tests the stateful iteration-block + ORM/DB query detector in python-parser.ts.
 * Covers: for-loop with Django ORM, while-loop with SQLAlchemy, nested loops,
 * cursor.execute inside loops, and clean code that should NOT trigger.
 */

import { describe, test, expect } from 'vitest';
import { parsePythonCode, scanPython } from '../../src/scanner/python-parser';

function scan(code: string) {
  return scanPython(parsePythonCode(code, 'test.py'));
}

function n1Findings(code: string) {
  return scan(code).filter((f) => f.type === 'PERFORMANCE_N_PLUS_ONE');
}

// ── For-loop with Django ORM ────────────────────────────────────────────────

describe('Python N+1 — for-loop with Django ORM', () => {
  test('flags objects.get() inside for loop', () => {
    const code = `
for user in users:
    profile = Profile.objects.get(user_id=user.id)
`;
    expect(n1Findings(code).length).toBeGreaterThan(0);
  });

  test('flags objects.filter() inside for loop', () => {
    const code = `
for order in orders:
    items = Item.objects.filter(order_id=order.id)
`;
    expect(n1Findings(code).length).toBeGreaterThan(0);
  });

  test('flags objects.first() inside for loop', () => {
    const code = `
for user in users:
    latest = Order.objects.first()
`;
    expect(n1Findings(code).length).toBeGreaterThan(0);
  });

  test('flags objects.all() inside for loop', () => {
    const code = `
for item in cart_items:
    related = Product.objects.all()
`;
    expect(n1Findings(code).length).toBeGreaterThan(0);
  });

  test('flags objects.count() inside for loop', () => {
    const code = `
for category in categories:
    total = Product.objects.count()
`;
    expect(n1Findings(code).length).toBeGreaterThan(0);
  });
});

// ── While-loop with SQLAlchemy ──────────────────────────────────────────────

describe('Python N+1 — while-loop with SQLAlchemy', () => {
  test('flags query.filter() inside while loop', () => {
    const code = `
while has_more:
    result = session.query.filter(id=next_id)
    has_more = result is not None
`;
    expect(n1Findings(code).length).toBeGreaterThan(0);
  });

  test('flags query.all() inside while loop', () => {
    const code = `
while page < total_pages:
    items = session.query.all()
    page += 1
`;
    expect(n1Findings(code).length).toBeGreaterThan(0);
  });

  test('flags query.first() inside while loop', () => {
    const code = `
while cursor:
    row = session.query.first()
    cursor = row.next
`;
    expect(n1Findings(code).length).toBeGreaterThan(0);
  });
});

// ── cursor.execute inside loops ─────────────────────────────────────────────

describe('Python N+1 — cursor.execute inside loops', () => {
  test('flags cursor.execute() inside for loop', () => {
    const code = `
for user_id in user_ids:
    cursor.execute("SELECT * FROM profiles WHERE user_id = %s", (user_id,))
`;
    expect(n1Findings(code).length).toBeGreaterThan(0);
  });

  test('flags cursor.execute() inside while loop', () => {
    const code = `
while idx < len(ids):
    cursor.execute("SELECT * FROM items WHERE id = %s", (ids[idx],))
    idx += 1
`;
    expect(n1Findings(code).length).toBeGreaterThan(0);
  });

  test('flags fetchone() inside for loop', () => {
    const code = `
for row_id in row_ids:
    result = cursor.fetchone()
`;
    expect(n1Findings(code).length).toBeGreaterThan(0);
  });
});

// ── Nested loops ────────────────────────────────────────────────────────────

describe('Python N+1 — nested loops', () => {
  test('flags query inside nested for loop', () => {
    const code = `
for user in users:
    for order in user.orders:
        payment = Payment.objects.get(order_id=order.id)
`;
    expect(n1Findings(code).length).toBeGreaterThan(0);
  });
});

// ── Negative cases (should NOT trigger) ─────────────────────────────────────

describe('Python N+1 — negative cases', () => {
  test('does not flag ORM query outside any loop', () => {
    const code = `
users = User.objects.filter(active=True)
profile = Profile.objects.get(user_id=1)
`;
    expect(n1Findings(code).length).toBe(0);
  });

  test('does not flag non-ORM calls inside loop', () => {
    const code = `
for user in users:
    print(user.name)
    user.process()
`;
    expect(n1Findings(code).length).toBe(0);
  });

  test('does not flag comments containing ORM patterns inside loop', () => {
    const code = `
for user in users:
    # Profile.objects.get(user_id=user.id) — commented out
    print(user.name)
`;
    expect(n1Findings(code).length).toBe(0);
  });

  test('does not flag query after loop body ends (back to base indent)', () => {
    const code = `
for user in users:
    print(user.name)
profile = Profile.objects.get(user_id=1)
`;
    expect(n1Findings(code).length).toBe(0);
  });
});

// ── Finding properties ──────────────────────────────────────────────────────

describe('Python N+1 — finding properties', () => {
  test('finding severity is low', () => {
    const code = `
for user in users:
    Profile.objects.get(user_id=user.id)
`;
    const findings = n1Findings(code);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.severity).toBe('low');
    }
  });

  test('finding includes file reference', () => {
    const result = scanPython(parsePythonCode(`
for user in users:
    Order.objects.filter(user_id=user.id)
`, 'app/models.py'));
    const n1 = result.filter((f) => f.type === 'PERFORMANCE_N_PLUS_ONE');
    expect(n1.length).toBeGreaterThan(0);
    expect(n1[0]!.file).toBe('app/models.py');
  });

  test('finding includes confidence', () => {
    const code = `
for user in users:
    Profile.objects.get(user_id=user.id)
`;
    const findings = n1Findings(code);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.confidence).toBeDefined();
    expect(findings[0]!.confidence).toBeGreaterThan(0);
  });
});
