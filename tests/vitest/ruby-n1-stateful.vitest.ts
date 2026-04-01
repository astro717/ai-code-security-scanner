/**
 * Unit tests for Ruby N+1 stateful detector (brace/do-end depth tracking).
 *
 * Tests the stateful iteration-block + ActiveRecord query detector in ruby-parser.ts.
 * Covers: brace-block syntax (.each { }), do-end syntax (.each do |x| end),
 * nested loops, and clean code that should NOT trigger.
 */

import { describe, test, expect } from 'vitest';
import { parseRubyCode, scanRuby } from '../../src/scanner/ruby-parser';

function scan(code: string) {
  return scanRuby(parseRubyCode(code, 'test.rb'));
}

function n1Findings(code: string) {
  return scan(code).filter((f) => f.type === 'PERFORMANCE_N_PLUS_ONE');
}

// ── Brace-block syntax (.each { }) ──────────────────────────────────────────

describe('N+1 stateful detector — brace blocks', () => {
  test('flags .find() inside .each { }', () => {
    const code = `
users.each { |user|
  profile = Profile.find(user.profile_id)
}
`;
    expect(n1Findings(code).length).toBeGreaterThan(0);
  });

  test('flags .where() inside .map { }', () => {
    const code = `
orders.map { |order|
  items = Item.where(order_id: order.id)
}
`;
    expect(n1Findings(code).length).toBeGreaterThan(0);
  });

  test('flags .first inside .select { }', () => {
    const code = `
posts.select { |post|
  comment = post.comments.first
}
`;
    expect(n1Findings(code).length).toBeGreaterThan(0);
  });

  test('does not fire outside iteration block', () => {
    const code = `
user = User.find(1)
profile = Profile.where(user_id: user.id).first
`;
    expect(n1Findings(code).length).toBe(0);
  });
});

// ── Do-end syntax (.each do |x| end) ───────────────────────────────────────

describe('N+1 stateful detector — do-end blocks', () => {
  test('flags .find() inside .each do ... end', () => {
    const code = `
users.each do |user|
  profile = Profile.find(user.profile_id)
end
`;
    expect(n1Findings(code).length).toBeGreaterThan(0);
  });

  test('flags .where() inside .map do ... end', () => {
    const code = `
orders.map do |order|
  Item.where(order_id: order.id).count
end
`;
    expect(n1Findings(code).length).toBeGreaterThan(0);
  });

  test('does not fire after end keyword closes the block', () => {
    const code = `
users.each do |user|
  puts user.name
end
profile = Profile.find(1)
`;
    expect(n1Findings(code).length).toBe(0);
  });
});

// ── Nested loops ────────────────────────────────────────────────────────────

describe('N+1 stateful detector — nested blocks', () => {
  test('flags query inside nested brace block', () => {
    const code = `
users.each { |user|
  user.orders.each { |order|
    payment = Payment.find(order.payment_id)
  }
}
`;
    expect(n1Findings(code).length).toBeGreaterThan(0);
  });
});

// ── Clean code that should NOT trigger ──────────────────────────────────────

describe('N+1 stateful detector — negative cases', () => {
  test('does not flag ActiveRecord call outside loops', () => {
    const code = `
users = User.where(active: true)
users.each { |u| puts u.name }
`;
    expect(n1Findings(code).length).toBe(0);
  });

  test('does not flag non-ActiveRecord method calls in loops', () => {
    const code = `
items.each { |item|
  puts item.to_s
  item.process!
}
`;
    expect(n1Findings(code).length).toBe(0);
  });

  test('does not flag comments containing ActiveRecord patterns', () => {
    const code = `
users.each { |user|
  # User.find(user.id) — this is commented out
  puts user.name
}
`;
    expect(n1Findings(code).length).toBe(0);
  });

  test('finding severity is low', () => {
    const code = `
users.each { |user|
  Profile.find(user.profile_id)
}
`;
    const findings = n1Findings(code);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.severity).toBe('low');
    }
  });

  test('finding includes file reference', () => {
    const result = scanRuby(parseRubyCode(`
users.each { |u|
  Order.where(user_id: u.id).count
}
`, 'app/models/user.rb'));
    const n1 = result.filter((f) => f.type === 'PERFORMANCE_N_PLUS_ONE');
    expect(n1.length).toBeGreaterThan(0);
    expect(n1[0]!.file).toBe('app/models/user.rb');
  });
});
