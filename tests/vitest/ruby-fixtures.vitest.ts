/**
 * Fixture-based tests for the Ruby scanner (ruby-parser.ts).
 *
 * Verifies that vulnerable.rb triggers expected finding types and clean.rb
 * produces zero findings.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import path from 'path';
import { parseRubyFile, parseRubyCode, scanRuby } from '../../src/scanner/ruby-parser';

const FIXTURES = path.join(__dirname, '..', 'fixtures');

describe('Ruby scanner — fixture files', () => {
  test('vulnerable.rb produces expected findings', () => {
    const parsed = parseRubyFile(path.join(FIXTURES, 'vulnerable.rb'));
    const findings = scanRuby(parsed);

    expect(findings.length).toBeGreaterThan(0);

    const types = new Set(findings.map((f) => f.type));

    // Expected vulnerability classes in vulnerable.rb
    expect(types.has('SQL_INJECTION')).toBe(true);
    expect(types.has('COMMAND_INJECTION')).toBe(true);
    expect(types.has('SECRET_HARDCODED')).toBe(true);
    expect(types.has('MASS_ASSIGNMENT')).toBe(true);
    expect(types.has('WEAK_CRYPTO')).toBe(true);
    expect(types.has('EVAL_INJECTION')).toBe(true);
    expect(types.has('LDAP_INJECTION')).toBe(true);
  });

  test('clean.rb produces zero findings', () => {
    const parsed = parseRubyFile(path.join(FIXTURES, 'clean.rb'));
    const findings = scanRuby(parsed);

    expect(findings.length).toBe(0);
  });

  test('findings include correct file path', () => {
    const filePath = path.join(FIXTURES, 'vulnerable.rb');
    const parsed = parseRubyFile(filePath);
    const findings = scanRuby(parsed);

    for (const f of findings) {
      expect(f.file).toBe(filePath);
    }
  });

  test('findings have valid severity levels', () => {
    const parsed = parseRubyFile(path.join(FIXTURES, 'vulnerable.rb'));
    const findings = scanRuby(parsed);

    const validSeverities = new Set(['critical', 'high', 'medium', 'low']);
    for (const f of findings) {
      expect(validSeverities.has(f.severity)).toBe(true);
    }
  });

  test('SQL injection findings are critical', () => {
    const parsed = parseRubyFile(path.join(FIXTURES, 'vulnerable.rb'));
    const findings = scanRuby(parsed);

    const sqlFindings = findings.filter((f) => f.type === 'SQL_INJECTION');
    expect(sqlFindings.length).toBeGreaterThan(0);
    for (const f of sqlFindings) {
      expect(f.severity).toBe('critical');
    }
  });
});

// ── Rails-specific inline detector tests ─────────────────────────────────────

describe('Ruby scanner — Rails SQL injection via string concatenation', () => {
  test('detects .where() with string concatenation', () => {
    const parsed = parseRubyCode('User.where("id = " + params[:id])');
    const findings = scanRuby(parsed);
    expect(findings.some((f) => f.type === 'SQL_INJECTION')).toBe(true);
  });

  test('detects find_by_sql with string concatenation', () => {
    const parsed = parseRubyCode('User.find_by_sql("SELECT * FROM users WHERE id = " + user_id)');
    const findings = scanRuby(parsed);
    expect(findings.some((f) => f.type === 'SQL_INJECTION')).toBe(true);
  });

  test('does NOT flag .where() with parameterized question mark', () => {
    const parsed = parseRubyCode('User.where("id = ?", params[:id])');
    const findings = scanRuby(parsed);
    // No SQL injection finding expected for parameterized queries
    const sqlConcat = findings.filter((f) => f.type === 'SQL_INJECTION' && f.message.includes('concatenation'));
    expect(sqlConcat.length).toBe(0);
  });
});

describe('Ruby scanner — unsafe use of send()', () => {
  test('detects .send() with params', () => {
    const parsed = parseRubyCode('@user.send(params[:method])');
    const findings = scanRuby(parsed);
    expect(findings.some((f) => f.type === 'COMMAND_INJECTION' && f.message.includes('send()'))).toBe(true);
  });

  test('detects .public_send() with request params', () => {
    const parsed = parseRubyCode('model.public_send(request.params[:action])');
    const findings = scanRuby(parsed);
    expect(findings.some((f) => f.type === 'COMMAND_INJECTION' && f.message.includes('public_send()'))).toBe(true);
  });

  test('does NOT flag .send() with a hardcoded symbol', () => {
    const parsed = parseRubyCode('obj.send(:save)');
    const findings = scanRuby(parsed);
    const sendFindings = findings.filter((f) => f.message.includes('send()'));
    expect(sendFindings.length).toBe(0);
  });
});

describe('Ruby scanner — unsafe mass assignment patterns', () => {
  test('detects assign_attributes with raw params', () => {
    const parsed = parseRubyCode('@user.assign_attributes(params[:user])');
    const findings = scanRuby(parsed);
    expect(findings.some((f) => f.type === 'MASS_ASSIGNMENT')).toBe(true);
  });

  test('detects update() with raw params', () => {
    const parsed = parseRubyCode('@user.update(params)');
    const findings = scanRuby(parsed);
    expect(findings.some((f) => f.type === 'MASS_ASSIGNMENT')).toBe(true);
  });

  test('detects attr_accessible :all', () => {
    const parsed = parseRubyCode('attr_accessible :all');
    const findings = scanRuby(parsed);
    expect(findings.some((f) => f.type === 'MASS_ASSIGNMENT')).toBe(true);
  });

  test('does NOT flag update() with permitted params', () => {
    const parsed = parseRubyCode('@user.update(params.require(:user).permit(:name, :email))');
    const findings = scanRuby(parsed);
    // The permit pattern breaks the raw params regex — should not match
    const massFindings = findings.filter((f) => f.type === 'MASS_ASSIGNMENT' && f.message.includes('params hash'));
    expect(massFindings.length).toBe(0);
  });
});
