/**
 * Ruby Rails-specific detector tests — Batch 2
 *
 * Covers Rails-specific patterns added in the second iteration:
 *   - N+1 query patterns (PERFORMANCE_N_PLUS_ONE)
 *   - send() / public_send() with user input (COMMAND_INJECTION)
 *   - Unsafe mass assignment via raw params (MASS_ASSIGNMENT)
 *   - SQL string concatenation (SQL_INJECTION)
 *
 * Each test group has both positive (must fire) and negative (must not fire) cases.
 */

import { describe, test, expect } from 'vitest';
import { parseRubyCode, scanRuby } from '../../src/scanner/ruby-parser';

// ── Helpers ──────────────────────────────────────────────────────────────────

function scan(code: string, file = 'test.rb') {
  return scanRuby(parseRubyCode(code, file));
}

function findingTypes(code: string): string[] {
  return scan(code).map((f) => f.type);
}

function hasType(code: string, type: string): boolean {
  return findingTypes(code).includes(type);
}

function noFindings(code: string): boolean {
  return scan(code).length === 0;
}

// ── PERFORMANCE_N_PLUS_ONE ────────────────────────────────────────────────────

describe('PERFORMANCE_N_PLUS_ONE — N+1 query detectors', () => {
  test('flags each block accessing an association with dot-chain', () => {
    const code = `
posts.each { |post| post.comments.count }
`;
    expect(hasType(code, 'PERFORMANCE_N_PLUS_ONE')).toBe(true);
  });

  test('flags each block accessing plural association', () => {
    const code = `
users.each { |u| u.orders.first }
`;
    expect(hasType(code, 'PERFORMANCE_N_PLUS_ONE')).toBe(true);
  });

  test('does not flag each block with no association access', () => {
    const code = `
posts.each { |post| puts post.title }
`;
    expect(hasType(code, 'PERFORMANCE_N_PLUS_ONE')).toBe(false);
  });

  test('does not flag eager-loaded iteration', () => {
    // includes() call on the collection — the pattern should not fire on simple string access
    const code = `
Post.includes(:comments).each { |post| puts post.title }
`;
    expect(hasType(code, 'PERFORMANCE_N_PLUS_ONE')).toBe(false);
  });

  test('finding includes correct severity (low)', () => {
    const code = `items.each { |item| item.tags.map { |t| t.name } }`;
    const findings = scan(code).filter((f) => f.type === 'PERFORMANCE_N_PLUS_ONE');
    for (const f of findings) {
      expect(f.severity).toBe('low');
    }
  });
});

// ── COMMAND_INJECTION via send() ──────────────────────────────────────────────

describe('COMMAND_INJECTION — send() with user input', () => {
  test('flags .send(params[...])', () => {
    const code = `obj.send(params[:action])`;
    expect(hasType(code, 'COMMAND_INJECTION')).toBe(true);
  });

  test('flags .send(request.params)', () => {
    const code = `model.send(request.params[:method])`;
    expect(hasType(code, 'COMMAND_INJECTION')).toBe(true);
  });

  test('flags .send with string interpolation of user input', () => {
    const code = 'obj.send("#{params[:action]}")';
    expect(hasType(code, 'COMMAND_INJECTION')).toBe(true);
  });

  test('does not flag .send with a literal symbol', () => {
    const code = `obj.send(:calculate)`;
    expect(hasType(code, 'COMMAND_INJECTION')).toBe(false);
  });

  test('does not flag .send with a plain string literal', () => {
    const code = `obj.send("to_s")`;
    expect(hasType(code, 'COMMAND_INJECTION')).toBe(false);
  });

  test('flags public_send with params', () => {
    const code = `model.public_send(params[:scope])`;
    expect(hasType(code, 'COMMAND_INJECTION')).toBe(true);
  });

  test('does not flag public_send with literal', () => {
    const code = `model.public_send(:active)`;
    expect(hasType(code, 'COMMAND_INJECTION')).toBe(false);
  });

  test('finding severity is critical for .send', () => {
    const code = `obj.send(params[:m])`;
    const findings = scan(code).filter((f) => f.type === 'COMMAND_INJECTION');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.severity).toBe('critical');
  });
});

// ── MASS_ASSIGNMENT via raw params ────────────────────────────────────────────

describe('MASS_ASSIGNMENT — unsafe mass assignment via raw params', () => {
  test('flags update() with raw params', () => {
    const code = `user.update(params[:user])`;
    expect(hasType(code, 'MASS_ASSIGNMENT')).toBe(true);
  });

  test('flags assign_attributes() with raw params', () => {
    const code = `@user.assign_attributes(params[:user])`;
    expect(hasType(code, 'MASS_ASSIGNMENT')).toBe(true);
  });

  test('flags update_attributes() with raw params', () => {
    const code = `record.update_attributes(params[:record])`;
    expect(hasType(code, 'MASS_ASSIGNMENT')).toBe(true);
  });

  test('does not flag update() with permitted params', () => {
    const code = `user.update(user_params)`;
    expect(hasType(code, 'MASS_ASSIGNMENT')).toBe(false);
  });

  test('does not flag permit() calls themselves (those are the fix)', () => {
    const code = `params.require(:user).permit(:name, :email)`;
    expect(hasType(code, 'MASS_ASSIGNMENT')).toBe(false);
  });

  test('flags permit(:all)', () => {
    const code = `params.permit(:all)`;
    expect(hasType(code, 'MASS_ASSIGNMENT')).toBe(true);
  });

  test('finding severity is high', () => {
    const code = `user.update(params[:user])`;
    const findings = scan(code).filter((f) => f.type === 'MASS_ASSIGNMENT');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.severity).toBe('high');
  });

  test('returns file reference in finding', () => {
    const code = `user.update(params[:user])`;
    const findings = scan(code, 'app/controllers/users_controller.rb').filter(
      (f) => f.type === 'MASS_ASSIGNMENT',
    );
    expect(findings[0]!.file).toBe('app/controllers/users_controller.rb');
  });
});

// ── SQL_INJECTION via string concatenation ────────────────────────────────────

describe('SQL_INJECTION — string concatenation patterns (Rails batch 2)', () => {
  test('flags .where() with string concatenation', () => {
    const code = `User.where("name = " + params[:name])`;
    expect(hasType(code, 'SQL_INJECTION')).toBe(true);
  });

  test('flags .select() with string concatenation', () => {
    const code = `User.select("* FROM users WHERE id = " + user_id)`;
    expect(hasType(code, 'SQL_INJECTION')).toBe(true);
  });

  test('flags .find_by_sql() with string concatenation', () => {
    const code = `User.find_by_sql("SELECT * FROM users WHERE token = " + params[:token])`;
    expect(hasType(code, 'SQL_INJECTION')).toBe(true);
  });

  test('does not flag .where() with placeholder', () => {
    const code = `User.where("active = ?", true)`;
    expect(hasType(code, 'SQL_INJECTION')).toBe(false);
  });

  test('does not flag .where() with hash', () => {
    const code = `User.where(active: true, role: :admin)`;
    expect(hasType(code, 'SQL_INJECTION')).toBe(false);
  });

  test('does not flag .where() with literal string only', () => {
    const code = `User.where("active = TRUE")`;
    expect(hasType(code, 'SQL_INJECTION')).toBe(false);
  });

  test('finding severity is critical', () => {
    const code = `User.where("name = " + params[:name])`;
    const findings = scan(code).filter((f) => f.type === 'SQL_INJECTION');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.severity).toBe('critical');
  });
});

// ── Mixed scenarios ───────────────────────────────────────────────────────────

describe('Mixed Rails vulnerability scenarios', () => {
  test('controller action with multiple vulnerability types', () => {
    const code = `
def create
  @user = User.new(params[:user])
  @user.send(params[:callback])
  User.where("role = " + params[:role]).each { |u| u.orders.map { |o| o.total } }
end
`;
    const types = findingTypes(code);
    expect(types).toContain('MASS_ASSIGNMENT');
    expect(types).toContain('COMMAND_INJECTION');
    expect(types).toContain('SQL_INJECTION');
  });

  test('clean controller action produces no findings', () => {
    const code = `
def create
  @user = User.new(user_params)
  redirect_to users_path
end

private

def user_params
  params.require(:user).permit(:name, :email)
end
`;
    expect(findingTypes(code)).not.toContain('MASS_ASSIGNMENT');
    expect(findingTypes(code)).not.toContain('COMMAND_INJECTION');
  });
});

// ── Snippet and line number accuracy ─────────────────────────────────────────

describe('Finding metadata accuracy', () => {
  test('line number is correct for send() finding', () => {
    const code = [
      'class UsersController',
      '  def action',
      '    @user.send(params[:method])',
      '  end',
      'end',
    ].join('\n');
    const findings = scan(code).filter((f) => f.type === 'COMMAND_INJECTION');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.line).toBe(3);
  });

  test('snippet is populated for SQL injection', () => {
    const code = `User.where("id = " + params[:id])`;
    const findings = scan(code).filter((f) => f.type === 'SQL_INJECTION');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.snippet).toBeTruthy();
    expect(findings[0]!.snippet!.length).toBeGreaterThan(0);
  });

  test('column points to first non-whitespace character', () => {
    const code = `    User.where("name = " + name)`;
    const findings = scan(code).filter((f) => f.type === 'SQL_INJECTION');
    expect(findings.length).toBeGreaterThan(0);
    // 4 spaces of indent → column = 4
    expect(findings[0]!.column).toBe(4);
  });
});
