/**
 * Fixture-based unit tests for the PERFORMANCE_N_PLUS_ONE detector in java-parser.ts.
 */

import { describe, it, expect } from 'vitest';
import { parseJavaCode, scanJava } from '../../src/scanner/java-parser';

function scan(code: string): string[] {
  return scanJava(parseJavaCode(code, 'Test.java')).map((f) => f.type);
}

function scanFull(code: string) {
  return scanJava(parseJavaCode(code, 'Test.java'));
}

describe('PERFORMANCE_N_PLUS_ONE — Java', () => {
  it('fires on JDBC executeQuery inside a for loop', () => {
    const code = `
for (int i = 0; i < ids.length; i++) {
  ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + ids[i]);
}`;
    expect(scan(code)).toContain('PERFORMANCE_N_PLUS_ONE');
  });

  it('fires on JPA findById inside enhanced for-each', () => {
    const code = `
for (Long id : orderIds) {
  Order order = entityManager.findById(id, Order.class);
  process(order);
}`;
    expect(scan(code)).toContain('PERFORMANCE_N_PLUS_ONE');
  });

  it('fires on Hibernate session.get inside for-each', () => {
    const code = `
for (String userId : userIds) {
  User u = session.get(User.class, userId);
  results.add(u);
}`;
    expect(scan(code)).toContain('PERFORMANCE_N_PLUS_ONE');
  });

  it('does NOT fire on a single query outside a loop', () => {
    const code = `ResultSet rs = stmt.executeQuery("SELECT * FROM orders");`;
    expect(scan(code)).not.toContain('PERFORMANCE_N_PLUS_ONE');
  });

  it('does NOT fire on non-DB code inside a loop', () => {
    const code = `
for (int i = 0; i < names.length; i++) {
  System.out.println(names[i]);
}`;
    expect(scan(code)).not.toContain('PERFORMANCE_N_PLUS_ONE');
  });

  it('reports the correct file path', () => {
    const result = scanJava(parseJavaCode(
      'for (Long id : ids) { session.get(User.class, id); }',
      '/project/src/UserRepo.java',
    ));
    const f = result.find((r) => r.type === 'PERFORMANCE_N_PLUS_ONE');
    expect(f?.file).toBe('/project/src/UserRepo.java');
  });

  it('finding has severity low', () => {
    const code = `
for (Long id : ids) {
  Order o = entityManager.findById(id, Order.class);
}`;
    const f = scanFull(code).find((r) => r.type === 'PERFORMANCE_N_PLUS_ONE');
    expect(f?.severity).toBe('low');
  });
});
