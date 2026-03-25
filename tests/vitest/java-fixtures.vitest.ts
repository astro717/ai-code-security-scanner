/**
 * Java scanner integration tests using fixture files.
 *
 * Tests that:
 *  - tests/fixtures/vulnerable.java triggers findings for known vulnerability patterns
 *  - tests/fixtures/clean.java produces zero findings
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import path from 'path';
import { parseJavaFile, scanJava } from '../../src/scanner/java-parser';

const FIXTURES_DIR = path.join(__dirname, '..', 'fixtures');

describe('Java scanner — vulnerable.java fixture', () => {
  const result = parseJavaFile(path.join(FIXTURES_DIR, 'vulnerable.java'));
  const findings = scanJava(result);

  test('produces at least one finding', () => {
    expect(findings.length).toBeGreaterThan(0);
  });

  test('every finding has a line number, severity, and message', () => {
    for (const f of findings) {
      expect(typeof f.line).toBe('number');
      expect(f.line).toBeGreaterThan(0);
      expect(['critical', 'high', 'medium', 'low']).toContain(f.severity);
      expect(typeof f.message).toBe('string');
      expect(f.message.length).toBeGreaterThan(0);
    }
  });

  test('SQL_INJECTION — detects executeQuery with concatenation (line 15)', () => {
    const hits = findings.filter((f) => f.type === 'SQL_INJECTION');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].severity).toBe('critical');
    expect(hits[0].line).toBe(15);
  });

  test('COMMAND_INJECTION — detects Runtime.exec with concatenation (line 20)', () => {
    const hits = findings.filter((f) => f.type === 'COMMAND_INJECTION');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].severity).toBe('critical');
    expect(hits[0].line).toBe(20);
  });

  test('SECRET_HARDCODED — detects hardcoded apiKey (line 24)', () => {
    const hits = findings.filter((f) => f.type === 'SECRET_HARDCODED');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].severity).toBe('high');
    expect(hits[0].line).toBe(24);
  });

  test('WEAK_CRYPTO — detects MessageDigest.getInstance("MD5") (line 28)', () => {
    const hits = findings.filter((f) => f.type === 'WEAK_CRYPTO');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].severity).toBe('high');
    expect(hits[0].line).toBe(28);
  });

  test('INSECURE_RANDOM — detects new Random() (line 41)', () => {
    const hits = findings.filter((f) => f.type === 'INSECURE_RANDOM');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].severity).toBe('medium');
    expect(hits[0].line).toBe(41);
  });

  test('UNSAFE_DESERIALIZATION — detects readObject() (line 48)', () => {
    const hits = findings.filter((f) => f.type === 'UNSAFE_DESERIALIZATION');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].severity).toBe('critical');
    expect(hits[0].line).toBe(48);
  });
});

describe('Java scanner — clean.java fixture', () => {
  const result = parseJavaFile(path.join(FIXTURES_DIR, 'clean.java'));
  const findings = scanJava(result);

  test('produces zero findings', () => {
    if (findings.length > 0) {
      const detail = findings.map((f) => `  line ${f.line}: [${f.type}] ${f.message}`).join('\n');
      throw new Error(`Expected 0 findings in clean.java but got ${findings.length}:\n${detail}`);
    }
    expect(findings.length).toBe(0);
  });
});
