/**
 * Auto-fix rule tests for the Java language.
 *
 * Covers: SQL_INJECTION, COMMAND_INJECTION, WEAK_CRYPTO, UNSAFE_DESERIALIZATION
 */

import { describe, it, expect } from 'vitest';
import { applyFixes } from '../../src/scanner/fixer';
import type { Finding } from '../../src/scanner/reporter';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

function makeFinding(overrides: Partial<Finding>): Finding {
  return {
    type: 'UNKNOWN',
    severity: 'high',
    message: 'test',
    file: '/tmp/test.java',
    line: 1,
    snippet: '',
    confidence: 0.9,
    ...overrides,
  };
}

function fixLine(type: string, lineContent: string): string | null {
  const tmpFile = path.join(os.tmpdir(), `fixer-java-${Date.now()}.java`);
  fs.writeFileSync(tmpFile, lineContent + '\n', 'utf-8');

  const finding = makeFinding({ type, file: tmpFile, line: 1, snippet: lineContent });
  applyFixes([finding], false);

  try {
    const content = fs.readFileSync(tmpFile, 'utf-8').trim();
    return content !== lineContent.trim() ? content : null;
  } finally {
    if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile);
  }
}

describe('fixer — Java SQL_INJECTION', () => {
  it('adds PreparedStatement note for Java SQL concatenation', () => {
    const result = fixLine('SQL_INJECTION', '    String sql = "SELECT * FROM users WHERE id = " + id;');
    expect(result).toContain('TODO(SQL_INJECTION)');
    expect(result).toContain('PreparedStatement');
  });

  it('does not annotate lines with PreparedStatement already', () => {
    const result = fixLine('SQL_INJECTION', '    PreparedStatement pstmt = conn.prepareStatement("SELECT ...");');
    expect(result).toBeNull();
  });
});

describe('fixer — Java COMMAND_INJECTION', () => {
  it('adds ProcessBuilder note for Runtime.exec usage', () => {
    const result = fixLine('COMMAND_INJECTION', '    Runtime.getRuntime().exec("cmd " + userInput);');
    expect(result).toContain('TODO(COMMAND_INJECTION)');
    expect(result).toContain('ProcessBuilder');
  });

  it('does not annotate lines without exec patterns', () => {
    const result = fixLine('COMMAND_INJECTION', '    System.out.println("hello");');
    expect(result).toBeNull();
  });
});

describe('fixer — Java WEAK_CRYPTO', () => {
  it('replaces MessageDigest.getInstance("MD5") with SHA-256', () => {
    const result = fixLine('WEAK_CRYPTO', '    MessageDigest md = MessageDigest.getInstance("MD5");');
    expect(result).toContain('SHA-256');
    expect(result).not.toContain('"MD5"');
  });

  it('replaces MessageDigest.getInstance("SHA-1") with SHA-256', () => {
    const result = fixLine('WEAK_CRYPTO', '    MessageDigest md = MessageDigest.getInstance("SHA-1");');
    expect(result).toContain('SHA-256');
  });

  it('does not modify lines already using SHA-256', () => {
    const result = fixLine('WEAK_CRYPTO', '    MessageDigest md = MessageDigest.getInstance("SHA-256");');
    expect(result).toBeNull();
  });
});

describe('fixer — Java UNSAFE_DESERIALIZATION', () => {
  it('adds deserialization safety note for ObjectInputStream usage', () => {
    const result = fixLine('UNSAFE_DESERIALIZATION', '    ObjectInputStream ois = new ObjectInputStream(stream);');
    expect(result).toContain('TODO(UNSAFE_DESERIALIZATION)');
    expect(result).toContain('ObjectInputStream');
  });

  it('adds note for readObject() calls', () => {
    const result = fixLine('UNSAFE_DESERIALIZATION', '    Object obj = ois.readObject();');
    expect(result).toContain('TODO(UNSAFE_DESERIALIZATION)');
  });
});
