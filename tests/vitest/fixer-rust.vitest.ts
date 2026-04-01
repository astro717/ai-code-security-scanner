/**
 * Auto-fix rule tests for the Rust language.
 *
 * Covers: COMMAND_INJECTION, INSECURE_RANDOM, WEAK_CRYPTO, UNSAFE_BLOCK
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
    file: '/tmp/test.rs',
    line: 1,
    snippet: '',
    confidence: 0.9,
    ...overrides,
  };
}

function fixLine(type: string, lineContent: string): string | null {
  const tmpFile = path.join(os.tmpdir(), `fixer-rust-${Date.now()}.rs`);
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

describe('fixer — Rust COMMAND_INJECTION', () => {
  it('adds TODO annotation for Command::new with variable args', () => {
    const result = fixLine('COMMAND_INJECTION', '    let cmd = Command::new("sh").arg(user_input).output();');
    expect(result).toContain('TODO(COMMAND_INJECTION)');
  });

  it('does not annotate Command::new with static string only', () => {
    const result = fixLine('COMMAND_INJECTION', '    let cmd = Command::new("ls");');
    expect(result).toBeNull();
  });
});

describe('fixer — Rust INSECURE_RANDOM', () => {
  it('replaces rand::random with OsRng equivalent', () => {
    const result = fixLine('INSECURE_RANDOM', '    let n = rand::random::<u64>();');
    expect(result).toContain('OsRng');
    expect(result).toContain('TODO(INSECURE_RANDOM)');
  });

  it('replaces thread_rng() with OsRng', () => {
    const result = fixLine('INSECURE_RANDOM', '    let mut rng = thread_rng();');
    expect(result).toContain('OsRng');
  });
});

describe('fixer — Rust WEAK_CRYPTO', () => {
  it('annotates md5::compute usage with sha2 migration hint', () => {
    const result = fixLine('WEAK_CRYPTO', '    let digest = md5::compute(data);');
    expect(result).toContain('TODO(WEAK_CRYPTO)');
    expect(result).toContain('sha2');
  });

  it('replaces Sha1::new() with Sha256::new()', () => {
    const result = fixLine('WEAK_CRYPTO', '    let mut hasher = Sha1::new();');
    expect(result).toContain('Sha256::new()');
    expect(result).not.toContain('Sha1::new()');
  });

  it('annotates use sha1:: import declarations', () => {
    const result = fixLine('WEAK_CRYPTO', 'use sha1::Sha1;');
    expect(result).toContain('TODO(WEAK_CRYPTO)');
  });
});

describe('fixer — Rust UNSAFE_BLOCK', () => {
  it('adds scope minimization guidance for unsafe blocks', () => {
    const result = fixLine('UNSAFE_BLOCK', '    unsafe { *ptr = 42; }');
    expect(result).toContain('TODO(UNSAFE_BLOCK)');
    expect(result).toContain('minimize');
  });

  it('does not annotate lines without unsafe block', () => {
    const result = fixLine('UNSAFE_BLOCK', '    let x = 42;');
    expect(result).toBeNull();
  });
});
