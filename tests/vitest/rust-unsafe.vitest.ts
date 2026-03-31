/**
 * Unit tests for UNSAFE_BLOCK detection in Rust code.
 *
 * Tests the detection of unsafe blocks and ensures proper classification
 * of code that uses unsafe constructs.
 */

import { describe, it, expect } from 'vitest';
import { parseRustCode, scanRust } from '../../src/scanner/rust-parser';

// Helper: scan inline snippet, return array of finding types
function scan(code: string): string[] {
  return scanRust(parseRustCode(code, 'test.rs')).map((f) => f.type);
}

// Helper: scan inline snippet, return all findings
function scanFull(code: string) {
  return scanRust(parseRustCode(code, 'test.rs'));
}

describe('UNSAFE_BLOCK', () => {
  it('fires on inline unsafe block', () => {
    const code = `unsafe { let x = *ptr; }`;
    expect(scan(code)).toContain('UNSAFE_BLOCK');
  });

  it('fires on multi-line unsafe block (opening brace)', () => {
    const code = `
unsafe {
  let x = *ptr;
  let y = *other_ptr;
}`;
    const findings = scan(code);
    expect(findings).toContain('UNSAFE_BLOCK');
  });

  it('fires on unsafe block without dereference', () => {
    const code = `unsafe { /* some comment */ }`;
    expect(scan(code)).toContain('UNSAFE_BLOCK');
  });

  it('fires on unsafe block with complex body', () => {
    const code = `
unsafe {
  std::ptr::copy_nonoverlapping(src, dst, len);
}`;
    expect(scan(code)).toContain('UNSAFE_BLOCK');
  });

  it('does NOT fire on safe code without unsafe', () => {
    const code = `let x = 42; let y = x + 1;`;
    expect(scan(code)).not.toContain('UNSAFE_BLOCK');
  });

  it('does NOT fire on word "unsafe" in comments', () => {
    const code = `// this is unsafe code`;
    expect(scan(code)).not.toContain('UNSAFE_BLOCK');
  });

  it('does NOT fire on word "unsafe" in string literals', () => {
    const code = `let msg = "this is unsafe";`;
    expect(scan(code)).not.toContain('UNSAFE_BLOCK');
  });

  it('sets correct severity (medium)', () => {
    const findings = scanFull('unsafe { let x = 1; }');
    const f = findings.find((f) => f.type === 'UNSAFE_BLOCK');
    expect(f?.severity).toBe('medium');
  });

  it('sets high confidence (0.95)', () => {
    const findings = scanFull('unsafe { }');
    const f = findings.find((f) => f.type === 'UNSAFE_BLOCK');
    expect(f?.confidence).toBe(0.95);
  });

  it('fires on unsafe block with SAFETY comment already present (still flags it)', () => {
    const code = `unsafe { // SAFETY: ptr is valid
  let x = *ptr;
}`;
    expect(scan(code)).toContain('UNSAFE_BLOCK');
  });

  it('detects multiple unsafe blocks in same code', () => {
    const code = `
unsafe { let a = *pa; }
unsafe { let b = *pb; }`;
    const findings = scanFull(code);
    const unsafeFindings = findings.filter((f) => f.type === 'UNSAFE_BLOCK');
    expect(unsafeFindings.length).toBeGreaterThanOrEqual(2);
  });

  it('reports correct line number for unsafe block', () => {
    const code = `\n\nunsafe { let x = 1; }`;
    const findings = scanFull(code);
    const f = findings.find((f) => f.type === 'UNSAFE_BLOCK');
    expect(f?.line).toBe(3);
  });
});
