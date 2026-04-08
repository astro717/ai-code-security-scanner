/**
 * Auto-fix rule tests for C/C++ language.
 *
 * Covers: BUFFER_OVERFLOW, FORMAT_STRING, COMMAND_INJECTION_C, INSECURE_RANDOM
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
    file: '/tmp/test.c',
    line: 1,
    snippet: '',
    confidence: 0.9,
    ...overrides,
  };
}

function fixLine(type: string, lineContent: string, ext = '.c'): string | null {
  const tmpFile = path.join(os.tmpdir(), `fixer-c-${Date.now()}${ext}`);
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

describe('fixer — C/C++ BUFFER_OVERFLOW', () => {
  it('replaces strcpy with strncpy including sizeof guard', () => {
    const result = fixLine('BUFFER_OVERFLOW', '    strcpy(dest, src);');
    expect(result).toContain('strncpy');
    expect(result).toContain('sizeof(dest)');
    expect(result).not.toContain('strcpy(');
  });

  it('replaces strcat with strncat', () => {
    const result = fixLine('BUFFER_OVERFLOW', '    strcat(buf, input);');
    expect(result).toContain('strncat');
    expect(result).not.toContain('strcat(');
  });

  it('works for .cpp files too', () => {
    const result = fixLine('BUFFER_OVERFLOW', '    strcpy(buffer, userInput);', '.cpp');
    expect(result).toContain('strncpy');
  });
});

describe('fixer — C/C++ FORMAT_STRING', () => {
  it('adds %s format specifier to printf(variable) calls', () => {
    const result = fixLine('FORMAT_STRING', '    printf(userInput);');
    expect(result).toContain('printf("%s"');
    expect(result).toContain('userInput');
  });

  it('does not modify printf("literal") calls', () => {
    const result = fixLine('FORMAT_STRING', '    printf("Hello World\\n");');
    expect(result).toBeNull();
  });

  it('fixes fprintf(file, userInput) pattern', () => {
    const result = fixLine('FORMAT_STRING', '    fprintf(stderr, msg);');
    // fprintf keeps the file descriptor and inserts a format string: fprintf(stderr, "%s", msg)
    expect(result).toContain('fprintf(stderr, "%s"');
  });
});

describe('fixer — C/C++ COMMAND_INJECTION_C', () => {
  it('adds execv() note for system() calls', () => {
    const result = fixLine('COMMAND_INJECTION_C', '    system(userInput);');
    expect(result).toContain('TODO(COMMAND_INJECTION_C)');
    expect(result).toContain('execv');
  });

  it('works for COMMAND_INJECTION type on C files', () => {
    const result = fixLine('COMMAND_INJECTION', '    system(cmd);');
    expect(result).toContain('TODO(COMMAND_INJECTION_C)');
  });

  it('does not annotate non-system() lines', () => {
    const result = fixLine('COMMAND_INJECTION_C', '    printf("running");');
    expect(result).toBeNull();
  });
});

describe('fixer — C/C++ INSECURE_RANDOM', () => {
  it('adds getrandom/arc4random note for rand() calls', () => {
    const result = fixLine('INSECURE_RANDOM', '    int n = rand();');
    expect(result).toContain('TODO(INSECURE_RANDOM)');
    expect(result).toContain('getrandom');
  });

  it('does not annotate lines already using getrandom', () => {
    const result = fixLine('INSECURE_RANDOM', '    getrandom(buf, 16, 0);');
    expect(result).toBeNull();
  });
});
