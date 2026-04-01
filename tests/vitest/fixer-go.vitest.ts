/**
 * Auto-fix rule tests for the Go language.
 *
 * Covers: PATH_TRAVERSAL, SQL_INJECTION, COMMAND_INJECTION_GO,
 *         INSECURE_RANDOM, WEAK_CRYPTO
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
    file: '/tmp/test.go',
    line: 1,
    snippet: '',
    confidence: 0.9,
    ...overrides,
  };
}

function fixLine(type: string, lineContent: string, filePath = '/tmp/test.go'): string | null {
  const tmpFile = path.join(os.tmpdir(), `fixer-go-${Date.now()}.go`);
  fs.writeFileSync(tmpFile, lineContent + '\n', 'utf-8');

  const finding = makeFinding({ type, file: tmpFile, line: 1, snippet: lineContent });
  const results = applyFixes([finding], false);

  try {
    const content = fs.readFileSync(tmpFile, 'utf-8').trim();
    return content !== lineContent.trim() ? content : null;
  } finally {
    if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile);
  }
}

describe('fixer — Go PATH_TRAVERSAL', () => {
  it('adds filepath.Clean guard comment to a Go file with traversal', () => {
    const result = fixLine('PATH_TRAVERSAL', '\tpath := userInput');
    expect(result).toContain('TODO(PATH_TRAVERSAL)');
    expect(result).toContain('filepath.Clean');
  });

  it('does not double-annotate lines already using filepath.Clean', () => {
    const result = fixLine('PATH_TRAVERSAL', '\tclean := filepath.Clean(userInput)');
    expect(result).toBeNull();
  });
});

describe('fixer — Go SQL_INJECTION', () => {
  it('adds parameterized query note to Go SQL concatenation', () => {
    const result = fixLine('SQL_INJECTION', '\trows, err := db.Query("SELECT * FROM users WHERE id = " + id)');
    expect(result).toContain('TODO(SQL_INJECTION)');
    expect(result).toContain('?');
  });

  it('does not annotate already-parameterized queries', () => {
    const result = fixLine('SQL_INJECTION', '\trows, _ := db.Query("SELECT * FROM users WHERE id = ?", id)');
    expect(result).toBeNull();
  });
});

describe('fixer — Go COMMAND_INJECTION_GO', () => {
  it('adds array-args note to exec.Command calls', () => {
    const result = fixLine('COMMAND_INJECTION_GO', '\tcmd := exec.Command("sh", "-c", userInput)');
    expect(result).toContain('TODO(COMMAND_INJECTION_GO)');
  });

  it('does not annotate lines without exec.Command', () => {
    const result = fixLine('COMMAND_INJECTION_GO', '\tfmt.Println("hello")');
    expect(result).toBeNull();
  });
});

describe('fixer — Go INSECURE_RANDOM', () => {
  it('adds crypto/rand note to math/rand usage', () => {
    const result = fixLine('INSECURE_RANDOM', '\tn := rand.Intn(100)');
    expect(result).toContain('TODO(INSECURE_RANDOM)');
    expect(result).toContain('crypto/rand');
  });

  it('does not annotate lines already using crypto/rand', () => {
    const result = fixLine('INSECURE_RANDOM', '\t_, _ = crypto/rand.Read(buf)');
    expect(result).toBeNull();
  });
});

describe('fixer — Go WEAK_CRYPTO', () => {
  it('adds sha256 note to md5 usage in Go', () => {
    const result = fixLine('WEAK_CRYPTO', '\th := md5.Sum(data)');
    expect(result).toContain('TODO(WEAK_CRYPTO)');
    expect(result).toContain('sha256');
  });

  it('adds sha256 note to sha1 usage in Go', () => {
    const result = fixLine('WEAK_CRYPTO', '\th := sha1.New()');
    expect(result).toContain('TODO(WEAK_CRYPTO)');
  });

  it('does not annotate lines already using sha256', () => {
    const result = fixLine('WEAK_CRYPTO', '\th := sha256.Sum256(data)');
    expect(result).toBeNull();
  });
});
