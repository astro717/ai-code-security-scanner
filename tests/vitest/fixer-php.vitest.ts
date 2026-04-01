/**
 * Auto-fix rule tests for the PHP language.
 *
 * Covers: SQL_INJECTION, XSS, EVAL_INJECTION, COMMAND_INJECTION, WEAK_CRYPTO
 *
 * Note: PHP rules were already present in fixer.ts. These tests verify them.
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
    file: '/tmp/test.php',
    line: 1,
    snippet: '',
    confidence: 0.9,
    ...overrides,
  };
}

function fixLine(type: string, lineContent: string): string | null {
  const tmpFile = path.join(os.tmpdir(), `fixer-php-${Date.now()}.php`);
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

describe('fixer — PHP SQL_INJECTION', () => {
  it('adds PDO prepared statement note', () => {
    const result = fixLine('SQL_INJECTION', '$result = mysql_query("SELECT * FROM users WHERE id = " . $id);');
    expect(result).toContain('TODO');
    expect(result).toContain('PDO');
  });

  it('does not annotate lines already using prepare()', () => {
    const result = fixLine('SQL_INJECTION', '$stmt = $pdo->prepare("SELECT ... WHERE id = ?");');
    expect(result).toBeNull();
  });
});

describe('fixer — PHP XSS', () => {
  it('wraps echo $_GET with htmlspecialchars', () => {
    const result = fixLine('XSS', "echo $_GET['name'];");
    expect(result).toContain('htmlspecialchars');
  });

  it('adds TODO note for complex XSS patterns', () => {
    const result = fixLine('XSS', 'echo "<div>" . $userInput . "</div>";');
    expect(result).toContain('TODO');
    expect(result).toContain('htmlspecialchars');
  });

  it('does not modify lines already using htmlspecialchars', () => {
    const result = fixLine('XSS', "echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');");
    expect(result).toBeNull();
  });
});

describe('fixer — PHP COMMAND_INJECTION', () => {
  it('adds escapeshellarg note for shell_exec', () => {
    const result = fixLine('COMMAND_INJECTION', '$out = shell_exec("ls " . $userInput);');
    expect(result).toContain('TODO');
    expect(result).toContain('escapeshellarg');
  });

  it('does not annotate lines already using escapeshellarg', () => {
    const result = fixLine('COMMAND_INJECTION', '$out = shell_exec("ls " . escapeshellarg($userInput));');
    expect(result).toBeNull();
  });
});

describe('fixer — PHP WEAK_CRYPTO', () => {
  it('replaces md5() with hash("sha256", ...)', () => {
    const result = fixLine('WEAK_CRYPTO', '$hash = md5($password);');
    expect(result).toContain("hash('sha256'");
    expect(result).not.toContain('md5(');
  });

  it('replaces sha1() with hash("sha256", ...)', () => {
    const result = fixLine('WEAK_CRYPTO', '$hash = sha1($data);');
    expect(result).toContain("hash('sha256'");
  });

  it('does not modify lines already using password_hash', () => {
    const result = fixLine('WEAK_CRYPTO', "$hash = password_hash($pw, PASSWORD_BCRYPT);");
    expect(result).toBeNull();
  });
});
