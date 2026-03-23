/**
 * Python language support for the AI Code Security Scanner.
 *
 * This module implements a regex-based scan pass for Python files. It does not
 * use a full Python AST parser (no native bindings required) — instead, it
 * operates on the raw source lines with pattern matching. This is intentionally
 * conservative: it only flags patterns that are nearly always vulnerabilities
 * and has a very low false-positive rate.
 *
 * Architecture note:
 * ─────────────────
 * The scanner uses a language-agnostic LanguageParseResult interface. To add a
 * new language, create a parser module that returns a LanguageParseResult and
 * register its extensions in LANGUAGE_EXTENSIONS (cli.ts / server.ts).
 * No changes to the core finding/reporting pipeline are needed.
 */

import * as fs from 'fs';
import type { Finding } from './reporter';

export interface PythonParseResult {
  language: 'python';
  code: string;
  lines: string[];
  filePath: string;
}

export function parsePythonFile(filePath: string): PythonParseResult {
  const code = fs.readFileSync(filePath, 'utf-8');
  return parsePythonCode(code, filePath);
}

export function parsePythonCode(code: string, filePath = 'input.py'): PythonParseResult {
  return { language: 'python', code, lines: code.split('\n'), filePath };
}

// ── Pattern-based detectors ───────────────────────────────────────────────────

interface PythonPattern {
  type: string;
  severity: Finding['severity'];
  pattern: RegExp;
  message: string;
}

const PYTHON_PATTERNS: PythonPattern[] = [
  // SQL injection via string formatting / concatenation
  {
    type: 'SQL_INJECTION',
    severity: 'critical',
    pattern: /\.execute\s*\(\s*(?:f['""]|['""][^'"")]*%\s*\(|['""][^'"")]*\+)/,
    message:
      'Python SQL execute() call uses string interpolation or concatenation. ' +
      'Use parameterised queries (cursor.execute(query, params)) instead.',
  },
  // OS command injection via os.system / subprocess.call with shell=True + variable
  {
    type: 'COMMAND_INJECTION',
    severity: 'critical',
    pattern: /os\.system\s*\(\s*(?!['"][^'"")]*['""](?:\s*\)|$))/,
    message:
      'os.system() called with a non-literal argument. ' +
      'Use subprocess.run() with a list of arguments and shell=False.',
  },
  {
    type: 'COMMAND_INJECTION',
    severity: 'critical',
    pattern: /subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True/,
    message:
      'subprocess called with shell=True. If any part of the command is user-controlled, ' +
      'this allows arbitrary shell command injection. Pass a list of arguments with shell=False.',
  },
  // eval / exec with dynamic content
  {
    type: 'EVAL_INJECTION',
    severity: 'critical',
    pattern: /\beval\s*\((?!\s*['"`])/,
    message:
      'eval() called with a non-literal argument. eval() executes arbitrary Python code ' +
      'and must never be called with user-supplied input.',
  },
  {
    type: 'EVAL_INJECTION',
    severity: 'high',
    pattern: /\bexec\s*\((?!\s*['"`])/,
    message:
      'exec() called with a non-literal argument. Like eval(), exec() can execute arbitrary ' +
      'code and must not receive untrusted input.',
  },
  // Pickle deserialization
  {
    type: 'UNSAFE_DESERIALIZATION',
    severity: 'critical',
    pattern: /\bpickle\.(loads?|Unpickler)\s*\(/,
    message:
      'pickle.load/loads deserializes arbitrary Python objects. ' +
      'Deserializing untrusted data with pickle can lead to arbitrary code execution. ' +
      'Use json or a safe serialization library instead.',
  },
  // Hardcoded secrets (password/token/secret = literal string)
  {
    type: 'SECRET',
    severity: 'high',
    pattern: /(?:password|passwd|secret|token|api_key|apikey)\s*=\s*['"][^'"]{4,}['"]/i,
    message:
      'Potential hardcoded credential. Secrets must be loaded from environment variables ' +
      'or a secrets manager, never stored in source code.',
  },
  // Weak crypto
  {
    type: 'WEAK_CRYPTO',
    severity: 'high',
    pattern: /hashlib\.(md5|sha1)\s*\(/i,
    message:
      'hashlib.md5() or hashlib.sha1() uses a cryptographically weak algorithm. ' +
      'For security-sensitive hashing, use SHA-256 or SHA-3. ' +
      'For passwords, use bcrypt, scrypt, or Argon2.',
  },
  // Path traversal
  {
    type: 'PATH_TRAVERSAL',
    severity: 'high',
    pattern: /open\s*\(\s*(?:request\.|req\.|f['""].*\{|[^'"")]*\+\s*(?:request|req|user|input))/,
    message:
      'File open() with a path derived from user input. Without path sanitization, ' +
      'attackers can traverse the filesystem with ../.. sequences.',
  },
  // SSRF via requests
  {
    type: 'SSRF',
    severity: 'high',
    pattern: /requests\.(get|post|put|delete|request)\s*\(\s*(?!['"])/,
    message:
      'requests call with a non-literal URL argument. If the URL is user-controlled, ' +
      'attackers can force the server to make requests to internal services (SSRF).',
  },
  // assert for security checks (assert is disabled in optimized mode)
  {
    type: 'INSECURE_ASSERT',
    severity: 'medium',
    pattern: /\bassert\s+(?:is_authenticated|is_admin|has_permission|user\.is|auth)/i,
    message:
      'assert used for authentication or permission checks. ' +
      'Python assert statements are stripped when running with -O (optimized mode). ' +
      'Use explicit if/raise instead.',
  },
  // Bind to 0.0.0.0 without explicit intent
  {
    type: 'INSECURE_BINDING',
    severity: 'low',
    pattern: /(?:host|bind)\s*=\s*['"]0\.0\.0\.0['"]/,
    message:
      'Server bound to 0.0.0.0. This exposes the service on all network interfaces. ' +
      'In production, bind to a specific interface or use a reverse proxy.',
  },
];

/**
 * Scans a parsed Python source for security vulnerabilities using pattern matching.
 * Returns findings in the same Finding format as JS/TS detectors.
 */
export function scanPython(result: PythonParseResult): Finding[] {
  const findings: Finding[] = [];

  result.lines.forEach((line, idx) => {
    const lineNum = idx + 1;
    const trimmed = line.trim();

    // Skip pure comments
    if (trimmed.startsWith('#')) return;

    for (const { type, severity, pattern, message } of PYTHON_PATTERNS) {
      if (pattern.test(line)) {
        findings.push({
          type,
          severity,
          line: lineNum,
          column: line.search(/\S/),
          snippet: trimmed.slice(0, 100),
          message,
          file: result.filePath,
        });
      }
    }
  });

  return findings;
}
