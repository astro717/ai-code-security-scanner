/**
 * Go language support for the AI Code Security Scanner.
 *
 * This module implements a regex-based scan pass for Go files. Like the Python
 * scanner, it operates on raw source lines with pattern matching — no Go AST
 * parser or native bindings required. The patterns are deliberately conservative
 * to minimise false positives.
 *
 * Covered vulnerability classes:
 *   - SSRF (net/http with user input)
 *   - SQL_INJECTION (fmt.Sprintf in queries)
 *   - COMMAND_INJECTION (exec.Command with user input)
 *   - SECRET_HARDCODED (hardcoded credentials)
 *   - EVAL_INJECTION (unsafe reflect / template execution)
 *   - WEAK_CRYPTO (md5, sha1)
 *   - PATH_TRAVERSAL (filepath.Join with user input)
 *   - INSECURE_RANDOM (math/rand for security)
 */

import * as fs from 'fs';
import type { Finding } from './reporter';

export interface GoParseResult {
  language: 'go';
  code: string;
  lines: string[];
  filePath: string;
}

export function parseGoFile(filePath: string): GoParseResult {
  const code = fs.readFileSync(filePath, 'utf-8');
  return parseGoCode(code, filePath);
}

export function parseGoCode(code: string, filePath = 'input.go'): GoParseResult {
  return { language: 'go', code, lines: code.split('\n'), filePath };
}

// ── Pattern-based detectors ───────────────────────────────────────────────────

interface GoPattern {
  type: string;
  severity: Finding['severity'];
  pattern: RegExp;
  message: string;
}

const GO_PATTERNS: GoPattern[] = [
  // SQL injection via fmt.Sprintf in query strings
  {
    type: 'SQL_INJECTION',
    severity: 'critical',
    pattern: /(?:db|tx)\.\w*(?:Query|Exec)\w*\s*\(\s*fmt\.Sprintf\s*\(/,
    message:
      'SQL query built with fmt.Sprintf. User input interpolated into SQL strings ' +
      'leads to SQL injection. Use parameterised queries (db.Query(query, args...)) instead.',
  },
  {
    type: 'SQL_INJECTION',
    severity: 'critical',
    pattern: /(?:db|tx)\.\w*(?:Query|Exec)\w*\s*\(\s*[^")]*\+/,
    message:
      'SQL query built with string concatenation. Use parameterised queries ' +
      '(db.Query(query, args...)) to prevent SQL injection.',
  },

  // Command injection via exec.Command with user input
  {
    type: 'COMMAND_INJECTION',
    severity: 'critical',
    pattern: /exec\.Command\s*\(\s*(?!")[^)]*(?:request|req\.|r\.|input|param|query|args|os\.Args)/i,
    message:
      'exec.Command() called with what appears to be user-controlled input. ' +
      'Validate and sanitise all arguments before passing them to external commands.',
  },
  {
    type: 'COMMAND_INJECTION',
    severity: 'critical',
    pattern: /exec\.Command\s*\(\s*"(?:sh|bash|cmd)"\s*,\s*"-c"\s*,/,
    message:
      'exec.Command invokes a shell with -c flag. If any part of the command string is ' +
      'user-controlled, this allows arbitrary command injection. Pass arguments as separate ' +
      'list elements without a shell intermediary.',
  },

  // SSRF via http.Get / http.Post with non-literal URL
  {
    type: 'SSRF',
    severity: 'high',
    pattern: /http\.(?:Get|Post|PostForm|Head)\s*\(\s*(?!")[^)]*(?:request|req\.|r\.|input|param|query)/i,
    message:
      'HTTP request made with a URL that appears to include user-controlled input. ' +
      'Without URL validation, attackers can force the server to make requests to ' +
      'internal services (SSRF).',
  },
  {
    type: 'SSRF',
    severity: 'high',
    pattern: /http\.NewRequest\s*\([^)]*(?:request|req\.|r\.|input|param|query)/i,
    message:
      'http.NewRequest with a URL derived from user input. Validate and restrict ' +
      'the target URL to prevent Server-Side Request Forgery.',
  },

  // Hardcoded secrets
  {
    type: 'SECRET_HARDCODED',
    severity: 'high',
    pattern: /(?:password|passwd|secret|token|apiKey|api_key)\s*(?::=|=)\s*"[^"]{4,}"/i,
    message:
      'Potential hardcoded credential in Go source. Secrets must be loaded from ' +
      'environment variables or a secrets manager, never stored in source code.',
  },

  // Weak crypto — md5, sha1
  {
    type: 'WEAK_CRYPTO',
    severity: 'high',
    pattern: /(?:md5|sha1)\.(?:New|Sum)\s*\(/i,
    message:
      'MD5 or SHA-1 used for hashing. These are cryptographically weak. ' +
      'Use SHA-256 (crypto/sha256) or SHA-3 for security-sensitive hashing. ' +
      'For passwords, use bcrypt or Argon2.',
  },

  // Path traversal via filepath.Join with user input
  {
    type: 'PATH_TRAVERSAL',
    severity: 'high',
    pattern: /filepath\.Join\s*\([^)]*(?:request|req\.|r\.|input|param|query|FormValue|URL\.Query)/i,
    message:
      'filepath.Join called with user-controlled input. Without path sanitisation, ' +
      'attackers can traverse the filesystem with ../ sequences. Use filepath.Clean ' +
      'and validate the result stays within the intended directory.',
  },

  // Insecure random — math/rand instead of crypto/rand
  {
    type: 'INSECURE_RANDOM',
    severity: 'medium',
    pattern: /\bmath\/rand\b/,
    message:
      'math/rand imported — this is not cryptographically secure. For tokens, ' +
      'passwords, or session IDs, use crypto/rand instead.',
  },
  {
    type: 'INSECURE_RANDOM',
    severity: 'medium',
    pattern: /\brand\.(?:Int|Intn|Float64|Float32|Seed)\s*\(/,
    message:
      'rand function call detected. If this is math/rand, it is not suitable for ' +
      'security-sensitive values. Use crypto/rand.Read() instead.',
  },

  // Unsafe template execution with user input
  {
    type: 'EVAL_INJECTION',
    severity: 'high',
    pattern: /template\.(?:New|Must)\s*\([^)]*\)\.Parse\s*\([^)]*(?:request|req\.|r\.|input|body)/i,
    message:
      'Go template parsed from user-controlled input. This can lead to server-side ' +
      'template injection. Use predefined template files, not user-supplied strings.',
  },

  // Unvalidated redirect
  {
    type: 'OPEN_REDIRECT',
    severity: 'medium',
    pattern: /http\.Redirect\s*\([^)]*(?:request|req\.|r\.(?:URL|Form|Header)|FormValue|query)/i,
    message:
      'http.Redirect with a target derived from user input. Without validation, ' +
      'this allows open redirect attacks. Ensure the redirect target is a relative ' +
      'URL or belongs to a trusted domain.',
  },
];

/**
 * Scans a parsed Go source for security vulnerabilities using pattern matching.
 * Returns findings in the same Finding format as JS/TS and Python detectors.
 */
export function scanGo(result: GoParseResult): Finding[] {
  const findings: Finding[] = [];

  result.lines.forEach((line, idx) => {
    const lineNum = idx + 1;
    const trimmed = line.trim();

    // Skip pure comments
    if (trimmed.startsWith('//')) return;

    for (const { type, severity, pattern, message } of GO_PATTERNS) {
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
