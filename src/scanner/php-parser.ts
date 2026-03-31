/**
 * PHP language support for the AI Code Security Scanner.
 *
 * This module implements a regex-based scan pass for PHP files. It operates on
 * raw source lines with pattern matching — no native PHP bindings required.
 * Patterns focus on common web vulnerabilities in AI-generated PHP code.
 *
 * Covered vulnerability classes:
 *   - SQL_INJECTION (string interpolation / concatenation in mysqli/PDO queries)
 *   - XSS (echo/print with unsanitized user input)
 *   - COMMAND_INJECTION (shell_exec, exec, system, passthru, backtick with user input)
 *   - PATH_TRAVERSAL (file_get_contents, include, require with user input)
 *   - EVAL_INJECTION (eval with user input)
 *   - SECRET_HARDCODED (hardcoded credentials)
 *   - SSRF (curl/file_get_contents with user-controlled URL)
 *   - OPEN_REDIRECT (header Location with user input)
 *   - UNSAFE_DESERIALIZATION (unserialize with user input)
 *   - INSECURE_RANDOM (rand/mt_rand for security use)
 *   - WEAK_CRYPTO (md5/sha1 for security hashing)
 *   - XML_INJECTION (simplexml_load_string without entity disabling)
 *   - SSTI (Twig raw filter with user input)
 */

import * as fs from 'fs';
import type { Finding } from './reporter';

export interface PHPParseResult {
  language: 'php';
  code: string;
  lines: string[];
  filePath: string;
}

export function parsePHPFile(filePath: string): PHPParseResult {
  const code = fs.readFileSync(filePath, 'utf-8');
  return parsePHPCode(code, filePath);
}

export function parsePHPCode(code: string, filePath = 'input.php'): PHPParseResult {
  return { language: 'php', code, lines: code.split('\n'), filePath };
}

// ── Pattern-based detectors ───────────────────────────────────────────────────

interface PHPPattern {
  type: string;
  severity: Finding['severity'];
  pattern: RegExp;
  message: string;
  confidence?: number;
}

const PHP_PATTERNS: PHPPattern[] = [
  // ── SQL Injection ───────────────────────────────────────────────────────────

  // mysqli_query / $mysqli->query with string concatenation or interpolation
  {
    type: 'SQL_INJECTION',
    severity: 'critical',
    pattern: /(?:mysqli_query|->query)\s*\(\s*(?:\$\w+\s*,\s*)?["'][^"'\n]*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)/,
    message:
      'SQL query built with direct concatenation of user input ($_GET/$_POST/$_REQUEST). ' +
      'Use prepared statements with parameterised queries (mysqli_prepare or PDO::prepare).',
    confidence: 0.95,
  },
  {
    type: 'SQL_INJECTION',
    severity: 'critical',
    pattern: /(?:mysqli_query|->query)\s*\(\s*(?:\$\w+\s*,\s*)?"\$[^"]*(?:\$_(?:GET|POST|REQUEST)|param|input|user)/i,
    message:
      'SQL query built with PHP string interpolation containing user input. ' +
      'Use prepared statements (PDO::prepare with bindParam/bindValue) instead.',
    confidence: 0.9,
  },
  // Raw SQL via concatenation (generic)
  {
    type: 'SQL_INJECTION',
    severity: 'critical',
    pattern: /\b(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)\b/i,
    message:
      'SQL statement concatenated with user-controlled superglobal. Use prepared statements ' +
      'with bound parameters to prevent SQL injection.',
    confidence: 0.9,
  },

  // ── XSS ─────────────────────────────────────────────────────────────────────

  {
    type: 'XSS',
    severity: 'high',
    pattern: /\b(?:echo|print)\s+\$_(?:GET|POST|REQUEST|COOKIE)\b/,
    message:
      'User input from superglobal echoed directly to output without escaping. ' +
      'Use htmlspecialchars($input, ENT_QUOTES, \'UTF-8\') to prevent XSS.',
    confidence: 0.95,
  },
  {
    type: 'XSS',
    severity: 'high',
    pattern: /\b(?:echo|print)\s+.*\$_(?:GET|POST|REQUEST|COOKIE)/,
    message:
      'User input from superglobal included in echo/print output. ' +
      'Escape with htmlspecialchars() before rendering to prevent XSS.',
    confidence: 0.85,
  },

  // ── Command Injection ───────────────────────────────────────────────────────

  {
    type: 'COMMAND_INJECTION',
    severity: 'critical',
    pattern: /\b(?:shell_exec|exec|system|passthru|popen|proc_open)\s*\([^)]*\$_(?:GET|POST|REQUEST)/,
    message:
      'Shell execution function called with user-controlled input. ' +
      'This allows arbitrary command execution. Use escapeshellarg() and escapeshellcmd() ' +
      'to sanitise arguments, or avoid shell commands entirely.',
    confidence: 0.95,
  },
  {
    type: 'COMMAND_INJECTION',
    severity: 'critical',
    pattern: /`[^`]*\$_(?:GET|POST|REQUEST|COOKIE)/,
    message:
      'Backtick shell execution with user input. This allows arbitrary command injection. ' +
      'Avoid backtick execution with user-controlled data entirely.',
    confidence: 0.95,
  },

  // ── Path Traversal ─────────────────────────────────────────────────────────

  {
    type: 'PATH_TRAVERSAL',
    severity: 'high',
    pattern: /\b(?:file_get_contents|file_put_contents|fopen|readfile|file)\s*\([^)]*\$_(?:GET|POST|REQUEST)/,
    message:
      'File operation with user-controlled path from superglobal. ' +
      'Without path validation, attackers can read/write arbitrary files via ../.. sequences. ' +
      'Use basename() and validate against an allowed directory.',
    confidence: 0.9,
  },
  {
    type: 'PATH_TRAVERSAL',
    severity: 'critical',
    pattern: /\b(?:include|require|include_once|require_once)\s*\(?[^);\n]*\$_(?:GET|POST|REQUEST)/,
    message:
      'PHP include/require with user-controlled path — Local File Inclusion (LFI) vulnerability. ' +
      'Attackers can include arbitrary files, leading to code execution. ' +
      'Never use user input in include/require paths.',
    confidence: 0.95,
  },

  // ── Eval Injection ─────────────────────────────────────────────────────────

  {
    type: 'EVAL_INJECTION',
    severity: 'critical',
    pattern: /\beval\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/,
    message:
      'eval() called with user-controlled input — this allows arbitrary PHP code execution. ' +
      'Remove eval entirely or use a safe alternative.',
    confidence: 0.95,
  },
  {
    type: 'EVAL_INJECTION',
    severity: 'critical',
    pattern: /\bpreg_replace\s*\(\s*['"]\/[^'"]*\/e['"]/,
    message:
      'preg_replace() with /e modifier evaluates the replacement as PHP code. ' +
      'This is deprecated and dangerous. Use preg_replace_callback() instead.',
    confidence: 0.95,
  },

  // ── Hardcoded Secrets ──────────────────────────────────────────────────────

  {
    type: 'SECRET_HARDCODED',
    severity: 'high',
    pattern: /(?:\$(?:password|passwd|secret|token|api_key|apikey|db_pass))\s*=\s*['"][^'"]{4,}['"]/i,
    message:
      'Potential hardcoded credential in PHP variable. Secrets must be loaded from environment ' +
      'variables (getenv()) or a secrets manager, never stored in source code.',
    confidence: 0.8,
  },

  // ── SSRF ────────────────────────────────────────────────────────────────────

  {
    type: 'SSRF',
    severity: 'high',
    pattern: /\b(?:file_get_contents|curl_setopt.*CURLOPT_URL)\s*\([^)]*\$_(?:GET|POST|REQUEST)/,
    message:
      'HTTP request made to a URL derived from user input. Without URL validation, ' +
      'attackers can force the server to request internal services (SSRF). ' +
      'Validate and whitelist target URLs.',
    confidence: 0.9,
  },
  {
    type: 'SSRF',
    severity: 'high',
    pattern: /curl_setopt\s*\([^)]*CURLOPT_URL\s*,[^)]*\$_(?:GET|POST|REQUEST)/,
    message:
      'cURL URL set from user-controlled input — SSRF risk. ' +
      'Validate the URL against an allowlist before making the request.',
    confidence: 0.9,
  },

  // ── Open Redirect ───────────────────────────────────��──────────────────────

  {
    type: 'OPEN_REDIRECT',
    severity: 'medium',
    pattern: /\bheader\s*\(\s*['"]Location:\s*[^'"]*\$_(?:GET|POST|REQUEST)/,
    message:
      'HTTP redirect with user-controlled Location header. Without validation, ' +
      'this allows open redirect attacks for phishing. Validate that the target ' +
      'is a relative URL or belongs to a trusted domain.',
    confidence: 0.9,
  },

  // ── Unsafe Deserialization ─────────────────────────────────────────────────

  {
    type: 'UNSAFE_DESERIALIZATION',
    severity: 'critical',
    pattern: /\bunserialize\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/,
    message:
      'unserialize() called with user-controlled input. PHP object injection can lead to ' +
      'arbitrary code execution via magic methods (__wakeup, __destruct). ' +
      'Use json_decode() instead, or validate/sign the serialized data.',
    confidence: 0.95,
  },

  // ── Insecure Random ────────────────────────────────────────────────────────

  {
    type: 'INSECURE_RANDOM',
    severity: 'medium',
    pattern: /\b(?:rand|mt_rand|array_rand)\s*\(/,
    message:
      'rand()/mt_rand() are not cryptographically secure. For tokens, passwords, ' +
      'or session IDs, use random_bytes() or random_int() instead.',
    confidence: 0.7,
  },

  // ── Weak Crypto ────────────────────────────────────────────────────────────

  {
    type: 'WEAK_CRYPTO',
    severity: 'high',
    pattern: /\b(?:md5|sha1)\s*\(\s*\$/,
    message:
      'md5()/sha1() used for hashing — these are cryptographically broken. ' +
      'For password hashing, use password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2ID. ' +
      'For data integrity, use hash(\'sha256\', $data).',
    confidence: 0.8,
  },

  // ── XML Injection (XXE) ────────────────────────────────────────────────────

  {
    type: 'XML_INJECTION',
    severity: 'high',
    pattern: /\bsimplexml_load_string\s*\(/,
    message:
      'simplexml_load_string() is vulnerable to XXE attacks by default. ' +
      'Call libxml_disable_entity_loader(true) before parsing, or use ' +
      'LIBXML_NOENT | LIBXML_NONET flags to disable external entities.',
    confidence: 0.75,
  },

  // ── SSTI (Twig) ────────────────────────────────────────────────────────────

  {
    type: 'SSTI',
    severity: 'high',
    pattern: /->render\s*\(\s*(?:.*?)createTemplate\s*\([^)]*\$_(?:GET|POST|REQUEST)/,
    message:
      'Twig template created from user-controlled input — Server-Side Template Injection (SSTI). ' +
      'Always use static template files and pass data as context variables.',
    confidence: 0.9,
  },

  // ── Insecure Binding ───────────────────────────────────────────────────────

  {
    type: 'INSECURE_BINDING',
    severity: 'low',
    pattern: /['"]0\.0\.0\.0['"]/,
    message:
      'Server bound to 0.0.0.0. This exposes the service on all network interfaces. ' +
      'In production, bind to a specific interface or use a reverse proxy.',
    confidence: 0.6,
  },
];

/**
 * Scans a parsed PHP source for security vulnerabilities using pattern matching.
 * Returns findings in the same Finding format as other language detectors.
 */
export function scanPHP(result: PHPParseResult): Finding[] {
  const findings: Finding[] = [];

  result.lines.forEach((line, idx) => {
    const lineNum = idx + 1;
    const trimmed = line.trim();

    // Skip comments
    if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*') || trimmed.startsWith('/*')) return;

    for (const { type, severity, pattern, message, confidence } of PHP_PATTERNS) {
      if (pattern.test(line)) {
        findings.push({
          type,
          severity,
          line: lineNum,
          column: line.search(/\S/),
          snippet: trimmed.slice(0, 100),
          message,
          ...(confidence !== undefined ? { confidence } : {}),
          file: result.filePath,
        });
      }
    }
  });

  return findings;
}
