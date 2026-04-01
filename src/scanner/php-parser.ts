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
 *   - PERFORMANCE_N_PLUS_ONE (DB queries inside foreach/while loops via PDO/Eloquent)
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
  confidence: number;
}

const PHP_PATTERNS: PHPPattern[] = [
  // ── SQL Injection ───────────────────────────────────────────────────────────
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
  {
    type: 'SQL_INJECTION',
    severity: 'critical',
    pattern: /\b(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)\b/i,
    message:
      'SQL statement concatenated with user-controlled superglobal. Use prepared statements.',
    confidence: 0.9,
  },

  // ── XSS ─────────────────────────────────────────────────────────────────────
  {
    type: 'XSS',
    severity: 'high',
    pattern: /\b(?:echo|print)\s+\$_(?:GET|POST|REQUEST|COOKIE)\b/,
    message:
      'User input from superglobal echoed directly to output without escaping. ' +
      "Use htmlspecialchars($input, ENT_QUOTES, 'UTF-8') to prevent XSS.",
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
      'Use escapeshellarg() and escapeshellcmd() to sanitise arguments.',
    confidence: 0.95,
  },
  {
    type: 'COMMAND_INJECTION',
    severity: 'critical',
    pattern: /`[^`]*\$_(?:GET|POST|REQUEST|COOKIE)/,
    message:
      'Backtick shell execution with user input. This allows arbitrary command injection.',
    confidence: 0.95,
  },

  // ── Path Traversal ─────────────────────────────────────────────────────────
  {
    type: 'PATH_TRAVERSAL',
    severity: 'high',
    pattern: /\b(?:file_get_contents|file_put_contents|fopen|readfile|file)\s*\([^)]*\$_(?:GET|POST|REQUEST)/,
    message:
      'File operation with user-controlled path from superglobal. ' +
      'Use basename() and validate against an allowed directory.',
    confidence: 0.9,
  },
  {
    type: 'PATH_TRAVERSAL',
    severity: 'critical',
    pattern: /\b(?:include|require|include_once|require_once)\s*\(?[^);\n]*\$_(?:GET|POST|REQUEST)/,
    message:
      'PHP include/require with user-controlled path — LFI vulnerability. ' +
      'Never use user input in include/require paths.',
    confidence: 0.95,
  },

  // ── Eval Injection ─────────────────────────────────────────────────────────
  {
    type: 'EVAL_INJECTION',
    severity: 'critical',
    pattern: /\beval\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/,
    message: 'eval() called with user-controlled input. This allows arbitrary PHP code execution.',
    confidence: 0.98,
  },
  {
    type: 'EVAL_INJECTION',
    severity: 'critical',
    pattern: /\bpreg_replace\s*\(\s*['"][^'"]*\/e[^'"]*['"]/,
    message:
      'preg_replace() with /e modifier evaluates replacement as PHP code. ' +
      "Use preg_replace_callback() instead.",
    confidence: 0.95,
  },

  // ── Hardcoded Secrets ───────────────────────────────────────────────────────
  {
    type: 'SECRET_HARDCODED',
    severity: 'high',
    pattern: /\$(?:password|passwd|api_key|apikey|secret|token|access_key|private_key)\s*=\s*["'][^"']{8,}["']/i,
    message:
      'Hardcoded credential or secret detected. Store secrets in environment variables.',
    confidence: 0.85,
  },

  // ── SSRF ───────────────────────────────────────────────────────────────────
  {
    type: 'SSRF',
    severity: 'high',
    pattern: /\bfile_get_contents\s*\([^)]*\$_(?:GET|POST|REQUEST)/,
    message:
      'file_get_contents() called with user-controlled URL — SSRF vulnerability.',
    confidence: 0.9,
  },
  {
    type: 'SSRF',
    severity: 'high',
    pattern: /\bcurl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$_(?:GET|POST|REQUEST)/,
    message:
      'curl request URL set from user-controlled superglobal — SSRF vulnerability.',
    confidence: 0.92,
  },

  // ── Open Redirect ──────────────────────────────────────────────────────────
  {
    type: 'OPEN_REDIRECT',
    severity: 'medium',
    pattern: /\bheader\s*\(\s*["']Location:\s*\$_(?:GET|POST|REQUEST|COOKIE)/,
    message:
      'Open redirect via header() with user-controlled URL.',
    confidence: 0.9,
  },
  {
    type: 'OPEN_REDIRECT',
    severity: 'medium',
    pattern: /\bheader\s*\(\s*["']Location:\s*[^"']*\$_(?:GET|POST|REQUEST)/,
    message:
      'Open redirect: header Location includes user-controlled superglobal.',
    confidence: 0.85,
  },

  // ── Unsafe Deserialization ──────────────────────────────────────────────────
  {
    type: 'UNSAFE_DESERIALIZATION',
    severity: 'critical',
    pattern: /\bunserialize\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE|SESSION)/,
    message:
      'unserialize() called with user-controlled data. Use json_decode() instead.',
    confidence: 0.95,
  },

  // ── Insecure Random ─────────────────────────────────────────────────────────
  {
    type: 'INSECURE_RANDOM',
    severity: 'medium',
    pattern: /\brand\s*\(/,
    message: 'rand() is not cryptographically secure. Use random_int() for security-sensitive values.',
    confidence: 0.8,
  },
  {
    type: 'INSECURE_RANDOM',
    severity: 'medium',
    pattern: /\bmt_rand\s*\(/,
    message: 'mt_rand() is predictable. Use random_int() or random_bytes() for cryptographic use.',
    confidence: 0.8,
  },

  // ── Weak Crypto ────────────────────────────────────────────────────────────
  {
    type: 'WEAK_CRYPTO',
    severity: 'high',
    pattern: /\bmd5\s*\(/,
    message: 'MD5 is broken. Use password_hash() for passwords, hash("sha256",...) for integrity.',
    confidence: 0.85,
  },
  {
    type: 'WEAK_CRYPTO',
    severity: 'high',
    pattern: /\bsha1\s*\(/,
    message: 'SHA-1 is deprecated for security use. Use password_hash() or hash("sha256",...).',
    confidence: 0.8,
  },

  // ── XML Injection ──────────────────────────────────────────────────────────
  {
    type: 'XML_INJECTION',
    severity: 'high',
    pattern: /\bsimplexml_load_string\s*\(/,
    message:
      'simplexml_load_string() without disabling external entities is vulnerable to XXE.',
    confidence: 0.75,
  },

  // ── SSTI (Twig) ────────────────────────────────────────────────────────────
  {
    type: 'SSTI',
    severity: 'high',
    pattern: /->render\s*\(\s*(?:.*?)createTemplate\s*\([^)]*\$_(?:GET|POST|REQUEST)/,
    message:
      'Twig template created from user-controlled input — SSTI vulnerability.',
    confidence: 0.9,
  },

  // ── Insecure Binding ───────────────────────────────────────────────────────
  {
    type: 'INSECURE_BINDING',
    severity: 'low',
    pattern: /['"]0\.0\.0\.0['"]/,
    message: 'Server bound to 0.0.0.0. Use a specific interface or reverse proxy in production.',
    confidence: 0.6,
  },

  // ── LDAP Injection ────────────────────────────────────────────────────────
  {
    type: 'LDAP_INJECTION',
    severity: 'high',
    pattern: /\b(?:ldap_search|ldap_list|ldap_read)\s*\([^)]*\$_(?:GET|POST|REQUEST)/,
    message:
      'LDAP query function called with user-controlled filter from superglobal. ' +
      'Use ldap_escape() to sanitise the filter argument before passing it to the query.',
    confidence: 0.92,
  },
  {
    type: 'LDAP_INJECTION',
    severity: 'high',
    pattern: /\b(?:ldap_search|ldap_list|ldap_read)\s*\([^,]+,\s*[^,]+,\s*["'][^"']*\.\s*\$(?:_(?:GET|POST|REQUEST)|input|user|param)/,
    message:
      'LDAP filter built with string concatenation of user input. ' +
      'Use ldap_escape($input, "", LDAP_ESCAPE_FILTER) to prevent LDAP injection.',
    confidence: 0.9,
  },
  {
    type: 'LDAP_INJECTION',
    severity: 'high',
    pattern: /\b(?:ldap_search|ldap_list|ldap_read)\s*\([^,]+,\s*[^,]+,\s*"\$[^"]*(?:\$_(?:GET|POST|REQUEST)|param|input|user)/i,
    message:
      'LDAP filter uses PHP string interpolation with user-controlled variable. ' +
      'Sanitise with ldap_escape() before interpolating into the filter string.',
    confidence: 0.88,
  },
];

// ── Stateful N+1 detector ─────────────────────────────────────────────────────
//
// Detects PDO/Eloquent/DB query calls inside foreach or while loops.

const LOOP_START_PATTERN = /\b(?:foreach|while)\s*\(/;
// PDO: $stmt->execute, $pdo->query, $db->query, ->fetchAll, ->fetch
// Eloquent: Model::find, Model::where, ->get(), ::all()
const DB_QUERY_IN_LOOP_PATTERN =
  /\b(?:\$\w+->(?:execute|query|fetchAll|fetch|fetchObject|prepare)\s*\(|->(?:find|where|get|all|first|select)\s*\(|DB::(?:select|table|query|statement)\s*\()/;

function detectN1(lines: string[], filePath: string): Finding[] {
  const findings: Finding[] = [];
  let inLoop = false;
  let loopBraceDepth = 0;
  let loopStartLine = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const trimmed = line.trim();

    if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) continue;

    if (!inLoop) {
      if (LOOP_START_PATTERN.test(line)) {
        inLoop = true;
        loopStartLine = i + 1;
        loopBraceDepth = 0;
      }
    }

    if (inLoop) {
      for (const char of line) {
        if (char === '{') loopBraceDepth++;
        if (char === '}') loopBraceDepth--;
      }

      if (DB_QUERY_IN_LOOP_PATTERN.test(line) && inLoop) {
        findings.push({
          type: 'PERFORMANCE_N_PLUS_ONE',
          severity: 'low',
          line: i + 1,
          column: line.search(/\S/),
          snippet: trimmed.slice(0, 100),
          message:
            'PDO/Eloquent query inside a foreach/while loop — N+1 query pattern. ' +
            'Each loop iteration issues a separate SQL round-trip. ' +
            'Use eager loading (Eloquent with()), batch queries, or a JOIN to reduce round-trips.',
          confidence: 0.8,
          file: filePath,
        });
      }

      if (loopBraceDepth <= 0 && loopStartLine > 0) {
        inLoop = false;
        loopStartLine = 0;
      }
    }
  }

  return findings;
}

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
    if (
      trimmed.startsWith('//') ||
      trimmed.startsWith('#') ||
      trimmed.startsWith('*') ||
      trimmed.startsWith('/*')
    )
      return;

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

  // Stateful N+1 detection
  findings.push(...detectN1(result.lines, result.filePath));

  return findings;
}
