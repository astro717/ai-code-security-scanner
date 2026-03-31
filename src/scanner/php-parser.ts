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
 *   - MISSING_AUTH (endpoint handlers lacking session/auth checks before sensitive ops)
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
      'eval() called with user-controlled input. This allows arbitrary PHP code execution. ' +
      'Never pass user input to eval().',
    confidence: 0.98,
  },
  {
    type: 'EVAL_INJECTION',
    severity: 'critical',
    pattern: /\bpreg_replace\s*\(\s*['"][^'"]*\/e[^'"]*['"]/,
    message:
      'preg_replace() used with /e modifier, which evaluates the replacement as PHP code. ' +
      "Use preg_replace_callback() instead — the /e modifier was removed in PHP 7.",
    confidence: 0.95,
  },

  // ── Hardcoded Secrets ───────────────────────────────────────────────────────
  {
    type: 'SECRET_HARDCODED',
    severity: 'high',
    pattern: /\$(?:password|passwd|api_key|apikey|secret|token|access_key|private_key)\s*=\s*["'][^"']{8,}["']/i,
    message:
      'Hardcoded credential or secret detected. Store secrets in environment variables ' +
      'or a secrets manager and retrieve with getenv() at runtime.',
    confidence: 0.85,
  },

  // ── SSRF ───────────────────────────────────────────────────────────────────
  {
    type: 'SSRF',
    severity: 'high',
    pattern: /\bfile_get_contents\s*\([^)]*\$_(?:GET|POST|REQUEST)/,
    message:
      'file_get_contents() called with user-controlled URL — Server-Side Request Forgery (SSRF). ' +
      'Validate and whitelist the URL scheme and host before making server-side requests.',
    confidence: 0.9,
  },
  {
    type: 'SSRF',
    severity: 'high',
    pattern: /\bcurl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$_(?:GET|POST|REQUEST)/,
    message:
      'curl request URL set from user-controlled superglobal — SSRF vulnerability. ' +
      'Validate URLs against an allowlist before making outbound requests.',
    confidence: 0.92,
  },

  // ── Open Redirect ──────────────────────────────────────────────────────────
  {
    type: 'OPEN_REDIRECT',
    severity: 'medium',
    pattern: /\bheader\s*\(\s*["']Location:\s*\$_(?:GET|POST|REQUEST|COOKIE)/,
    message:
      'Open redirect via header() with user-controlled URL. ' +
      'Validate redirects against an allowlist of trusted destinations.',
    confidence: 0.9,
  },
  {
    type: 'OPEN_REDIRECT',
    severity: 'medium',
    pattern: /\bheader\s*\(\s*["']Location:\s*[^"']*\$_(?:GET|POST|REQUEST)/,
    message:
      'Open redirect: header Location includes user-controlled superglobal. ' +
      'Restrict redirect targets to known safe URLs.',
    confidence: 0.85,
  },

  // ── Unsafe Deserialization ──────────────────────────────────────────────────
  {
    type: 'UNSAFE_DESERIALIZATION',
    severity: 'critical',
    pattern: /\bunserialize\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE|SESSION)/,
    message:
      'unserialize() called with user-controlled data. This can lead to Remote Code Execution ' +
      'via PHP object injection. Use json_decode() for data exchange instead.',
    confidence: 0.95,
  },

  // ── Insecure Random ─────────────────────────────────────────────────────────
  {
    type: 'INSECURE_RANDOM',
    severity: 'medium',
    pattern: /\brand\s*\(/,
    message:
      'rand() is not cryptographically secure. Use random_int() for security-sensitive ' +
      'values such as tokens, nonces, and CSRF values.',
    confidence: 0.8,
  },
  {
    type: 'INSECURE_RANDOM',
    severity: 'medium',
    pattern: /\bmt_rand\s*\(/,
    message:
      'mt_rand() (Mersenne Twister) is predictable and not suitable for security use. ' +
      'Use random_int() or random_bytes() for cryptographically secure randomness.',
    confidence: 0.8,
  },

  // ── Weak Crypto ────────────────────────────────────────────────────────────
  {
    type: 'WEAK_CRYPTO',
    severity: 'high',
    pattern: /\bmd5\s*\(/,
    message:
      'MD5 is a broken hash function. For passwords, use password_hash() with PASSWORD_BCRYPT ' +
      "or PASSWORD_ARGON2ID. For data integrity, use hash('sha256', ...).",
    confidence: 0.85,
  },
  {
    type: 'WEAK_CRYPTO',
    severity: 'high',
    pattern: /\bsha1\s*\(/,
    message:
      'SHA-1 is deprecated for security use. For passwords, use password_hash(). ' +
      "For data integrity, use hash('sha256', ...).",
    confidence: 0.8,
  },

  // ── XML Injection ──────────────────────────────────────────────────────────
  {
    type: 'XML_INJECTION',
    severity: 'high',
    pattern: /\bsimplexml_load_string\s*\(/,
    message:
      'simplexml_load_string() without disabling external entities is vulnerable to XXE. ' +
      "Use libxml_disable_entity_loader(true) and LIBXML_NOENT flag, or switch to json_decode() for data exchange.",
    confidence: 0.75,
  },
  {
    type: 'XML_INJECTION',
    severity: 'high',
    pattern: /\bnew\s+DOMDocument\s*\(\s*\)(?:[^;]*\n){0,3}.*\bloadXML\s*\([^)]*\$_(?:GET|POST|REQUEST)/,
    message:
      'DOMDocument::loadXML() with user-controlled input is vulnerable to XXE injection. ' +
      'Disable external entities before parsing: $dom->substituteEntities = false.',
    confidence: 0.8,
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

  // ── Missing Auth ───────────────────────────────────────────────────────────
  // Flags endpoint handlers that process sensitive superglobal data ($_POST,
  // $_GET for mutations) without a preceding session_start() / auth check.
  // Pattern: a function/method that accesses $_POST or makes a DB call but
  // does NOT contain session_start() or any is_logged_in / auth guard call.
  {
    type: 'MISSING_AUTH',
    severity: 'high',
    pattern: /\$_SERVER\s*\[\s*['"]REQUEST_METHOD['"]\s*\]\s*===?\s*['"](?:POST|PUT|DELETE|PATCH)['"]/,
    message:
      'HTTP method check detected without an adjacent auth guard. Ensure sensitive endpoints ' +
      'call session_start() and verify user identity (e.g. $_SESSION["user_id"] or an auth middleware) ' +
      'before processing the request.',
    confidence: 0.7,
  },
];

// ── Stateful MISSING_AUTH detector ───────────────────────────────────────────
//
// Scans functions/methods that access $_POST/$_GET for mutations but lack
// any session_start() or auth-checking call in their body.

const AUTH_GUARD_PATTERN = /\b(?:session_start|is_logged_in|checkAuth|requireAuth|Auth::check|auth_required|isAuthenticated)\s*\(/i;
const SENSITIVE_OP_PATTERN = /\$_(?:POST|PUT|DELETE|PATCH)\b|\$_GET\[.*(?:id|action|delete|update|create)/i;
const FUNCTION_START_PATTERN = /\bfunction\s+\w+\s*\(/;

function detectMissingAuth(lines: string[], filePath: string): Finding[] {
  const findings: Finding[] = [];
  let inFunction = false;
  let functionStartLine = 0;
  let braceDepth = 0;
  let hasSensitiveOp = false;
  let hasAuthGuard = false;
  let functionName = '';

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const trimmed = line.trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) continue;

    if (!inFunction) {
      const fnMatch = line.match(/\bfunction\s+(\w+)\s*\(/);
      if (fnMatch) {
        inFunction = true;
        functionStartLine = i + 1;
        braceDepth = 0;
        hasSensitiveOp = false;
        hasAuthGuard = false;
        functionName = fnMatch[1] ?? 'anonymous';
      }
    }

    if (inFunction) {
      for (const char of line) {
        if (char === '{') braceDepth++;
        if (char === '}') braceDepth--;
      }

      if (AUTH_GUARD_PATTERN.test(line)) hasAuthGuard = true;
      if (SENSITIVE_OP_PATTERN.test(line)) hasSensitiveOp = true;

      if (braceDepth === 0 && functionStartLine > 0) {
        if (hasSensitiveOp && !hasAuthGuard) {
          findings.push({
            type: 'MISSING_AUTH',
            severity: 'high',
            line: functionStartLine,
            column: 0,
            snippet: `function ${functionName}(...)`,
            message:
              `Function '${functionName}' processes sensitive user input ($_POST/$_GET) without an ` +
              'auth guard. Add session_start() and verify $_SESSION["user_id"] (or equivalent) ' +
              'at the top of the function.',
            confidence: 0.75,
            file: filePath,
          });
        }
        inFunction = false;
        functionStartLine = 0;
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

  // Stateful MISSING_AUTH detection
  findings.push(...detectMissingAuth(result.lines, result.filePath));

  return findings;
}
