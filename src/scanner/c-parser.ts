/**
 * C/C++ language support for the AI Code Security Scanner.
 *
 * This module implements a regex-based scan pass for C and C++ files (.c, .cpp,
 * .cc, .cxx, .h, .hpp). It operates on raw source lines with pattern matching —
 * no native compilation or libclang required. Patterns are conservative to
 * minimise false positives in real-world systems code.
 *
 * Covered vulnerability classes:
 *   - BUFFER_OVERFLOW (unsafe string/buffer functions: gets, strcpy, strcat, sprintf, scanf)
 *   - FORMAT_STRING (printf/fprintf family with non-literal format strings)
 *   - COMMAND_INJECTION (system() / popen() with string concatenation or user input)
 *   - SECRET_HARDCODED (hardcoded credentials in string literals)
 *   - PATH_TRAVERSAL (fopen/open with user-controlled paths)
 *   - INSECURE_RANDOM (rand() / srand(time()) for security use)
 *   - WEAK_CRYPTO (MD5, SHA1 via common OpenSSL library calls)
 */

import * as fs from 'fs';
import type { Finding } from './reporter';

export interface CParseResult {
  language: 'c';
  code: string;
  lines: string[];
  filePath: string;
}

export function parseCFile(filePath: string): CParseResult {
  const code = fs.readFileSync(filePath, 'utf-8');
  return parseCCode(code, filePath);
}

export function parseCCode(code: string, filePath = 'input.c'): CParseResult {
  return { language: 'c', code, lines: code.split('\n'), filePath };
}

// ── Pattern-based detectors ───────────────────────────────────────────────────

interface CPattern {
  type: string;
  severity: Finding['severity'];
  pattern: RegExp;
  message: string;
}

const C_PATTERNS: CPattern[] = [
  // Buffer overflow — unsafe C string/buffer functions
  {
    type: 'BUFFER_OVERFLOW',
    severity: 'critical',
    pattern: /\bgets\s*\(/,
    message:
      'gets() is unconditionally unsafe — it performs no bounds checking and will overflow any ' +
      'fixed-size buffer. Replace with fgets(buf, sizeof(buf), stdin).',
  },
  {
    type: 'BUFFER_OVERFLOW',
    severity: 'high',
    pattern: /\bstrcpy\s*\(/,
    message:
      'strcpy() does not check the destination buffer size. If the source string exceeds the ' +
      'destination, this causes a buffer overflow. Use strlcpy() or strncpy() with explicit bounds.',
  },
  {
    type: 'BUFFER_OVERFLOW',
    severity: 'high',
    pattern: /\bstrcat\s*\(/,
    message:
      'strcat() does not check the destination buffer size. Use strlcat() or strncat() with ' +
      'explicit length bounds to prevent buffer overflows.',
  },
  {
    type: 'BUFFER_OVERFLOW',
    severity: 'high',
    pattern: /\bsprintf\s*\(/,
    message:
      'sprintf() writes to a buffer without a size limit. Use snprintf() with an explicit ' +
      'buffer size argument to prevent buffer overflows.',
  },
  {
    type: 'BUFFER_OVERFLOW',
    severity: 'high',
    pattern: /\bscanf\s*\(\s*"[^"]*%s/,
    message:
      'scanf() with %s format specifier reads an unbounded string into a buffer. ' +
      'Use scanf("%<N>s", buf) with an explicit width limit, or use fgets().',
  },
  {
    type: 'BUFFER_OVERFLOW',
    severity: 'high',
    pattern: /\bvsprintf\s*\(/,
    message:
      'vsprintf() writes to a buffer without a size limit. Use vsnprintf() with an explicit size.',
  },

  // Format string vulnerabilities
  {
    type: 'FORMAT_STRING',
    severity: 'critical',
    pattern: /\b(?:printf|fprintf|syslog)\s*\(\s*(?!")[^,)]+(?:,|\))/,
    message:
      'printf/fprintf called with a non-literal format string as the first argument. If the ' +
      'format string is user-controlled, this allows reading arbitrary memory or code execution. ' +
      'Always use a literal format string: printf("%s", user_input).',
  },

  // Command injection via system() and popen()
  {
    type: 'COMMAND_INJECTION',
    severity: 'critical',
    pattern: /\bsystem\s*\([^)]*(?:sprintf|strcat|snprintf|argv|input|user|param)/,
    message:
      'system() called with what appears to be a dynamically-constructed command string. ' +
      'If any part is user-controlled, this allows arbitrary command injection. ' +
      'Use execve() with a fixed argument list instead.',
  },
  {
    type: 'COMMAND_INJECTION',
    severity: 'critical',
    pattern: /\bpopen\s*\([^)]*(?:sprintf|strcat|argv|input|user)/,
    message:
      'popen() called with a dynamically-constructed command. User-controlled input in shell ' +
      'commands allows command injection. Use execve() with individual arguments.',
  },

  // Hardcoded secrets
  {
    type: 'SECRET_HARDCODED',
    severity: 'high',
    pattern: /(?:password|passwd|secret|token|api_key|apikey|private_key)\s*=\s*"[^"]{4,}"/i,
    message:
      'Potential hardcoded credential in C/C++ source. Secrets must be loaded from environment ' +
      'variables (getenv()) or a configuration file outside the source tree.',
  },

  // Path traversal
  {
    type: 'PATH_TRAVERSAL',
    severity: 'high',
    pattern: /\b(?:fopen|open)\s*\([^)]*(?:argv|input|user|param|getenv)/,
    message:
      'fopen()/open() called with a user-controlled path. Without path canonicalisation, ' +
      'attackers can traverse the filesystem using ../ sequences. Use realpath() to resolve and ' +
      'validate the path before opening.',
  },

  // Insecure random
  {
    type: 'INSECURE_RANDOM',
    severity: 'medium',
    pattern: /\brand\s*\(\s*\)/,
    message:
      'rand() is a low-quality pseudo-random number generator and must not be used for ' +
      'security-sensitive values (tokens, session IDs, cryptographic keys). ' +
      'Use getrandom() on Linux or arc4random() on BSD/macOS.',
  },
  {
    type: 'INSECURE_RANDOM',
    severity: 'medium',
    pattern: /\bsrand\s*\(\s*time\s*\(/,
    message:
      'srand(time(NULL)) seeds the PRNG with a predictable value. An attacker who knows ' +
      'the approximate process start time can predict all subsequent rand() outputs.',
  },

  // Weak crypto
  {
    type: 'WEAK_CRYPTO',
    severity: 'high',
    pattern: /\bMD5\s*\(|MD5_Init\s*\(|MD5_Update\s*\(/,
    message:
      'MD5 hashing is cryptographically broken and collision-prone. ' +
      'Use SHA-256 (SHA256_Init/SHA256_Update/SHA256_Final) or SHA-3 for security-sensitive hashing.',
  },
  {
    type: 'WEAK_CRYPTO',
    severity: 'high',
    pattern: /\bSHA1\s*\(|SHA1_Init\s*\(|SHA_Init\s*\(/,
    message:
      'SHA-1 is cryptographically weak and vulnerable to collision attacks. ' +
      'Use SHA-256 or SHA-3 (SHA256, SHA3_256 in OpenSSL) for security-sensitive hashing.',
  },
];

/**
 * Scans a parsed C/C++ source for security vulnerabilities using pattern matching.
 * Returns findings in the same Finding format as other language detectors.
 */
export function scanC(result: CParseResult): Finding[] {
  const findings: Finding[] = [];

  result.lines.forEach((line, idx) => {
    const lineNum = idx + 1;
    const trimmed = line.trim();

    // Skip pure comments and preprocessor directives
    if (
      trimmed.startsWith('//') ||
      trimmed.startsWith('*') ||
      trimmed.startsWith('/*') ||
      trimmed.startsWith('#include') ||
      trimmed.startsWith('#define') ||
      trimmed.startsWith('#pragma')
    ) return;

    for (const { type, severity, pattern, message } of C_PATTERNS) {
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
