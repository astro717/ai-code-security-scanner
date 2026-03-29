/**
 * Kotlin / Android language support for the AI Code Security Scanner.
 *
 * Implements regex-based detection for common mobile security issues in
 * Kotlin source files (.kt, .kts). Focused on Android-specific patterns
 * where security mistakes are most common and highest impact.
 *
 * Detected finding types:
 *   SECRET_HARDCODED       — API keys / tokens in source
 *   INSECURE_RANDOM        — java.util.Random for security-sensitive values
 *   WEAK_CRYPTO            — MD5 / SHA-1 MessageDigest calls
 *   INSECURE_SHARED_PREFS  — SharedPreferences storing sensitive data unencrypted
 *   WEBVIEW_LOAD_URL     — WebView.loadUrl with user-controlled input
 *   SQL_INJECTION          — rawQuery / execSQL with string concatenation
 *   PATH_TRAVERSAL         — File() constructor with user-controlled path
 */

import * as fs from 'fs';
import type { Finding } from './reporter';

export interface KotlinParseResult {
  language: 'kotlin';
  code: string;
  lines: string[];
  filePath: string;
}

export function parseKotlinFile(filePath: string): KotlinParseResult {
  const code = fs.readFileSync(filePath, 'utf-8');
  return parseKotlinCode(code, filePath);
}

export function parseKotlinCode(code: string, filePath = 'input.kt'): KotlinParseResult {
  return { language: 'kotlin', code, lines: code.split('\n'), filePath };
}

// ── Pattern-based detectors ───────────────────────────────────────────────────

interface KotlinPattern {
  type: string;
  severity: Finding['severity'];
  pattern: RegExp;
  message: string;
  /** Detection confidence [0.0–1.0]. High-specificity patterns use 0.9+, heuristics use lower values. */
  confidence?: number;
}

const KOTLIN_PATTERNS: KotlinPattern[] = [
  // Hardcoded secrets
  {
    type: 'SECRET_HARDCODED',
    severity: 'high',
    pattern: /(?:val|var|const\s+val)\s+\w*(?:password|passwd|secret|token|api_?key|apiKey|private_?key|access_?key)\w*\s*=\s*"[^"]{4,}"/i,
    message:
      'Potential hardcoded credential in Kotlin source. Secrets must be loaded from ' +
      'environment variables, Android Keystore, or a secure secrets manager.',
    confidence: 0.87,
  },

  // Insecure random for security-sensitive contexts
  {
    type: 'INSECURE_RANDOM',
    severity: 'medium',
    pattern: /\bjava\.util\.Random\s*\(\s*\)|\bRandom\s*\(\s*\)(?!\.nextBits)/,
    message:
      'java.util.Random is not cryptographically secure. For security-sensitive values ' +
      '(tokens, session IDs, nonces) use java.security.SecureRandom instead.',
    confidence: 0.80,
  },

  // Weak crypto — MD5/SHA-1 MessageDigest
  {
    type: 'WEAK_CRYPTO',
    severity: 'high',
    pattern: /MessageDigest\.getInstance\s*\(\s*"(?:MD5|SHA-?1)"/i,
    message:
      'MessageDigest with MD5 or SHA-1 is cryptographically weak. Use SHA-256 or SHA-3 ' +
      'for general hashing. For passwords, use Android Keystore with PBKDF2 or bcrypt.',
    confidence: 0.96,
  },

  // Insecure SharedPreferences — storing sensitive values without EncryptedSharedPreferences
  {
    type: 'INSECURE_SHARED_PREFS',
    severity: 'medium',
    pattern: /\.edit\s*\(\s*\)(?:\s*\.\s*\w+)*\s*\.\s*put(?:String|Int|Long|Float|Boolean)\s*\(\s*"(?:\w*(?:password|token|secret|key)\w*)"/i,
    message:
      'SharedPreferences.putString/putInt storing what appears to be a sensitive value. ' +
      'Use EncryptedSharedPreferences (Jetpack Security) to protect sensitive data at rest.',
    confidence: 0.76,
  },

  // WebView.loadUrl with non-literal URL (potential open redirect / XSS)
  {
    type: 'WEBVIEW_LOAD_URL',
    severity: 'high',
    pattern: /\.loadUrl\s*\(\s*(?!["']https?:\/\/)[^)]*(?:intent|uri|url|param|input|request|get|query)/i,
    message:
      'WebView.loadUrl called with a non-literal URL that may include user-controlled input. ' +
      'Validate and allowlist URLs before loading to prevent open redirect and XSS attacks.',
    confidence: 0.74,
  },

  // SQL injection via rawQuery / execSQL with string concatenation or interpolation
  {
    type: 'SQL_INJECTION',
    severity: 'critical',
    pattern: /(?:rawQuery|execSQL)\s*\(\s*(?:"[^"]*"\s*\+|"[^"]*\$\{|\$\{[^}]+\})/,
    message:
      'rawQuery() or execSQL() called with a query string that appears to include string ' +
      'concatenation or interpolation. Use parameterised queries with selectionArgs instead.',
    confidence: 0.92,
  },

  // Path traversal via File() constructor with user-controlled path
  {
    type: 'PATH_TRAVERSAL',
    severity: 'high',
    pattern: /\bFile\s*\(\s*(?:intent|uri|path|param|input|request|get|query|args\[)/i,
    message:
      'File() constructor called with what appears to be user-controlled input. ' +
      'Without path canonicalization and validation, this allows path traversal attacks.',
    confidence: 0.79,
  },

  // Exported activities / receivers without permission (manifest-level, but code hint)
  {
    type: 'INSECURE_BINDING',
    severity: 'low',
    pattern: /@SuppressLint\s*\(\s*"ExportedPreferenceActivity"\s*\)/,
    message:
      'ExportedPreferenceActivity suppression detected. Exported activities without ' +
      'android:permission are accessible to any app on the device.',
    confidence: 0.88,
  },

  // N+1 query pattern — database query call indented inside a loop body
  // Because the scanner is line-by-line, matches query lines deeply indented (8+ spaces)
  // inside a forEach/for block where the surrounding context suggests a loop.
  {
    type: 'PERFORMANCE_N_PLUS_ONE',
    severity: 'medium',
    pattern: /^\s{8,}(?:db|repository|dao|userRepository|orderRepository|itemRepository)\s*\.\s*(?:rawQuery|execSQL|findBy\w+|query|get\w+|fetch\w+)\s*\(/,
    message:
      'Database query appears to be called from inside a loop body (deeply indented). ' +
      'This is a classic N+1 query pattern: one query per iteration causes O(n) database ' +
      'roundtrips. Batch the query outside the loop or use a JOIN/IN clause instead.',
    confidence: 0.65,
  },
];

/**
 * Scans a parsed Kotlin source for security vulnerabilities using pattern matching.
 * Returns findings in the same Finding format as other language parsers.
 */
export function scanKotlin(result: KotlinParseResult): Finding[] {
  const findings: Finding[] = [];

  // ── Stateful N+1 detection: for/forEach loop + Room/SQLite/Exposed DB calls ──
  // Uses a brace-depth counter to track when we are inside a loop body.
  let inLoop = false;
  let loopBraceDepth = 0;

  // Patterns that indicate entry into a for or forEach loop
  const LOOP_ENTRY = /\b(?:for\s*\(|\.forEach\s*(?:\{|\())/;
  // Room, SQLite, Exposed DB query calls inside a loop body
  const N1_QUERY = /\b(?:dao|repository|db|database|roomDb|appDb)\s*\.\s*(?:query|rawQuery|execSQL|get\w+|find\w+|fetch\w+|select\w+|insert\w+|update\w+|delete\w+)\s*\(|\b(?:transaction|withContext)\s*\{[^}]*(?:dao|repository|db)\s*\./i;

  result.lines.forEach((line, idx) => {
    const lineNum = idx + 1;
    const trimmed = line.trim();

    // Skip pure comment lines
    if (trimmed.startsWith('//') || trimmed.startsWith('*')) return;

    const openBraces = (line.match(/\{/g) ?? []).length;
    const closeBraces = (line.match(/\}/g) ?? []).length;

    if (!inLoop && LOOP_ENTRY.test(line)) {
      inLoop = true;
      loopBraceDepth = openBraces - closeBraces;
    } else if (inLoop) {
      loopBraceDepth += openBraces - closeBraces;
      if (loopBraceDepth <= 0) {
        inLoop = false;
        loopBraceDepth = 0;
      } else if (N1_QUERY.test(line)) {
        findings.push({
          type: 'PERFORMANCE_N_PLUS_ONE',
          severity: 'medium',
          line: lineNum,
          column: line.search(/\S/),
          snippet: trimmed.slice(0, 100),
          message:
            'Database query inside a for/forEach loop — this is an N+1 query pattern. ' +
            'Each iteration issues a separate DB round-trip. Use a batch query, JOIN, or ' +
            'IN clause outside the loop to avoid O(n) database calls.',
          file: result.filePath,
        });
      }
    }

    for (const { type, severity, pattern, message, confidence } of KOTLIN_PATTERNS) {
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
