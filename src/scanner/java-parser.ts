/**
 * Java language support for the AI Code Security Scanner.
 *
 * This module implements a regex-based scan pass for Java files. Like the Python
 * and Go scanners, it operates on raw source lines with pattern matching — no
 * Java AST parser or native bindings required. The patterns are deliberately
 * conservative to minimise false positives.
 *
 * Covered vulnerability classes:
 *   - SQL_INJECTION (string concatenation in JDBC queries)
 *   - COMMAND_INJECTION (Runtime.exec with user input)
 *   - SECRET_HARDCODED (hardcoded credentials)
 *   - WEAK_CRYPTO (MD5, SHA-1, DES)
 *   - PATH_TRAVERSAL (File constructor with user input)
 *   - INSECURE_RANDOM (java.util.Random for security)
 *   - EVAL_INJECTION (ScriptEngine.eval with dynamic input)
 *   - UNSAFE_DESERIALIZATION (ObjectInputStream.readObject)
 *   - XSS (direct output of user input in servlets)
 *   - SSRF (URL/HttpURLConnection with user input)
 *   - PERFORMANCE_N_PLUS_ONE (JDBC/JPA query inside a loop)
 */

import * as fs from 'fs';
import type { Finding } from './reporter';

export interface JavaParseResult {
  language: 'java';
  code: string;
  lines: string[];
  filePath: string;
}

export function parseJavaFile(filePath: string): JavaParseResult {
  const code = fs.readFileSync(filePath, 'utf-8');
  return parseJavaCode(code, filePath);
}

export function parseJavaCode(code: string, filePath = 'input.java'): JavaParseResult {
  return { language: 'java', code, lines: code.split('\n'), filePath };
}

// ── Pattern-based detectors ───────────────────────────────────────────────────

interface JavaPattern {
  type: string;
  severity: Finding['severity'];
  pattern: RegExp;
  message: string;
  /** Detection confidence [0.0–1.0]. High-specificity patterns use 0.9+, heuristics use lower values. */
  confidence?: number;
}

const JAVA_PATTERNS: JavaPattern[] = [
  // SQL injection via string concatenation in JDBC
  {
    type: 'SQL_INJECTION',
    severity: 'critical',
    pattern: /(?:executeQuery|executeUpdate|execute|prepareStatement)\s*\([^)]*\+/,
    message:
      'SQL query built with string concatenation in JDBC. User input interpolated into ' +
      'SQL strings leads to SQL injection. Use PreparedStatement with parameterised queries instead.',
    confidence: 0.93,
  },
  {
    type: 'SQL_INJECTION',
    severity: 'critical',
    pattern: /(?:createQuery|createNativeQuery)\s*\([^)]*\+/,
    message:
      'JPA/Hibernate query built with string concatenation. Use parameterised queries ' +
      'or Criteria API to prevent SQL injection.',
    confidence: 0.91,
  },

  // Command injection via Runtime.exec
  {
    type: 'COMMAND_INJECTION',
    severity: 'critical',
    pattern: /Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+/,
    message:
      'Runtime.exec() called with string concatenation. If any part of the command is ' +
      'user-controlled, this allows arbitrary command injection. Use ProcessBuilder with ' +
      'a list of arguments instead.',
    confidence: 0.94,
  },
  {
    type: 'COMMAND_INJECTION',
    severity: 'critical',
    pattern: /Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(\s*(?!["'])[a-zA-Z]/,
    message:
      'Runtime.exec() called with a non-literal argument. If any part of the command is ' +
      'user-controlled, this allows arbitrary command execution. Use ProcessBuilder with ' +
      'a list of arguments and avoid shell interpretation.',
    confidence: 0.88,
  },
  {
    type: 'COMMAND_INJECTION',
    severity: 'critical',
    pattern: /new\s+ProcessBuilder\s*\([^)]*(?:request|req\.|param|input|getParameter)/i,
    message:
      'ProcessBuilder constructed with user-controlled input. Validate and sanitise ' +
      'all arguments before passing them to external commands.',
    confidence: 0.80,
  },

  // Hardcoded secrets
  {
    type: 'SECRET_HARDCODED',
    severity: 'high',
    pattern: /(?:password|passwd|secret|token|apiKey|api_key|private_key)\s*=\s*"[^"]{4,}"/i,
    message:
      'Potential hardcoded credential in Java source. Secrets must be loaded from ' +
      'environment variables, system properties, or a secrets manager.',
    confidence: 0.85,
  },

  // Weak crypto — MD5, SHA-1, DES
  {
    type: 'WEAK_CRYPTO',
    severity: 'high',
    pattern: /MessageDigest\.getInstance\s*\(\s*"(?:MD5|SHA-?1)"\s*\)/i,
    message:
      'Weak hashing algorithm (MD5 or SHA-1) used via MessageDigest. ' +
      'Use SHA-256 or SHA-3 for security-sensitive hashing. For passwords, use bcrypt or Argon2.',
    confidence: 0.96,
  },
  {
    type: 'WEAK_CRYPTO',
    severity: 'high',
    pattern: /Cipher\.getInstance\s*\(\s*"(?:DES|DESede|RC4|Blowfish)(?:\/|\s*")/i,
    message:
      'Weak or deprecated cipher algorithm used. DES, 3DES, RC4, and Blowfish are ' +
      'considered insecure. Use AES-256-GCM or ChaCha20-Poly1305.',
    confidence: 0.95,
  },

  // Path traversal via File constructor with user input
  {
    type: 'PATH_TRAVERSAL',
    severity: 'high',
    pattern: /new\s+File\s*\([^)]*(?:request|req\.|param|getParameter|input)/i,
    message:
      'File object created with user-controlled input. Without path sanitisation, ' +
      'attackers can traverse the filesystem with ../ sequences. Validate and canonicalise paths.',
    confidence: 0.82,
  },

  // Insecure random — java.util.Random instead of SecureRandom
  {
    type: 'INSECURE_RANDOM',
    severity: 'medium',
    pattern: /new\s+(?:java\.util\.)?Random\s*\(/,
    message:
      'java.util.Random is not cryptographically secure. For tokens, passwords, ' +
      'or session IDs, use java.security.SecureRandom instead.',
    confidence: 0.78,
  },

  // Unsafe deserialization — ObjectInputStream.readObject
  {
    type: 'UNSAFE_DESERIALIZATION',
    severity: 'critical',
    pattern: /\.readObject\s*\(/,
    message:
      'ObjectInputStream.readObject() deserializes arbitrary Java objects. ' +
      'Deserializing untrusted data can lead to remote code execution. ' +
      'Use ObjectInputFilter (Java 9+) or avoid Java serialization entirely.',
    confidence: 0.75,
  },

  // XSS via direct output in servlets
  {
    type: 'XSS',
    severity: 'high',
    pattern: /getWriter\(\)\.(?:print|println|write)\s*\([^)]*(?:getParameter|request\.get)/i,
    message:
      'User input written directly to HTTP response without encoding. ' +
      'This allows Cross-Site Scripting (XSS). HTML-encode all user input before output.',
    confidence: 0.84,
  },

  // SSRF via URL/HttpURLConnection with user input
  {
    type: 'SSRF',
    severity: 'high',
    pattern: /new\s+URL\s*\(\s*(?!")[^)]*(?:request|req\.|param|getParameter|input)/i,
    message:
      'URL object created with user-controlled input. Without URL validation, ' +
      'attackers can force the server to make requests to internal services (SSRF).',
    confidence: 0.79,
  },

  // ScriptEngine eval
  {
    type: 'EVAL_INJECTION',
    severity: 'critical',
    pattern: /\.eval\s*\(\s*(?!")[^)]*(?:request|req\.|param|getParameter|input)/i,
    message:
      'ScriptEngine.eval() called with user-controlled input. This executes arbitrary ' +
      'code and must never receive untrusted input.',
    confidence: 0.86,
  },

  // XXE (XML external entity injection)
  {
    type: 'XML_INJECTION',
    severity: 'critical',
    pattern: /DocumentBuilderFactory\.newInstance\s*\(\s*\)/,
    message:
      'DocumentBuilderFactory created without disabling external entity processing. ' +
      'This may allow XXE attacks that read local files or trigger SSRF. ' +
      'Call factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true).',
    confidence: 0.72,
  },
  {
    type: 'XML_INJECTION',
    severity: 'high',
    pattern: /SAXParserFactory\.newInstance\s*\(\s*\)/,
    message:
      'SAXParserFactory created without configuring secure processing. ' +
      'Enable FEATURE_SECURE_PROCESSING and disable external entity resolution to prevent XXE.',
    confidence: 0.70,
  },

  // LDAP injection
  {
    type: 'LDAP_INJECTION',
    severity: 'high',
    pattern: /ctx\.search\s*\([^)]*\+/,
    message:
      'LDAP DirContext.search() called with a concatenated filter string. ' +
      'User input in LDAP filters allows LDAP injection. Use parameterised queries.',
    confidence: 0.89,
  },

  // N+1 query pattern — detected statefully in scanJava (see loop-tracking logic below)
  // These placeholder entries are not used directly; the stateful detector handles them.
];

/**
 * Scans a parsed Java source for security vulnerabilities using pattern matching.
 * Returns findings in the same Finding format as JS/TS, Python, and Go detectors.
 */
export function scanJava(result: JavaParseResult): Finding[] {
  const findings: Finding[] = [];

  // Stateful N+1 detection: track whether we are inside a for/for-each loop.
  let inForLoop = false;
  let loopBraceDepth = 0;

  result.lines.forEach((line, idx) => {
    const lineNum = idx + 1;
    const trimmed = line.trim();

    // Skip pure comments
    if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) return;

    // ── Stateful for-loop N+1 detection ───────────────────────────────────────
    const openBraces = (line.match(/\{/g) ?? []).length;
    const closeBraces = (line.match(/\}/g) ?? []).length;

    // Detect entry into a for or enhanced for-each loop
    if (/\bfor\s*\(/.test(line)) {
      inForLoop = true;
      loopBraceDepth = openBraces - closeBraces;
      // Also check for DB calls on the same line as the for statement
      const n1PatternInline = /\b(?:executeQuery|executeUpdate|createQuery|findById|entityManager\.find\b|session\.get\b|session\.load\b)/;
      if (n1PatternInline.test(line)) {
        findings.push({
          type: 'PERFORMANCE_N_PLUS_ONE',
          severity: 'low',
          line: lineNum,
          column: line.search(/\S/),
          snippet: trimmed.slice(0, 100),
          message:
            'JDBC/JPA/Hibernate query inside a for loop — N+1 query pattern detected. ' +
            'Each loop iteration issues a separate SQL round-trip. ' +
            'Use a JOIN FETCH, @BatchSize, or batch SELECT ... WHERE id IN (...) instead.',
          file: result.filePath,
        });
      }
      if (loopBraceDepth <= 0) {
        inForLoop = false;
        loopBraceDepth = 0;
      }
    } else if (inForLoop) {
      loopBraceDepth += openBraces - closeBraces;
      if (loopBraceDepth <= 0) {
        inForLoop = false;
        loopBraceDepth = 0;
      } else {
        // Check for JDBC/JPA/Hibernate DB calls inside the loop body
        const n1Pattern = /\b(?:executeQuery|executeUpdate|createQuery|findById|entityManager\.find\b|session\.get\b|session\.load\b)/;
        if (n1Pattern.test(line)) {
          findings.push({
            type: 'PERFORMANCE_N_PLUS_ONE',
            severity: 'low',
            line: lineNum,
            column: line.search(/\S/),
            snippet: trimmed.slice(0, 100),
            message:
              'JDBC/JPA/Hibernate query inside a for loop — N+1 query pattern detected. ' +
              'Each loop iteration issues a separate SQL round-trip. ' +
              'Use a JOIN FETCH, @BatchSize, or batch SELECT ... WHERE id IN (...) instead.',
            file: result.filePath,
          });
        }
      }
    }
    // ──────────────────────────────────────────────────────────────────────────

    for (const { type, severity, pattern, message, confidence } of JAVA_PATTERNS) {
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
