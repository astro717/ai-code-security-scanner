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
  },
  {
    type: 'SQL_INJECTION',
    severity: 'critical',
    pattern: /(?:createQuery|createNativeQuery)\s*\([^)]*\+/,
    message:
      'JPA/Hibernate query built with string concatenation. Use parameterised queries ' +
      'or Criteria API to prevent SQL injection.',
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
  },
  {
    type: 'COMMAND_INJECTION',
    severity: 'critical',
    pattern: /Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(\s*(?!["'])[a-zA-Z]/,
    message:
      'Runtime.exec() called with a non-literal argument. If any part of the command is ' +
      'user-controlled, this allows arbitrary command execution. Use ProcessBuilder with ' +
      'a list of arguments and avoid shell interpretation.',
  },
  {
    type: 'COMMAND_INJECTION',
    severity: 'critical',
    pattern: /new\s+ProcessBuilder\s*\([^)]*(?:request|req\.|param|input|getParameter)/i,
    message:
      'ProcessBuilder constructed with user-controlled input. Validate and sanitise ' +
      'all arguments before passing them to external commands.',
  },

  // Hardcoded secrets
  {
    type: 'SECRET_HARDCODED',
    severity: 'high',
    pattern: /(?:password|passwd|secret|token|apiKey|api_key|private_key)\s*=\s*"[^"]{4,}"/i,
    message:
      'Potential hardcoded credential in Java source. Secrets must be loaded from ' +
      'environment variables, system properties, or a secrets manager.',
  },

  // Weak crypto — MD5, SHA-1, DES
  {
    type: 'WEAK_CRYPTO',
    severity: 'high',
    pattern: /MessageDigest\.getInstance\s*\(\s*"(?:MD5|SHA-?1)"\s*\)/i,
    message:
      'Weak hashing algorithm (MD5 or SHA-1) used via MessageDigest. ' +
      'Use SHA-256 or SHA-3 for security-sensitive hashing. For passwords, use bcrypt or Argon2.',
  },
  {
    type: 'WEAK_CRYPTO',
    severity: 'high',
    pattern: /Cipher\.getInstance\s*\(\s*"(?:DES|DESede|RC4|Blowfish)(?:\/|\s*")/i,
    message:
      'Weak or deprecated cipher algorithm used. DES, 3DES, RC4, and Blowfish are ' +
      'considered insecure. Use AES-256-GCM or ChaCha20-Poly1305.',
  },

  // Path traversal via File constructor with user input
  {
    type: 'PATH_TRAVERSAL',
    severity: 'high',
    pattern: /new\s+File\s*\([^)]*(?:request|req\.|param|getParameter|input)/i,
    message:
      'File object created with user-controlled input. Without path sanitisation, ' +
      'attackers can traverse the filesystem with ../ sequences. Validate and canonicalise paths.',
  },

  // Insecure random — java.util.Random instead of SecureRandom
  {
    type: 'INSECURE_RANDOM',
    severity: 'medium',
    pattern: /new\s+(?:java\.util\.)?Random\s*\(/,
    message:
      'java.util.Random is not cryptographically secure. For tokens, passwords, ' +
      'or session IDs, use java.security.SecureRandom instead.',
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
  },

  // XSS via direct output in servlets
  {
    type: 'XSS',
    severity: 'high',
    pattern: /getWriter\(\)\.(?:print|println|write)\s*\([^)]*(?:getParameter|request\.get)/i,
    message:
      'User input written directly to HTTP response without encoding. ' +
      'This allows Cross-Site Scripting (XSS). HTML-encode all user input before output.',
  },

  // SSRF via URL/HttpURLConnection with user input
  {
    type: 'SSRF',
    severity: 'high',
    pattern: /new\s+URL\s*\(\s*(?!")[^)]*(?:request|req\.|param|getParameter|input)/i,
    message:
      'URL object created with user-controlled input. Without URL validation, ' +
      'attackers can force the server to make requests to internal services (SSRF).',
  },

  // ScriptEngine eval
  {
    type: 'EVAL_INJECTION',
    severity: 'critical',
    pattern: /\.eval\s*\(\s*(?!")[^)]*(?:request|req\.|param|getParameter|input)/i,
    message:
      'ScriptEngine.eval() called with user-controlled input. This executes arbitrary ' +
      'code and must never receive untrusted input.',
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
  },
  {
    type: 'XML_INJECTION',
    severity: 'high',
    pattern: /SAXParserFactory\.newInstance\s*\(\s*\)/,
    message:
      'SAXParserFactory created without configuring secure processing. ' +
      'Enable FEATURE_SECURE_PROCESSING and disable external entity resolution to prevent XXE.',
  },

  // LDAP injection
  {
    type: 'LDAP_INJECTION',
    severity: 'high',
    pattern: /ctx\.search\s*\([^)]*\+/,
    message:
      'LDAP DirContext.search() called with a concatenated filter string. ' +
      'User input in LDAP filters allows LDAP injection. Use parameterised queries.',
  },

  // N+1 query pattern — JDBC/JPA call inside a for/foreach/while loop
  // Matches patterns where a query method is called within a loop body.
  {
    type: 'PERFORMANCE_N_PLUS_ONE',
    severity: 'low',
    pattern: /for\s*\([^)]+\)\s*\{[^}]*(?:executeQuery|executeUpdate|createQuery|findById|\.get\s*\(\s*\w+\s*\)\.load)/,
    message:
      'JDBC/JPA query inside a for loop — N+1 query pattern detected. ' +
      'Each loop iteration issues a separate SQL round-trip. ' +
      'Use a JOIN FETCH, @BatchSize, or batch SELECT ... WHERE id IN (...) instead.',
  },
  {
    type: 'PERFORMANCE_N_PLUS_ONE',
    severity: 'low',
    pattern: /for\s*\(\s*\w[\w\s<>]*:\s*\w+\s*\)\s*\{[^}]*(?:executeQuery|executeUpdate|findById|entityManager\.find|session\.get|session\.load)/,
    message:
      'JPA/Hibernate query inside an enhanced for-each loop — N+1 query pattern. ' +
      'Use JOIN FETCH, Hibernate @BatchSize, or a bulk IN-query to eliminate the per-iteration round-trip.',
  },
];

/**
 * Scans a parsed Java source for security vulnerabilities using pattern matching.
 * Returns findings in the same Finding format as JS/TS, Python, and Go detectors.
 */
export function scanJava(result: JavaParseResult): Finding[] {
  const findings: Finding[] = [];

  result.lines.forEach((line, idx) => {
    const lineNum = idx + 1;
    const trimmed = line.trim();

    // Skip pure comments
    if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) return;

    for (const { type, severity, pattern, message } of JAVA_PATTERNS) {
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
