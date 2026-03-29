/**
 * Swift / iOS language support for the AI Code Security Scanner.
 *
 * Implements a regex-based scan pass for Swift files (.swift). Focused on
 * iOS and macOS-specific security vulnerabilities common in AI-generated code.
 *
 * Detected finding types:
 *   SSRF                 — URLSession with user-controlled URLs
 *   SECRET_HARDCODED     — hardcoded API keys / tokens / passwords
 *   INSECURE_SHARED_PREFS — sensitive data stored in UserDefaults instead of Keychain
 *   UNSAFE_WEBVIEW       — WKWebView with allowsArbitraryLoads enabled
 *   WEAK_CRYPTO          — CommonCrypto MD5 / SHA1 usage
 */

import * as fs from 'fs';
import type { Finding } from './reporter';

export interface SwiftParseResult {
  language: 'swift';
  code: string;
  lines: string[];
  filePath: string;
}

export function parseSwiftFile(filePath: string): SwiftParseResult {
  const code = fs.readFileSync(filePath, 'utf-8');
  return parseSwiftCode(code, filePath);
}

export function parseSwiftCode(code: string, filePath = 'input.swift'): SwiftParseResult {
  return { language: 'swift', code, lines: code.split('\n'), filePath };
}

// ── Pattern-based detectors ───────────────────────────────────────────────────

interface SwiftPattern {
  type: string;
  severity: Finding['severity'];
  pattern: RegExp;
  message: string;
}

const SWIFT_PATTERNS: SwiftPattern[] = [
  // SSRF: URLSession.shared.dataTask / URLSession.shared.data with user-controlled URL
  {
    type: 'SSRF',
    severity: 'high',
    pattern: /URLSession\s*\.\s*shared\s*\.\s*(?:dataTask|data|download|upload)\s*\(\s*with\s*:\s*(?!URL\s*\(\s*string\s*:\s*")/,
    message:
      'URLSession request made with a potentially user-controlled URL. Without URL validation, ' +
      'attackers can force the app to make requests to internal services (SSRF). Validate the URL ' +
      'against an allowlist of trusted hosts before making requests.',
  },
  {
    type: 'SSRF',
    severity: 'high',
    pattern: /URLRequest\s*\(\s*url\s*:\s*(?:user|input|param|request|url)\w*/i,
    message:
      'URLRequest constructed with a variable that may be user-controlled. Validate the URL ' +
      'against an allowlist of trusted hosts to prevent SSRF.',
  },

  // Keychain misuse: sensitive data stored in UserDefaults
  {
    type: 'INSECURE_SHARED_PREFS',
    severity: 'high',
    pattern: /UserDefaults\s*\.\s*standard\s*\.\s*set\s*\([^,]+,\s*forKey\s*:\s*"[^"]*(?:password|passwd|token|secret|key|credential|auth)[^"]*"/i,
    message:
      'Sensitive data (password, token, or credential) stored in UserDefaults. UserDefaults are ' +
      'stored in plaintext in the app sandbox and can be extracted by attackers. Use the iOS Keychain ' +
      'via SecItemAdd/SecItemCopyMatching or a Keychain wrapper library instead.',
  },
  {
    type: 'INSECURE_SHARED_PREFS',
    severity: 'high',
    pattern: /UserDefaults\s*\.\s*standard\s*\.\s*setValue\s*\([^,]+,\s*forKey\s*:\s*"[^"]*(?:password|passwd|token|secret|key|credential|auth)[^"]*"/i,
    message:
      'Sensitive value stored in UserDefaults with a security-sensitive key name. Use the iOS Keychain ' +
      'instead of UserDefaults for credentials and tokens.',
  },

  // WKWebView with allowsArbitraryLoads / NSAllowsArbitraryLoads
  {
    type: 'UNSAFE_WEBVIEW',
    severity: 'medium',
    pattern: /"?NSAllowsArbitraryLoads"?\s*[=:]\s*true/i,
    message:
      'NSAllowsArbitraryLoads is enabled in App Transport Security settings. This disables TLS ' +
      'enforcement and allows cleartext HTTP connections, exposing the app to man-in-the-middle attacks. ' +
      'Remove this key and ensure all endpoints support HTTPS.',
  },
  {
    type: 'UNSAFE_WEBVIEW',
    severity: 'medium',
    pattern: /allowsArbitraryLoads\s*=\s*true/,
    message:
      'WKWebViewConfiguration.allowsArbitraryLoads is set to true. This disables App Transport ' +
      'Security and permits cleartext connections. Remove this setting and use HTTPS exclusively.',
  },

  // Hardcoded secrets / API keys
  {
    type: 'SECRET_HARDCODED',
    severity: 'critical',
    pattern: /(?:let|var)\s+\w*(?:apiKey|api_key|secret|token|password|passwd|accessKey|access_key|privateKey|private_key)\w*\s*(?::|=)\s*"[A-Za-z0-9/+_\-]{8,}"/i,
    message:
      'Potential hardcoded secret or API key detected in Swift source. Credentials embedded in ' +
      'source code are exposed in the compiled binary and version control history. Load secrets from ' +
      'a secure backend, environment configuration, or the iOS Keychain.',
  },
  {
    type: 'SECRET_HARDCODED',
    severity: 'high',
    pattern: /"(?:sk|pk|rk|ak|ey)[-_][A-Za-z0-9]{16,}"/,
    message:
      'Possible API key literal detected (matches common key prefix patterns). Hardcoded credentials ' +
      'should be stored in the iOS Keychain or loaded from a secure configuration endpoint.',
  },

  // Weak cryptography: CommonCrypto MD5 / SHA1
  {
    type: 'WEAK_CRYPTO',
    severity: 'medium',
    pattern: /CC_MD5\s*\(/,
    message:
      'CC_MD5 (CommonCrypto MD5) is used. MD5 is cryptographically broken and unsuitable for ' +
      'security-sensitive hashing (passwords, signatures, integrity checks). Use CC_SHA256 or ' +
      'CryptoKit\'s SHA256 instead.',
  },
  {
    type: 'WEAK_CRYPTO',
    severity: 'medium',
    pattern: /CC_SHA1\s*\(/,
    message:
      'CC_SHA1 (CommonCrypto SHA-1) is used. SHA-1 is deprecated for security purposes due to known ' +
      'collision attacks. Use CC_SHA256 or CryptoKit\'s SHA256 for security-sensitive operations.',
  },
  {
    type: 'WEAK_CRYPTO',
    severity: 'medium',
    pattern: /kCCAlgorithmDES\b/,
    message:
      'DES encryption is used via CommonCrypto. DES has a 56-bit key and is considered insecure. ' +
      'Use AES-256 (kCCAlgorithmAES) with a secure key size instead.',
  },
  {
    type: 'WEAK_CRYPTO',
    severity: 'medium',
    pattern: /Insecure\.MD5|Insecure\.SHA1/,
    message:
      'CryptoKit Insecure.MD5 or Insecure.SHA1 is used. These are marked insecure by Apple for ' +
      'a reason — use SHA256 or SHA512 for security-sensitive hashing.',
  },
];

// ── Sliding-window N+1 patterns ───────────────────────────────────────────────
// These require multi-line context (loop + fetch inside) so are handled separately.

/**
 * Regex that matches a Swift loop-open line (forEach, for-in, or map block opener).
 * We detect: `.forEach {`, `.forEach({`, `for x in`, `.map {`, `.map({`
 */
const SWIFT_LOOP_OPEN = /(?:\.\s*(?:forEach|map)\s*(?:\{|\(\s*\{)|^\s*for\s+\S+\s+in\s+)/;

/**
 * Regex that matches a CoreData or URLSession fetch call that would indicate an N+1.
 * Covers: fetchRequest.execute, context.fetch, dataTask(with:, data(from:
 */
const SWIFT_N1_FETCH = /(?:fetchRequest\.execute|context\.fetch\s*\(|\.dataTask\s*\(\s*with\s*:|\.data\s*\(\s*from\s*:)/;

/**
 * Post-loop sliding-window pass for N+1 detection.
 * When a loop-open line is found, looks ahead up to 5 lines for a fetch call.
 */
function detectSwiftN1(parsed: SwiftParseResult): Finding[] {
  const findings: Finding[] = [];
  const lines = parsed.lines;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const trimmed = line.trim();

    // Skip comment lines
    if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;

    if (!SWIFT_LOOP_OPEN.test(line)) continue;

    // Look ahead up to 5 lines for a fetch call
    const windowEnd = Math.min(i + 5, lines.length - 1);
    for (let j = i + 1; j <= windowEnd; j++) {
      const innerLine = lines[j]!;
      const innerTrimmed = innerLine.trim();
      if (innerTrimmed.startsWith('//') || innerTrimmed.startsWith('*') || innerTrimmed.startsWith('/*')) continue;

      if (SWIFT_N1_FETCH.test(innerLine)) {
        findings.push({
          type: 'N1_QUERY',
          severity: 'high',
          line: j + 1,
          column: 0,
          snippet: innerLine.trim().slice(0, 120),
          message:
            'URLSession or CoreData fetch call inside a loop — likely N+1 query pattern. ' +
            'Each iteration makes a separate network or database request. Batch fetch all data ' +
            'before the loop (e.g. batch URLSession requests or use an NSBatchFetchRequest) ' +
            'to avoid O(n) round-trips.',
          file: parsed.filePath,
        });
        break; // One finding per loop opening
      }
    }
  }

  return findings;
}

/**
 * Scans a Swift parse result for security vulnerabilities using pattern matching.
 * Returns an array of findings (may be empty if the file is clean).
 */
export function scanSwift(parsed: SwiftParseResult): Finding[] {
  const findings: Finding[] = [];

  for (let i = 0; i < parsed.lines.length; i++) {
    const line = parsed.lines[i]!;
    const lineNum = i + 1;
    const trimmed = line.trim();

    // Skip pure comment lines
    if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;

    for (const pat of SWIFT_PATTERNS) {
      if (pat.pattern.test(line)) {
        findings.push({
          type: pat.type,
          severity: pat.severity,
          line: lineNum,
          column: 0,
          snippet: line.trim().slice(0, 120),
          message: pat.message,
          file: parsed.filePath,
        });
        break; // One finding per line per pass (avoid duplicates for overlapping patterns)
      }
    }
  }

  // Post-loop sliding-window pass for N+1 detection
  findings.push(...detectSwiftN1(parsed));

  return findings;
}
