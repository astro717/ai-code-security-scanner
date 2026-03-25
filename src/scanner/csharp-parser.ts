/**
 * C# language support for the AI Code Security Scanner.
 *
 * This module implements a regex-based scan pass for C# files. It operates on
 * raw source lines with pattern matching — no Roslyn or native bindings required.
 * The patterns are deliberately conservative to minimise false positives.
 *
 * Covered vulnerability classes:
 *   - SQL_INJECTION (string interpolation / concatenation in ADO.NET / EF queries)
 *   - COMMAND_INJECTION (Process.Start with user input)
 *   - SECRET_HARDCODED (hardcoded credentials)
 *   - WEAK_CRYPTO (MD5, SHA1, DES, RC2)
 *   - PATH_TRAVERSAL (File/Directory access with user input)
 *   - INSECURE_RANDOM (System.Random for security use)
 *   - UNSAFE_DESERIALIZATION (BinaryFormatter deserializes untrusted data)
 *   - XSS (Response.Write with unencoded user input in ASP.NET)
 *   - SSRF (HttpClient/WebClient/WebRequest with user input)
 *   - OPEN_REDIRECT (Response.Redirect with user input)
 */

import * as fs from 'fs';
import type { Finding } from './reporter';

export interface CSharpParseResult {
  language: 'csharp';
  code: string;
  lines: string[];
  filePath: string;
}

export function parseCSharpFile(filePath: string): CSharpParseResult {
  const code = fs.readFileSync(filePath, 'utf-8');
  return parseCSharpCode(code, filePath);
}

export function parseCSharpCode(code: string, filePath = 'input.cs'): CSharpParseResult {
  return { language: 'csharp', code, lines: code.split('\n'), filePath };
}

// ── Pattern-based detectors ───────────────────────────────────────────────────

interface CSharpPattern {
  type: string;
  severity: Finding['severity'];
  pattern: RegExp;
  message: string;
}

const CSHARP_PATTERNS: CSharpPattern[] = [
  // SQL injection via string interpolation/concatenation in ADO.NET
  {
    type: 'SQL_INJECTION',
    severity: 'critical',
    pattern: /new\s+SqlCommand\s*\(\s*(?:\$"|"[^"]*"\s*\+)/,
    message:
      'SqlCommand constructed with string interpolation or concatenation. User input in SQL ' +
      'strings leads to SQL injection. Use SqlParameter or parameterised queries instead.',
  },
  {
    type: 'SQL_INJECTION',
    severity: 'critical',
    pattern: /\.CommandText\s*=\s*(?:\$"|"[^"]*"\s*\+)/,
    message:
      'CommandText set with string interpolation or concatenation. Use parameterised queries ' +
      'to prevent SQL injection.',
  },
  {
    type: 'SQL_INJECTION',
    severity: 'critical',
    pattern: /(?:FromSqlRaw|ExecuteSqlRaw|ExecuteSqlCommand)\s*\(\s*(?:\$"|"[^"]*"\s*\+)/,
    message:
      'Entity Framework raw SQL called with string interpolation or concatenation. ' +
      'Use FromSqlInterpolated / ExecuteSqlInterpolated or parameterised overloads instead.',
  },

  // Command injection via Process.Start
  {
    type: 'COMMAND_INJECTION',
    severity: 'critical',
    pattern: /Process\.Start\s*\([^)]*(?:Request\.|input|param|user|args)/i,
    message:
      'Process.Start() called with user-controlled input. This allows arbitrary command ' +
      'injection. Validate and whitelist all arguments before spawning external processes.',
  },
  {
    type: 'COMMAND_INJECTION',
    severity: 'critical',
    pattern: /ProcessStartInfo\s*\([^)]*(?:Request\.|input|param|user)/i,
    message:
      'ProcessStartInfo constructed with user-controlled input. Validate all arguments ' +
      'before passing them to external processes.',
  },

  // Hardcoded secrets
  {
    type: 'SECRET_HARDCODED',
    severity: 'high',
    pattern: /(?:password|passwd|secret|token|apiKey|api_key|privateKey|connectionString)\s*=\s*"[^"]{4,}"/i,
    message:
      'Potential hardcoded credential in C# source. Secrets must be loaded from environment ' +
      'variables, appsettings.json (with Azure Key Vault or Secret Manager), or a secrets manager.',
  },

  // Weak crypto
  {
    type: 'WEAK_CRYPTO',
    severity: 'high',
    pattern: /(?:MD5|SHA1|DES|RC2)\.Create\s*\(/i,
    message:
      'Weak or broken cryptographic algorithm used (.Create()). ' +
      'MD5, SHA1, DES, and RC2 are deprecated for security use. Use SHA-256/SHA-3 or AES-256-GCM.',
  },
  {
    type: 'WEAK_CRYPTO',
    severity: 'high',
    pattern: /new\s+(?:MD5CryptoServiceProvider|SHA1CryptoServiceProvider|DESCryptoServiceProvider|RC2CryptoServiceProvider)\s*\(/,
    message:
      'Deprecated cryptographic service provider instantiated. These algorithms are cryptographically ' +
      'broken. Use AesGcm, HMACSHA256, or Aes.Create() with a 256-bit key.',
  },

  // Path traversal
  {
    type: 'PATH_TRAVERSAL',
    severity: 'high',
    pattern: /(?:File\.|Directory\.|Path\.Combine)\s*(?:\w+\s*\()?\s*[^;]*(?:Request\.|input|param|user)/i,
    message:
      'File or directory operation with user-controlled input. Without path canonicalisation, ' +
      'attackers can traverse the filesystem using ../ sequences. Use Path.GetFullPath() and ' +
      'verify the result starts with the allowed base directory.',
  },

  // Insecure random
  {
    type: 'INSECURE_RANDOM',
    severity: 'medium',
    pattern: /new\s+Random\s*\(/,
    message:
      'System.Random is not cryptographically secure and must not be used for security-sensitive ' +
      'values (tokens, passwords, session IDs). Use RandomNumberGenerator or RNGCryptoServiceProvider.',
  },

  // Unsafe deserialization
  {
    type: 'UNSAFE_DESERIALIZATION',
    severity: 'critical',
    pattern: /new\s+BinaryFormatter\s*\(/,
    message:
      'BinaryFormatter is unsafe and banned in .NET 5+. Deserializing untrusted data with ' +
      'BinaryFormatter can lead to remote code execution. Use System.Text.Json or MessagePack.',
  },

  // XSS via Response.Write in ASP.NET
  {
    type: 'XSS',
    severity: 'high',
    pattern: /Response\.Write\s*\([^)]*(?:Request\.|input|param|user|QueryString)/i,
    message:
      'User input written directly to HTTP response via Response.Write() without HTML encoding. ' +
      'Use Server.HtmlEncode() or HttpUtility.HtmlEncode() before writing to the response.',
  },

  // SSRF via HttpClient/WebClient with user input
  {
    type: 'SSRF',
    severity: 'high',
    pattern: /(?:GetAsync|PostAsync|GetStringAsync|DownloadString|Create)\s*\([^)]*(?:Request\.|input|param|user)/i,
    message:
      'HTTP request made with user-controlled URL. Without URL validation, attackers can force ' +
      'the server to make requests to internal services (SSRF). Validate and whitelist target URLs.',
  },

  // Open redirect
  {
    type: 'OPEN_REDIRECT',
    severity: 'medium',
    pattern: /Response\.Redirect\s*\([^)]*(?:Request\.|input|param|user|returnUrl|redirect)/i,
    message:
      'Response.Redirect() called with user-controlled input. This can be exploited for phishing ' +
      'via open redirect. Validate that the target URL is a relative path or a known safe domain.',
  },
];

/**
 * Scans a parsed C# source for security vulnerabilities using pattern matching.
 * Returns findings in the same Finding format as other language detectors.
 */
export function scanCSharp(result: CSharpParseResult): Finding[] {
  const findings: Finding[] = [];

  result.lines.forEach((line, idx) => {
    const lineNum = idx + 1;
    const trimmed = line.trim();

    // Skip pure comments and preprocessor directives
    if (
      trimmed.startsWith('//') ||
      trimmed.startsWith('*') ||
      trimmed.startsWith('/*') ||
      trimmed.startsWith('#')
    ) return;

    for (const { type, severity, pattern, message } of CSHARP_PATTERNS) {
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
