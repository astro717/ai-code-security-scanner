/**
 * C# language support for the AI Code Security Scanner.
 *
 * This module implements a regex-based scan pass for C# files. It operates on
 * raw source lines with pattern matching — no Roslyn or native bindings required.
 * The patterns are deliberately conservative to minimise false positives.
 *
 * Covered vulnerability classes:
 *   - SQL_INJECTION (string interpolation / concatenation in ADO.NET / EF queries)
 *   - COMMAND_INJECTION_CS (Process.Start with user input)
 *   - SECRET_HARDCODED (hardcoded credentials)
 *   - WEAK_CRYPTO (MD5, SHA1, DES, RC2)
 *   - PATH_TRAVERSAL (File/Directory access with user input)
 *   - INSECURE_RANDOM (System.Random for security use)
 *   - UNSAFE_DESERIALIZATION (BinaryFormatter deserializes untrusted data)
 *   - XSS (Response.Write with unencoded user input in ASP.NET)
 *   - SSRF (HttpClient/WebClient/WebRequest with user input)
 *   - OPEN_REDIRECT (Response.Redirect with user input)
 *   - UNSAFE_BLOCK (unsafe{} blocks with pointer manipulation)
 *   - MISSING_AUTH (ASP.NET controller endpoints missing [Authorize])
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
    type: 'SQL_INJECTION_CS',
    severity: 'critical',
    pattern: /new\s+SqlCommand\s*\(\s*(?:\$"|"[^"]*"\s*\+)/,
    message:
      'SqlCommand constructed with string interpolation or concatenation. User input in SQL ' +
      'strings leads to SQL injection. Use SqlParameter or parameterised queries instead.',
  },
  {
    type: 'SQL_INJECTION_CS',
    severity: 'critical',
    pattern: /\.CommandText\s*=\s*(?:\$"|"[^"]*"\s*\+)/,
    message:
      'CommandText set with string interpolation or concatenation. Use parameterised queries ' +
      'to prevent SQL injection.',
  },
  {
    type: 'SQL_INJECTION_CS',
    severity: 'critical',
    pattern: /(?:FromSqlRaw|ExecuteSqlRaw|ExecuteSqlCommand)\s*\(\s*(?:\$"|"[^"]*"\s*\+)/,
    message:
      'Entity Framework raw SQL called with string interpolation or concatenation. ' +
      'Use FromSqlInterpolated / ExecuteSqlInterpolated or parameterised overloads instead.',
  },

  // Command injection via Process.Start
  {
    type: 'COMMAND_INJECTION_CS',
    severity: 'critical',
    pattern: /Process\.Start\s*\([^)]*(?:Request\.|input|param|user|args)/i,
    message:
      'Process.Start() called with user-controlled input. This allows arbitrary command ' +
      'injection. Validate and whitelist all arguments before spawning external processes.',
  },
  {
    type: 'COMMAND_INJECTION_CS',
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
    type: 'PATH_TRAVERSAL_CS',
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

  // C# unsafe block — managed memory-safety is suspended
  {
    type: 'UNSAFE_BLOCK',
    severity: 'medium',
    pattern: /\bunsafe\s*\{/,
    message:
      'C# unsafe block detected — managed memory-safety guarantees (bounds checking, null reference protection) ' +
      'are suspended within this scope. Pointer arithmetic and direct memory access can cause buffer overflows ' +
      'and use-after-free vulnerabilities. Minimize the unsafe scope and document why it is necessary.',
    confidence: 0.9,
  },
];

/**
 * Scans a parsed C# source for security vulnerabilities using pattern matching.
 * Returns findings in the same Finding format as other language detectors.
 */
export function scanCSharp(result: CSharpParseResult): Finding[] {
  const findings: Finding[] = [];

  // ── Stateful N+1 detection: foreach/for loop + EF Core / ADO.NET calls ──────
  // Uses a brace-depth counter to track when we are inside a loop body.
  // Fires PERFORMANCE_N_PLUS_ONE when an EF Core or ADO.NET query is found
  // inside the loop.
  let inLoop = false;
  let loopBraceDepth = 0;

  // Patterns that indicate entry into a foreach or for loop
  const LOOP_ENTRY = /\b(?:foreach|for)\s*\(/;
  // EF Core or ADO.NET query calls inside a loop body
  const N1_QUERY = /\b(?:context|_context|dbContext|DbContext|_db|db)\s*\.\s*(?:\w+\s*\.)?\s*(?:Find|FindAsync|FirstOrDefault|FirstOrDefaultAsync|Where|ToList|ToListAsync|SingleOrDefault|SingleOrDefaultAsync|Any|AnyAsync|Count|CountAsync|Sum|SumAsync|Include|ThenInclude)\s*\(|\bExecuteReader\s*\(|\bExecuteScalar\s*\(|\bnew\s+SqlCommand\s*\(/i;

  result.lines.forEach((line, idx) => {
    const lineNum = idx + 1;
    const trimmed = line.trim();

    // Skip pure comments and preprocessor directives
    if (
      trimmed.startsWith('//') ||
      trimmed.startsWith('*') ||
      trimmed.startsWith('/*') ||
      trimmed.startsWith('#')
    ) {
      // Still need to count braces for loop depth even in block comments, but
      // single-line comments and preprocessor directives can be skipped entirely.
      return;
    }

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
          severity: 'low',
          line: lineNum,
          column: line.search(/\S/),
          snippet: trimmed.slice(0, 100),
          message:
            'Database query inside a foreach/for loop — this is an N+1 query pattern. ' +
            'Each iteration issues a separate DB round-trip. Use eager loading ' +
            '(.Include()), batch queries, or load data before the loop to avoid N+1 performance issues.',
          file: result.filePath,
        });
      }
    }
    // ──────────────────────────────────────────────────────────────────────────

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

  // ── Stateful MISSING_AUTH detection ─────────────────────────────────────────
  // Two-pass: first detect whether we're inside a Controller class, then flag
  // public action methods that lack [Authorize] or [AllowAnonymous] attributes.
  // A class-level [Authorize] exempts all its methods.
  let inController = false;
  let classHasAuthorize = false;
  let classBraceDepth = 0;
  let recentAttributes: string[] = [];  // accumulates attributes before a method

  const CONTROLLER_CLASS = /\bclass\s+\w+\s*(?:<[^>]*>)?\s*:\s*(?:.*?)(?:Controller|ControllerBase)\b/;
  const ACTION_METHOD = /\bpublic\s+(?:async\s+)?(?:Task<|IActionResult|ActionResult|JsonResult|ViewResult|ContentResult|FileResult|ObjectResult|StatusCodeResult)/;
  const ATTR_LINE = /^\s*\[([^\]]+)\]/;

  result.lines.forEach((line, idx) => {
    const lineNum = idx + 1;
    const trimmed = line.trim();

    if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) return;

    const openBraces = (line.match(/\{/g) ?? []).length;
    const closeBraces = (line.match(/\}/g) ?? []).length;

    if (!inController) {
      // Check for [Authorize] on lines immediately before the class
      const attrMatch = ATTR_LINE.exec(line);
      if (attrMatch) {
        recentAttributes.push(attrMatch[1]!);
      } else if (CONTROLLER_CLASS.test(line)) {
        inController = true;
        classHasAuthorize = recentAttributes.some(a => /\bAuthorize\b/.test(a));
        classBraceDepth = openBraces - closeBraces;
        recentAttributes = [];
      } else if (!/^\s*$/.test(line)) {
        // Non-empty, non-attribute, non-class line — reset accumulated attributes
        recentAttributes = [];
      }
    } else {
      classBraceDepth += openBraces - closeBraces;

      if (classBraceDepth <= 0) {
        inController = false;
        classHasAuthorize = false;
        classBraceDepth = 0;
        recentAttributes = [];
        return;
      }

      const attrMatch = ATTR_LINE.exec(line);
      if (attrMatch) {
        recentAttributes.push(attrMatch[1]!);
      } else if (ACTION_METHOD.test(line) && !classHasAuthorize) {
        const hasAuth = recentAttributes.some(a => /\bAuthorize\b|\bAllowAnonymous\b/.test(a));
        if (!hasAuth) {
          findings.push({
            type: 'MISSING_AUTH',
            severity: 'high',
            line: lineNum,
            column: line.search(/\S/),
            snippet: trimmed.slice(0, 100),
            message:
              'ASP.NET controller action missing [Authorize] attribute — this endpoint is accessible ' +
              'without authentication. Add [Authorize] to enforce auth, or [AllowAnonymous] to mark it ' +
              'as intentionally public.',
            file: result.filePath,
            confidence: 0.85,
          });
        }
        recentAttributes = [];
      } else if (!/^\s*$/.test(line)) {
        recentAttributes = [];
      }
    }
  });

  return findings;
}
