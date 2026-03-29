/**
 * Python language support for the AI Code Security Scanner.
 *
 * This module implements a regex-based scan pass for Python files. It does not
 * use a full Python AST parser (no native bindings required) — instead, it
 * operates on the raw source lines with pattern matching. This is intentionally
 * conservative: it only flags patterns that are nearly always vulnerabilities
 * and has a very low false-positive rate.
 *
 * Architecture note:
 * ─────────────────
 * The scanner uses a language-agnostic LanguageParseResult interface. To add a
 * new language, create a parser module that returns a LanguageParseResult and
 * register its extensions in LANGUAGE_EXTENSIONS (cli.ts / server.ts).
 * No changes to the core finding/reporting pipeline are needed.
 */

import * as fs from 'fs';
import type { Finding } from './reporter';

export interface PythonParseResult {
  language: 'python';
  code: string;
  lines: string[];
  filePath: string;
}

export function parsePythonFile(filePath: string): PythonParseResult {
  const code = fs.readFileSync(filePath, 'utf-8');
  return parsePythonCode(code, filePath);
}

export function parsePythonCode(code: string, filePath = 'input.py'): PythonParseResult {
  return { language: 'python', code, lines: code.split('\n'), filePath };
}

// ── Pattern-based detectors ───────────────────────────────────────────────────

interface PythonPattern {
  type: string;
  severity: Finding['severity'];
  pattern: RegExp;
  message: string;
  /** Detection confidence [0.0–1.0]. High-specificity patterns use 0.9+, heuristics use lower values. */
  confidence?: number;
}

const PYTHON_PATTERNS: PythonPattern[] = [
  // SQL injection via string formatting / concatenation.
  // Scans to end-of-call (closing paren) rather than end-of-quote so that
  // single quotes embedded inside a double-quoted SQL string — e.g.
  // "WHERE name = '" + username — do not prematurely terminate the match.
  {
    type: 'SQL_INJECTION',
    severity: 'critical',
    pattern: /\.execute\s*\(\s*(?:f['"]|['"][^)\n]*(?:\+|%\s*\())/,
    message:
      'Python SQL execute() call uses string interpolation or concatenation. ' +
      'Use parameterised queries (cursor.execute(query, params)) instead.',
    confidence: 0.95,
  },
  // OS command injection via os.system / subprocess.call with shell=True + variable
  {
    type: 'COMMAND_INJECTION',
    severity: 'critical',
    pattern: /os\.system\s*\(\s*(?!['"][^'"")]*['""](?:\s*\)|$))/,
    message:
      'os.system() called with a non-literal argument. ' +
      'Use subprocess.run() with a list of arguments and shell=False.',
    confidence: 0.90,
  },
  {
    type: 'COMMAND_INJECTION',
    severity: 'critical',
    pattern: /subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True/,
    message:
      'subprocess called with shell=True. If any part of the command is user-controlled, ' +
      'this allows arbitrary shell command injection. Pass a list of arguments with shell=False.',
    confidence: 0.95,
  },
  // eval / exec with dynamic content
  {
    type: 'EVAL_INJECTION',
    severity: 'critical',
    pattern: /\beval\s*\((?!\s*['"`])/,
    message:
      'eval() called with a non-literal argument. eval() executes arbitrary Python code ' +
      'and must never be called with user-supplied input.',
    confidence: 0.92,
  },
  {
    type: 'EVAL_INJECTION',
    severity: 'high',
    pattern: /\bexec\s*\((?!\s*['"`])/,
    message:
      'exec() called with a non-literal argument. Like eval(), exec() can execute arbitrary ' +
      'code and must not receive untrusted input.',
    confidence: 0.90,
  },
  // Pickle deserialization
  {
    type: 'UNSAFE_DESERIALIZATION',
    severity: 'critical',
    pattern: /\bpickle\.(loads?|Unpickler)\s*\(/,
    message:
      'pickle.load/loads deserializes arbitrary Python objects. ' +
      'Deserializing untrusted data with pickle can lead to arbitrary code execution. ' +
      'Use json or a safe serialization library instead.',
    confidence: 0.93,
  },
  // Hardcoded secrets (password/token/secret = literal string)
  {
    type: 'SECRET_HARDCODED',
    severity: 'high',
    pattern: /(?:password|passwd|secret|token|api_key|apikey)\s*=\s*['"][^'"]{4,}['"]/i,
    message:
      'Potential hardcoded credential. Secrets must be loaded from environment variables ' +
      'or a secrets manager, never stored in source code.',
    confidence: 0.85,
  },
  // Weak crypto
  {
    type: 'WEAK_CRYPTO',
    severity: 'high',
    pattern: /hashlib\.(md5|sha1)\s*\(/i,
    message:
      'hashlib.md5() or hashlib.sha1() uses a cryptographically weak algorithm. ' +
      'For security-sensitive hashing, use SHA-256 or SHA-3. ' +
      'For passwords, use bcrypt, scrypt, or Argon2.',
    confidence: 0.95,
  },
  // Path traversal
  {
    type: 'PATH_TRAVERSAL',
    severity: 'high',
    pattern: /open\s*\([^)]*\+/,
    message:
      'File open() with a path derived from user input. Without path sanitization, ' +
      'attackers can traverse the filesystem with ../.. sequences.',
    confidence: 0.70,
  },
  // SSRF via requests
  {
    type: 'SSRF',
    severity: 'high',
    pattern: /requests\.(get|post|put|delete|request)\s*\(\s*(?!['"])/,
    message:
      'requests call with a non-literal URL argument. If the URL is user-controlled, ' +
      'attackers can force the server to make requests to internal services (SSRF).',
    confidence: 0.75,
  },
  // assert for security checks (assert is disabled in optimized mode)
  {
    type: 'INSECURE_ASSERT',
    severity: 'medium',
    pattern: /\bassert\s+(?:is_authenticated|is_admin|has_permission|user\.is|auth)/i,
    message:
      'assert used for authentication or permission checks. ' +
      'Python assert statements are stripped when running with -O (optimized mode). ' +
      'Use explicit if/raise instead.',
    confidence: 0.88,
  },
  // Bind to 0.0.0.0 without explicit intent
  {
    type: 'INSECURE_BINDING',
    severity: 'low',
    pattern: /(?:host|bind)\s*=\s*['"]0\.0\.0\.0['"]/,
    message:
      'Server bound to 0.0.0.0. This exposes the service on all network interfaces. ' +
      'In production, bind to a specific interface or use a reverse proxy.',
    confidence: 0.92,
  },

  // ── XML injection (XXE) ────────────────────────────────────────────────────

  // xml.etree.ElementTree usage without defusedxml
  {
    type: 'XML_INJECTION',
    severity: 'high',
    pattern: /\bxml\.etree\.ElementTree\b|(?<!\w)ET\.(?:fromstring|parse|iterparse|XMLParser)\s*\(/,
    message:
      'xml.etree.ElementTree is vulnerable to XML External Entity (XXE) attacks. ' +
      'Use defusedxml.ElementTree instead, which disables external entity expansion by default.',
    confidence: 0.90,
  },

  // Direct import of xml.etree.ElementTree (catches "import xml.etree.ElementTree")
  {
    type: 'XML_INJECTION',
    severity: 'high',
    pattern: /^(?:from|import)\s+xml\.etree/,
    message:
      'Importing xml.etree directly instead of defusedxml. The standard library XML parsers ' +
      'are vulnerable to XXE attacks. Use defusedxml as a drop-in replacement.',
    confidence: 0.95,
  },

  // ── XSS / template injection ────────────────────────────────────────────────

  // Jinja2 / Mako render_template_string with user input (SSTI)
  // Severity: high — SSTI can escalate to RCE but requires the template string to be
  // user-controlled; rated high to align with the test contract and common threat models.
  // If your deployment treats SSTI as RCE-equivalent, override to critical via the rules config.
  {
    type: 'SSTI',
    severity: 'high',
    pattern: /render_template_string\s*\(/,
    message:
      'render_template_string() renders a template from a string. If any part of the ' +
      'template string is user-controlled, this allows Server-Side Template Injection (SSTI), ' +
      'which can lead to arbitrary server-side code execution. Use render_template() with a ' +
      'static template file and pass data as context variables instead.',
    confidence: 0.85,
  },

  // Django mark_safe with variable content
  {
    type: 'XSS',
    severity: 'high',
    pattern: /mark_safe\s*\([^)"'\n]*(?:request|input|param|data|body|query|get|post)/i,
    message:
      'mark_safe() called with a value that appears to include user input. This bypasses ' +
      "Django's auto-escaping and allows XSS. Ensure content is sanitised before marking safe.",
    confidence: 0.80,
  },

  // ── Insecure random ──────────────────────────────────────────────────────────

  {
    type: 'INSECURE_RANDOM',
    severity: 'medium',
    pattern: /\brandom\.(?:random|randint|randrange|choice|shuffle|sample)\s*\(/,
    message:
      'Python random module is not cryptographically secure. For security-sensitive values ' +
      '(tokens, passwords, salts, session IDs) use secrets.token_bytes(), ' +
      'secrets.token_hex(), or secrets.token_urlsafe() instead.',
    confidence: 0.75,
  },

  // ── Open redirect ────────────────────────────────────────────────────────────

  // Flask / Django redirect with user-controlled URL
  {
    type: 'OPEN_REDIRECT',
    severity: 'medium',
    pattern: /(?:redirect|HttpResponseRedirect)\s*\([^)\n]*(?:request\.(?:GET|POST|args|form|values)|params|url|next)\b/,
    message:
      'Redirect target appears to include user-controlled input. Without validation ' +
      'this allows open redirect attacks. Validate that the destination is a relative URL ' +
      'or belongs to a trusted domain before redirecting.',
    confidence: 0.78,
  },

  // ── SQL injection (additional patterns) ──────────────────────────────────────

  // ORM raw() / extra() with string formatting
  {
    type: 'SQL_INJECTION',
    severity: 'critical',
    pattern: /\.(?:raw|extra)\s*\([^)\n]*(?:%s|%d|\{|f['"'])/,
    message:
      'ORM raw() or extra() query built with string formatting. User input in the query ' +
      'string leads to SQL injection. Use parameterised queries or ORM filters.',
    confidence: 0.92,
  },

  // ── Path traversal (additional pattern) ──────────────────────────────────────

  // os.path.join with user-controlled argument.
  // Narrowed to explicit taint sources (request/req objects, Flask/Django
  // args/form/values dicts, and common parameter variable names). Generic
  // local variable names like "safe_name" are intentionally excluded so that
  // properly-sanitised paths do not produce false positives.
  {
    type: 'PATH_TRAVERSAL',
    severity: 'high',
    pattern: /os\.path\.join\s*\([^)\n]*(?:request\.|req\.|flask\.request|args\[|form\[|request\.(?:GET|POST|args|form|values|params|data|files))/i,
    message:
      'os.path.join() called with what appears to be user-controlled input. A path like ' +
      '"/etc/passwd" as a component overrides earlier segments. Validate and sanitise ' +
      'all user-supplied path components.',
    confidence: 0.82,
  },

  // ── Shell injection (additional patterns) ─────────────────────────────────────

  // os.system with variable (not a string literal)
  {
    type: 'COMMAND_INJECTION',
    severity: 'critical',
    pattern: /os\.system\s*\([^)\n]*(?:request|input|param|data|body|query|get|post|args|form|\+|%|f['"'])/i,
    message:
      'os.system() called with a value that appears to include user input. User-controlled ' +
      'shell commands allow arbitrary code execution. Use subprocess with a list of arguments ' +
      'and shell=False.',
    confidence: 0.88,
  },
];

/**
 * Scans a parsed Python source for security vulnerabilities using pattern matching.
 * Returns findings in the same Finding format as JS/TS detectors.
 */
export function scanPython(result: PythonParseResult): Finding[] {
  const findings: Finding[] = [];

  // ── Stateful N+1 detection ──────────────────────────────────────────────────
  // Python uses indentation-based blocks, so we track whether we are inside a
  // for/while loop by recording the indentation level of the loop header and
  // considering all subsequent lines with greater indentation as "inside the loop".
  let loopIndent = -1;  // -1 = not inside a loop

  // Django ORM / SQLAlchemy query calls that cause a DB round-trip
  const PY_ORM_QUERY = /\.(?:objects\.(?:get|filter|exclude|all|first|last|count|exists|create|update|delete|values|values_list|annotate|aggregate|select_related|prefetch_related|order_by|distinct)|query\.(?:filter|filter_by|get|all|first|one|one_or_none|count|delete|update)|execute|fetchone|fetchall|fetchmany|scalar)\s*\(/;
  const PY_LOOP_START = /^(\s*)(?:for\s+.+\s+in\s+|while\s+)/;

  result.lines.forEach((line, idx) => {
    const lineNum = idx + 1;
    const trimmed = line.trim();

    // Skip pure comments and blank lines
    if (trimmed.startsWith('#') || trimmed === '') return;

    // Compute leading whitespace width (spaces; treat tab as 4 spaces)
    const leadingSpaces = line.search(/\S/);
    const indent = leadingSpaces >= 0 ? leadingSpaces : 0;

    // ── Loop tracking ───────────────────────────────────────────────────────
    if (loopIndent >= 0) {
      // Still inside the loop body if current indent is greater than loop header
      if (indent <= loopIndent) {
        // Exited the loop body
        loopIndent = -1;
      } else if (PY_ORM_QUERY.test(line)) {
        findings.push({
          type: 'PERFORMANCE_N_PLUS_ONE',
          severity: 'low',
          line: lineNum,
          column: indent,
          snippet: trimmed.slice(0, 100),
          message:
            'ORM or database query called inside a loop — this is an N+1 query pattern. ' +
            'Each iteration issues a separate DB round-trip. For Django, use select_related() ' +
            'or prefetch_related() to batch-load associations. For SQLAlchemy, use joinedload() ' +
            'or subqueryload(). Alternatively, batch the query before the loop.',
          file: result.filePath,
          confidence: 0.8,
        });
      }
    }

    // Check if this line starts a new loop (even if we just exited one)
    const loopMatch = PY_LOOP_START.exec(line);
    if (loopMatch) {
      loopIndent = indent;
    }

    // ── Pattern-based detection ─────────────────────────────────────────────
    for (const { type, severity, pattern, message, confidence } of PYTHON_PATTERNS) {
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
