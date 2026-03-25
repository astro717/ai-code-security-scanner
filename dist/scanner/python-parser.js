"use strict";
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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.parsePythonFile = parsePythonFile;
exports.parsePythonCode = parsePythonCode;
exports.scanPython = scanPython;
const fs = __importStar(require("fs"));
function parsePythonFile(filePath) {
    const code = fs.readFileSync(filePath, 'utf-8');
    return parsePythonCode(code, filePath);
}
function parsePythonCode(code, filePath = 'input.py') {
    return { language: 'python', code, lines: code.split('\n'), filePath };
}
const PYTHON_PATTERNS = [
    // SQL injection via string formatting / concatenation.
    // Scans to end-of-call (closing paren) rather than end-of-quote so that
    // single quotes embedded inside a double-quoted SQL string — e.g.
    // "WHERE name = '" + username — do not prematurely terminate the match.
    {
        type: 'SQL_INJECTION',
        severity: 'critical',
        pattern: /\.execute\s*\(\s*(?:f['"]|['"][^)\n]*(?:\+|%\s*\())/,
        message: 'Python SQL execute() call uses string interpolation or concatenation. ' +
            'Use parameterised queries (cursor.execute(query, params)) instead.',
    },
    // OS command injection via os.system / subprocess.call with shell=True + variable
    {
        type: 'COMMAND_INJECTION',
        severity: 'critical',
        pattern: /os\.system\s*\(\s*(?!['"][^'"")]*['""](?:\s*\)|$))/,
        message: 'os.system() called with a non-literal argument. ' +
            'Use subprocess.run() with a list of arguments and shell=False.',
    },
    {
        type: 'COMMAND_INJECTION',
        severity: 'critical',
        pattern: /subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True/,
        message: 'subprocess called with shell=True. If any part of the command is user-controlled, ' +
            'this allows arbitrary shell command injection. Pass a list of arguments with shell=False.',
    },
    // eval / exec with dynamic content
    {
        type: 'EVAL_INJECTION',
        severity: 'critical',
        pattern: /\beval\s*\((?!\s*['"`])/,
        message: 'eval() called with a non-literal argument. eval() executes arbitrary Python code ' +
            'and must never be called with user-supplied input.',
    },
    {
        type: 'EVAL_INJECTION',
        severity: 'high',
        pattern: /\bexec\s*\((?!\s*['"`])/,
        message: 'exec() called with a non-literal argument. Like eval(), exec() can execute arbitrary ' +
            'code and must not receive untrusted input.',
    },
    // Pickle deserialization
    {
        type: 'UNSAFE_DESERIALIZATION',
        severity: 'critical',
        pattern: /\bpickle\.(loads?|Unpickler)\s*\(/,
        message: 'pickle.load/loads deserializes arbitrary Python objects. ' +
            'Deserializing untrusted data with pickle can lead to arbitrary code execution. ' +
            'Use json or a safe serialization library instead.',
    },
    // Hardcoded secrets (password/token/secret = literal string)
    {
        type: 'SECRET_HARDCODED',
        severity: 'high',
        pattern: /(?:password|passwd|secret|token|api_key|apikey)\s*=\s*['"][^'"]{4,}['"]/i,
        message: 'Potential hardcoded credential. Secrets must be loaded from environment variables ' +
            'or a secrets manager, never stored in source code.',
    },
    // Weak crypto
    {
        type: 'WEAK_CRYPTO',
        severity: 'high',
        pattern: /hashlib\.(md5|sha1)\s*\(/i,
        message: 'hashlib.md5() or hashlib.sha1() uses a cryptographically weak algorithm. ' +
            'For security-sensitive hashing, use SHA-256 or SHA-3. ' +
            'For passwords, use bcrypt, scrypt, or Argon2.',
    },
    // Path traversal
    {
        type: 'PATH_TRAVERSAL',
        severity: 'high',
        pattern: /open\s*\(\s*(?:request\.|req\.|f['""].*\{|[^'"")]*\+\s*(?:request|req|user|input))/,
        message: 'File open() with a path derived from user input. Without path sanitization, ' +
            'attackers can traverse the filesystem with ../.. sequences.',
    },
    // SSRF via requests
    {
        type: 'SSRF',
        severity: 'high',
        pattern: /requests\.(get|post|put|delete|request)\s*\(\s*(?!['"])/,
        message: 'requests call with a non-literal URL argument. If the URL is user-controlled, ' +
            'attackers can force the server to make requests to internal services (SSRF).',
    },
    // assert for security checks (assert is disabled in optimized mode)
    {
        type: 'INSECURE_ASSERT',
        severity: 'medium',
        pattern: /\bassert\s+(?:is_authenticated|is_admin|has_permission|user\.is|auth)/i,
        message: 'assert used for authentication or permission checks. ' +
            'Python assert statements are stripped when running with -O (optimized mode). ' +
            'Use explicit if/raise instead.',
    },
    // Bind to 0.0.0.0 without explicit intent
    {
        type: 'INSECURE_BINDING',
        severity: 'low',
        pattern: /(?:host|bind)\s*=\s*['"]0\.0\.0\.0['"]/,
        message: 'Server bound to 0.0.0.0. This exposes the service on all network interfaces. ' +
            'In production, bind to a specific interface or use a reverse proxy.',
    },
    // ── XSS / template injection ────────────────────────────────────────────────
    // Jinja2 / Mako render_template_string with user input (SSTI risk)
    {
        type: 'XSS',
        severity: 'high',
        pattern: /render_template_string\s*\(/,
        message: 'render_template_string() renders a template from a string, which can lead to ' +
            'Server-Side Template Injection (SSTI) if any part of the template string is ' +
            'user-controlled. Use render_template() with a static template file instead.',
    },
    // Django mark_safe with variable content
    {
        type: 'XSS',
        severity: 'high',
        pattern: /mark_safe\s*\([^)"'\n]*(?:request|input|param|data|body|query|get|post)/i,
        message: 'mark_safe() called with a value that appears to include user input. This bypasses ' +
            "Django's auto-escaping and allows XSS. Ensure content is sanitised before marking safe.",
    },
    // ── Insecure random ──────────────────────────────────────────────────────────
    {
        type: 'INSECURE_RANDOM',
        severity: 'medium',
        pattern: /\brandom\.(?:random|randint|randrange|choice|shuffle|sample)\s*\(/,
        message: 'Python random module is not cryptographically secure. For security-sensitive values ' +
            '(tokens, passwords, salts, session IDs) use secrets.token_bytes(), ' +
            'secrets.token_hex(), or secrets.token_urlsafe() instead.',
    },
    // ── Open redirect ────────────────────────────────────────────────────────────
    // Flask / Django redirect with user-controlled URL
    {
        type: 'OPEN_REDIRECT',
        severity: 'medium',
        pattern: /(?:redirect|HttpResponseRedirect)\s*\([^)\n]*(?:request\.(?:GET|POST|args|form|values)|params|url|next)\b/,
        message: 'Redirect target appears to include user-controlled input. Without validation ' +
            'this allows open redirect attacks. Validate that the destination is a relative URL ' +
            'or belongs to a trusted domain before redirecting.',
    },
    // ── SQL injection (additional patterns) ──────────────────────────────────────
    // ORM raw() / extra() with string formatting
    {
        type: 'SQL_INJECTION',
        severity: 'critical',
        pattern: /\.(?:raw|extra)\s*\([^)\n]*(?:%s|%d|\{|f['"'])/,
        message: 'ORM raw() or extra() query built with string formatting. User input in the query ' +
            'string leads to SQL injection. Use parameterised queries or ORM filters.',
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
        message: 'os.path.join() called with what appears to be user-controlled input. A path like ' +
            '"/etc/passwd" as a component overrides earlier segments. Validate and sanitise ' +
            'all user-supplied path components.',
    },
    // ── Shell injection (additional patterns) ─────────────────────────────────────
    // os.system with variable (not a string literal)
    {
        type: 'COMMAND_INJECTION',
        severity: 'critical',
        pattern: /os\.system\s*\([^)\n]*(?:request|input|param|data|body|query|get|post|args|form|\+|%|f['"'])/i,
        message: 'os.system() called with a value that appears to include user input. User-controlled ' +
            'shell commands allow arbitrary code execution. Use subprocess with a list of arguments ' +
            'and shell=False.',
    },
];
/**
 * Scans a parsed Python source for security vulnerabilities using pattern matching.
 * Returns findings in the same Finding format as JS/TS detectors.
 */
function scanPython(result) {
    const findings = [];
    result.lines.forEach((line, idx) => {
        const lineNum = idx + 1;
        const trimmed = line.trim();
        // Skip pure comments
        if (trimmed.startsWith('#'))
            return;
        for (const { type, severity, pattern, message } of PYTHON_PATTERNS) {
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
//# sourceMappingURL=python-parser.js.map