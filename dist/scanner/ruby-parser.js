"use strict";
/**
 * Ruby language support for the AI Code Security Scanner.
 *
 * This module implements a regex-based scan pass for Ruby files. It operates on
 * raw source lines with pattern matching — no native Ruby bindings required.
 * Patterns focus on Rails-specific vulnerabilities common in AI-generated code.
 *
 * Covered vulnerability classes:
 *   - SQL_INJECTION (string interpolation in ActiveRecord queries)
 *   - XSS (html_safe, raw with user input)
 *   - COMMAND_INJECTION (backtick execution, system(), exec(), Open3 with interpolation)
 *   - SECRET_HARDCODED (hardcoded credentials)
 *   - MASS_ASSIGNMENT (permit(:all) or unrestricted permit)
 *   - PATH_TRAVERSAL (File.read/open with user input)
 *   - INSECURE_RANDOM (rand() for security use)
 *   - WEAK_CRYPTO (MD5, SHA1 via Digest library)
 *   - OPEN_REDIRECT (redirect_to with user input)
 *   - EVAL_INJECTION (eval with user input)
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
exports.parseRubyFile = parseRubyFile;
exports.parseRubyCode = parseRubyCode;
exports.scanRuby = scanRuby;
const fs = __importStar(require("fs"));
function parseRubyFile(filePath) {
    const code = fs.readFileSync(filePath, 'utf-8');
    return parseRubyCode(code, filePath);
}
function parseRubyCode(code, filePath = 'input.rb') {
    return { language: 'ruby', code, lines: code.split('\n'), filePath };
}
const RUBY_PATTERNS = [
    // SQL injection via string interpolation in ActiveRecord
    {
        type: 'SQL_INJECTION',
        severity: 'critical',
        pattern: /\.where\s*\(\s*"[^"]*#\{/,
        message: 'ActiveRecord .where() called with string interpolation. User input in SQL strings leads ' +
            'to SQL injection. Use parameterised form: .where("column = ?", value) or a hash condition.',
    },
    {
        type: 'SQL_INJECTION',
        severity: 'critical',
        pattern: /\.(?:find_by_sql|execute|select|joins)\s*\([^)]*#\{/,
        message: 'Raw SQL query built with Ruby string interpolation. Use ActiveRecord parameterised ' +
            'queries or ActiveRecord::Base.sanitize_sql to prevent SQL injection.',
    },
    {
        type: 'SQL_INJECTION',
        severity: 'critical',
        pattern: /ActiveRecord::Base\.connection\.execute\s*\([^)]*(?:params|request|#\{)/,
        message: 'connection.execute() called with user-controlled or interpolated input. Use bind ' +
            'parameters or sanitize_sql_for_assignment to prevent SQL injection.',
    },
    // XSS via html_safe / raw
    {
        type: 'XSS',
        severity: 'high',
        pattern: /(?:params|request|session|cookies)\[.*\].*\.html_safe/,
        message: 'User input marked as html_safe. This disables Rails automatic HTML escaping and allows ' +
            'Cross-Site Scripting. HTML-encode user input with html_escape() or h() before rendering.',
    },
    {
        type: 'XSS',
        severity: 'high',
        pattern: /raw\s*\(?(?:params|request|session|cookies)/,
        message: 'raw() called with user-controlled input. The raw helper bypasses HTML escaping in Rails ' +
            'views. Use the h() helper or let ERB escape automatically.',
    },
    {
        type: 'XSS',
        severity: 'medium',
        pattern: /\.html_safe\s*$/,
        message: 'html_safe marking detected. Verify the string does not contain user-controlled content; ' +
            'marking untrusted content as html_safe is the most common source of XSS in Rails apps.',
    },
    // Command injection
    {
        type: 'COMMAND_INJECTION',
        severity: 'critical',
        pattern: /`[^`]*#\{/,
        message: 'Backtick shell execution with string interpolation. If any interpolated value is user ' +
            'controlled, this allows arbitrary command injection. Use Open3.capture2e with an argument ' +
            'array (no shell interpretation) instead.',
    },
    {
        type: 'COMMAND_INJECTION',
        severity: 'critical',
        pattern: /\b(?:system|exec|spawn)\s*\([^)]*(?:params|request|#\{)/,
        message: 'Shell command execution with user-controlled or interpolated input. Use an array form ' +
            '(system(cmd, arg1, arg2)) to prevent shell interpretation of arguments.',
    },
    {
        type: 'COMMAND_INJECTION',
        severity: 'critical',
        pattern: /Open3\.(?:popen3|capture2|capture3)\s*\([^)]*(?:params|request|#\{)/,
        message: 'Open3 called with user-controlled input as part of a shell command string. Pass an ' +
            'argument array to avoid shell interpolation: Open3.capture2("cmd", arg1, arg2).',
    },
    // Hardcoded secrets
    {
        type: 'SECRET_HARDCODED',
        severity: 'high',
        pattern: /(?:password|passwd|secret|token|api_key|apiKey|private_key)\s*=\s*['"][^'"]{4,}['"]/i,
        message: 'Potential hardcoded credential in Ruby source. Secrets must be loaded from environment ' +
            'variables (ENV[]) or Rails credentials (Rails.application.credentials).',
    },
    // Mass assignment via permit(:all)
    {
        type: 'MASS_ASSIGNMENT',
        severity: 'high',
        pattern: /\.permit\s*\(\s*:all\s*\)/,
        message: 'Strong parameters configured with permit(:all). This allows an attacker to set any ' +
            'model attribute, including privileged fields. Explicitly list permitted attributes.',
    },
    // Path traversal
    {
        type: 'PATH_TRAVERSAL',
        severity: 'high',
        pattern: /File\s*\.\s*(?:read|open|new|expand_path)\s*\([^)]*(?:params|request|#\{)/,
        message: 'File operation with user-controlled path. Without path canonicalisation, attackers can ' +
            'traverse the filesystem using ../ sequences. Use File.expand_path and verify the result ' +
            'starts with the expected base directory.',
    },
    // Insecure random
    {
        type: 'INSECURE_RANDOM',
        severity: 'medium',
        pattern: /\brand\b\s*(?:\(|\n)/,
        message: 'Kernel#rand is not cryptographically secure and must not be used for tokens, session IDs, ' +
            'or any security-sensitive values. Use SecureRandom.hex, SecureRandom.urlsafe_base64, or ' +
            'SecureRandom.uuid instead.',
    },
    // Weak crypto via Ruby Digest library
    {
        type: 'WEAK_CRYPTO',
        severity: 'high',
        pattern: /Digest::(?:MD5|SHA1)\s*\./,
        message: 'Weak hashing algorithm used via Ruby Digest library. MD5 and SHA-1 are cryptographically ' +
            'broken. Use Digest::SHA256 or OpenSSL::Digest::SHA256. For passwords, use bcrypt.',
    },
    // Open redirect
    {
        type: 'OPEN_REDIRECT',
        severity: 'medium',
        pattern: /redirect_to\s+(?:params|request\.referer|#\{)[^,);\n]*/,
        message: 'redirect_to called with user-controlled URL. Without validation, this allows phishing via ' +
            'open redirect. Validate that the target is a relative path or a known safe domain.',
    },
    // Eval with user input
    {
        type: 'EVAL_INJECTION',
        severity: 'critical',
        pattern: /\beval\s*\([^)]*(?:params|request|#\{)/,
        message: 'eval() called with user-controlled or interpolated input. This executes arbitrary Ruby ' +
            'code and must never receive untrusted input.',
    },
];
/**
 * Scans a parsed Ruby source for security vulnerabilities using pattern matching.
 * Returns findings in the same Finding format as other language detectors.
 */
function scanRuby(result) {
    const findings = [];
    result.lines.forEach((line, idx) => {
        const lineNum = idx + 1;
        const trimmed = line.trim();
        // Skip pure comments
        if (trimmed.startsWith('#'))
            return;
        for (const { type, severity, pattern, message } of RUBY_PATTERNS) {
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
//# sourceMappingURL=ruby-parser.js.map