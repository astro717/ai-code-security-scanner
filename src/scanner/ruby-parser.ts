/**
 * Ruby language support for the AI Code Security Scanner.
 *
 * This module implements a regex-based scan pass for Ruby files. It operates on
 * raw source lines with pattern matching — no native Ruby bindings required.
 * Patterns focus on Rails-specific vulnerabilities common in AI-generated code.
 *
 * Covered vulnerability classes:
 *   - SQL_INJECTION (string interpolation in ActiveRecord queries)
 *   - PERFORMANCE_N_PLUS_ONE (N+1 query anti-patterns in loops)
 *   - XSS (html_safe, raw with user input)
 *   - COMMAND_INJECTION (backtick execution, system(), exec(), Open3 with interpolation)
 *   - SECRET_HARDCODED (hardcoded credentials)
 *   - MASS_ASSIGNMENT (permit(:all) or unrestricted permit)
 *   - PATH_TRAVERSAL (File.read/open with user input)
 *   - INSECURE_RANDOM (rand() for security use)
 *   - WEAK_CRYPTO (MD5, SHA1 via Digest library)
 *   - OPEN_REDIRECT (redirect_to with user input)
 *   - EVAL_INJECTION (eval with user input)
 *   - LDAP_INJECTION (Net::LDAP search with string interpolation)
 */

import * as fs from 'fs';
import type { Finding } from './reporter';

export interface RubyParseResult {
  language: 'ruby';
  code: string;
  lines: string[];
  filePath: string;
}

export function parseRubyFile(filePath: string): RubyParseResult {
  const code = fs.readFileSync(filePath, 'utf-8');
  return parseRubyCode(code, filePath);
}

export function parseRubyCode(code: string, filePath = 'input.rb'): RubyParseResult {
  return { language: 'ruby', code, lines: code.split('\n'), filePath };
}

// ── Pattern-based detectors ───────────────────────────────────────────────────

interface RubyPattern {
  type: string;
  severity: Finding['severity'];
  pattern: RegExp;
  message: string;
}

const RUBY_PATTERNS: RubyPattern[] = [
  // SQL injection via string interpolation in ActiveRecord
  {
    type: 'SQL_INJECTION',
    severity: 'critical',
    pattern: /\.where\s*\(\s*"[^"]*#\{/,
    message:
      'ActiveRecord .where() called with string interpolation. User input in SQL strings leads ' +
      'to SQL injection. Use parameterised form: .where("column = ?", value) or a hash condition.',
  },
  {
    type: 'SQL_INJECTION',
    severity: 'critical',
    pattern: /\.(?:find_by_sql|execute|select|joins)\s*\([^)]*#\{/,
    message:
      'Raw SQL query built with Ruby string interpolation. Use ActiveRecord parameterised ' +
      'queries or ActiveRecord::Base.sanitize_sql to prevent SQL injection.',
  },
  {
    type: 'SQL_INJECTION',
    severity: 'critical',
    pattern: /ActiveRecord::Base\.connection\.execute\s*\([^)]*(?:params|request|#\{)/,
    message:
      'connection.execute() called with user-controlled or interpolated input. Use bind ' +
      'parameters or sanitize_sql_for_assignment to prevent SQL injection.',
  },

  // XSS via html_safe / raw
  {
    type: 'XSS',
    severity: 'high',
    pattern: /(?:params|request|session|cookies)\[.*\].*\.html_safe/,
    message:
      'User input marked as html_safe. This disables Rails automatic HTML escaping and allows ' +
      'Cross-Site Scripting. HTML-encode user input with html_escape() or h() before rendering.',
  },
  {
    type: 'XSS',
    severity: 'high',
    pattern: /raw\s*\(?(?:params|request|session|cookies)/,
    message:
      'raw() called with user-controlled input. The raw helper bypasses HTML escaping in Rails ' +
      'views. Use the h() helper or let ERB escape automatically.',
  },
  {
    type: 'XSS',
    severity: 'medium',
    pattern: /\.html_safe\s*$/,
    message:
      'html_safe marking detected. Verify the string does not contain user-controlled content; ' +
      'marking untrusted content as html_safe is the most common source of XSS in Rails apps.',
  },

  // Command injection
  {
    type: 'COMMAND_INJECTION',
    severity: 'critical',
    pattern: /`[^`]*#\{/,
    message:
      'Backtick shell execution with string interpolation. If any interpolated value is user ' +
      'controlled, this allows arbitrary command injection. Use Open3.capture2e with an argument ' +
      'array (no shell interpretation) instead.',
  },
  {
    type: 'COMMAND_INJECTION',
    severity: 'critical',
    pattern: /\b(?:system|exec|spawn)\s*\([^)]*(?:params|request|#\{)/,
    message:
      'Shell command execution with user-controlled or interpolated input. Use an array form ' +
      '(system(cmd, arg1, arg2)) to prevent shell interpretation of arguments.',
  },
  {
    type: 'COMMAND_INJECTION',
    severity: 'critical',
    pattern: /Open3\.(?:popen3|capture2|capture3)\s*\([^)]*(?:params|request|#\{)/,
    message:
      'Open3 called with user-controlled input as part of a shell command string. Pass an ' +
      'argument array to avoid shell interpolation: Open3.capture2("cmd", arg1, arg2).',
  },

  // Hardcoded secrets
  {
    type: 'SECRET_HARDCODED',
    severity: 'high',
    pattern: /(?:password|passwd|secret|token|api_key|apiKey|private_key)\s*=\s*['"][^'"]{4,}['"]/i,
    message:
      'Potential hardcoded credential in Ruby source. Secrets must be loaded from environment ' +
      'variables (ENV[]) or Rails credentials (Rails.application.credentials).',
  },

  // Mass assignment via permit(:all)
  {
    type: 'MASS_ASSIGNMENT',
    severity: 'high',
    pattern: /\.permit\s*\(\s*:all\s*\)/,
    message:
      'Strong parameters configured with permit(:all). This allows an attacker to set any ' +
      'model attribute, including privileged fields. Explicitly list permitted attributes.',
  },

  // Path traversal
  {
    type: 'PATH_TRAVERSAL',
    severity: 'high',
    pattern: /File\s*\.\s*(?:read|open|new|expand_path)\s*\([^)]*(?:params|request|#\{)/,
    message:
      'File operation with user-controlled path. Without path canonicalisation, attackers can ' +
      'traverse the filesystem using ../ sequences. Use File.expand_path and verify the result ' +
      'starts with the expected base directory.',
  },

  // Insecure random
  {
    type: 'INSECURE_RANDOM',
    severity: 'medium',
    pattern: /\brand\b\s*(?:\(|\n)/,
    message:
      'Kernel#rand is not cryptographically secure and must not be used for tokens, session IDs, ' +
      'or any security-sensitive values. Use SecureRandom.hex, SecureRandom.urlsafe_base64, or ' +
      'SecureRandom.uuid instead.',
  },

  // Weak crypto via Ruby Digest library
  {
    type: 'WEAK_CRYPTO',
    severity: 'high',
    pattern: /Digest::(?:MD5|SHA1)\s*\./,
    message:
      'Weak hashing algorithm used via Ruby Digest library. MD5 and SHA-1 are cryptographically ' +
      'broken. Use Digest::SHA256 or OpenSSL::Digest::SHA256. For passwords, use bcrypt.',
  },

  // Open redirect
  {
    type: 'OPEN_REDIRECT',
    severity: 'medium',
    pattern: /redirect_to\s+(?:params|request\.referer|#\{)[^,);\n]*/,
    message:
      'redirect_to called with user-controlled URL. Without validation, this allows phishing via ' +
      'open redirect. Validate that the target is a relative path or a known safe domain.',
  },

  // Eval with user input
  {
    type: 'EVAL_INJECTION',
    severity: 'critical',
    pattern: /\beval\s*\([^)]*(?:params|request|#\{)/,
    message:
      'eval() called with user-controlled or interpolated input. This executes arbitrary Ruby ' +
      'code and must never receive untrusted input.',
  },

  // LDAP injection via Net::LDAP with string interpolation
  {
    type: 'LDAP_INJECTION',
    severity: 'high',
    pattern: /Net::LDAP.*\.search\s*\([^)]*(?:#\{|params|request)/,
    message:
      'Net::LDAP search built with string interpolation or user-controlled input. This allows ' +
      'LDAP injection. Use Net::LDAP::Filter.eq or other filter constructors to build safe queries.',
  },
  {
    type: 'LDAP_INJECTION',
    severity: 'high',
    pattern: /\.search\s*\(\s*(?:filter|base)\s*:\s*"[^"]*#\{.*\}.*".*Net::LDAP/,
    message:
      'Net::LDAP search filter built with string interpolation. This allows LDAP injection. ' +
      'Use Net::LDAP::Filter.eq or other filter constructors to build safe queries.',
  },
  {
    type: 'LDAP_INJECTION',
    severity: 'high',
    pattern: /\.search\s*\(.*filter:\s*"[^"]*#\{/,
    message:
      'LDAP search filter built with string interpolation. User input in LDAP filter strings ' +
      'leads to LDAP injection. Use Net::LDAP::Filter.eq to construct filters safely.',
  },

  // ── Rails-specific: SQL injection via string concatenation ────────────────
  // (complement to the interpolation patterns above — covers "..."+var patterns)
  {
    type: 'SQL_INJECTION',
    severity: 'critical',
    pattern: /\.where\s*\(\s*"[^"]*"\s*\+/,
    message:
      'ActiveRecord .where() called with SQL string built via concatenation. This allows SQL ' +
      'injection. Use parameterised form: .where("column = ?", value) or a hash condition.',
  },
  {
    type: 'SQL_INJECTION',
    severity: 'critical',
    pattern: /\.(?:find_by_sql|execute|select|joins)\s*\([^)]*"\s*\+/,
    message:
      'Raw SQL query built via string concatenation. Use ActiveRecord parameterised queries or ' +
      'ActiveRecord::Base.sanitize_sql to prevent SQL injection.',
  },

  // ── Rails-specific: unsafe use of send() with user input ─────────────────
  // send() and public_send() with user-controlled method names allow arbitrary method dispatch
  {
    type: 'COMMAND_INJECTION',
    severity: 'critical',
    pattern: /\.send\s*\(\s*(?:params|request|#\{)/,
    message:
      'send() called with user-controlled method name. An attacker can invoke any method on the ' +
      'object, including dangerous ones. Use a whitelist of allowed method names before dispatching.',
  },
  {
    type: 'COMMAND_INJECTION',
    severity: 'high',
    pattern: /\.public_send\s*\(\s*(?:params|request|#\{)/,
    message:
      'public_send() called with user-controlled method name. While restricted to public methods, ' +
      'this still allows an attacker to call unintended methods. Validate against an allowlist first.',
  },

  // ── Rails-specific: N+1 query patterns ────────────────────────────────────
  // Accessing an association inside an each loop without eager loading
  {
    type: 'PERFORMANCE_N_PLUS_ONE',
    severity: 'low',
    pattern: /\beach\s+do\s*\|[^|]+\|\s*\n[^e]*\.\w+\s*\.\s*(?:each|map|select|count|first|last|find)/,
    message:
      'Potential N+1 query: association accessed in a loop without eager loading. Use ' +
      '.includes(:association), .preload(:association), or .eager_load(:association) to batch load.',
  },
  {
    type: 'PERFORMANCE_N_PLUS_ONE',
    severity: 'low',
    pattern: /\.each\s*\{[^}]*\.[a-z_]+s\s*\./,
    message:
      'Potential N+1 query: collection association accessed inside an iteration block. ' +
      'Eager-load with .includes(:relation) to avoid one query per record.',
  },

  // ── Rails-specific: unsafe mass assignment via strong params bypass ────────
  // assign_attributes / update / update_attributes with raw params hash
  {
    type: 'MASS_ASSIGNMENT',
    severity: 'high',
    pattern: /\.(?:assign_attributes|update|update_attributes)\s*\(\s*params(?:\[:[^\]]+\])?\s*\)/,
    message:
      'Model updated directly with raw params hash. Without strong parameters (.permit), any ' +
      'attribute can be set including privileged fields. Use params.require(:model).permit(...).',
  },
  {
    type: 'MASS_ASSIGNMENT',
    severity: 'high',
    pattern: /\bModel\.new\s*\(\s*params(?:\[:[^\]]+\])?\s*\)/,
    message:
      'ActiveRecord model instantiated directly from params hash without strong parameters. ' +
      'Use params.require(:model).permit(:field1, :field2) to limit assignable attributes.',
  },
  {
    type: 'MASS_ASSIGNMENT',
    severity: 'medium',
    pattern: /attr_accessible\s*:all/,
    message:
      'attr_accessible :all grants mass assignment of every attribute. This is dangerous in ' +
      'Rails 3.x apps. Explicitly list safe attributes or migrate to strong parameters.',
  },
];

/**
 * Scans a parsed Ruby source for security vulnerabilities using pattern matching.
 * Returns findings in the same Finding format as other language detectors.
 */
export function scanRuby(result: RubyParseResult): Finding[] {
  const findings: Finding[] = [];

  result.lines.forEach((line, idx) => {
    const lineNum = idx + 1;
    const trimmed = line.trim();

    // Skip pure comments
    if (trimmed.startsWith('#')) return;

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
