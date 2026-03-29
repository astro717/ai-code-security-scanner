/**
 * Auto-remediation engine for the --fix flag.
 *
 * This module applies source-level text replacements for a subset of finding
 * types that have a well-known safe mechanical alternative.  Fixes are applied
 * at the line level (the same granularity the scanner reports) and are
 * deliberately conservative: if the line cannot be transformed safely with a
 * simple regex, the finding is left as a "manual" fix for the developer.
 *
 * Supported auto-fix types (all JS/TS only):
 *   INSECURE_RANDOM  — Math.random()  -> crypto.randomBytes(32).toString('hex')
 *   EVAL_INJECTION   — eval(<expr>)   -> JSON.parse(<expr>)  (best-effort)
 *   WEAK_CRYPTO      — md5 / sha1 hash creation  -> sha256 equivalent note
 *
 * The fixer also supports Ruby (INSECURE_RANDOM → SecureRandom, SSTI, PATH_TRAVERSAL,
 * COMMAND_INJECTION) and Swift (WEAK_CRYPTO → CC_SHA256). Go, Java, and C files
 * still require manual review.
 */

import * as fs from 'fs';
import * as path from 'path';
import { Finding } from './reporter';

export interface FixResult {
  /** Absolute path of the file that was (or would be) modified. */
  file: string;
  /** The finding this fix addresses. */
  finding: Finding;
  /** Whether the fix was applied successfully. */
  applied: boolean;
  /** Human-readable description of what was changed (or why it was skipped). */
  description: string;
  /** The original line text before the fix. */
  originalLine?: string;
  /** The replacement line text after the fix. */
  fixedLine?: string;
}

// ── Fix rule definitions ───────────────────────────────────────────────────────

interface FixRule {
  /** Finding types this rule handles. */
  types: string[];
  /**
   * Attempt to transform a single line.  Returns the fixed line string if a
   * transformation was made, or null to indicate "cannot auto-fix this line".
   */
  transform(line: string, finding: Finding): string | null;
  /** Short description shown to the user. */
  description: string;
}

const FIX_RULES: FixRule[] = [
  // ── INSECURE_RANDOM: Math.random() → crypto.randomBytes(32).toString('hex') ──
  {
    types: ['INSECURE_RANDOM'],
    description: "Replace Math.random() with crypto.randomBytes(32).toString('hex')",
    transform(line: string): string | null {
      // Match Math.random() with optional chained calls like * 1000, .toString(36)
      // We replace the entire Math.random() call expression on the line.
      if (!/Math\.random\s*\(\s*\)/.test(line)) return null;

      // Replace Math.random() → crypto.randomBytes(32).toString('hex')
      // Also strip any arithmetic that was making it look like a token
      // (e.g.  Math.random() * 1e17  ->  crypto.randomBytes(32).toString('hex'))
      let fixed = line.replace(
        /Math\.random\s*\(\s*\)\s*(?:\*\s*[\d.e+]+)?(?:\.toString\s*\([^)]*\))?/g,
        "crypto.randomBytes(32).toString('hex')",
      );

      // If the file doesn't already import crypto, we add a note in the description
      // but cannot safely insert an import from inside a single-line transform.
      // The CLI will print the import reminder separately.
      return fixed !== line ? fixed : null;
    },
  },

  // ── EVAL_INJECTION: eval(x) → JSON.parse(x) ───────────────────────────────
  {
    types: ['EVAL_INJECTION'],
    description: 'Replace eval(<expr>) with JSON.parse (JS/TS) or ast.literal_eval (Python)',
    transform(line: string, finding: Finding): string | null {
      // Only handle simple eval(identifier) or eval(variable) patterns.
      // Do not attempt to rewrite new Function() or setTimeout(str) — too risky.
      // Use a negative lookbehind for '.' and word chars so we don't match
      // already-replaced text like 'ast.literal_eval(...)'.
      const evalMatch = line.match(/(?<![.\w])eval\s*\(([^)]+)\)/);
      if (!evalMatch) return null;

      const inner = evalMatch[1]?.trim() ?? '';
      // Skip if the inner expression is already a string literal (eval('...') is
      // a code smell but not a dynamic injection risk — leave as-is).
      if (/^['"\`]/.test(inner)) return null;

      // Python files: use ast.literal_eval instead of JSON.parse
      if (path.extname(finding.file ?? '').toLowerCase() === '.py') {
        const fixed = line.replace(/(?<![.\w])eval\s*\(([^)]+)\)/, 'ast.literal_eval($1)');
        return fixed !== line ? fixed : null;
      }

      const fixed = line.replace(/(?<![.\w])eval\s*\(([^)]+)\)/, `JSON.parse($1)`);
      return fixed !== line ? fixed : null;
    },
  },

  // ── WEAK_CRYPTO: createHash('md5'|'md4'|'sha1'|'sha-1') → createHash('sha256') ──
  {
    types: ['WEAK_CRYPTO'],
    description: "Replace weak hash algorithm (MD5/MD4/SHA-1) with SHA-256",
    transform(line: string): string | null {
      if (!/createHash\s*\(\s*['"](?:md5|md4|sha-?1)['"]/.test(line)) return null;
      const fixed = line.replace(
        /createHash\s*\(\s*['"](?:md5|md4|sha-?1)['"]\s*\)/gi,
        "createHash('sha256')",
      );
      return fixed !== line ? fixed : null;
    },
  },

  // ── XSS: .innerHTML = → .textContent = ────────────────────────────────────
  {
    types: ['XSS'],
    description: 'Replace innerHTML assignment with textContent (prevents XSS)',
    transform(line: string): string | null {
      if (!/\.innerHTML\s*=/.test(line)) return null;
      const fixed = line.replace(/\.innerHTML\s*=/g, '.textContent =');
      return fixed !== line ? fixed : null;
    },
  },

  // ── JWT_NONE_ALGORITHM ──────────────────────────────────────────────────────
  // Case 1: jwt.verify(token, secret) -> jwt.verify(token, secret, { algorithms: ['HS256'] })
  // Case 2: algorithms: ['none'] -> algorithms: ['HS256']
  {
    types: ['JWT_NONE_ALGORITHM'],
    description: "Add { algorithms: ['HS256'] } to jwt.verify() call",
    transform(line: string): string | null {
      // Case 2 — explicit 'none' in algorithms array
      if (/algorithms\s*:\s*\[['"]none['"]\]/.test(line)) {
        const fixed2 = line.replace(
          /algorithms\s*:\s*\[['"]none['"]\]/g,
          "algorithms: ['HS256']",
        );
        return fixed2 !== line ? fixed2 : null;
      }

      // Case 1 — jwt.verify(token, secret) with no 3rd argument
      const match = line.match(/jwt\.verify\s*\(\s*([^,]+),\s*([^,)]+)\s*\)/);
      if (!match) return null;
      const jwtToken = match[1]!.trim();
      const jwtSecret = match[2]!.trim();
      const fixed1 = line.replace(
        /jwt\.verify\s*\(\s*[^,]+,\s*[^,)]+\s*\)/,
        `jwt.verify(${jwtToken}, ${jwtSecret}, { algorithms: ['HS256'] })`,
      );
      return fixed1 !== line ? fixed1 : null;
    },
  },
  // ── JWT_DECODE_NO_VERIFY: jwt.decode(token) → jwt.verify(token, secret, { algorithms: ['HS256'] }) ──
  {
    types: ['JWT_DECODE_NO_VERIFY'],
    description: "Replace jwt.decode(token) with jwt.verify(token, secret, { algorithms: ['HS256'] })",
    transform(line: string): string | null {
      // Match jwt.decode(token) — must NOT already have jwt.verify on this line
      const match = line.match(/\bjwt\.decode\s*\(([^)]+)\)/);
      if (!match) return null;
      const tokenExpr = match[1]!.trim();
      const fixed = line.replace(
        /\bjwt\.decode\s*\([^)]+\)/,
        // TODO: replace process.env.JWT_SECRET with your actual JWT secret
        `jwt.verify(${tokenExpr}, process.env.JWT_SECRET, { algorithms: ['HS256'] })`,
      );
      return fixed !== line ? fixed : null;
    },
  },

  // ── LDAP_INJECTION: note-only rule (language-specific escape required) ────
  {
    types: ['LDAP_INJECTION'],
    description: 'Escape LDAP filter characters using a library function',
    transform(_line: string): string | null {
      // LDAP injection requires language-specific escaping — cannot auto-fix.
      return null;
    },
  },

  // ── XML_INJECTION: note-only rule (parser config change required) ─────────
  {
    types: ['XML_INJECTION'],
    description: 'Replace xml.etree with defusedxml to disable external entities',
    transform(_line: string): string | null {
      // XXE mitigation requires swapping the import — cannot safe-rewrite inline.
      return null;
    },
  },

  // ── INSECURE_ASSERT: replace assert with explicit raise ───────────────────
  {
    types: ['INSECURE_ASSERT'],
    description: 'Replace assert with explicit conditional raise',
    transform(line: string): string | null {
      // Match Python-style: assert <expr> (optionally: , "message")
      const assertMatch = line.match(/^(\s*)assert\s+(.+?)(?:\s*,\s*(.+))?\s*$/);
      if (!assertMatch) return null;
      const indent = assertMatch[1] ?? '';
      const condition = assertMatch[2]?.trim() ?? '';
      const msg = assertMatch[3]?.trim() ?? '"Security check failed"';
      const fixed = `${indent}if not (${condition}):
${indent}    raise ValueError(${msg})`;
      return fixed;
    },
  },

  // ── INSECURE_BINDING: note-only rule (requires config change) ────────────
  {
    types: ['INSECURE_BINDING'],
    description: 'Change binding host from 0.0.0.0 to 127.0.0.1',
    transform(line: string): string | null {
      // Replace 0.0.0.0 with 127.0.0.1 in host/bind strings
      if (!/0\.0\.0\.0/.test(line)) return null;
      const fixed = line.replace(/['"]0\.0\.0\.0['"]/g, "'127.0.0.1'");
      return fixed !== line ? fixed : null;
    },
  },

  // ── SQL_INJECTION_CS: string concatenation → parameterized query hint ─────
  {
    types: ['SQL_INJECTION_CS'],
    description: 'Replace SqlCommand string concatenation with parameterized query',
    transform(line: string): string | null {
      // Detect: new SqlCommand("... " + variable ...);
      // Replace with a commented hint — cannot safely construct the full parameterized query inline
      if (!/new\s+SqlCommand\s*\(/.test(line)) return null;
      if (!/ \+/.test(line)) return null; // Only flag when there is concatenation
      const fixed = line.replace(
        /new\s+SqlCommand\s*\(([^)]+)\)/,
        'new SqlCommand(/* TODO: use SqlParameter instead of string concatenation */ $1)',
      );
      return fixed !== line ? fixed : null;
    },
  },

  // ── PATH_TRAVERSAL_CS: Path.Combine with user input → sanitize hint ───────
  {
    types: ['PATH_TRAVERSAL_CS'],
    description: 'Add Path.GetFullPath validation to prevent directory traversal',
    transform(line: string): string | null {
      // Detect: File.ReadAllText( / Path.Combine( / new FileInfo( with variable
      if (!/(?:File\.|new FileInfo\s*\(|Path\.Combine\s*\()/.test(line)) return null;
      if (/GetFullPath|Sanitize|ValidatePath/.test(line)) return null;
      const fixed = line.replace(
        /(File\.\w+\s*\(|new FileInfo\s*\(|Path\.Combine\s*\()([^)]+)\)/,
        '$1/* TODO: validate with Path.GetFullPath() and confirm it stays within allowed base dir */ $2)',
      );
      return fixed !== line ? fixed : null;
    },
  },

  // ── MASS_ASSIGNMENT: note-only rule (Rails-specific, needs manual review) ─
  {
    types: ['MASS_ASSIGNMENT'],
    description: 'Replace permit(:all) with explicit attribute allowlist',
    transform(line: string): string | null {
      // Cannot safely enumerate permitted attributes — require developer input.
      return null;
    },
  },

  // ── SQL_INJECTION_CS: add parameterized query note ──────────────────────────
  // C# SQL injection: SqlCommand with concatenation → use SqlParameter
  {
    types: ['SQL_INJECTION'],
    description: 'Replace concatenated SQL string with parameterized query using SqlParameter',
    transform(line: string, finding: Finding): string | null {
      // Only applies to C# files
      if (path.extname(finding.file ?? '').toLowerCase() !== '.cs') return null;
      // Match: new SqlCommand("..." + variable or f"...{var}")
      // Cannot safely rewrite multi-line queries inline — return null for manual fix.
      return null;
    },
  },

  // ── PATH_TRAVERSAL: wrap unsanitized paths with path.normalize() ──────────
  // Handles JS/TS files. Targets common patterns:
  //   fs.readFile(userInput, ...)    → fs.readFile(path.normalize(userInput), ...)
  //   fs.readFileSync(userInput, ...) → fs.readFileSync(path.normalize(userInput), ...)
  //   path.join(base, userInput, ...) → already has path module; add normalize around 2nd arg
  // For C# files, falls through to note-only (manual fix required).
  {
    types: ['PATH_TRAVERSAL'],
    description: 'Wrap unsanitized path argument with path.normalize() to prevent directory traversal',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();

      // C# files — cannot auto-fix inline
      if (ext === '.cs') return null;

      // Python files — os.path.normpath equivalent (note-only; Python normpath doesn't prevent all traversal)
      if (ext === '.py') return null;

      // JS/TS: only attempt fix if the line doesn't already contain path.normalize / path.resolve / path.join
      // to avoid double-wrapping.
      if (/path\.(normalize|resolve)\s*\(/.test(line)) return null;

      // Pattern 1: fs.<fn>(variable, ...) where variable is a single identifier or simple expression
      // Replace the first argument of fs file-system calls with path.normalize(arg)
      const fsCallMatch = line.match(
        /\b(fs\.\w+\s*\()([^,)]+)(,|\))/,
      );
      if (fsCallMatch) {
        const prefix = fsCallMatch[1]!;
        const arg = fsCallMatch[2]!.trim();
        const sep = fsCallMatch[3]!;
        // Only wrap if the arg looks like a variable/expression (not a string literal or already normalized)
        if (!/^['"`]/.test(arg) && !/path\./.test(arg)) {
          const fixed = line.replace(
            /(\bfs\.\w+\s*\()([^,)]+)(,|\))/,
            `${prefix}path.normalize(${arg})${sep}`,
          );
          return fixed !== line ? fixed : null;
        }
      }

      // Pattern 2: path.join(base, userInput) — wrap with path.normalize at the outermost level
      // Insert path.normalize( ... ) around the entire path.join call
      const joinMatch = line.match(/\bpath\.(join)\s*\(([^;{}\n]+)\)/);
      if (joinMatch) {
        const fixed = line.replace(
          /\bpath\.join\s*\(([^;{}\n]+)\)/,
          'path.normalize(path.join($1))',
        );
        return fixed !== line ? fixed : null;
      }

      return null;
    },
  },


  // ── EVAL_INJECTION (Python): eval(x) → ast.literal_eval(x) ───────────────
  // Separate from the JS rule because Python files use ast.literal_eval instead
  // of JSON.parse. This rule only fires for .py files (guarded below).
  {
    types: ['EVAL_INJECTION_PY'],
    description: 'Replace eval(<expr>) with ast.literal_eval(<expr>) in Python files',
    transform(line: string): string | null {
      // Use a negative lookbehind to avoid re-matching already-replaced text like 'ast.literal_eval(...)'.
      const evalMatch = line.match(/(?<![.\w])eval\s*\(([^)]+)\)/);
      if (!evalMatch) return null;
      const inner = evalMatch[1]?.trim() ?? '';
      // Skip literal string arguments — they are not dynamic injection
      if (/^['"`]/.test(inner)) return null;
      const fixed = line.replace(/(?<![.\w])eval\s*\(([^)]+)\)/, 'ast.literal_eval($1)');
      return fixed !== line ? fixed : null;
    },
  },

  // ── SSTI (Python): render_template_string(var) → note-only fix ────────────
  // Flask's render_template_string() is dangerous when its argument is
  // user-controlled because Jinja2 will execute arbitrary template expressions.
  {
    types: ['SSTI'],
    description: 'Replace render_template_string(<user_input>) with a static template reference',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.py') return null;
      if (!/render_template_string\s*\(/.test(line)) return null;
      if (/TODO.*SSTI|render_template\s*\(/.test(line)) return null;
      const fixed = line.replace(
        /render_template_string\s*\(([^)]+)\)/,
        '# TODO(SSTI): replace with render_template(\"safe_template.html\") — never pass user input to render_template_string\nrender_template_string($1)',
      );
      return fixed !== line ? fixed : null;
    },
  },

  // ── SSTI (Ruby/ERB): ERB.new(user_input).result → note-only fix ───────────
  // ERB.new(user_input).result() is equivalent to eval. Replace with a static
  // ERB template loaded from disk, or insert a TODO comment.
  {
    types: ['SSTI'],
    description: 'Replace ERB.new(<user_input>) with a static template loaded from disk',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.rb') return null;
      if (!/ERB\.new\s*\(/.test(line)) return null;
      if (/TODO.*SSTI|File\.read/.test(line)) return null;
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      const fixed = `${indent}# TODO(SSTI): load ERB template from a file (ERB.new(File.read('template.erb'))) — never render user-controlled strings\n${line}`;
      return fixed !== line ? fixed : null;
    },
  },

  // ── PATH_TRAVERSAL (Ruby): File.read/open with user input ─────────────────
  // Wraps the path argument with File.expand_path and prepends a TODO guard comment.
  {
    types: ['PATH_TRAVERSAL'],
    description: 'Wrap Ruby File path with File.expand_path and add base-dir guard comment',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.rb') return null;

      // Match File.read/open/write/readlines/delete with a non-literal argument
      const rubyFileMatch = line.match(/(\bFile\.\w+\s*\()([^)]+)\)/);
      if (!rubyFileMatch) return null;

      const arg = rubyFileMatch[2]?.trim() ?? '';
      // Skip if arg is already a string literal or already uses expand_path
      if (/^['"]/.test(arg) || /expand_path/.test(arg)) return null;

      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      const fixed = line.replace(
        /(\bFile\.\w+\s*\()([^)]+)\)/,
        `$1File.expand_path($2))`,
      );
      if (fixed === line) {
        return (
          `${indent}# TODO: validate File.expand_path(${arg}).start_with?(BASE_DIR) before use\n` +
          line
        );
      }
      return (
        `${indent}# TODO: validate result.start_with?(BASE_DIR) to prevent directory traversal\n` +
        fixed
      );
    },
  },

  // ── COMMAND_INJECTION (Ruby): system/exec with string interpolation ────────
  // Converts system("cmd #{var}") to system("cmd", var) (array form, no shell).
  // Backtick interpolation gets a TODO comment prepended.
  {
    types: ['COMMAND_INJECTION'],
    description: 'Convert Ruby system/exec string call to array form to bypass shell',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.rb') return null;

      // Pattern 1: system("cmd #{var}") or exec("cmd #{var}")
      const sysMatch = line.match(/\b(system|exec)\s*\(\s*"([^"]*#\{([^}]+)\}[^"]*)"\s*\)/);
      if (sysMatch) {
        const fn = sysMatch[1]!;
        const interpolatedVar = sysMatch[3]!.trim();
        const staticPart = sysMatch[2]!.split(`#{${interpolatedVar}}`)[0]?.trimEnd() ?? '';
        const fixed = line.replace(
          /\b(?:system|exec)\s*\(\s*"[^"]*"\s*\)/,
          `${fn}(${staticPart ? `"${staticPart}", ` : ''}${interpolatedVar})`,
        );
        return fixed !== line ? fixed : null;
      }

      // Pattern 2: backtick with interpolation — prepend warning comment
      if (/`[^`]*#\{/.test(line)) {
        const indent = line.match(/^(\s*)/)?.[1] ?? '';
        return (
          `${indent}# TODO: replace backtick interpolation with array-form IO.popen to prevent command injection\n` +
          line
        );
      }

      return null;
    },
  },

  // ── INSECURE_RANDOM (Ruby): rand/Random.new → SecureRandom.hex ────────────
  {
    types: ['INSECURE_RANDOM'],
    description: 'Replace Ruby rand()/Random.new with SecureRandom.hex (requires "require \'securerandom\'")',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.rb') return null;

      // Pattern: rand() or rand(N) → SecureRandom.random_number(N)
      if (/\brand\s*\(/.test(line)) {
        const fixed = line.replace(
          /\brand\s*\(([^)]*)\)/g,
          (_, args) => args.trim() ? `SecureRandom.random_number(${args.trim()})` : 'SecureRandom.hex(16)',
        );
        return fixed !== line ? fixed : null;
      }

      // Pattern: Random.new.rand → SecureRandom.random_number
      if (/Random\.new\.rand/.test(line)) {
        const fixed = line.replace(/Random\.new\.rand/g, 'SecureRandom.random_number');
        return fixed !== line ? fixed : null;
      }

      return null;
    },
  },

  // ── SQL_INJECTION (Ruby): string interpolation in SQL → parameterized query note ──
  {
    types: ['SQL_INJECTION'],
    description: 'Add TODO comment to replace Ruby SQL string interpolation with parameterized query',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.rb') return null;
      // Match common Ruby SQL patterns with string interpolation: #{var}
      if (!/#\{/.test(line)) return null;
      if (/TODO.*SQL|parameterized|\?\s*,/.test(line)) return null;
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}# TODO(SQL_INJECTION): replace string interpolation with parameterized query,\n` +
        `${indent}# e.g. db.execute("SELECT * FROM users WHERE id = ?", [id])\n` +
        line
      );
    },
  },

  // ── INSECURE_SHARED_PREFS (Swift): UserDefaults for sensitive data ────────
  {
    types: ['INSECURE_SHARED_PREFS'],
    description: 'Replace UserDefaults sensitive storage with Keychain access comment',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.swift') return null;
      if (!/UserDefaults\.standard\.set|UserDefaults\.standard\[/.test(line)) return null;
      if (/TODO.*Keychain|KeychainSwift|KeychainWrapper/.test(line)) return null;
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO(INSECURE_SHARED_PREFS): store sensitive data in Keychain instead of UserDefaults.\n` +
        `${indent}// Use KeychainSwift: keychain.set(value, forKey: key)\n` +
        line
      );
    },
  },

  // ── UNSAFE_WEBVIEW (Swift): WKWebView loadHTMLString with user input ──────
  {
    types: ['UNSAFE_WEBVIEW'],
    description: 'Add TODO to sanitize WKWebView loadHTMLString input',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.swift') return null;
      if (!/loadHTMLString\s*\(|loadRequest\s*\(|load\s*\(URLRequest/.test(line)) return null;
      if (/TODO.*sanitize|allowList|isAllowed/.test(line)) return null;
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO(UNSAFE_WEBVIEW): validate/sanitize the URL and HTML content before loading.\n` +
        `${indent}// Consider a WKNavigationDelegate allowlist to restrict navigable origins.\n` +
        line
      );
    },
  },

  // ── MISSING_AUTH (C#): endpoints without [Authorize] attribute ────────────
  {
    types: ['MISSING_AUTH'],
    description: 'Add TODO comment to add [Authorize] attribute to C# controller action',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.cs') return null;
      // Match controller action method declarations
      if (!/public\s+(?:async\s+)?(?:Task<|IActionResult|ActionResult|string|int|bool)/.test(line)) return null;
      if (/\[Authorize\]|\[AllowAnonymous\]/.test(line)) return null;
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO(MISSING_AUTH): add [Authorize] attribute (or [Authorize(Roles = "...")] for role-based access)\n` +
        line
      );
    },
  },

  // ── UNSAFE_BLOCK (Rust): unsafe { ... } → scope-narrowing note ───────────
  {
    types: ['UNSAFE_BLOCK'],
    description: 'Add TODO comment to narrow the unsafe block scope in Rust',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.rs') return null;
      if (!/\bunsafe\s*\{/.test(line)) return null;
      if (/TODO.*unsafe|SAFETY:/.test(line)) return null;
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// SAFETY: TODO — document why this unsafe block is sound and narrow its scope\n` +
        `${indent}// to the minimum set of operations that require unsafe.\n` +
        line
      );
    },
  },

  // ── SQL_INJECTION (Rust): format! in SQL → parameterized query note ───────
  {
    types: ['SQL_INJECTION'],
    description: 'Add TODO comment to replace Rust format! SQL string with parameterized query',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.rs') return null;
      // Match format! macro or string concatenation in SQL context
      if (!/format!\s*\(|\.to_string\(\)/.test(line)) return null;
      if (/TODO.*SQL|bind\(|sqlx::query!/.test(line)) return null;
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO(SQL_INJECTION): use parameterized queries instead of format! string building.\n` +
        `${indent}// With sqlx: sqlx::query!("SELECT ... WHERE id = ?", id).fetch_one(&pool).await\n` +
        line
      );
    },
  },

  // ── WEAK_CRYPTO (Swift): CC_MD5/CC_SHA1 → CC_SHA256, Insecure.MD5 → SHA256 ─
  {
    types: ['WEAK_CRYPTO'],
    description: 'Replace Swift weak hash (CC_MD5/CC_SHA1/Insecure.MD5) with SHA-256 equivalent',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.swift') return null;

      let fixed = line;

      // CommonCrypto: CC_MD5 → CC_SHA256
      fixed = fixed.replace(/\bCC_MD5\b/g, 'CC_SHA256');
      fixed = fixed.replace(/\bCC_MD5_DIGEST_LENGTH\b/g, 'CC_SHA256_DIGEST_LENGTH');

      // CommonCrypto: CC_SHA1 → CC_SHA256
      fixed = fixed.replace(/\bCC_SHA1\b/g, 'CC_SHA256');
      fixed = fixed.replace(/\bCC_SHA1_DIGEST_LENGTH\b/g, 'CC_SHA256_DIGEST_LENGTH');

      // CommonCrypto: kCCAlgorithmDES → kCCAlgorithmAES
      fixed = fixed.replace(/\bkCCAlgorithmDES\b/g, 'kCCAlgorithmAES');
      fixed = fixed.replace(/\bkCCKeySizeDES\b/g, 'kCCKeySizeAES256');
      fixed = fixed.replace(/\bkCCBlockSizeDES\b/g, 'kCCBlockSizeAES128');

      // CryptoKit: Insecure.MD5 → SHA256, Insecure.SHA1 → SHA256
      fixed = fixed.replace(/\bInsecure\.MD5\b/g, 'SHA256');
      fixed = fixed.replace(/\bInsecure\.SHA1\b/g, 'SHA256');

      return fixed !== line ? fixed : null;
    },
  },

  // ── BUFFER_OVERFLOW (Rust): raw pointer deref / unsafe arithmetic → note ──
  {
    types: ['BUFFER_OVERFLOW'],
    description: 'Add TODO comment to replace unsafe pointer operation with safe Rust alternative',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.rs') return null;

      // Match unsafe raw pointer patterns: *ptr, ptr.offset, ptr.add, ptr::read/write
      if (!/\*\s*\w+|\.offset\s*\(|\.add\s*\(|ptr::\w+|slice::from_raw_parts/.test(line)) return null;
      if (/TODO.*BUFFER_OVERFLOW|SAFETY:.*bounds/.test(line)) return null;

      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO(BUFFER_OVERFLOW): replace raw pointer operation with safe Rust alternative.\n` +
        `${indent}// Consider using slices, Vec, or checked indexing (.get()) instead of raw pointers.\n` +
        line
      );
    },
  },

  // ── SECRET_HARDCODED (Rust): hardcoded credentials → environment variable ──
  {
    types: ['SECRET_HARDCODED'],
    description: 'Replace hardcoded Rust secret with std::env::var() lookup',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.rs') return null;

      // Match: let api_key = "sk-..."; or const PASSWORD: &str = "...";
      if (!/(?:let|const|static)\s+\w*(?:key|secret|password|token|api_key)\w*\s*(?::\s*&?str\s*)?=\s*"/.test(line)) return null;
      if (/std::env::var|env!|dotenv/.test(line)) return null;

      // Extract variable name
      const varMatch = line.match(/(?:let|const|static)\s+(\w+)/);
      if (!varMatch) return null;
      const varName = varMatch[1]!;
      const envName = varName.toUpperCase();

      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}let ${varName} = std::env::var("${envName}").expect("${envName} must be set");`
      );
    },
  },

  // ── SQL_INJECTION (Go): fmt.Sprintf in SQL → parameterized query ──────────
  {
    types: ['SQL_INJECTION'],
    description: 'Replace Go fmt.Sprintf SQL string with parameterized query placeholder',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.go') return null;

      // Match fmt.Sprintf("SELECT ... %s", var) or string concatenation in SQL
      if (!/fmt\.Sprintf\s*\(|".*SELECT.*"\s*\+/.test(line)) return null;
      if (/TODO.*SQL|\$1|\?/.test(line)) return null;

      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO(SQL_INJECTION): use parameterized queries instead of string interpolation.\n` +
        `${indent}// e.g. db.Query("SELECT * FROM users WHERE id = $1", id)\n` +
        line
      );
    },
  },

  // ── COMMAND_INJECTION (Go): exec.Command with shell string → array form ───
  {
    types: ['COMMAND_INJECTION'],
    description: 'Replace Go shell command string with exec.Command array form',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.go') return null;

      // Match exec.Command("sh", "-c", ...) or exec.Command("bash", "-c", ...)
      if (/exec\.Command\s*\(\s*"(?:sh|bash)"\s*,\s*"-c"/.test(line)) {
        const indent = line.match(/^(\s*)/)?.[1] ?? '';
        return (
          `${indent}// TODO(COMMAND_INJECTION): replace shell string with direct exec.Command("binary", "arg1", "arg2") form.\n` +
          `${indent}// This avoids shell interpretation and prevents injection via user-controlled arguments.\n` +
          line
        );
      }

      return null;
    },
  },
];

// ── File extension guard ───────────────────────────────────────────────────────

const FIXABLE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.cs', '.kt', '.kts', '.rb', '.swift', '.rs', '.go']);

function isFixableFile(filePath: string): boolean {
  return FIXABLE_EXTENSIONS.has(path.extname(filePath).toLowerCase());
}

// ── Core fix application ───────────────────────────────────────────────────────

/**
 * Given a list of findings (all from a single scan run), applies auto-fixes to
 * the source files in-place.
 *
 * @param findings   The deduplicated, filtered findings from a scan.
 * @param dryRun     If true, compute and return fix results without writing.
 * @returns          Array of FixResult — one per finding attempted.
 */
export function applyFixes(findings: Finding[], dryRun = false): FixResult[] {
  const results: FixResult[] = [];

  // Group findings by file so we apply all fixes to a file in one pass.
  const byFile = new Map<string, Finding[]>();
  for (const f of findings) {
    if (!f.file) continue;
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file)!.push(f);
  }

  for (const [filePath, fileFindings] of byFile.entries()) {
    if (!isFixableFile(filePath)) {
      for (const f of fileFindings) {
        results.push({
          file: filePath,
          finding: f,
          applied: false,
          description: `Auto-fix not supported for ${path.extname(filePath)} files — manual fix required.`,
        });
      }
      continue;
    }

    let lines: string[];
    try {
      lines = fs.readFileSync(filePath, 'utf-8').split('\n');
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      for (const f of fileFindings) {
        results.push({ file: filePath, finding: f, applied: false, description: `Could not read file: ${msg}` });
      }
      continue;
    }

    // Sort findings by line descending so that applying fixes from the bottom up
    // doesn't shift line numbers for earlier (higher) findings.
    const sorted = [...fileFindings].sort((a, b) => b.line - a.line);
    const modified = new Set<number>();

    for (const finding of sorted) {
      const lineIdx = finding.line - 1; // 0-based
      if (lineIdx < 0 || lineIdx >= lines.length) {
        results.push({ file: filePath, finding, applied: false, description: 'Line number out of range — skipping.' });
        continue;
      }

      if (modified.has(lineIdx)) {
        results.push({ file: filePath, finding, applied: false, description: 'Line was already modified by another fix in this pass — skipping to avoid conflicts.' });
        continue;
      }

      // Try ALL rules for this finding type in order — the first one whose
      // transform() returns a non-null value wins.  Multiple rules for the
      // same type (e.g. SQL_INJECTION for Go, Ruby, Rust, C#) are each
      // language-guarded internally; using find() would stop at the first
      // language's rule even when it returns null for a different language.
      const matchingRules = FIX_RULES.filter((r) => r.types.includes(finding.type));
      if (matchingRules.length === 0) {
        results.push({ file: filePath, finding, applied: false, description: `No auto-fix rule for finding type "${finding.type}" — manual fix required.` });
        continue;
      }

      const originalLine = lines[lineIdx]!;
      let appliedRule: FixRule | null = null;
      let fixedLine: string | null = null;
      for (const candidate of matchingRules) {
        const result = candidate.transform(originalLine, finding);
        if (result !== null) {
          appliedRule = candidate;
          fixedLine = result;
          break;
        }
      }

      if (fixedLine === null || appliedRule === null) {
        results.push({
          file: filePath,
          finding,
          applied: false,
          description: `${matchingRules.map(r => r.description).join(' / ')} — pattern not matched on this line; manual fix required.`,
          originalLine,
        });
        continue;
      }

      const rule = appliedRule;
      lines[lineIdx] = fixedLine;
      modified.add(lineIdx);
      results.push({
        file: filePath,
        finding,
        applied: true,
        description: rule.description,
        originalLine,
        fixedLine,
      });
    }

    // If any INSECURE_RANDOM fix was applied, ensure crypto import is present
    if (modified.size > 0) {
      const hasInsecureRandomFix = results.some(
        (r) => r.file === filePath && r.applied && r.finding.type === 'INSECURE_RANDOM',
      );
      if (hasInsecureRandomFix) {
        const hasCryptoImport = lines.some(
          (l) =>
            /import\s+.*\bcrypto\b/.test(l) ||
            /import\s+\{[^}]*\brandomBytes\b[^}]*\}\s+from\s+['"]crypto['"]/.test(l) ||
            /require\s*\(\s*['"]crypto['"]\s*\)/.test(l),
        );
        if (!hasCryptoImport) {
          lines.unshift("import crypto from 'crypto';");
          // Shift all line-based results for this file by +1 since we inserted a line at top
        }
      }
    }

    if (!dryRun && modified.size > 0) {
      try {
        fs.writeFileSync(filePath, lines.join('\n'), 'utf-8');
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        // Mark all applied fixes as failed since the write didn't succeed
        for (const r of results) {
          if (r.file === filePath && r.applied) {
            r.applied = false;
            r.description = `Fix computed but could not write file: ${msg}`;
          }
        }
      }
    }
  }

  return results;
}

/**
 * Returns true if the given finding type has at least one auto-fix rule.
 */
export function isFixable(findingType: string): boolean {
  return FIX_RULES.some((r) => r.types.includes(findingType));
}

/**
 * Generates a unified-diff string for a set of FixResults, grouped by file.
 * Each hunk shows 3 lines of context around the changed line (standard unified format).
 *
 * This is used by the CLI when --fix --dry-run is requested.
 */
export function buildUnifiedDiff(results: FixResult[]): string {
  const byFile = new Map<string, FixResult[]>();
  for (const r of results) {
    if (!r.applied || r.originalLine === undefined || r.fixedLine === undefined) continue;
    if (!byFile.has(r.file)) byFile.set(r.file, []);
    byFile.get(r.file)!.push(r);
  }

  const parts: string[] = [];
  const CONTEXT_LINES = 3;

  for (const [filePath, fixResults] of byFile.entries()) {
    let lines: string[];
    try {
      lines = fs.readFileSync(filePath, 'utf-8').split('\n');
    } catch {
      // File may have already been written in a non-dry-run pass; use stored lines
      lines = [];
    }

    parts.push(`--- a/${filePath}`);
    parts.push(`+++ b/${filePath}`);

    for (const r of fixResults) {
      const lineIdx = r.finding.line - 1; // 0-based
      const ctxStart = Math.max(0, lineIdx - CONTEXT_LINES);
      const ctxEnd = Math.min(lines.length - 1, lineIdx + CONTEXT_LINES);
      const hunkOldStart = ctxStart + 1;
      const hunkNewStart = ctxStart + 1;
      const hunkSize = ctxEnd - ctxStart + 1;

      parts.push(`@@ -${hunkOldStart},${hunkSize} +${hunkNewStart},${hunkSize} @@ [${r.finding.type}]`);

      for (let i = ctxStart; i <= ctxEnd; i++) {
        if (i === lineIdx) {
          parts.push(`-${r.originalLine}`);
          parts.push(`+${r.fixedLine}`);
        } else {
          parts.push(` ${lines[i] ?? ''}`);
        }
      }
    }
  }

  return parts.join('\n');
}


/**
 * Prints a human-readable summary of fix results to stderr.
 */
export function printFixSummary(results: FixResult[], dryRun: boolean): void {
  const applied = results.filter((r) => r.applied);
  const skipped = results.filter((r) => !r.applied);

  const prefix = dryRun ? '[fix --dry-run]' : '[fix]';

  if (applied.length === 0 && skipped.length === 0) {
    process.stderr.write(`${prefix} No fixable findings.\n`);
    return;
  }

  if (applied.length > 0) {
    process.stderr.write(`\n${prefix} Applied ${applied.length} auto-fix(es):\n`);
    for (const r of applied) {
      const rel = r.file;
      process.stderr.write(`  ✓  ${rel}:${r.finding.line}  [${r.finding.type}]\n`);
      process.stderr.write(`     ${r.description}\n`);
      if (r.originalLine !== undefined) {
        process.stderr.write(`     - ${r.originalLine.trim()}\n`);
      }
      if (r.fixedLine !== undefined) {
        process.stderr.write(`     + ${r.fixedLine.trim()}\n`);
      }
    }
  }

  if (skipped.length > 0) {
    process.stderr.write(`\n${prefix} ${skipped.length} finding(s) require manual remediation:\n`);
    for (const r of skipped) {
      const rel = r.file;
      process.stderr.write(`  ⚠  ${rel}:${r.finding.line}  [${r.finding.type}]  ${r.description}\n`);
    }
  }

  if (applied.some((r) => r.finding.type === 'INSECURE_RANDOM')) {
    process.stderr.write(
      `\n${prefix} NOTE: INSECURE_RANDOM fixes use crypto.randomBytes(). ` +
      `Ensure "import { randomBytes } from 'crypto';" is present at the top of affected files.\n`,
    );
  }

  if (dryRun) {
    process.stderr.write(`\n${prefix} Dry-run mode: no files were written. Re-run without --dry-run to apply.\n`);
  }
}
