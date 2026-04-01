/**
 * Auto-remediation engine for the --fix flag.
 *
 * This module applies source-level text replacements for a subset of finding
 * types that have a well-known safe mechanical alternative.  Fixes are applied
 * at the line level (the same granularity the scanner reports) and are
 * deliberately conservative: if the line cannot be transformed safely with a
 * simple regex, the finding is left as a "manual" fix for the developer.
 *
 * Supported auto-fix types by language:
 *
 * JavaScript / TypeScript (.ts, .tsx, .js, .jsx, .mjs, .cjs):
 *   INSECURE_RANDOM    — Math.random()  → crypto.randomBytes(32).toString('hex')
 *   EVAL_INJECTION     — eval(<expr>)   → JSON.parse(<expr>)  (best-effort)
 *   WEAK_CRYPTO        — md5 / sha1 hash creation → sha256 note
 *   SQL_INJECTION      — string-concatenated queries → parameterised query note
 *   PATH_TRAVERSAL     — path.join with user input → path.resolve note
 *   COMMAND_INJECTION  — exec with user input → note-only
 *
 * Python (.py):
 *   EVAL_INJECTION     — eval(x) → ast.literal_eval(x)
 *   PATH_TRAVERSAL     — note-only (os.path.normpath doesn't fully prevent traversal)
 *   SSTI               — render_template_string(var) → note-only
 *
 * Ruby (.rb):
 *   SSTI               — ERB.new(user_input).result → note-only
 *   PATH_TRAVERSAL     — File.read/open → File.expand_path + base-dir guard
 *   COMMAND_INJECTION  — system/exec string → array form
 *
 * C# (.cs):
 *   SQL_INJECTION      — SqlCommand with concatenation → SqlParameter note
 *
 * Kotlin (.kt, .kts):
 *   Supported extension — individual rule coverage is added incrementally.
 *
 * Go (.go):
 *   PATH_TRAVERSAL     — filepath.Clean + base-dir check note
 *   SQL_INJECTION      — parameterized query note
 *   COMMAND_INJECTION_GO — separate args note
 *   INSECURE_RANDOM    — crypto/rand note
 *   WEAK_CRYPTO        — sha256 note
 *
 * Java (.java):
 *   SQL_INJECTION      — PreparedStatement note
 *   COMMAND_INJECTION  — ProcessBuilder note
 *   WEAK_CRYPTO        — MessageDigest.getInstance("MD5"|"SHA-1") → "SHA-256" replacement
 *   UNSAFE_DESERIALIZATION — ObjectInputStream note
 *
 * Swift (.swift):
 *   INSECURE_RANDOM    — SecRandomCopyBytes note
 *   WEAK_CRYPTO        — CryptoKit SHA256 note
 *   FORCE_UNWRAP       — guard let / if let note
 *   FORCE_TRY          — do/catch note
 *   WEBVIEW_LOAD_URL   — navigationDelegate + allowlist note
 *
 * C/C++ (.c, .cpp, .h, .hpp):
 *   BUFFER_OVERFLOW    — strcpy → strncpy, strcat → strncat (mechanical)
 *   FORMAT_STRING      — printf(var) → printf("%s", var) (mechanical)
 *   COMMAND_INJECTION_C — system() → execv() array args note
 *   INSECURE_RANDOM    — rand() → getrandom()/arc4random() note
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

  // ── SQL_INJECTION (PHP): string concatenation → PDO parameterized query note ─
  {
    types: ['SQL_INJECTION'],
    description: 'Add TODO note to use PDO parameterized queries instead of string concatenation',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.php') return null;
      if (/prepare\s*\(|bindParam|bindValue|execute\s*\(\[/.test(line)) return null;
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO: Use PDO parameterized queries: $stmt = $pdo->prepare("... WHERE id = ?"); $stmt->execute([$id]);\n` +
        line
      );
    },
  },

  // ── XSS (PHP): echo $_GET → wrap with htmlspecialchars ────────────────────
  {
    types: ['XSS'],
    description: 'Wrap PHP output with htmlspecialchars() to prevent XSS',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.php') return null;
      if (/htmlspecialchars|htmlentities/.test(line)) return null;
      // Pattern: echo $_GET['x'] or echo $_POST['x'] etc.
      const m = line.match(/^(\s*)(echo|print)\s+(\$_(GET|POST|REQUEST|COOKIE)\[['"]?\w+['"]?\])\s*;/);
      if (m) {
        return `${m[1]}${m[2]} htmlspecialchars(${m[3]}, ENT_QUOTES, 'UTF-8');`;
      }
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO: Wrap output with htmlspecialchars($var, ENT_QUOTES, 'UTF-8') to prevent XSS\n` +
        line
      );
    },
  },

  // ── COMMAND_INJECTION (PHP): shell_exec with user input → escapeshellarg ───
  {
    types: ['COMMAND_INJECTION'],
    description: 'Wrap PHP shell argument with escapeshellarg() to prevent command injection',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.php') return null;
      if (/escapeshellarg|escapeshellcmd/.test(line)) return null;
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO: Wrap user input with escapeshellarg() before passing to shell functions\n` +
        line
      );
    },
  },

  // ── INSECURE_RANDOM (PHP): rand()/mt_rand() → random_int()/random_bytes() ──
  {
    types: ['INSECURE_RANDOM'],
    description: 'Replace PHP rand()/mt_rand() with cryptographically secure random_int()',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.php') return null;
      // Replace rand( with random_int(
      if (/\brand\s*\(/.test(line)) {
        return line.replace(/\brand\s*\(/, 'random_int(');
      }
      // Replace mt_rand( with random_int(
      if (/\bmt_rand\s*\(/.test(line)) {
        return line.replace(/\bmt_rand\s*\(/, 'random_int(');
      }
      return null;
    },
  },

  // ── WEAK_CRYPTO (PHP): md5()/sha1() → password_hash() note ───────────────
  {
    types: ['WEAK_CRYPTO'],
    description: 'Replace PHP md5()/sha1() with password_hash() for passwords or hash() for data integrity',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.php') return null;
      if (/password_hash|hash\s*\(\s*'sha256'/.test(line)) return null;
      if (/\bmd5\s*\(/.test(line)) {
        return line.replace(/\bmd5\s*\(/, 'hash(\'sha256\', ');
      }
      if (/\bsha1\s*\(/.test(line)) {
        return line.replace(/\bsha1\s*\(/, 'hash(\'sha256\', ');
      }
      return null;
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

  // ── INSECURE_SHARED_PREFS (Kotlin/Android): getSharedPreferences → EncryptedSharedPreferences ──
  {
    types: ['INSECURE_SHARED_PREFS'],
    description: 'Note: replace getSharedPreferences with EncryptedSharedPreferences for sensitive data',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.kt' && ext !== '.kts') return null;
      if (/EncryptedSharedPreferences/.test(line)) return null;
      if (!/getSharedPreferences\s*\(/.test(line)) return null;
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO(INSECURE_SHARED_PREFS): Replace getSharedPreferences with EncryptedSharedPreferences\n` +
        `${indent}// val masterKey = MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()\n` +
        `${indent}// val prefs = EncryptedSharedPreferences.create(context, "secure_prefs", masterKey,\n` +
        `${indent}//     EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,\n` +
        `${indent}//     EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM)\n` +
        line
      );
    },
  },

  // ── WEBVIEW_LOAD_URL (Kotlin/Android): loadUrl with user input → validate before loading ──
  {
    types: ['WEBVIEW_LOAD_URL'],
    description: 'Note: validate URL before passing to WebView.loadUrl() to prevent JavaScript injection',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.kt' && ext !== '.kts') return null;
      if (!/\.loadUrl\s*\(/.test(line)) return null;
      // If already has URL validation patterns, skip
      if (/startsWith\s*\(["']https|Uri\.parse|allowedUrls|whitelist/i.test(line)) return null;
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO(WEBVIEW_LOAD_URL): Validate URL before loading. Example:\n` +
        `${indent}// val allowedHosts = setOf("example.com", "api.example.com")\n` +
        `${indent}// val uri = Uri.parse(url)\n` +
        `${indent}// if (uri.scheme != "https" || !allowedHosts.contains(uri.host)) return\n` +
        line
      );
    },
  },

  // ── INSECURE_RANDOM (Rust): rand::random / thread_rng → OsRng ──────────────
  // rand::random::<u64>() and thread_rng() in security contexts should use
  // the OS-backed OsRng instead of the pseudo-random thread-local source.
  {
    types: ['INSECURE_RANDOM'],
    description: 'Replace rand::random / thread_rng with OsRng (cryptographically secure) in Rust',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.rs') return null;

      // Pattern 1: rand::random::<T>() → OsRng call with TODO
      if (/rand::random\s*(?:::<[^>]+>)?\s*\(\s*\)/.test(line)) {
        const indent = line.match(/^(\s*)/)?.[1] ?? '';
        const fixed = line.replace(
          /rand::random\s*(?:::<[^>]+>)?\s*\(\s*\)/g,
          '{ use rand::rngs::OsRng; use rand::RngCore; OsRng.next_u64() }',
        );
        if (fixed !== line) {
          return `${indent}// TODO(INSECURE_RANDOM): OsRng requires the "os-rng" feature in Cargo.toml\n${fixed}`;
        }
      }

      // Pattern 2: thread_rng() → OsRng
      if (/\bthread_rng\s*\(\s*\)/.test(line)) {
        const indent = line.match(/^(\s*)/)?.[1] ?? '';
        const fixed = line.replace(/\bthread_rng\s*\(\s*\)/g, '{ use rand::rngs::OsRng; OsRng }');
        if (fixed !== line) {
          return `${indent}// TODO(INSECURE_RANDOM): replaced thread_rng with OsRng — add rand "os-rng" feature\n${fixed}`;
        }
      }

      return null;
    },
  },

  // ── WEAK_CRYPTO (Rust): md5/sha1 crate usage → sha2::Sha256 annotation ────
  {
    types: ['WEAK_CRYPTO'],
    description: 'Annotate md5/sha1 crate usage with sha2::Sha256 migration hint in Rust',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.rs') return null;

      // Pattern 1: md5::compute(...) → annotation
      if (/\bmd5::compute\s*\(/.test(line)) {
        const indent = line.match(/^(\s*)/)?.[1] ?? '';
        return (
          `${indent}// TODO(WEAK_CRYPTO): replace md5::compute with sha2::Sha256::digest() — add sha2 to Cargo.toml\n` +
          line
        );
      }

      // Pattern 2: Sha1::new() → Sha256::new() direct replacement
      if (/\bSha1\s*::\s*new\s*\(\s*\)/.test(line)) {
        const fixed = line.replace(/\bSha1\s*::\s*new\s*\(\s*\)/g, 'Sha256::new()');
        if (fixed !== line) {
          const indent = line.match(/^(\s*)/)?.[1] ?? '';
          return (
            `${indent}// TODO(WEAK_CRYPTO): updated SHA-1 → SHA-256; ensure sha2 is in Cargo.toml and import sha2::Sha256\n` +
            fixed
          );
        }
      }

      // Pattern 3: use sha1:: or use md5:: import declaration → annotate
      if (/^\s*use\s+(?:sha1|md5)::/.test(line)) {
        const indent = line.match(/^(\s*)/)?.[1] ?? '';
        return (
          `${indent}// TODO(WEAK_CRYPTO): replace sha1/md5 dependency with sha2 crate (Sha256) — update Cargo.toml\n` +
          line
        );
      }

      return null;
    },
  },

  // ── COMMAND_INJECTION (Rust): Command::new with user-controlled args ────────
  // Adds a TODO annotation — full auto-fix requires argument allowlisting that
  // is too context-dependent for a single-line transform.
  {
    types: ['COMMAND_INJECTION'],
    description: 'Add TODO annotation for Command::new with potentially unsanitized args in Rust',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.rs') return null;

      if (!/Command::new\s*\(|\.arg\s*\(/.test(line)) return null;
      // Skip if already annotated
      if (/TODO.*COMMAND_INJECTION/.test(line)) return null;
      // Skip if the Command::new arg is a static string literal with no chained .arg()
      if (/Command::new\s*\(\s*"[^"]*"\s*\)\s*;?\s*$/.test(line)) return null;

      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO(COMMAND_INJECTION): validate/allowlist all Command args — never pass raw user input\n` +
        line
      );
    },
  },

  // ── UNSAFE_BLOCK (Rust): unsafe { } block — scope minimization guidance ─────
  {
    types: ['UNSAFE_BLOCK'],
    description: 'Add TODO annotation to minimize the unsafe block scope in Rust',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.rs') return null;
      if (!/\bunsafe\s*\{/.test(line)) return null;
      if (/TODO.*UNSAFE_BLOCK/.test(line)) return null;
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO(UNSAFE_BLOCK): minimize the unsafe block — only include the exact lines that require unsafe operations\n` +
        line
      );
    },
  },

  // ── Go language auto-fix rules ────────────────────────────────────────────────

  // ── PATH_TRAVERSAL (Go): filepath.Join with user input → filepath.Clean + base check ──
  {
    types: ['PATH_TRAVERSAL'],
    description: 'Add filepath.Clean and base-directory guard for Go path traversal',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.go') return null;
      if (/filepath\.Clean|strings\.HasPrefix/.test(line)) return null;
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO(PATH_TRAVERSAL): use filepath.Clean(p) and verify strings.HasPrefix(clean, baseDir) before use\n` +
        line
      );
    },
  },

  // ── SQL_INJECTION (Go): string-concatenated query → parameterized note ───────
  {
    types: ['SQL_INJECTION'],
    description: 'Add TODO note to use parameterized queries (db.Query with ?) in Go',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.go') return null;
      if (/\?\s*,|\$\d+/.test(line)) return null; // already parameterized
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO(SQL_INJECTION): use parameterized query: db.Query("SELECT ... WHERE id = ?", id)\n` +
        line
      );
    },
  },

  // ── COMMAND_INJECTION_GO (Go): exec.Command with shell string → array args note ──
  {
    types: ['COMMAND_INJECTION_GO'],
    description: 'Note: pass arguments as separate strings to exec.Command to avoid shell injection in Go',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.go') return null;
      if (!/exec\.Command\s*\(|exec\.CommandContext\s*\(/.test(line)) return null;
      if (/TODO.*COMMAND_INJECTION_GO/.test(line)) return null;
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO(COMMAND_INJECTION_GO): pass each argument separately — exec.Command("cmd", arg1, arg2) — never use "sh", "-c"\n` +
        line
      );
    },
  },

  // ── INSECURE_RANDOM (Go): math/rand → crypto/rand note ───────────────────────
  {
    types: ['INSECURE_RANDOM'],
    description: 'Note: replace math/rand with crypto/rand for cryptographic operations in Go',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.go') return null;
      if (/crypto\/rand/.test(line)) return null;
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO(INSECURE_RANDOM): replace math/rand with crypto/rand — import "crypto/rand"; rand.Read(buf)\n` +
        line
      );
    },
  },

  // ── WEAK_CRYPTO (Go): md5/sha1 import → sha256 note ─────────────────────────
  {
    types: ['WEAK_CRYPTO'],
    description: 'Note: replace md5/sha1 with crypto/sha256 in Go',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.go') return null;
      if (/sha256|sha512/.test(line)) return null;
      if (/\bmd5\b|\bsha1\b/.test(line)) {
        const indent = line.match(/^(\s*)/)?.[1] ?? '';
        return (
          `${indent}// TODO(WEAK_CRYPTO): replace md5/sha1 with crypto/sha256 — import "crypto/sha256"; sha256.Sum256(data)\n` +
          line
        );
      }
      return null;
    },
  },

  // ── Java language auto-fix rules ─────────────────────────────────────────────

  // ── SQL_INJECTION (Java): SqlCommand/string concat → PreparedStatement note ──
  {
    types: ['SQL_INJECTION'],
    description: 'Note: use PreparedStatement with ? placeholders instead of string concatenation in Java',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.java') return null;
      if (/PreparedStatement|prepareStatement|setString|setInt/.test(line)) return null;
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO(SQL_INJECTION): PreparedStatement pstmt = conn.prepareStatement("SELECT ... WHERE id = ?"); pstmt.setString(1, id);\n` +
        line
      );
    },
  },

  // ── COMMAND_INJECTION (Java): Runtime.exec with string concat → array form note ──
  {
    types: ['COMMAND_INJECTION'],
    description: 'Note: use ProcessBuilder with separate args instead of Runtime.exec(String) in Java',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.java') return null;
      if (!/Runtime\.getRuntime\(\)\.exec|ProcessBuilder/.test(line)) return null;
      if (/TODO.*COMMAND_INJECTION/.test(line)) return null;
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO(COMMAND_INJECTION): new ProcessBuilder("cmd", arg1, arg2).start() — never concatenate user input into shell strings\n` +
        line
      );
    },
  },

  // ── WEAK_CRYPTO (Java): MessageDigest MD5/SHA-1 → SHA-256 note ───────────────
  {
    types: ['WEAK_CRYPTO'],
    description: 'Note: replace MD5/SHA-1 MessageDigest with SHA-256 in Java',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.java') return null;
      if (!/MessageDigest\.getInstance\s*\(/.test(line)) return null;
      if (/SHA-256|SHA-512|SHA-384/.test(line)) return null;
      const fixed = line.replace(
        /MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1|SHA1)["']\s*\)/gi,
        'MessageDigest.getInstance("SHA-256")',
      );
      return fixed !== line ? fixed : null;
    },
  },

  // ── UNSAFE_DESERIALIZATION (Java): ObjectInputStream → note-only ─────────────
  {
    types: ['UNSAFE_DESERIALIZATION'],
    description: 'Note: replace ObjectInputStream with a safe deserialization alternative in Java',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.java') return null;
      if (!/ObjectInputStream|readObject\s*\(/.test(line)) return null;
      if (/TODO.*UNSAFE_DESERIALIZATION/.test(line)) return null;
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO(UNSAFE_DESERIALIZATION): replace ObjectInputStream with a safe alternative (e.g. Jackson with type restrictions or XStream with allowlists)\n` +
        line
      );
    },
  },

  // ── Swift language auto-fix rules ────────────────────────────────────────────

  // ── INSECURE_RANDOM (Swift): arc4random → SecRandomCopyBytes note ────────────
  {
    types: ['INSECURE_RANDOM'],
    description: 'Note: replace arc4random with SecRandomCopyBytes in Swift',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.swift') return null;
      if (!/arc4random/.test(line)) return null;
      if (/SecRandomCopyBytes/.test(line)) return null;
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO(INSECURE_RANDOM): replace arc4random with SecRandomCopyBytes(kSecRandomDefault, count, &buf)\n` +
        line
      );
    },
  },

  // ── WEAK_CRYPTO (Swift): CC_MD5/CC_SHA1/Insecure.MD5 → CryptoKit SHA256 note ─
  {
    types: ['WEAK_CRYPTO'],
    description: 'Note: replace CommonCrypto MD5/SHA1 with CryptoKit SHA256 in Swift',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.swift') return null;
      if (!/CC_MD5|CC_SHA1|Insecure\.MD5|Insecure\.SHA1|kCCAlgorithmDES/.test(line)) return null;
      if (/SHA256|CryptoKit/.test(line)) return null;
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO(WEAK_CRYPTO): replace with CryptoKit — import CryptoKit; let hash = SHA256.hash(data: data)\n` +
        line
      );
    },
  },

  // ── FORCE_UNWRAP (Swift): Type! → guard let / if let note ────────────────────
  {
    types: ['FORCE_UNWRAP'],
    description: 'Note: replace implicitly unwrapped optional (Type!) with guard let / if let in Swift',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.swift') return null;
      if (!/(?:let|var)\s+\w+\s*:\s*\w+\s*!/.test(line)) return null;
      if (/TODO.*FORCE_UNWRAP/.test(line)) return null;
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO(FORCE_UNWRAP): replace implicitly unwrapped optional with optional (?) and use guard let / if let\n` +
        line
      );
    },
  },

  // ── FORCE_TRY (Swift): try! → do/catch note ───────────────────────────────────
  {
    types: ['FORCE_TRY'],
    description: 'Note: replace try! with do/catch error handling in Swift',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.swift') return null;
      if (!/\btry!\s/.test(line)) return null;
      if (/TODO.*FORCE_TRY/.test(line)) return null;
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO(FORCE_TRY): replace try! with do { let x = try ... } catch { /* handle error */ }\n` +
        line
      );
    },
  },

  // ── WEBVIEW_LOAD_URL (Swift): WKWebView loadURL → navigationDelegate + allowlist note ──
  {
    types: ['WEBVIEW_LOAD_URL'],
    description: 'Note: add navigationDelegate and URL allowlist before loading URLs in WKWebView',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (ext !== '.swift') return null;
      if (!/\.load\s*\(|\.loadHTMLString\s*\(/.test(line)) return null;
      if (/TODO.*WEBVIEW_LOAD_URL|navigationDelegate/.test(line)) return null;
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO(WEBVIEW_LOAD_URL): implement WKNavigationDelegate.webView(_:decidePolicyFor:) to allowlist allowed hosts\n` +
        line
      );
    },
  },

  // ── C/C++ language auto-fix rules ────────────────────────────────────────────

  // ── BUFFER_OVERFLOW (C/C++): strcpy/strcat → strncpy/strncat note ────────────
  {
    types: ['BUFFER_OVERFLOW'],
    description: 'Replace strcpy/strcat with size-bounded strncpy/strncat in C/C++',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (!['.c', '.cpp', '.h', '.hpp'].includes(ext)) return null;

      // Direct mechanical replacement for strcpy → strncpy
      if (/\bstrcpy\s*\(/.test(line)) {
        const m = line.match(/\bstrcpy\s*\(\s*([^,]+),\s*([^)]+)\)/);
        if (m) {
          const dest = m[1]!.trim();
          const src = m[2]!.trim();
          const fixed = line.replace(
            /\bstrcpy\s*\([^)]+\)/,
            `strncpy(${dest}, ${src}, sizeof(${dest}) - 1)`,
          );
          return fixed !== line ? fixed : null;
        }
      }

      // Direct mechanical replacement for strcat → strncat
      if (/\bstrcat\s*\(/.test(line)) {
        const m = line.match(/\bstrcat\s*\(\s*([^,]+),\s*([^)]+)\)/);
        if (m) {
          const dest = m[1]!.trim();
          const src = m[2]!.trim();
          const fixed = line.replace(
            /\bstrcat\s*\([^)]+\)/,
            `strncat(${dest}, ${src}, sizeof(${dest}) - strlen(${dest}) - 1)`,
          );
          return fixed !== line ? fixed : null;
        }
      }

      return null;
    },
  },

  // ── FORMAT_STRING (C/C++): printf(userInput) → printf("%s", userInput) ────────
  {
    types: ['FORMAT_STRING'],
    description: 'Add format string literal to printf to prevent format string injection in C/C++',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (!['.c', '.cpp', '.h', '.hpp'].includes(ext)) return null;
      // Match printf(variable) or printf(expr) but NOT printf("literal...")
      const m = line.match(/\b(printf|fprintf|sprintf|snprintf)\s*\(\s*(?!["'])([^,)]+)\s*\)/);
      if (!m) return null;
      const fn = m[1]!;
      const arg = m[2]!.trim();
      const fixed = line.replace(
        /\b(?:printf|fprintf|sprintf|snprintf)\s*\(\s*(?!["'])([^,)]+)\s*\)/,
        `${fn}("%s", ${arg})`,
      );
      return fixed !== line ? fixed : null;
    },
  },

  // ── COMMAND_INJECTION_C (C/C++): system() → execv() array args note ──────────
  {
    types: ['COMMAND_INJECTION_C', 'COMMAND_INJECTION'],
    description: 'Note: replace system() with execv() with separate args array in C/C++',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (!['.c', '.cpp', '.h', '.hpp'].includes(ext)) return null;
      if (!/\bsystem\s*\(/.test(line)) return null;
      if (/TODO.*COMMAND_INJECTION_C/.test(line)) return null;
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO(COMMAND_INJECTION_C): replace system() with execv() — char *args[] = {"cmd", arg, NULL}; execv("/usr/bin/cmd", args);\n` +
        line
      );
    },
  },

  // ── INSECURE_RANDOM (C/C++): rand() → getrandom()/arc4random() note ─────────
  {
    types: ['INSECURE_RANDOM'],
    description: 'Note: replace rand() with getrandom() or arc4random() for secure random in C/C++',
    transform(line: string, finding: Finding): string | null {
      const ext = path.extname(finding.file ?? '').toLowerCase();
      if (!['.c', '.cpp', '.h', '.hpp'].includes(ext)) return null;
      if (!/\brand\s*\(\s*\)/.test(line)) return null;
      if (/getrandom|arc4random|RAND_bytes/.test(line)) return null;
      const indent = line.match(/^(\s*)/)?.[1] ?? '';
      return (
        `${indent}// TODO(INSECURE_RANDOM): replace rand() with getrandom(buf, size, 0) or arc4random() for cryptographically secure random values\n` +
        line
      );
    },
  },
];

// ── File extension guard ───────────────────────────────────────────────────────

const FIXABLE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.cs', '.kt', '.kts', '.rb', '.php', '.rs', '.go', '.java', '.swift', '.c', '.cpp', '.h', '.hpp']);

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
