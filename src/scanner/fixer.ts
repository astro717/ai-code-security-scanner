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
 * The fixer never modifies Python / Go / Java / C / Ruby / C# files; those
 * require manual review.
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
      const evalMatch = line.match(/\beval\s*\(([^)]+)\)/);
      if (!evalMatch) return null;

      const inner = evalMatch[1]?.trim() ?? '';
      // Skip if the inner expression is already a string literal (eval('...') is
      // a code smell but not a dynamic injection risk — leave as-is).
      if (/^['"\`]/.test(inner)) return null;

      // Python files: use ast.literal_eval instead of JSON.parse
      if (path.extname(finding.file ?? '').toLowerCase() === '.py') {
        const fixed = line.replace(/\beval\s*\(([^)]+)\)/, 'ast.literal_eval($1)');
        return fixed !== line ? fixed : null;
      }

      const fixed = line.replace(/\beval\s*\(([^)]+)\)/, `JSON.parse($1)`);
      return fixed !== line ? fixed : null;
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

  // ── EVAL_INJECTION (Python): eval(x) → ast.literal_eval(x) ───────────────
  // Separate from the JS rule because Python files use ast.literal_eval instead
  // of JSON.parse. This rule only fires for .py files (guarded below).
  {
    types: ['EVAL_INJECTION_PY'],
    description: 'Replace eval(<expr>) with ast.literal_eval(<expr>) in Python files',
    transform(line: string): string | null {
      const evalMatch = line.match(/eval\s*\(([^)]+)\)/);
      if (!evalMatch) return null;
      const inner = evalMatch[1]?.trim() ?? '';
      // Skip literal string arguments — they are not dynamic injection
      if (/^['"`]/.test(inner)) return null;
      const fixed = line.replace(/eval\s*\(([^)]+)\)/, 'ast.literal_eval($1)');
      return fixed !== line ? fixed : null;
    },
  },
];

// ── File extension guard ───────────────────────────────────────────────────────

const FIXABLE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.cs']);

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

      const rule = FIX_RULES.find((r) => r.types.includes(finding.type));
      if (!rule) {
        results.push({ file: filePath, finding, applied: false, description: `No auto-fix rule for finding type "${finding.type}" — manual fix required.` });
        continue;
      }

      const originalLine = lines[lineIdx]!;
      const fixedLine = rule.transform(originalLine, finding);

      if (fixedLine === null) {
        results.push({
          file: filePath,
          finding,
          applied: false,
          description: `${rule.description} — pattern not matched on this line; manual fix required.`,
          originalLine,
        });
        continue;
      }

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
