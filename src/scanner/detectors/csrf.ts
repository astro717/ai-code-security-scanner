/**
 * CSRF detection for Express.js / Node.js applications.
 *
 * Detects cases where:
 *  - The `csurf` / `csrf-csrf` middleware is not imported but POST/PUT/DELETE routes are defined
 *  - CSRF protection middleware is explicitly disabled (app.disable('x-powered-by') + no csrf import)
 *
 * This is a line-based heuristic detector since CSRF absence is hard to prove structurally.
 * Only flags when mutating routes are present AND no csrf-related middleware import is found.
 */

import type { ParseResult } from '../parser';
import type { Finding } from '../reporter';

/** Patterns that indicate a CSRF-protecting middleware is in use */
const CSRF_PROTECTION_PATTERNS = [
  /\brequire\s*\(\s*['"]csurf['"]\s*\)/,
  /\brequire\s*\(\s*['"]csrf-csrf['"]\s*\)/,
  /\brequire\s*\(\s*['"]@dr\.pogodin\/csurf['"]\s*\)/,
  /\bcsrf\s*\(/,
  /\bcsrfProtection\b/,
  /\bcsrfMiddleware\b/,
  /\bcsrfToken\b/,
  /from\s+['"]csurf['"]/,
  /from\s+['"]csrf-csrf['"]/,
];

/** Patterns that indicate a state-changing route (POST/PUT/DELETE/PATCH) */
const MUTATING_ROUTE_PATTERN =
  /\b(?:app|router)\s*\.\s*(?:post|put|delete|patch)\s*\(\s*['"]/;

/** Patterns suggesting this is an Express app */
const EXPRESS_IMPORT_PATTERN = /require\s*\(\s*['"]express['"]\s*\)|from\s+['"]express['"]/;

export function detectCSRF(result: ParseResult): Finding[] {
  const findings: Finding[] = [];

  // Only run on TS/JS files
  const lines = result.code.split('\n');

  const hasExpressImport = lines.some((l) => EXPRESS_IMPORT_PATTERN.test(l));
  if (!hasExpressImport) return findings;

  const hasCsrfProtection = lines.some((l) => CSRF_PROTECTION_PATTERNS.some((p) => p.test(l)));
  if (hasCsrfProtection) return findings;

  // Flag each mutating route without CSRF protection
  lines.forEach((line, idx) => {
    if (!MUTATING_ROUTE_PATTERN.test(line)) return;
    const trimmed = line.trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('*')) return;

    const methodMatch = line.match(/\b(app|router)\s*\.\s*(post|put|delete|patch)\s*\(/i);
    const method = methodMatch?.[2]?.toUpperCase() ?? 'POST';

    findings.push({
      type: 'CSRF',
      severity: 'high',
      line: idx + 1,
      column: line.search(/\S/),
      snippet: trimmed.slice(0, 100),
      message:
        `Express ${method} route defined without CSRF protection middleware. ` +
        "Install 'csurf' (or 'csrf-csrf') and apply it to state-changing routes. " +
        'Alternatively, verify CSRF tokens manually via a custom middleware.',
      confidence: 0.7,
      file: result.filePath,
    });
  });

  return findings;
}
