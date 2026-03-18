#!/usr/bin/env node
import { program } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import { minimatch } from 'minimatch';
import { parseFile } from './scanner/parser';
import { detectSecrets } from './scanner/detectors/secrets';
import { detectSQLInjection } from './scanner/detectors/sql';
import { detectShellInjection } from './scanner/detectors/shell';
import { detectEval } from './scanner/detectors/eval';
import { detectXSS } from './scanner/detectors/xss';
import { detectPathTraversal } from './scanner/detectors/pathTraversal';
import { detectPrototypePollution } from './scanner/detectors/prototypePollution';
import { detectInsecureRandom } from './scanner/detectors/insecureRandom';
import { detectOpenRedirect } from './scanner/detectors/openRedirect';
import { detectSSRF } from './scanner/detectors/ssrf';
import { detectCommandInjection } from './scanner/detectors/commandInjection';
import { detectCORSMisconfiguration } from './scanner/detectors/cors';
import { Finding, printFindings, formatJSON, summarize } from './scanner/reporter';

const SUPPORTED_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs']);

// ── .aiscanner ignore file ────────────────────────────────────────────────────

/**
 * Loads ignore patterns from a `.aiscanner` file in the given directory (or
 * any of its ancestors up to the filesystem root).  Each non-empty line that
 * does not start with `#` is treated as a glob pattern.
 *
 * Returns an empty array if no `.aiscanner` file is found.
 */
function loadAiScannerIgnore(startDir: string): string[] {
  let dir = startDir;
  while (true) {
    const candidate = path.join(dir, '.aiscanner');
    if (fs.existsSync(candidate)) {
      try {
        const lines = fs.readFileSync(candidate, 'utf8')
          .split(/\r?\n/)
          .map((l) => l.trim())
          .filter((l) => l.length > 0 && !l.startsWith('#'));
        if (lines.length > 0) {
          console.error(`[ignore] Loaded ${lines.length} pattern(s) from ${candidate}`);
        }
        return lines;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`[ignore] Warning: could not read ${candidate}: ${msg}`);
        return [];
      }
    }
    const parent = path.dirname(dir);
    if (parent === dir) break; // reached filesystem root
    dir = parent;
  }
  return [];
}

function isIgnored(filePath: string, ignorePatterns: string[]): boolean {
  // Normalise to forward slashes for cross-platform glob matching
  const normalised = filePath.split(path.sep).join('/');
  return ignorePatterns.some((pattern) =>
    minimatch(normalised, pattern, { matchBase: true, dot: true }),
  );
}

function collectFiles(targetPath: string, ignorePatterns: string[] = []): string[] {
  const stat = fs.statSync(targetPath);
  if (stat.isFile()) {
    return isIgnored(targetPath, ignorePatterns) ? [] : [targetPath];
  }

  const files: string[] = [];
  function walk(dir: string) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (isIgnored(full, ignorePatterns)) continue;
      if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
        walk(full);
      } else if (entry.isFile() && SUPPORTED_EXTENSIONS.has(path.extname(entry.name))) {
        files.push(full);
      }
    }
  }
  walk(targetPath);
  return files;
}

function scanFile(filePath: string): Finding[] {
  try {
    const parsed = parseFile(filePath);
    return [
      ...detectSecrets(parsed),
      ...detectSQLInjection(parsed),
      ...detectShellInjection(parsed),
      ...detectEval(parsed),
      ...detectXSS(parsed),
      ...detectPathTraversal(parsed),
      ...detectPrototypePollution(parsed),
      ...detectInsecureRandom(parsed),
      ...detectOpenRedirect(parsed),
      ...detectSSRF(parsed),
      ...detectCommandInjection(parsed),
      ...detectCORSMisconfiguration(parsed),
    ].map((f) => ({ ...f, file: filePath }));
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`  [skip] ${filePath}: ${msg}`);
    return [];
  }
}

function buildSARIF(findings: Finding[]): object {
  const rules = Array.from(new Set(findings.map((f) => f.type))).map((id) => ({
    id,
    name: id,
    shortDescription: { text: id },
  }));

  const results = findings.map((f) => ({
    ruleId: f.type,
    level:
      f.severity === 'critical' || f.severity === 'high' ? 'error' :
      f.severity === 'medium' ? 'warning' : 'note',
    message: { text: f.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.file ?? 'unknown' },
          region: { startLine: f.line, startColumn: f.column },
        },
      },
    ],
  }));

  return {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [{ tool: { driver: { name: 'ai-code-security-scanner', version: '0.1.0', rules } }, results }],
  };
}

program
  .name('ai-sec-scan')
  .description('AST-based security scanner for AI-generated code')
  .version('0.1.0')
  .argument('[path]', 'File or directory to scan', '.')
  .option('--json', 'Output results as JSON')
  .option('--sarif', 'Output results as SARIF 2.1.0')
  .option('--format <format>', 'Output format: text | json | sarif (overrides --json / --sarif flags)')
  .option('--severity <level>', 'Minimum severity to report (critical|high|medium|low)', 'low')
  .option(
    '--min-severity <level>',
    'Minimum severity level that triggers a non-zero exit code (critical|high|medium|low). ' +
    'Defaults to high when omitted (only critical/high cause failure).',
  )
  .option('--ignore <glob>', 'Glob pattern to exclude (repeatable, e.g. --ignore \'**/node_modules/**\')', (val, acc: string[]) => { acc.push(val); return acc; }, [] as string[])
  .action(async (targetPath: string, options: { json: boolean; sarif: boolean; severity: string; minSeverity?: string; ignore: string[] }) => {
  .action(async (targetPath: string, options: { json: boolean; sarif: boolean; format?: string; severity: string; ignore: string[] }) => {
    const resolved = path.resolve(targetPath);

    if (!fs.existsSync(resolved)) {
      console.error(`Error: path not found: ${resolved}`);
      process.exit(1);
    }

    // Load .aiscanner ignore file patterns from the project root (the scan target dir, or its ancestors)
    const scanRoot = fs.statSync(resolved).isDirectory() ? resolved : path.dirname(resolved);
    const fileIgnorePatterns = loadAiScannerIgnore(scanRoot);

    // Merge: .aiscanner patterns + --ignore flags (CLI flags take precedence by appending last)
    const effectiveIgnore = [...fileIgnorePatterns, ...options.ignore];

    const files = collectFiles(resolved, effectiveIgnore);
    const allFindings: Finding[] = [];

    for (const file of files) {
      allFindings.push(...scanFile(file));
    }

    const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

    // --severity controls which findings are reported
    const minReport = severityOrder[options.severity] ?? 3;
    const filtered = allFindings.filter((f) => (severityOrder[f.severity] ?? 3) <= minReport);

    // --format takes highest precedence; --sarif / --json are convenience aliases
    const effectiveFormat = options.format ?? (options.sarif ? 'sarif' : options.json ? 'json' : 'text');

    if (effectiveFormat === 'sarif') {
      console.log(JSON.stringify(buildSARIF(filtered), null, 2));
    } else if (effectiveFormat === 'json') {
      console.log(formatJSON(filtered));
    } else {
      await printFindings(filtered, resolved);
    }

    const summary = summarize(filtered);

    // --min-severity controls which severity triggers a non-zero exit code.
    // If not set, fall back to the legacy behaviour (exit 1 on critical or high).
    if (options.minSeverity) {
      const exitThreshold = severityOrder[options.minSeverity] ?? 1;
      const hasViolation = filtered.some((f) => (severityOrder[f.severity] ?? 3) <= exitThreshold);
      if (hasViolation) {
        process.exit(1);
      }
    } else {
      // Legacy default: exit non-zero on critical or high
      if (summary.critical > 0 || summary.high > 0) {
        process.exit(1);
      }
    }
  });

program.parse();
