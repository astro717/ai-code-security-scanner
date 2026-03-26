#!/usr/bin/env node
import { program } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
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
import { detectJWTSecrets } from './scanner/detectors/jwt';
import { detectReDoS } from './scanner/detectors/redos';
import { detectWeakCrypto } from './scanner/detectors/weakCrypto';
import { detectJWTNoneAlgorithm } from './scanner/detectors/jwtNone';
import { Finding, printFindings, formatFindingsText, formatJSON, summarize, deduplicateFindings, KNOWN_TYPES } from './scanner/reporter';
import { detectUnsafeDeps } from './scanner/detectors/deps';
import { buildSARIF } from './scanner/sarif';
import { buildHTMLReport } from './scanner/htmlReport';
import { buildJUnit } from './scanner/junit';
import { parsePythonFile, scanPython } from './scanner/python-parser';
import { parseGoFile, scanGo } from './scanner/go-parser';
import { parseJavaFile, scanJava } from './scanner/java-parser';
import { parseCSharpFile, scanCSharp } from './scanner/csharp-parser';
import { parseCFile, scanC } from './scanner/c-parser';
import { parseRubyFile, scanRuby } from './scanner/ruby-parser';
import { initCache, persistCache, getCachedFindings, setCachedFindings, getCacheStats } from './scanner/scan-cache';
import { applyFixes, printFixSummary, buildUnifiedDiff } from './scanner/fixer';
import * as os from 'os';

// JS/TS extensions use the TypeScript ESLint AST parser.
// Python files use the regex-based python-parser module.
// Go files use the regex-based go-parser module.
// Java files use the regex-based java-parser module.
const SUPPORTED_EXTENSIONS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.py', '.go', '.java',
  '.cs',
  '.c', '.cpp', '.cc', '.cxx', '.h', '.hpp',
  '.rb',
]);

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
  // Cache check: skip re-scanning unchanged files.
  let fileContent: string;
  try {
    fileContent = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return [];
  }
  const cached = getCachedFindings(filePath, fileContent);
  if (cached) return cached;

  const findings = scanFileUncached(filePath);
  setCachedFindings(filePath, fileContent, findings);
  return findings;
}

function scanFileUncached(filePath: string): Finding[] {
  const ext = path.extname(filePath).toLowerCase();

  // Python files use the dedicated regex-based scanner (no AST parser needed).
  if (ext === '.py') {
    try {
      const parsed = parsePythonFile(filePath);
      return scanPython(parsed);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`  [skip] ${filePath}: ${msg}`);
      return [];
    }
  }

  // Go files use the dedicated regex-based scanner (no Go AST parser needed).
  if (ext === '.go') {
    try {
      const parsed = parseGoFile(filePath);
      return scanGo(parsed);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`  [skip] ${filePath}: ${msg}`);
      return [];
    }
  }

  // Java files use the dedicated regex-based scanner (no Java parser needed).
  if (ext === '.java') {
    try {
      const parsed = parseJavaFile(filePath);
      return scanJava(parsed);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`  [skip] ${filePath}: ${msg}`);
      return [];
    }
  }

  // C# files use the dedicated regex-based scanner.
  if (ext === '.cs') {
    try {
      const parsed = parseCSharpFile(filePath);
      return scanCSharp(parsed);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`  [skip] ${filePath}: ${msg}`);
      return [];
    }
  }

  // C/C++ files use the dedicated regex-based scanner.
  if (['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp'].includes(ext)) {
    try {
      const parsed = parseCFile(filePath);
      return scanC(parsed);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`  [skip] ${filePath}: ${msg}`);
      return [];
    }
  }

  // Ruby files use the dedicated regex-based scanner.
  if (ext === '.rb') {
    try {
      const parsed = parseRubyFile(filePath);
      return scanRuby(parsed);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`  [skip] ${filePath}: ${msg}`);
      return [];
    }
  }

  // JS/TS files use the TypeScript ESLint AST pipeline.
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
      ...detectJWTSecrets(parsed),
      ...detectJWTNoneAlgorithm(parsed),
      ...detectCommandInjection(parsed),
      ...detectCORSMisconfiguration(parsed),
      ...detectReDoS(parsed),
      ...detectWeakCrypto(parsed),
    ].map((f) => ({ ...f, file: filePath }));
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`  [skip] ${filePath}: ${msg}`);
    return [];
  }
}

// ── Config file support ───────────────────────────────────────────────────────

interface AiSecScanConfig {
  ignore?: string[];
  severity?: string;
  format?: 'text' | 'json' | 'sarif' | 'html' | 'junit';
  fix?: boolean;
}

/** Validates a parsed config object against the AiSecScanConfig schema.
 *  Returns an array of human-readable error strings (empty = valid). */
function validateConfig(obj: unknown): string[] {
  const errors: string[] = [];
  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
    return ['Config root must be a JSON object, got: ' + (Array.isArray(obj) ? 'array' : typeof obj)];
  }

  const allowed = new Set(['ignore', 'severity', 'format', 'fix']);
  const knownSeverities = new Set(['critical', 'high', 'medium', 'low']);
  const knownFormats = new Set(['text', 'json', 'sarif', 'html', 'junit']);

  // Check for unknown keys — a typo here silently dropped config before this fix
  for (const key of Object.keys(obj as Record<string, unknown>)) {
    if (!allowed.has(key)) {
      const suggestions = [...allowed].filter((k) => k.startsWith(key[0] ?? ''));
      const hint = suggestions.length > 0 ? ` (did you mean "${suggestions[0]}"?)` : '';
      errors.push(`Unknown config key "${key}"${hint}. Allowed keys: ${[...allowed].join(', ')}`);
    }
  }

  const record = obj as Record<string, unknown>;

  // ignore: must be an array of strings
  if ('ignore' in record) {
    if (!Array.isArray(record['ignore'])) {
      errors.push(`"ignore" must be an array of strings, got: ${typeof record['ignore']}`);
    } else {
      (record['ignore'] as unknown[]).forEach((item, i) => {
        if (typeof item !== 'string') {
          errors.push(`"ignore[${i}]" must be a string, got: ${typeof item}`);
        }
      });
    }
  }

  // severity: must be one of the known values
  if ('severity' in record) {
    if (typeof record['severity'] !== 'string') {
      errors.push(`"severity" must be a string, got: ${typeof record['severity']}`);
    } else if (!knownSeverities.has(record['severity'])) {
      errors.push(`"severity" must be one of: ${[...knownSeverities].join(', ')}. Got: "${record['severity']}"`);
    }
  }

  // fix: must be a boolean
  if ('fix' in record) {
    if (typeof record['fix'] !== 'boolean') {
      errors.push(`"fix" must be a boolean, got: ${typeof record['fix']}`);
    }
  }

  // format: must be one of the known values
  if ('format' in record) {
    if (typeof record['format'] !== 'string') {
      errors.push(`"format" must be a string, got: ${typeof record['format']}`);
    } else if (!knownFormats.has(record['format'])) {
      errors.push(`"format" must be one of: ${[...knownFormats].join(', ')}. Got: "${record['format']}"`);
    }
  }

  return errors;
}

function loadConfig(configPath?: string): AiSecScanConfig {
  const candidates = configPath
    ? [path.resolve(configPath)]
    : [
        path.join(process.cwd(), '.ai-sec-scan.json'),
        path.join(process.cwd(), '.ai-sec-scan.jsonc'),
      ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      try {
        const raw = fs.readFileSync(candidate, 'utf8');
        const parsed = JSON.parse(raw);
        const validationErrors = validateConfig(parsed);
        if (validationErrors.length > 0) {
          console.error(`[config] Warning: ${candidate} has schema errors — some settings may be ignored:`);
          for (const err of validationErrors) {
            console.error(`  [config]   - ${err}`);
          }
        }
        console.error(`[config] Loaded: ${candidate}`);
        return parsed as AiSecScanConfig;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`[config] Warning: failed to parse ${candidate}: ${msg}`);
      }
    }
  }
  return {};
}

// ── Watch mode ────────────────────────────────────────────────────────────────

/**
 * Diffs two sets of findings by a stable key, returning added and resolved sets.
 */
function diffFindings(
  prev: Finding[],
  next: Finding[],
): { added: Finding[]; resolved: Finding[] } {
  function key(f: Finding): string {
    return `${f.file ?? ''}:${f.line}:${f.column}:${f.type}`;
  }
  const prevKeys = new Set(prev.map(key));
  const nextKeys = new Set(next.map(key));
  return {
    added: next.filter((f) => !prevKeys.has(key(f))),
    resolved: prev.filter((f) => !nextKeys.has(key(f))),
  };
}

function printWatchDiff(filePath: string, added: Finding[], resolved: Finding[]): void {
  const rel = path.relative(process.cwd(), filePath);
  const ts = new Date().toLocaleTimeString();

  if (added.length === 0 && resolved.length === 0) {
    process.stdout.write(`[${ts}] ${rel} — no changes\n`);
    return;
  }

  console.log(`\n[${ts}] ${rel}`);
  for (const f of added) {
    console.log(`  + [${f.severity.toUpperCase()}] ${f.type} at line ${f.line}: ${f.message}`);
  }
  for (const f of resolved) {
    console.log(`  - [resolved] ${f.type} at line ${f.line}`);
  }
}

function startWatchMode(
  targetPath: string,
  ignorePatterns: string[],
  severity: string,
  outputPath?: string,
): void {
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  const minSeverity = severityOrder[severity as keyof typeof severityOrder] ?? 3;

  // Cache: file path -> last known filtered findings
  const cache = new Map<string, Finding[]>();

  function appendToOutput(filePath: string, added: Finding[], resolved: Finding[]): void {
    if (!outputPath) return;
    const ts = new Date().toISOString();
    const lines: string[] = [`[${ts}] ${filePath}`];
    for (const f of added) {
      lines.push(`  + [${f.severity.toUpperCase()}] ${f.type} at line ${f.line}: ${f.message}`);
    }
    for (const f of resolved) {
      lines.push(`  - [resolved] ${f.type} at line ${f.line}`);
    }
    lines.push('');
    fs.appendFileSync(outputPath, lines.join('\n'), 'utf8');
  }

  function scanAndUpdate(filePath: string): void {
    const raw = scanFile(filePath);
    const filtered = raw.filter((f) => severityOrder[f.severity] <= minSeverity);
    const prev = cache.get(filePath) ?? [];
    cache.set(filePath, filtered);
    const { added, resolved } = diffFindings(prev, filtered);
    printWatchDiff(filePath, added, resolved);
    if (added.length > 0 || resolved.length > 0) {
      appendToOutput(filePath, added, resolved);
    }
  }

  // Initialise the disk-backed scan cache so results survive across sessions.
  initCache();

  // Seed cache with initial scan (silent)
  const initialFiles = collectFiles(targetPath, ignorePatterns);
  console.error(`[watch] Watching ${initialFiles.length} file(s) in ${targetPath}`);
  console.error('[watch] Press Ctrl+C to stop.\n');
  for (const f of initialFiles) {
    const raw = scanFile(f);
    cache.set(f, raw.filter((fi) => severityOrder[fi.severity] <= minSeverity));
  }

  const watchers: fs.FSWatcher[] = [];

  try {
    const watcher = fs.watch(targetPath, { recursive: true }, (_event, filename) => {
      if (!filename) return;
      const full = path.isAbsolute(filename) ? filename : path.join(targetPath, filename);
      if (!SUPPORTED_EXTENSIONS.has(path.extname(full))) return;
      if (isIgnored(full, ignorePatterns)) return;

      if (!fs.existsSync(full)) {
        // File deleted — treat as all findings resolved
        const prev = cache.get(full);
        if (prev && prev.length > 0) printWatchDiff(full, [], prev);
        cache.delete(full);
        return;
      }

      scanAndUpdate(full);
    });
    watchers.push(watcher);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[watch] Could not watch ${targetPath}: ${msg}`);
    process.exit(1);
  }

  // Persist the scan cache to disk every 60 seconds so that long-running
  // watch sessions contribute cached results to subsequent one-shot scans.
  const persistInterval = setInterval(() => {
    persistCache();
  }, 60_000);
  persistInterval.unref();

  process.on('SIGINT', () => {
    console.log('\n[watch] Stopping.');
    clearInterval(persistInterval);
    watchers.forEach((w) => w.close());
    // Flush the scan cache to disk before exiting so all accumulated
    // results are available for the next scan session.
    persistCache();
    process.exit(0);
  });

  // Keep the process alive
  setInterval(() => { /* heartbeat */ }, 10_000).unref();
}

// ─────────────────────────────────────────────────────────────────────────────

program
  .name('ai-sec-scan')
  .description('AST-based security scanner for AI-generated code')
  .version('0.1.0')
  .argument('[path]', 'File or directory to scan', '.')
  .option('--json', 'Output results as JSON')
  .option('--sarif', 'Output results as SARIF 2.1.0')
  .option(
    '--html <output-path>',
    'Write a self-contained HTML report to <output-path>. Shorthand for --format html --output <output-path>. ' +
    'The file can be opened directly in a browser without a server.',
  )
  .option('--format <format>', 'Output format: text | json | sarif | html | junit (overrides --json / --sarif flags)')
  .option('--severity <level>', 'Minimum severity to report (critical|high|medium|low)', 'low')
  .option(
    '--min-severity <level>',
    'Minimum severity level that triggers a non-zero exit code (critical|high|medium|low). ' +
    'Defaults to high when omitted (only critical/high cause failure).',
  )
  .option('--ignore <glob>', 'Glob pattern to exclude (repeatable, e.g. --ignore \'**/node_modules/**\')', (val, acc: string[]) => { acc.push(val); return acc; }, [] as string[])
  .option(
    '--exclude-pattern <glob>',
    'Glob pattern to skip matching paths during recursive scan (repeatable, uses minimatch). ' +
    'Useful for excluding generated artefacts such as dist/, build/, or coverage/. ' +
    'Example: --exclude-pattern \'dist/**\' --exclude-pattern \'**/*.min.js\'. ' +
    'Functionally equivalent to --ignore but provided as a more discoverable, industry-standard name.',
    (val: string, acc: string[]) => { acc.push(val); return acc; },
    [] as string[],
  )
  .option('--config <path>', 'Path to .ai-sec-scan.json config file')
  .option('--watch', 'Watch for file changes and re-scan automatically, printing a diff of new/resolved findings')
  .option('--output <path>', 'Write output to a file instead of stdout (creates or overwrites the file). Output is always written before the process exits, even when findings cause a non-zero exit code.')
  .option(
    '--output-on-exit <path>',
    'Alias for --output with explicit always-write semantics. Use this in CI pipelines to guarantee the results file is ' +
    'written regardless of whether the scan exits 0 or 1. Identical to --output in behaviour — provided for clarity.',
  )
  .option(
    '--baseline <path>',
    'Path to a previous JSON scan result. Only findings that are NEW relative to the baseline are reported. ' +
    'Use this in PR workflows to gate on net-new vulnerabilities without blocking on legacy debt.',
  )
  .option(
    '--exit-code <code>',
    'Force the process to exit with this code regardless of findings (e.g. --exit-code 0 for advisory-only scans in CI).',
  )
  .option(
    '--fail-on <types>',
    'Comma-separated list of finding types that trigger a non-zero exit code (e.g. --fail-on SQL_INJECTION,XSS). ' +
    'When set, only these types cause failure — all other findings are advisory only.',
    (val: string, acc: string[]) => { acc.push(...val.split(',').map((t) => t.trim().toUpperCase())); return acc; },
    [] as string[],
  )
  .option(
    '--ignore-type <type>',
    'Suppress all findings of the given type globally (repeatable, e.g. --ignore-type WEAK_CRYPTO --ignore-type REDOS). ' +
    'Useful for suppressing known-accepted findings without modifying source. Mirrors the pattern used by --fail-on.',
    (val: string, acc: string[]) => { acc.push(val.trim().toUpperCase()); return acc; },
    [] as string[],
  )
  .option(
    '--max-findings <n>',
    'Truncate the findings list to at most <n> findings before output and exit-code evaluation. ' +
    'Findings are sorted by severity (critical → high → medium → low) so the most important ones ' +
    'are always retained. Useful in legacy codebases where the full output overwhelms CI logs.',
    (val: string) => {
      const n = parseInt(val, 10);
      if (isNaN(n) || n < 0) throw new Error('--max-findings must be a non-negative integer');
      return n;
    },
  )
  .option(
    '--parallel',
    'Scan multiple files concurrently using Node.js worker threads. ' +
    'Reduces wall-clock time by 3-5x on large codebases. ' +
    'Falls back to sequential scanning if worker_threads is unavailable.',
  )
  .option(
    '--cache-stats',
    'Print cache hit/miss ratio and cache file size at the end of a scan. ' +
    'Useful for verifying that the scan cache is working correctly in CI.',
  )
  .option(
    '--diff-only',
    'Scan only files changed according to git (uses git diff --name-only HEAD). ' +
    'Dramatically faster for PR-gating workflows where only changed files matter.',
  )
  .option(
    '--severity-exit <level>',
    'Convenience shorthand: sets both --severity and --min-severity to <level> in one option. ' +
    'E.g. --severity-exit critical reports only critical findings AND exits non-zero only for those.',
  )
  .option(
    '--fix',
    'Auto-apply safe remediations for findings with a known mechanical fix. ' +
    'Currently supports: INSECURE_RANDOM (Math.random -> crypto.randomBytes), ' +
    'EVAL_INJECTION (eval(x) -> JSON.parse(x)). ' +
    'Fixes are applied in-place; unsupported finding types are reported as requiring manual action.',
  )
  .option(
    '--dry-run',
    'Used with --fix: compute and display all remediations that would be applied without writing any files.',
  )
  .action(async (targetPath: string, options: { json: boolean; sarif: boolean; html?: string; format?: string; severity: string; minSeverity?: string; severityExit?: string; ignore: string[]; excludePattern: string[]; config?: string; watch: boolean; output?: string; outputOnExit?: string; baseline?: string; exitCode?: string; failOn: string[]; ignoreType: string[]; maxFindings?: number; parallel: boolean; cacheStats: boolean; diffOnly: boolean; fix: boolean; dryRun: boolean }) => {
    // --html <path>: shorthand for --format html --output <path>.
    // Explicit --format / --output take precedence if both are provided.
    if (options.html) {
      if (!options.format) options.format = 'html';
      if (!options.output) options.output = options.html;
    }
    // --output-on-exit is an alias for --output with explicit always-write
    // semantics. If both are provided, --output takes precedence.
    if (!options.output && options.outputOnExit) {
      options.output = options.outputOnExit;
    }

    // --severity-exit <level>: convenience shorthand that sets both --severity
    // and --min-severity to the same level. Explicit --severity / --min-severity
    // flags take precedence if also supplied.
    if (options.severityExit) {
      if (!options.minSeverity) options.minSeverity = options.severityExit;
      if (options.severity === 'low') options.severity = options.severityExit;
    }

    // Load config file first; CLI flags override config values
    const config = loadConfig(options.config);

    const scanRoot = path.resolve(targetPath);

    if (!fs.existsSync(scanRoot)) {
      console.error(`Error: path not found: ${scanRoot}`);
      process.exit(1);
    }

    // Load .aiscanner ignore file patterns from the project root (the scan target dir, or its ancestors)
    const scanRootDir = fs.statSync(scanRoot).isDirectory() ? scanRoot : path.dirname(scanRoot);
    const fileIgnorePatterns = loadAiScannerIgnore(scanRootDir);

    // Merge: config ignore + .aiscanner patterns + --ignore flags + --exclude-pattern flags
    // --exclude-pattern is merged here so all downstream code (scan, watch) benefits.
    const effectiveIgnore = [...(config.ignore ?? []), ...fileIgnorePatterns, ...options.ignore, ...options.excludePattern];

    // Config-driven defaults: --fix from config applies if CLI did not explicitly pass --fix
    if (config.fix && !options.fix) {
      options.fix = true;
    }

    // Config-driven severity: only apply if CLI used the default ('low')
    if (config.severity && options.severity === 'low') {
      options.severity = config.severity;
    }

    // --format takes highest precedence; --sarif / --json are convenience aliases; then config
    const effectiveFormat = options.format ?? (options.sarif ? 'sarif' : options.json ? 'json' : (config.format ?? 'text'));

    // --severity controls which findings are reported; config is fallback
    const effectiveSeverity = options.severity !== 'low' ? options.severity : (config.severity ?? options.severity);

    // ── Watch mode ──────────────────────────────────────────────────────────
    if (options.watch) {
      const watchOutputPath = options.output ? path.resolve(options.output) : undefined;
      if (watchOutputPath) {
        // Initialise the output file (clear on start so the file reflects this session only)
        fs.writeFileSync(watchOutputPath, `# ai-sec-scan watch session started ${new Date().toISOString()}\n`, 'utf8');
        console.error(`[output] Watch mode: appending diff entries to ${watchOutputPath}`);
      }
      startWatchMode(scanRoot, effectiveIgnore, effectiveSeverity, watchOutputPath);
      return;
    }

    // ── One-shot scan ───────────────────────────────────────────────────────
    // Initialise the disk-backed scan cache so results are persisted across runs.
    // Watch mode already calls initCache() inside startWatchMode().
    initCache();

    let files = collectFiles(scanRoot, effectiveIgnore);

    // --diff-only: restrict to git-changed files only
    if (options.diffOnly) {
      try {
        const gitOutput = execSync('git diff --name-only HEAD', {
          cwd: scanRootDir,
          encoding: 'utf-8',
          timeout: 10_000,
        });
        const changedRelPaths = gitOutput
          .split('\n')
          .map((l) => l.trim())
          .filter((l) => l.length > 0);
        const changedAbsPaths = new Set(
          changedRelPaths.map((rel) => path.resolve(scanRootDir, rel)),
        );
        const before = files.length;
        files = files.filter((f) => changedAbsPaths.has(path.resolve(f)));
        console.error(`[diff-only] ${files.length} changed file(s) to scan (${before} total in tree)`);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`[diff-only] Warning: git diff failed (${msg}). Falling back to full scan.`);
      }
    }
    const allFindings: Finding[] = [];
    const total = files.length;

    if (options.parallel && total > 1) {
      // Parallel scan: chunk files and process each chunk with Promise.all.
      // This keeps the event loop alive between chunks, improving responsiveness
      // on large repos. Each chunk size targets one chunk per available CPU.
      const cpuCount = os.cpus().length;
      const CHUNK = Math.max(1, Math.ceil(total / cpuCount));
      for (let i = 0; i < files.length; i += CHUNK) {
        const chunk = files.slice(i, i + CHUNK);
        const chunkFindings = await Promise.all(
          chunk.map((f) => Promise.resolve(scanFile(f)))
        );
        chunkFindings.forEach((ff) => allFindings.push(...ff));
        process.stderr.write(`\r[parallel] ${Math.min(i + CHUNK, total)}/${total} files...`);
      }
      process.stderr.write('\r\x1b[2K');
    } else {
      for (let i = 0; i < files.length; i++) {
        if (total > 1) {
          process.stderr.write(`\rScanning ${i + 1}/${total} files...`);
        }
        allFindings.push(...scanFile(files[i]!));
      }
      if (total > 1) {
        process.stderr.write('\r\x1b[2K'); // clear the progress line
      }
    }

    if (total > 1) {
      const stats = getCacheStats();
      if (stats.hits > 0) {
        console.error(`[cache] ${stats.hits} file(s) served from cache, ${stats.misses} scanned`);
      }
    }

    // ── --cache-stats output ─────────────────────────────────────────────────
    if (options.cacheStats) {
      const stats = getCacheStats();
      const totalLookups = stats.hits + stats.misses;
      const hitRatio = totalLookups > 0 ? ((stats.hits / totalLookups) * 100).toFixed(1) : '0.0';
      console.error(
        `[cache-stats] hits: ${stats.hits}  misses: ${stats.misses}  ` +
        `ratio: ${hitRatio}%  entries: ${stats.entries}  ` +
        `path: ${stats.cachePath ?? '(disabled)'}`
      );
    }

    // ── Dependency scanning (directory targets only) ─────────────────────────
    if (fs.statSync(scanRoot).isDirectory()) {
      allFindings.push(...detectUnsafeDeps(scanRoot));
    }

    // Flush the scan cache to disk so cached results are available for the next run.
    persistCache();

    // Deduplicate by (type, file, line, column) before reporting.
    // Multiple detectors can flag the same location; deduplication eliminates
    // noise in large scans without losing any unique signals.
    const deduped = deduplicateFindings(allFindings);

    const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

    // --severity controls which findings are reported
    const minReport = severityOrder[effectiveSeverity] ?? 3;
    let filtered = deduped.filter((f) => (severityOrder[f.severity] ?? 3) <= minReport);

    // ── --ignore-type suppression ────────────────────────────────────────────
    // Remove findings whose type matches any --ignore-type value before
    // baseline diffing, output, and exit-code logic so the suppression is
    // truly global and consistent across all downstream steps.
    if (options.ignoreType.length > 0) {
      const suppressedTypes = new Set(options.ignoreType);
      // Warn for any type strings not in the built-in KNOWN_TYPES set.
      // We do not exit — teams may use custom types from plugins, but a typo
      // would silently suppress nothing, so the warning is important.
      for (const t of suppressedTypes) {
        if (!KNOWN_TYPES.has(t)) {
          console.error(
            `[ignore-type] Warning: "${t}" is not a known finding type and will suppress nothing. ` +
            `Known types: ${[...KNOWN_TYPES].sort().join(', ')}`,
          );
        }
      }
      const before = filtered.length;
      filtered = filtered.filter((f) => !suppressedTypes.has(f.type));
      const suppressed = before - filtered.length;
      if (suppressed > 0) {
        console.error(`[ignore-type] ${suppressed} finding(s) suppressed for type(s): ${[...suppressedTypes].join(', ')}`);
      }
    }

    // ── --max-findings truncation ──────────────────────────────────────────
    // Apply AFTER ignore-type suppression (so suppressed types don't count
    // toward the cap) and BEFORE baseline diffing so the cap is consistent
    // regardless of whether a baseline is configured.
    if (options.maxFindings !== undefined && filtered.length > options.maxFindings) {
      const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
      filtered = [...filtered]
        .sort((a, b) => (severityOrder[a.severity] ?? 3) - (severityOrder[b.severity] ?? 3))
        .slice(0, options.maxFindings);
      console.error(
        `[max-findings] Output truncated to ${options.maxFindings} highest-severity finding(s). ` +
        'Use a higher --max-findings value or fix issues to see all results.',
      );
    }

    // ── Baseline diffing ─────────────────────────────────────────────────────
    // --baseline <file>: load a previous JSON scan result and filter out any
    // findings that are already present in the baseline. Only net-new findings
    // are reported, which is ideal for PR-gating workflows.
    if (options.baseline) {
      const baselinePath = path.resolve(options.baseline);
      if (!fs.existsSync(baselinePath)) {
        console.error(`[baseline] Error: file not found: ${baselinePath}`);
        process.exit(1);
      }
      try {
        const raw = JSON.parse(fs.readFileSync(baselinePath, 'utf8')) as { findings?: Finding[] };
        const baselineFindings: Finding[] = raw.findings ?? [];
        const baselineKeys = new Set(
          baselineFindings.map((f) => `${f.type}|${f.file ?? ''}|${f.line}|${f.column}`),
        );
        const beforeCount = filtered.length;
        filtered = filtered.filter((f) => {
          const key = `${f.type}|${f.file ?? ''}|${f.line}|${f.column}`;
          return !baselineKeys.has(key);
        });
        const suppressed = beforeCount - filtered.length;
        if (suppressed > 0) {
          console.error(`[baseline] ${suppressed} finding(s) suppressed as pre-existing (baseline: ${baselinePath})`);
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`[baseline] Warning: could not load baseline file: ${msg}`);
      }
    }

    // ── --fix: auto-remediation ─────────────────────────────────────────────
    if (options.fix || options.dryRun) {
      if (options.dryRun && !options.fix) {
        console.error('[fix] --dry-run requires --fix. Ignoring --dry-run.');
      } else {
        const fixResults = applyFixes(filtered, options.dryRun ?? false);
        printFixSummary(fixResults, options.dryRun ?? false);
        if (options.dryRun) {
          const diff = buildUnifiedDiff(fixResults);
          if (diff.trim()) {
            process.stderr.write('\n[fix --dry-run] Unified diff:\n');
            process.stderr.write(diff + '\n');
          }
        }
        // Re-filter: remove findings that were successfully fixed from the reported output
        // so the scan output reflects the remaining (unfixed) state.
        if (!options.dryRun) {
          const fixedKeys = new Set(
            fixResults
              .filter((r) => r.applied)
              .map((r) => `${r.finding.type}|${r.file ?? ''}|${r.finding.line}|${r.finding.column}`),
          );
          filtered = filtered.filter(
            (f) => !fixedKeys.has(`${f.type}|${f.file ?? ''}|${f.line}|${f.column}`),
          );
        }
      }
    }

    // --output routes output to a file; otherwise use stdout
    const outputPath = options.output ? path.resolve(options.output) : undefined;
    function emit(text: string): void {
      if (outputPath) {
        fs.writeFileSync(outputPath, text + '\n', 'utf8');
        console.error(`[output] Written to ${outputPath}`);
      } else {
        console.log(text);
      }
    }

    if (effectiveFormat === 'sarif') {
      emit(JSON.stringify(buildSARIF(filtered), null, 2));
    } else if (effectiveFormat === 'json') {
      emit(formatJSON(filtered));
    } else if (effectiveFormat === 'junit') {
      emit(buildJUnit(filtered, scanRoot));
      if (outputPath) {
        console.error('[junit] JUnit XML report written. Import into your CI system as a test result artifact.');
      }
    } else if (effectiveFormat === 'html') {
      emit(buildHTMLReport(filtered, scanRoot));
      if (outputPath) {
        console.error('[html] Self-contained HTML report written. Open in a browser to review.');
      }
    } else {
      if (outputPath) {
        // Write the same structured text as the terminal output (no ANSI codes)
        emit(formatFindingsText(filtered, scanRoot));
      } else {
        await printFindings(filtered, scanRoot);
      }
    }

    const summary = summarize(filtered);

    // --exit-code <N>: force process to exit with the given code, bypassing all
    // severity-based exit logic. Useful for advisory-only CI scans.
    if (options.exitCode !== undefined) {
      const forced = parseInt(options.exitCode, 10);
      if (!isNaN(forced)) {
        process.exit(forced);
      }
      // Invalid value — warn and fall through to normal exit logic
      console.error(`[exit-code] Invalid value "${options.exitCode}" — ignoring.`);
    }

    // --fail-on <types>: exit non-zero only when specific finding types are present.
    // Takes priority over --min-severity when both are supplied.
    if (options.failOn.length > 0) {
      const failTypes = new Set(options.failOn);
      const hasTargetedViolation = filtered.some((f) => failTypes.has(f.type));
      if (hasTargetedViolation) {
        const matched = [...new Set(filtered.filter((f) => failTypes.has(f.type)).map((f) => f.type))];
        console.error(`[fail-on] Failing because targeted finding type(s) found: ${matched.join(', ')}`);
        process.exit(1);
      }
    } else if (options.minSeverity) {
      // --min-severity controls which severity triggers a non-zero exit code.
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
