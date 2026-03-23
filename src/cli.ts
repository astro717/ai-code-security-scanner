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
import { detectJWTSecrets } from './scanner/detectors/jwt';
import { detectReDoS } from './scanner/detectors/redos';
import { detectWeakCrypto } from './scanner/detectors/weakCrypto';
import { detectJWTNoneAlgorithm } from './scanner/detectors/jwtNone';
import { Finding, printFindings, formatFindingsText, formatJSON, summarize } from './scanner/reporter';
import { detectUnsafeDeps } from './scanner/detectors/deps';
import { buildSARIF } from './scanner/sarif';
import { buildHTMLReport } from './scanner/htmlReport';

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
  format?: 'text' | 'json' | 'sarif' | 'html';
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
        const parsed = JSON.parse(raw) as AiSecScanConfig;
        console.error(`[config] Loaded: ${candidate}`);
        return parsed;
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

  process.on('SIGINT', () => {
    console.log('\n[watch] Stopping.');
    watchers.forEach((w) => w.close());
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
  .option('--format <format>', 'Output format: text | json | sarif | html (overrides --json / --sarif flags)')
  .option('--severity <level>', 'Minimum severity to report (critical|high|medium|low)', 'low')
  .option(
    '--min-severity <level>',
    'Minimum severity level that triggers a non-zero exit code (critical|high|medium|low). ' +
    'Defaults to high when omitted (only critical/high cause failure).',
  )
  .option('--ignore <glob>', 'Glob pattern to exclude (repeatable, e.g. --ignore \'**/node_modules/**\')', (val, acc: string[]) => { acc.push(val); return acc; }, [] as string[])
  .option('--config <path>', 'Path to .ai-sec-scan.json config file')
  .option('--watch', 'Watch for file changes and re-scan automatically, printing a diff of new/resolved findings')
  .option('--output <path>', 'Write output to a file instead of stdout (creates or overwrites the file)')
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
  .action(async (targetPath: string, options: { json: boolean; sarif: boolean; format?: string; severity: string; minSeverity?: string; ignore: string[]; config?: string; watch: boolean; output?: string; exitCode?: string; failOn: string[] }) => {
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

    // Merge: config ignore + .aiscanner patterns + --ignore flags
    const effectiveIgnore = [...(config.ignore ?? []), ...fileIgnorePatterns, ...options.ignore];

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
    const files = collectFiles(scanRoot, effectiveIgnore);
    const allFindings: Finding[] = [];
    const total = files.length;

    for (let i = 0; i < files.length; i++) {
      if (total > 1) {
        process.stderr.write(`\rScanning ${i + 1}/${total} files...`);
      }
      allFindings.push(...scanFile(files[i]!));
    }

    if (total > 1) {
      process.stderr.write('\r\x1b[2K'); // clear the progress line
    }

    // ── Dependency scanning (directory targets only) ─────────────────────────
    if (fs.statSync(scanRoot).isDirectory()) {
      allFindings.push(...detectUnsafeDeps(scanRoot));
    }

    const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

    // --severity controls which findings are reported
    const minReport = severityOrder[effectiveSeverity] ?? 3;
    const filtered = allFindings.filter((f) => (severityOrder[f.severity] ?? 3) <= minReport);

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
