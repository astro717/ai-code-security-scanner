#!/usr/bin/env node
"use strict";
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
const commander_1 = require("commander");
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const minimatch_1 = require("minimatch");
const parser_1 = require("./scanner/parser");
const secrets_1 = require("./scanner/detectors/secrets");
const sql_1 = require("./scanner/detectors/sql");
const shell_1 = require("./scanner/detectors/shell");
const eval_1 = require("./scanner/detectors/eval");
const xss_1 = require("./scanner/detectors/xss");
const pathTraversal_1 = require("./scanner/detectors/pathTraversal");
const prototypePollution_1 = require("./scanner/detectors/prototypePollution");
const insecureRandom_1 = require("./scanner/detectors/insecureRandom");
const openRedirect_1 = require("./scanner/detectors/openRedirect");
const ssrf_1 = require("./scanner/detectors/ssrf");
const commandInjection_1 = require("./scanner/detectors/commandInjection");
const cors_1 = require("./scanner/detectors/cors");
const jwt_1 = require("./scanner/detectors/jwt");
const redos_1 = require("./scanner/detectors/redos");
const weakCrypto_1 = require("./scanner/detectors/weakCrypto");
const jwtNone_1 = require("./scanner/detectors/jwtNone");
const reporter_1 = require("./scanner/reporter");
const deps_1 = require("./scanner/detectors/deps");
const sarif_1 = require("./scanner/sarif");
const htmlReport_1 = require("./scanner/htmlReport");
const python_parser_1 = require("./scanner/python-parser");
const go_parser_1 = require("./scanner/go-parser");
const java_parser_1 = require("./scanner/java-parser");
const scan_cache_1 = require("./scanner/scan-cache");
const cache_1 = require("./scanner/cache");
// JS/TS extensions use the TypeScript ESLint AST parser.
// Python files use the regex-based python-parser module.
// Go files use the regex-based go-parser module.
// Java files use the regex-based java-parser module.
const SUPPORTED_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.go', '.java']);
// ── .aiscanner ignore file ────────────────────────────────────────────────────
/**
 * Loads ignore patterns from a `.aiscanner` file in the given directory (or
 * any of its ancestors up to the filesystem root).  Each non-empty line that
 * does not start with `#` is treated as a glob pattern.
 *
 * Returns an empty array if no `.aiscanner` file is found.
 */
function loadAiScannerIgnore(startDir) {
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
            }
            catch (err) {
                const msg = err instanceof Error ? err.message : String(err);
                console.error(`[ignore] Warning: could not read ${candidate}: ${msg}`);
                return [];
            }
        }
        const parent = path.dirname(dir);
        if (parent === dir)
            break; // reached filesystem root
        dir = parent;
    }
    return [];
}
function isIgnored(filePath, ignorePatterns) {
    const normalised = filePath.split(path.sep).join('/');
    return ignorePatterns.some((pattern) => (0, minimatch_1.minimatch)(normalised, pattern, { matchBase: true, dot: true }));
}
function collectFiles(targetPath, ignorePatterns = []) {
    const stat = fs.statSync(targetPath);
    if (stat.isFile()) {
        return isIgnored(targetPath, ignorePatterns) ? [] : [targetPath];
    }
    const files = [];
    function walk(dir) {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const full = path.join(dir, entry.name);
            if (isIgnored(full, ignorePatterns))
                continue;
            if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
                walk(full);
            }
            else if (entry.isFile() && SUPPORTED_EXTENSIONS.has(path.extname(entry.name))) {
                files.push(full);
            }
        }
    }
    walk(targetPath);
    return files;
}
function scanFile(filePath) {
    // Cache check: skip re-scanning unchanged files.
    let fileContent;
    try {
        fileContent = fs.readFileSync(filePath, 'utf-8');
    }
    catch {
        return [];
    }
    const cached = (0, cache_1.getCachedFindings)(filePath, fileContent);
    if (cached)
        return cached;
    const findings = scanFileUncached(filePath);
    (0, cache_1.setCachedFindings)(filePath, fileContent, findings);
    return findings;
}
function scanFileUncached(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    // Python files use the dedicated regex-based scanner (no AST parser needed).
    if (ext === '.py') {
        try {
            const parsed = (0, python_parser_1.parsePythonFile)(filePath);
            return (0, python_parser_1.scanPython)(parsed);
        }
        catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            console.error(`  [skip] ${filePath}: ${msg}`);
            return [];
        }
    }
    // Go files use the dedicated regex-based scanner (no Go AST parser needed).
    if (ext === '.go') {
        try {
            const parsed = (0, go_parser_1.parseGoFile)(filePath);
            return (0, go_parser_1.scanGo)(parsed);
        }
        catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            console.error(`  [skip] ${filePath}: ${msg}`);
            return [];
        }
    }
    // Java files use the dedicated regex-based scanner (no Java parser needed).
    if (ext === '.java') {
        try {
            const parsed = (0, java_parser_1.parseJavaFile)(filePath);
            return (0, java_parser_1.scanJava)(parsed);
        }
        catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            console.error(`  [skip] ${filePath}: ${msg}`);
            return [];
        }
    }
    // JS/TS files use the TypeScript ESLint AST pipeline.
    try {
        const parsed = (0, parser_1.parseFile)(filePath);
        return [
            ...(0, secrets_1.detectSecrets)(parsed),
            ...(0, sql_1.detectSQLInjection)(parsed),
            ...(0, shell_1.detectShellInjection)(parsed),
            ...(0, eval_1.detectEval)(parsed),
            ...(0, xss_1.detectXSS)(parsed),
            ...(0, pathTraversal_1.detectPathTraversal)(parsed),
            ...(0, prototypePollution_1.detectPrototypePollution)(parsed),
            ...(0, insecureRandom_1.detectInsecureRandom)(parsed),
            ...(0, openRedirect_1.detectOpenRedirect)(parsed),
            ...(0, ssrf_1.detectSSRF)(parsed),
            ...(0, jwt_1.detectJWTSecrets)(parsed),
            ...(0, jwtNone_1.detectJWTNoneAlgorithm)(parsed),
            ...(0, commandInjection_1.detectCommandInjection)(parsed),
            ...(0, cors_1.detectCORSMisconfiguration)(parsed),
            ...(0, redos_1.detectReDoS)(parsed),
            ...(0, weakCrypto_1.detectWeakCrypto)(parsed),
        ].map((f) => ({ ...f, file: filePath }));
    }
    catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`  [skip] ${filePath}: ${msg}`);
        return [];
    }
}
/** Validates a parsed config object against the AiSecScanConfig schema.
 *  Returns an array of human-readable error strings (empty = valid). */
function validateConfig(obj) {
    const errors = [];
    if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
        return ['Config root must be a JSON object, got: ' + (Array.isArray(obj) ? 'array' : typeof obj)];
    }
    const allowed = new Set(['ignore', 'severity', 'format']);
    const knownSeverities = new Set(['critical', 'high', 'medium', 'low']);
    const knownFormats = new Set(['text', 'json', 'sarif']);
    // Check for unknown keys — a typo here silently dropped config before this fix
    for (const key of Object.keys(obj)) {
        if (!allowed.has(key)) {
            const suggestions = [...allowed].filter((k) => k.startsWith(key[0] ?? ''));
            const hint = suggestions.length > 0 ? ` (did you mean "${suggestions[0]}"?)` : '';
            errors.push(`Unknown config key "${key}"${hint}. Allowed keys: ${[...allowed].join(', ')}`);
        }
    }
    const record = obj;
    // ignore: must be an array of strings
    if ('ignore' in record) {
        if (!Array.isArray(record['ignore'])) {
            errors.push(`"ignore" must be an array of strings, got: ${typeof record['ignore']}`);
        }
        else {
            record['ignore'].forEach((item, i) => {
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
        }
        else if (!knownSeverities.has(record['severity'])) {
            errors.push(`"severity" must be one of: ${[...knownSeverities].join(', ')}. Got: "${record['severity']}"`);
        }
    }
    // format: must be one of the known values
    if ('format' in record) {
        if (typeof record['format'] !== 'string') {
            errors.push(`"format" must be a string, got: ${typeof record['format']}`);
        }
        else if (!knownFormats.has(record['format'])) {
            errors.push(`"format" must be one of: ${[...knownFormats].join(', ')}. Got: "${record['format']}"`);
        }
    }
    return errors;
}
function loadConfig(configPath) {
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
                return parsed;
            }
            catch (err) {
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
function diffFindings(prev, next) {
    function key(f) {
        return `${f.file ?? ''}:${f.line}:${f.column}:${f.type}`;
    }
    const prevKeys = new Set(prev.map(key));
    const nextKeys = new Set(next.map(key));
    return {
        added: next.filter((f) => !prevKeys.has(key(f))),
        resolved: prev.filter((f) => !nextKeys.has(key(f))),
    };
}
function printWatchDiff(filePath, added, resolved) {
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
function startWatchMode(targetPath, ignorePatterns, severity, outputPath) {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    const minSeverity = severityOrder[severity] ?? 3;
    // Cache: file path -> last known filtered findings
    const cache = new Map();
    function appendToOutput(filePath, added, resolved) {
        if (!outputPath)
            return;
        const ts = new Date().toISOString();
        const lines = [`[${ts}] ${filePath}`];
        for (const f of added) {
            lines.push(`  + [${f.severity.toUpperCase()}] ${f.type} at line ${f.line}: ${f.message}`);
        }
        for (const f of resolved) {
            lines.push(`  - [resolved] ${f.type} at line ${f.line}`);
        }
        lines.push('');
        fs.appendFileSync(outputPath, lines.join('\n'), 'utf8');
    }
    function scanAndUpdate(filePath) {
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
    (0, scan_cache_1.initCache)();
    // Seed cache with initial scan (silent)
    const initialFiles = collectFiles(targetPath, ignorePatterns);
    console.error(`[watch] Watching ${initialFiles.length} file(s) in ${targetPath}`);
    console.error('[watch] Press Ctrl+C to stop.\n');
    for (const f of initialFiles) {
        const raw = scanFile(f);
        cache.set(f, raw.filter((fi) => severityOrder[fi.severity] <= minSeverity));
    }
    const watchers = [];
    try {
        const watcher = fs.watch(targetPath, { recursive: true }, (_event, filename) => {
            if (!filename)
                return;
            const full = path.isAbsolute(filename) ? filename : path.join(targetPath, filename);
            if (!SUPPORTED_EXTENSIONS.has(path.extname(full)))
                return;
            if (isIgnored(full, ignorePatterns))
                return;
            if (!fs.existsSync(full)) {
                // File deleted — treat as all findings resolved
                const prev = cache.get(full);
                if (prev && prev.length > 0)
                    printWatchDiff(full, [], prev);
                cache.delete(full);
                return;
            }
            scanAndUpdate(full);
        });
        watchers.push(watcher);
    }
    catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`[watch] Could not watch ${targetPath}: ${msg}`);
        process.exit(1);
    }
    // Persist the scan cache to disk every 60 seconds so that long-running
    // watch sessions contribute cached results to subsequent one-shot scans.
    const persistInterval = setInterval(() => {
        (0, scan_cache_1.persistCache)();
    }, 60000);
    persistInterval.unref();
    process.on('SIGINT', () => {
        console.log('\n[watch] Stopping.');
        clearInterval(persistInterval);
        watchers.forEach((w) => w.close());
        // Flush the scan cache to disk before exiting so all accumulated
        // results are available for the next scan session.
        (0, scan_cache_1.persistCache)();
        process.exit(0);
    });
    // Keep the process alive
    setInterval(() => { }, 10000).unref();
}
// ─────────────────────────────────────────────────────────────────────────────
commander_1.program
    .name('ai-sec-scan')
    .description('AST-based security scanner for AI-generated code')
    .version('0.1.0')
    .argument('[path]', 'File or directory to scan', '.')
    .option('--json', 'Output results as JSON')
    .option('--sarif', 'Output results as SARIF 2.1.0')
    .option('--html <output-path>', 'Write a self-contained HTML report to <output-path>. Shorthand for --format html --output <output-path>. ' +
    'The file can be opened directly in a browser without a server.')
    .option('--format <format>', 'Output format: text | json | sarif | html (overrides --json / --sarif flags)')
    .option('--severity <level>', 'Minimum severity to report (critical|high|medium|low)', 'low')
    .option('--min-severity <level>', 'Minimum severity level that triggers a non-zero exit code (critical|high|medium|low). ' +
    'Defaults to high when omitted (only critical/high cause failure).')
    .option('--ignore <glob>', 'Glob pattern to exclude (repeatable, e.g. --ignore \'**/node_modules/**\')', (val, acc) => { acc.push(val); return acc; }, [])
    .option('--exclude-pattern <glob>', 'Glob pattern to skip matching paths during recursive scan (repeatable, uses minimatch). ' +
    'Useful for excluding generated artefacts such as dist/, build/, or coverage/. ' +
    'Example: --exclude-pattern \'dist/**\' --exclude-pattern \'**/*.min.js\'. ' +
    'Functionally equivalent to --ignore but provided as a more discoverable, industry-standard name.', (val, acc) => { acc.push(val); return acc; }, [])
    .option('--config <path>', 'Path to .ai-sec-scan.json config file')
    .option('--watch', 'Watch for file changes and re-scan automatically, printing a diff of new/resolved findings')
    .option('--output <path>', 'Write output to a file instead of stdout (creates or overwrites the file). Output is always written before the process exits, even when findings cause a non-zero exit code.')
    .option('--output-on-exit <path>', 'Alias for --output with explicit always-write semantics. Use this in CI pipelines to guarantee the results file is ' +
    'written regardless of whether the scan exits 0 or 1. Identical to --output in behaviour — provided for clarity.')
    .option('--baseline <path>', 'Path to a previous JSON scan result. Only findings that are NEW relative to the baseline are reported. ' +
    'Use this in PR workflows to gate on net-new vulnerabilities without blocking on legacy debt.')
    .option('--exit-code <code>', 'Force the process to exit with this code regardless of findings (e.g. --exit-code 0 for advisory-only scans in CI).')
    .option('--fail-on <types>', 'Comma-separated list of finding types that trigger a non-zero exit code (e.g. --fail-on SQL_INJECTION,XSS). ' +
    'When set, only these types cause failure — all other findings are advisory only.', (val, acc) => { acc.push(...val.split(',').map((t) => t.trim().toUpperCase())); return acc; }, [])
    .option('--ignore-type <type>', 'Suppress all findings of the given type globally (repeatable, e.g. --ignore-type WEAK_CRYPTO --ignore-type REDOS). ' +
    'Useful for suppressing known-accepted findings without modifying source. Mirrors the pattern used by --fail-on.', (val, acc) => { acc.push(val.trim().toUpperCase()); return acc; }, [])
    .option('--max-findings <n>', 'Truncate the findings list to at most <n> findings before output and exit-code evaluation. ' +
    'Findings are sorted by severity (critical → high → medium → low) so the most important ones ' +
    'are always retained. Useful in legacy codebases where the full output overwhelms CI logs.', (val) => {
    const n = parseInt(val, 10);
    if (isNaN(n) || n < 0)
        throw new Error('--max-findings must be a non-negative integer');
    return n;
})
    .option('--severity-exit <level>', 'Convenience shorthand: sets both --severity and --min-severity to <level> in one option. ' +
    'E.g. --severity-exit critical reports only critical findings AND exits non-zero only for those.')
    .action(async (targetPath, options) => {
    // --html <path>: shorthand for --format html --output <path>.
    // Explicit --format / --output take precedence if both are provided.
    if (options.html) {
        if (!options.format)
            options.format = 'html';
        if (!options.output)
            options.output = options.html;
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
        if (!options.minSeverity)
            options.minSeverity = options.severityExit;
        if (options.severity === 'low')
            options.severity = options.severityExit;
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
    const allFindings = [];
    const total = files.length;
    for (let i = 0; i < files.length; i++) {
        if (total > 1) {
            process.stderr.write(`\rScanning ${i + 1}/${total} files...`);
        }
        allFindings.push(...scanFile(files[i]));
    }
    if (total > 1) {
        process.stderr.write('\r\x1b[2K'); // clear the progress line
        const stats = (0, cache_1.getCacheStats)();
        if (stats.hits > 0) {
            console.error(`[cache] ${stats.hits} file(s) served from cache, ${stats.misses} scanned`);
        }
    }
    // ── Dependency scanning (directory targets only) ─────────────────────────
    if (fs.statSync(scanRoot).isDirectory()) {
        allFindings.push(...(0, deps_1.detectUnsafeDeps)(scanRoot));
    }
    // Deduplicate by (type, file, line, column) before reporting.
    // Multiple detectors can flag the same location; deduplication eliminates
    // noise in large scans without losing any unique signals.
    const deduped = (0, reporter_1.deduplicateFindings)(allFindings);
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
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
            if (!reporter_1.KNOWN_TYPES.has(t)) {
                console.error(`[ignore-type] Warning: "${t}" is not a known finding type and will suppress nothing. ` +
                    `Known types: ${[...reporter_1.KNOWN_TYPES].sort().join(', ')}`);
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
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        filtered = [...filtered]
            .sort((a, b) => (severityOrder[a.severity] ?? 3) - (severityOrder[b.severity] ?? 3))
            .slice(0, options.maxFindings);
        console.error(`[max-findings] Output truncated to ${options.maxFindings} highest-severity finding(s). ` +
            'Use a higher --max-findings value or fix issues to see all results.');
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
            const raw = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
            const baselineFindings = raw.findings ?? [];
            const baselineKeys = new Set(baselineFindings.map((f) => `${f.type}|${f.file ?? ''}|${f.line}|${f.column}`));
            const beforeCount = filtered.length;
            filtered = filtered.filter((f) => {
                const key = `${f.type}|${f.file ?? ''}|${f.line}|${f.column}`;
                return !baselineKeys.has(key);
            });
            const suppressed = beforeCount - filtered.length;
            if (suppressed > 0) {
                console.error(`[baseline] ${suppressed} finding(s) suppressed as pre-existing (baseline: ${baselinePath})`);
            }
        }
        catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            console.error(`[baseline] Warning: could not load baseline file: ${msg}`);
        }
    }
    // --output routes output to a file; otherwise use stdout
    const outputPath = options.output ? path.resolve(options.output) : undefined;
    function emit(text) {
        if (outputPath) {
            fs.writeFileSync(outputPath, text + '\n', 'utf8');
            console.error(`[output] Written to ${outputPath}`);
        }
        else {
            console.log(text);
        }
    }
    if (effectiveFormat === 'sarif') {
        emit(JSON.stringify((0, sarif_1.buildSARIF)(filtered), null, 2));
    }
    else if (effectiveFormat === 'json') {
        emit((0, reporter_1.formatJSON)(filtered));
    }
    else if (effectiveFormat === 'html') {
        emit((0, htmlReport_1.buildHTMLReport)(filtered, scanRoot));
        if (outputPath) {
            console.error('[html] Self-contained HTML report written. Open in a browser to review.');
        }
    }
    else {
        if (outputPath) {
            // Write the same structured text as the terminal output (no ANSI codes)
            emit((0, reporter_1.formatFindingsText)(filtered, scanRoot));
        }
        else {
            await (0, reporter_1.printFindings)(filtered, scanRoot);
        }
    }
    const summary = (0, reporter_1.summarize)(filtered);
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
    }
    else if (options.minSeverity) {
        // --min-severity controls which severity triggers a non-zero exit code.
        const exitThreshold = severityOrder[options.minSeverity] ?? 1;
        const hasViolation = filtered.some((f) => (severityOrder[f.severity] ?? 3) <= exitThreshold);
        if (hasViolation) {
            process.exit(1);
        }
    }
    else {
        // Legacy default: exit non-zero on critical or high
        if (summary.critical > 0 || summary.high > 0) {
            process.exit(1);
        }
    }
});
commander_1.program.parse();
//# sourceMappingURL=cli.js.map