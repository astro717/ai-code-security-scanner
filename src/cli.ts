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
import { detectJWTSecrets } from './scanner/detectors/jwt';
import { Finding, printFindings, formatJSON, summarize } from './scanner/reporter';

const SUPPORTED_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs']);

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
      ...detectJWTSecrets(parsed),
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
  .option('--severity <level>', 'Minimum severity to report (critical|high|medium|low)', 'low')
  .option('--ignore <glob>', 'Glob pattern to exclude (repeatable, e.g. --ignore \'**/node_modules/**\')', (val, acc: string[]) => { acc.push(val); return acc; }, [] as string[])
  .action(async (targetPath: string, options: { json: boolean; sarif: boolean; severity: string; ignore: string[] }) => {
    const resolved = path.resolve(targetPath);

    if (!fs.existsSync(resolved)) {
      console.error(`Error: path not found: ${resolved}`);
      process.exit(1);
    }

    const files = collectFiles(resolved, options.ignore);
    const allFindings: Finding[] = [];

    for (const file of files) {
      allFindings.push(...scanFile(file));
    }

    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    const minSeverity = severityOrder[options.severity as keyof typeof severityOrder] ?? 3;
    const filtered = allFindings.filter((f) => severityOrder[f.severity] <= minSeverity);

    if (options.sarif) {
      console.log(JSON.stringify(buildSARIF(filtered), null, 2));
    } else if (options.json) {
      console.log(formatJSON(filtered));
    } else {
      await printFindings(filtered, resolved);
    }

    const summary = summarize(filtered);
    if (summary.critical > 0 || summary.high > 0) {
      process.exit(1);
    }
  });

program.parse();
