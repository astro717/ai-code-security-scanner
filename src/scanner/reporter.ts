export type Severity = 'critical' | 'high' | 'medium' | 'low';

/**
 * The canonical set of finding type strings emitted by the built-in detectors.
 * Export this constant so consumers (e.g. CLI --ignore-type validation) can
 * check whether a user-supplied type string is recognised.
 */
export const KNOWN_TYPES = new Set([
  'COMMAND_INJECTION',
  'CORS_MISCONFIGURATION',
  'EVAL_INJECTION',
  'INSECURE_RANDOM',
  'JWT_DECODE_NO_VERIFY',
  'JWT_HARDCODED_SECRET',
  'JWT_NONE_ALGORITHM',
  'JWT_WEAK_SECRET',
  'OPEN_REDIRECT',
  'PATH_TRAVERSAL',
  'PROTOTYPE_POLLUTION',
  'REDOS',
  'SECRET_HARDCODED',
  'SHELL_INJECTION',
  'SQL_INJECTION',
  'SSRF',
  'UNSAFE_DEPENDENCY',
  'VULNERABLE_DEPENDENCY',
  'WEAK_CRYPTO',
  'XSS',
  'UNSAFE_DESERIALIZATION',
  'INSECURE_ASSERT',
  'INSECURE_BINDING',
]);

export interface Finding {
  type: string;
  severity: Severity;
  line: number;
  column: number;
  snippet: string;
  message: string;
  file?: string;
}

export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

/**
 * Removes duplicate findings based on a stable key of (type, file, line, column).
 * When multiple detectors independently flag the same code location with the same
 * finding type, only the first occurrence is kept. Preserves original order.
 */
export function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.type}|${f.file ?? ''}|${f.line}|${f.column}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function summarize(findings: Finding[]): ScanSummary {
  return {
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
    total: findings.length,
  };
}

export function formatJSON(findings: Finding[]): string {
  return JSON.stringify({ findings, summary: summarize(findings) }, null, 2);
}

// Lazy chalk import for CommonJS compatibility
async function getChalk() {
  // chalk v5 is ESM-only; use dynamic import
  const { default: chalk } = await import('chalk');
  return chalk;
}

const SEVERITY_LABELS: Record<Severity, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
};

/**
 * Returns the same structured text that `printFindings` writes to the
 * terminal, but without ANSI colour codes so it is suitable for writing to a
 * file via --output.
 */
export function formatFindingsText(findings: Finding[], targetPath: string): string {
  const lines: string[] = [];
  lines.push(`\nScanning: ${targetPath}\n`);

  if (findings.length === 0) {
    lines.push('No vulnerabilities found.\n');
    return lines.join('\n');
  }

  for (const f of findings) {
    const fileRef = f.file ? `${f.file}:` : '';
    lines.push(`  [${SEVERITY_LABELS[f.severity]}] [${f.type}] ${fileRef}line ${f.line}`);
    lines.push(`  -> ${f.message}`);
    if (f.snippet) {
      lines.push(`     ${f.snippet.slice(0, 80)}`);
    }
    lines.push('');
  }

  const summary = summarize(findings);
  const parts = [];
  if (summary.critical) parts.push(`${summary.critical} critical`);
  if (summary.high) parts.push(`${summary.high} high`);
  if (summary.medium) parts.push(`${summary.medium} medium`);
  if (summary.low) parts.push(`${summary.low} low`);

  lines.push(`Found ${summary.total} issue(s): ${parts.join(' · ')}`);
  lines.push('');
  return lines.join('\n');
}

export async function printFindings(findings: Finding[], targetPath: string): Promise<void> {
  const chalk = await getChalk();

  const severityColor = (s: Severity, text: string) => {
    switch (s) {
      case 'critical': return chalk.bgRed.white.bold(` ${text} `);
      case 'high': return chalk.red.bold(text);
      case 'medium': return chalk.yellow(text);
      case 'low': return chalk.gray(text);
    }
  };

  console.log(chalk.bold(`\n🔍 Scanning: ${targetPath}\n`));

  if (findings.length === 0) {
    console.log(chalk.green.bold('✓ No vulnerabilities found.\n'));
    return;
  }

  for (const f of findings) {
    const fileRef = f.file ? chalk.dim(`${f.file}:`) : '';
    console.log(
      `  ${severityColor(f.severity, SEVERITY_LABELS[f.severity])} ` +
      chalk.cyan(`[${f.type}]`) +
      ` ${fileRef}${chalk.yellow(`line ${f.line}`)}`
    );
    console.log(`  ${chalk.dim('→')} ${f.message}`);
    if (f.snippet) {
      console.log(`  ${chalk.dim('  ')}${chalk.bgGray.white(` ${f.snippet.slice(0, 80)} `)}`);
    }
    console.log();
  }

  const summary = summarize(findings);
  const parts = [];
  if (summary.critical) parts.push(chalk.bgRed.white.bold(` ${summary.critical} critical `));
  if (summary.high) parts.push(chalk.red.bold(`${summary.high} high`));
  if (summary.medium) parts.push(chalk.yellow(`${summary.medium} medium`));
  if (summary.low) parts.push(chalk.gray(`${summary.low} low`));

  console.log(chalk.bold(`Found ${summary.total} issue(s): `) + parts.join(chalk.dim(' · ')));
  console.log();
}
