"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.summarize = summarize;
exports.formatJSON = formatJSON;
exports.printFindings = printFindings;
function summarize(findings) {
    return {
        critical: findings.filter((f) => f.severity === 'critical').length,
        high: findings.filter((f) => f.severity === 'high').length,
        medium: findings.filter((f) => f.severity === 'medium').length,
        low: findings.filter((f) => f.severity === 'low').length,
        total: findings.length,
    };
}
function formatJSON(findings) {
    return JSON.stringify({ findings, summary: summarize(findings) }, null, 2);
}
// Lazy chalk import for CommonJS compatibility
async function getChalk() {
    // chalk v5 is ESM-only; use dynamic import
    const { default: chalk } = await import('chalk');
    return chalk;
}
const SEVERITY_LABELS = {
    critical: 'CRITICAL',
    high: 'HIGH',
    medium: 'MEDIUM',
    low: 'LOW',
};
async function printFindings(findings, targetPath) {
    const chalk = await getChalk();
    const severityColor = (s, text) => {
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
        console.log(`  ${severityColor(f.severity, SEVERITY_LABELS[f.severity])} ` +
            chalk.cyan(`[${f.type}]`) +
            ` ${fileRef}${chalk.yellow(`line ${f.line}`)}`);
        console.log(`  ${chalk.dim('→')} ${f.message}`);
        if (f.snippet) {
            console.log(`  ${chalk.dim('  ')}${chalk.bgGray.white(` ${f.snippet.slice(0, 80)} `)}`);
        }
        console.log();
    }
    const summary = summarize(findings);
    const parts = [];
    if (summary.critical)
        parts.push(chalk.bgRed.white.bold(` ${summary.critical} critical `));
    if (summary.high)
        parts.push(chalk.red.bold(`${summary.high} high`));
    if (summary.medium)
        parts.push(chalk.yellow(`${summary.medium} medium`));
    if (summary.low)
        parts.push(chalk.gray(`${summary.low} low`));
    console.log(chalk.bold(`Found ${summary.total} issue(s): `) + parts.join(chalk.dim(' · ')));
    console.log();
}
//# sourceMappingURL=reporter.js.map