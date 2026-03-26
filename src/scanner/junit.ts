/**
 * JUnit XML output format for CI test result integration.
 *
 * Produces a JUnit XML document where each finding becomes a test failure.
 * Findings are grouped by file (each file = a test suite). This format is
 * consumed natively by Jenkins, GitLab CI, CircleCI, and most CI systems
 * that display test results in their UI.
 *
 * The XML is self-contained and follows the JUnit XML schema used by
 * https://llg.cubic.org/docs/junit/ and adopted by major CI platforms.
 */

import { Finding, summarize } from './reporter';

function escapeXml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Builds a JUnit XML string from the given findings.
 *
 * @param findings - The filtered list of findings to render.
 * @param scanRoot - Absolute path of the scan target (used in the testsuite name).
 */
export function buildJUnit(findings: Finding[], scanRoot: string): string {
  const summary = summarize(findings);

  // Group findings by file
  const byFile = new Map<string, Finding[]>();
  for (const f of findings) {
    const key = f.file ?? 'unknown';
    if (!byFile.has(key)) byFile.set(key, []);
    byFile.get(key)!.push(f);
  }

  const suites: string[] = [];

  for (const [filePath, fileFindings] of byFile.entries()) {
    const testCases = fileFindings.map((f) => {
      const name = `[${f.severity.toUpperCase()}] ${f.type} at line ${f.line}`;
      const message = escapeXml(f.message);
      const detail = escapeXml(
        `Type: ${f.type}\nSeverity: ${f.severity}\nFile: ${f.file ?? 'unknown'}\nLine: ${f.line}, Column: ${f.column}\nSnippet: ${f.snippet ?? '(no snippet)'}`,
      );
      return `    <testcase name="${escapeXml(name)}" classname="${escapeXml(filePath)}">
      <failure message="${message}" type="${escapeXml(f.type)}">${detail}</failure>
    </testcase>`;
    });

    suites.push(
      `  <testsuite name="${escapeXml(filePath)}" tests="${fileFindings.length}" failures="${fileFindings.length}" errors="0">
${testCases.join('\n')}
  </testsuite>`,
    );
  }

  // If no findings, emit a single passing test suite
  if (findings.length === 0) {
    suites.push(
      `  <testsuite name="${escapeXml(scanRoot)}" tests="1" failures="0" errors="0">
    <testcase name="security-scan" classname="${escapeXml(scanRoot)}"/>
  </testsuite>`,
    );
  }

  return `<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="ai-code-security-scanner" tests="${summary.total || 1}" failures="${summary.total}" errors="0">
${suites.join('\n')}
</testsuites>`;
}
