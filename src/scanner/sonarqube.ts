/**
 * SonarQube Generic Issue Import format output for the AI Code Security Scanner.
 *
 * Produces a JSON file conforming to the SonarQube External Issues import format:
 * https://docs.sonarsource.com/sonarqube/latest/analyzing-source-code/importing-external-issues/external-analyzer-reports/
 *
 * Usage in SonarQube:
 *   sonar.externalIssuesReportPaths=scan-results-sonarqube.json
 *
 * Usage with the CLI:
 *   ai-sec-scan . --format sonarqube --output scan-results.json
 */

import { Finding } from './reporter';

// ── Severity mapping ──────────────────────────────────────────────────────────

/**
 * Maps scanner severity to SonarQube severity levels.
 *
 * SonarQube supports: BLOCKER, CRITICAL, MAJOR, MINOR, INFO
 * Scanner uses: critical, high, medium, low
 */
function toSonarSeverity(severity: Finding['severity']): string {
  switch (severity) {
    case 'critical': return 'BLOCKER';
    case 'high':     return 'CRITICAL';
    case 'medium':   return 'MAJOR';
    case 'low':      return 'MINOR';
    default:         return 'INFO';
  }
}

// ── SonarQube issue type ──────────────────────────────────────────────────────

// All findings from this scanner are security vulnerabilities.
const SONARQUBE_TYPE = 'VULNERABILITY';

// ── Main builder ──────────────────────────────────────────────────────────────

export interface SonarQubeIssue {
  engineId: string;
  ruleId: string;
  severity: string;
  type: string;
  primaryLocation: {
    message: string;
    filePath: string;
    textRange: {
      startLine: number;
      endLine: number;
      startColumn: number;
      endColumn: number;
    };
  };
  effortMinutes?: number;
}

export interface SonarQubeReport {
  issues: SonarQubeIssue[];
}

/**
 * Converts an array of findings to a SonarQube Generic Issue Import JSON string.
 *
 * @param findings  Deduplicated, filtered findings from a scan.
 * @returns         Serialized JSON string ready to write to a file.
 */
export function buildSonarQube(findings: Finding[]): string {
  const issues: SonarQubeIssue[] = findings.map((f) => {
    const startColumn = f.column ?? 0;
    // Estimate end column from snippet length; cap at 200 for readability
    const snippetLen = f.snippet?.length ?? 1;
    const endColumn = Math.min(startColumn + snippetLen, 200);

    const issue: SonarQubeIssue = {
      engineId: 'ai-code-security-scanner',
      ruleId: f.type,
      severity: toSonarSeverity(f.severity),
      type: SONARQUBE_TYPE,
      primaryLocation: {
        message: f.message,
        filePath: f.file ?? '',
        textRange: {
          startLine: Math.max(1, f.line),
          endLine: Math.max(1, f.line),
          startColumn,
          endColumn,
        },
      },
    };

    // Effort in minutes: a rough heuristic based on severity
    const effortMap: Record<string, number> = {
      critical: 60,
      high: 30,
      medium: 15,
      low: 5,
    };
    const effort = effortMap[f.severity];
    if (effort !== undefined) {
      issue.effortMinutes = effort;
    }

    return issue;
  });

  const report: SonarQubeReport = { issues };
  return JSON.stringify(report, null, 2);
}
