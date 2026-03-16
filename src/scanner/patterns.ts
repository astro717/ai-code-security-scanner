export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface VulnerabilityPattern {
  id: string;
  name: string;
  severity: Severity;
  description: string;
  remediation: string;
}

export const VULNERABILITY_PATTERNS: Record<string, VulnerabilityPattern> = {
  SECRET_HARDCODED: {
    id: 'SECRET_HARDCODED',
    name: 'Hardcoded Secret',
    severity: 'critical',
    description: 'Sensitive credentials or API keys hardcoded in source code.',
    remediation: 'Use environment variables or a secrets manager instead.',
  },
  SQL_INJECTION: {
    id: 'SQL_INJECTION',
    name: 'SQL Injection',
    severity: 'critical',
    description: 'User input concatenated into a SQL query without sanitization.',
    remediation: 'Use parameterized queries or prepared statements.',
  },
  SHELL_INJECTION: {
    id: 'SHELL_INJECTION',
    name: 'Shell Injection',
    severity: 'high',
    description: 'Shell command constructed with unsanitized user input.',
    remediation: 'Avoid shell interpolation; use execFile with argument arrays.',
  },
  EVAL_INJECTION: {
    id: 'EVAL_INJECTION',
    name: 'Eval with Dynamic Input',
    severity: 'high',
    description: 'eval() or equivalent executed with a non-literal argument.',
    remediation: 'Avoid eval(); use JSON.parse() or safe alternatives.',
  },
  UNSAFE_DEPENDENCY: {
    id: 'UNSAFE_DEPENDENCY',
    name: 'Unsafe Dependency Version',
    severity: 'medium',
    description: 'Dependency pinned to latest/* or missing lockfile.',
    remediation: 'Pin to a specific version and commit package-lock.json.',
  },
};
