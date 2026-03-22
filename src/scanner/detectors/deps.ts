import * as fs from 'fs';
import * as path from 'path';
import { Finding } from '../reporter';

// ── Known vulnerable package versions ────────────────────────────────────────
// When a project dependency is pinned to a version below the safe threshold,
// a VULNERABLE_DEPENDENCY finding is emitted. Keep this list up to date as
// new CVEs are published.

export const KNOWN_VULNERABLE: Record<string, { below: string; severity: 'critical' | 'high' | 'medium'; cve: string }> = {
  'lodash':        { below: '4.17.21', severity: 'critical', cve: 'CVE-2021-23337 / prototype pollution' },
  'lodash.merge':  { below: '4.6.2',   severity: 'critical', cve: 'CVE-2020-8203 / prototype pollution' },
  'minimist':      { below: '1.2.6',   severity: 'critical', cve: 'CVE-2021-44906 / prototype pollution' },
  'node-fetch':    { below: '3.0.0',   severity: 'high',     cve: 'CVE-2022-0235 / exposure of sensitive info' },
  'axios':         { below: '1.6.0',   severity: 'high',     cve: 'CVE-2023-45857 / CSRF via forged request' },
  'jsonwebtoken':  { below: '9.0.0',   severity: 'high',     cve: 'CVE-2022-23529 / arbitrary file write' },
  'express':       { below: '4.19.0',  severity: 'medium',   cve: 'CVE-2024-29041 / open redirect' },
  'semver':        { below: '7.5.2',   severity: 'high',     cve: 'CVE-2022-25883 / ReDoS' },
};

// ── Helpers ───────────────────────────────────────────────────────────────────

export function parseVersion(v: string): number[] {
  return v.replace(/^[\^~>=<v]/, '').split('.').map((n) => parseInt(n, 10) || 0);
}

export function isBelow(current: string, threshold: string): boolean {
  const c = parseVersion(current);
  const t = parseVersion(threshold);
  for (let i = 0; i < 3; i++) {
    if ((c[i] ?? 0) < (t[i] ?? 0)) return true;
    if ((c[i] ?? 0) > (t[i] ?? 0)) return false;
  }
  return false;
}

// ── Core analysis ─────────────────────────────────────────────────────────────

function analyseDepMap(
  allDeps: Record<string, string>,
  fileRef: string,
): Finding[] {
  const findings: Finding[] = [];

  for (const [name, version] of Object.entries(allDeps)) {
    // Unpinned versions
    if (version === 'latest' || version === '*' || version === 'x') {
      findings.push({
        type: 'UNSAFE_DEPENDENCY',
        severity: 'medium',
        line: 1,
        column: 0,
        snippet: `"${name}": "${version}"`,
        message: `Dependency "${name}" pinned to "${version}" — unpinned versions can introduce breaking changes or malicious updates.`,
        file: fileRef,
      });
    }

    // Known vulnerable versions
    const vuln = KNOWN_VULNERABLE[name];
    if (vuln && isBelow(version, vuln.below)) {
      findings.push({
        type: 'VULNERABLE_DEPENDENCY',
        severity: vuln.severity,
        line: 1,
        column: 0,
        snippet: `"${name}": "${version}"`,
        message: `"${name}@${version}" is vulnerable (${vuln.cve}). Upgrade to >=${vuln.below}.`,
        file: fileRef,
      });
    }
  }

  return findings;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Scan a package.json provided as a raw JSON string (e.g. from the scan server
 * when the client uploads the file contents directly).
 */
export function detectUnsafeDepsFromJson(packageJsonStr: string): Finding[] {
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(packageJsonStr);
  } catch {
    return [];
  }

  const allDeps: Record<string, string> = {
    ...((pkg.dependencies as Record<string, string>) ?? {}),
    ...((pkg.devDependencies as Record<string, string>) ?? {}),
  };

  return analyseDepMap(allDeps, 'package.json');
}

/**
 * Scan a project directory for an unsafe package.json. Also checks for a
 * missing lockfile. Used by the CLI when scanning a directory target.
 */
export function detectUnsafeDeps(projectDir: string): Finding[] {
  const findings: Finding[] = [];
  const pkgPath = path.join(projectDir, 'package.json');

  if (!fs.existsSync(pkgPath)) return findings;

  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
  } catch {
    return findings;
  }

  const allDeps: Record<string, string> = {
    ...((pkg.dependencies as Record<string, string>) ?? {}),
    ...((pkg.devDependencies as Record<string, string>) ?? {}),
  };

  findings.push(...analyseDepMap(allDeps, pkgPath));

  // Check for missing lockfile
  const lockFiles = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'];
  const hasLockfile = lockFiles.some((lf) => fs.existsSync(path.join(projectDir, lf)));
  if (!hasLockfile && Object.keys(allDeps).length > 0) {
    findings.push({
      type: 'UNSAFE_DEPENDENCY',
      severity: 'medium',
      line: 1,
      column: 0,
      snippet: 'No lockfile found',
      message: 'No package lockfile found (package-lock.json / yarn.lock / pnpm-lock.yaml). Dependency versions are not reproducible.',
      file: pkgPath,
    });
  }

  return findings;
}
