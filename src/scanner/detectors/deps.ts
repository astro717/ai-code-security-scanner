import * as fs from 'fs';
import * as path from 'path';
import { Finding } from '../reporter';

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

  const allDeps = {
    ...((pkg.dependencies as Record<string, string>) ?? {}),
    ...((pkg.devDependencies as Record<string, string>) ?? {}),
  };

  for (const [name, version] of Object.entries(allDeps)) {
    if (version === 'latest' || version === '*' || version === 'x') {
      findings.push({
        type: 'UNSAFE_DEPENDENCY',
        severity: 'medium',
        line: 1,
        column: 0,
        snippet: `"${name}": "${version}"`,
        message: `Dependency "${name}" pinned to "${version}" — unpinned versions can introduce breaking changes or malicious updates.`,
        file: pkgPath,
      });
    }
  }

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
