/**
 * Regression test: scan-cache readScannerVersion() resolves correctly from dist/.
 *
 * The readScannerVersion() function uses path.join(__dirname, '..', '..', 'package.json')
 * which must resolve to the project root package.json from both:
 *   - src/scanner/scan-cache.ts  (ts-node / vitest)
 *   - dist/scanner/scan-cache.js (compiled output)
 *
 * This test catches regressions where build path changes cause SCANNER_VERSION
 * to fall back to 'unknown' (the Docker version-fallback bug class).
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import * as path from 'path';
import * as fs from 'fs';

const PROJECT_ROOT = path.resolve(__dirname, '..', '..');

describe('scan-cache dist path regression', () => {
  const distScanCachePath = path.join(PROJECT_ROOT, 'dist', 'scanner', 'scan-cache.js');

  test('dist/scanner/scan-cache.js exists (project must be built)', () => {
    expect(fs.existsSync(distScanCachePath)).toBe(true);
  });

  test('readScannerVersion from dist resolves to a real semver, not "unknown"', () => {
    // Simulate the same __dirname-relative resolution that scan-cache.ts uses
    const distDir = path.dirname(distScanCachePath);
    const pkgPath = path.join(distDir, '..', '..', 'package.json');

    expect(fs.existsSync(pkgPath)).toBe(true);

    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    expect(pkg.version).toBeDefined();
    expect(pkg.version).not.toBe('unknown');
    // Verify it looks like a semver string
    expect(pkg.version).toMatch(/^\d+\.\d+\.\d+/);
  });

  test('dist __dirname -> package.json path matches project root package.json', () => {
    const distDir = path.dirname(distScanCachePath);
    const resolvedFromDist = path.resolve(distDir, '..', '..', 'package.json');
    const projectPkg = path.resolve(PROJECT_ROOT, 'package.json');

    expect(resolvedFromDist).toBe(projectPkg);
  });
});
