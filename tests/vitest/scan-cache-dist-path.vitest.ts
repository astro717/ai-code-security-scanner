/**
 * Regression test: scan-cache dist/ path prefix handling.
 *
 * Verifies that compiled JS output files in dist/ and their TypeScript source
 * counterparts in src/ are treated as INDEPENDENT cache entries. The cache
 * must not deduplicate them (e.g. by stripping path prefixes) — a change to
 * the compiled JS should not invalidate the source-file cache entry, and
 * vice versa.
 *
 * Background: a previous bug would cause cache lookups for dist/foo.js to
 * bleed into the cache entry for src/foo.ts (or produce spurious duplicate
 * findings) when both files were scanned in the same run.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  initCache,
  getCachedFindings,
  setCachedFindings,
  clearCache,
  getCacheStats,
} from '../../src/scanner/scan-cache';
import type { Finding } from '../../src/scanner/reporter';

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    type: 'SQL_INJECTION',
    severity: 'critical',
    line: 5,
    column: 4,
    snippet: 'db.query("SELECT * FROM users WHERE id = " + id)',
    message: 'SQL injection detected',
    file: '/fake/file.ts',
    ...overrides,
  };
}

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-cache-dist-'));
  initCache({ cacheDir: tmpDir });
});

afterEach(() => {
  clearCache();
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
});

// ── dist/ path regression tests ───────────────────────────────────────────────

describe('scan-cache — dist/ path prefix regression', () => {
  const SOURCE_FILE = '/project/src/services/auth.ts';
  const DIST_FILE = '/project/dist/services/auth.js';
  // The compiled file has the same logical content but different path and extension
  const SOURCE_CONTENT = 'const token = Math.random(); // TypeScript source';
  const DIST_CONTENT = '"use strict";\nconst token = Math.random(); // compiled JS';

  const SOURCE_FINDING = makeFinding({ file: SOURCE_FILE, type: 'INSECURE_RANDOM', line: 1 });
  const DIST_FINDING = makeFinding({ file: DIST_FILE, type: 'INSECURE_RANDOM', line: 2 });

  test('dist/ and src/ paths are independent cache keys — miss before any write', () => {
    // Neither path has been cached yet — both should miss
    expect(getCachedFindings(SOURCE_FILE, SOURCE_CONTENT)).toBeNull();
    expect(getCachedFindings(DIST_FILE, DIST_CONTENT)).toBeNull();
  });

  test('caching src file does NOT produce a hit for dist/ equivalent', () => {
    // Cache only the source file
    setCachedFindings(SOURCE_FILE, SOURCE_CONTENT, [SOURCE_FINDING]);

    // dist/ path should still miss — it was never cached
    const distResult = getCachedFindings(DIST_FILE, DIST_CONTENT);
    expect(distResult).toBeNull();
  });

  test('caching dist/ file does NOT produce a hit for src/ equivalent', () => {
    // Cache only the dist file
    setCachedFindings(DIST_FILE, DIST_CONTENT, [DIST_FINDING]);

    // Source path should still miss
    const srcResult = getCachedFindings(SOURCE_FILE, SOURCE_CONTENT);
    expect(srcResult).toBeNull();
  });

  test('src and dist entries are stored and retrieved independently', () => {
    // Cache both files with different findings
    setCachedFindings(SOURCE_FILE, SOURCE_CONTENT, [SOURCE_FINDING]);
    setCachedFindings(DIST_FILE, DIST_CONTENT, [DIST_FINDING]);

    // Each should return its own finding, not the other's
    const srcResult = getCachedFindings(SOURCE_FILE, SOURCE_CONTENT);
    expect(srcResult).not.toBeNull();
    expect(srcResult!).toHaveLength(1);
    expect(srcResult![0]!.file).toBe(SOURCE_FILE);
    expect(srcResult![0]!.line).toBe(SOURCE_FINDING.line);

    const distResult = getCachedFindings(DIST_FILE, DIST_CONTENT);
    expect(distResult).not.toBeNull();
    expect(distResult!).toHaveLength(1);
    expect(distResult![0]!.file).toBe(DIST_FILE);
    expect(distResult![0]!.line).toBe(DIST_FINDING.line);
  });

  test('two separate cache entries are created — one per file path', () => {
    setCachedFindings(SOURCE_FILE, SOURCE_CONTENT, [SOURCE_FINDING]);
    setCachedFindings(DIST_FILE, DIST_CONTENT, [DIST_FINDING]);

    const stats = getCacheStats();
    // Both files must have their own entry — total should be 2 (plus any from other tests,
    // but since each test gets a fresh tmpDir and clearCache(), it should be exactly 2).
    expect(stats.entries).toBe(2);
  });

  test('updating dist/ content invalidates dist/ entry but not src/ entry', () => {
    const DIST_CONTENT_V2 = '"use strict";\nconst token = Math.random(); // v2 compiled';

    setCachedFindings(SOURCE_FILE, SOURCE_CONTENT, [SOURCE_FINDING]);
    setCachedFindings(DIST_FILE, DIST_CONTENT, [DIST_FINDING]);

    // The dist file is recompiled — different content hash
    const distMiss = getCachedFindings(DIST_FILE, DIST_CONTENT_V2);
    expect(distMiss).toBeNull();

    // Source entry should be unaffected
    const srcHit = getCachedFindings(SOURCE_FILE, SOURCE_CONTENT);
    expect(srcHit).not.toBeNull();
    expect(srcHit!).toHaveLength(1);
  });

  test('deeply nested dist path is a distinct key from a shallow dist path', () => {
    const DIST_NESTED = '/project/dist/services/nested/deep/auth.js';
    const DIST_SHALLOW = '/project/dist/auth.js';
    const content = 'const x = 1;';
    const findingNested = makeFinding({ file: DIST_NESTED, line: 1 });
    const findingShallow = makeFinding({ file: DIST_SHALLOW, line: 2 });

    setCachedFindings(DIST_NESTED, content, [findingNested]);
    setCachedFindings(DIST_SHALLOW, content, [findingShallow]);

    const nestedResult = getCachedFindings(DIST_NESTED, content);
    const shallowResult = getCachedFindings(DIST_SHALLOW, content);

    // Same content but different paths — each must return its own findings
    expect(nestedResult![0]!.line).toBe(1);
    expect(shallowResult![0]!.line).toBe(2);
  });

  test('dist/ file with identical content to src/ still produces a cache miss for src/ if only dist/ was cached', () => {
    // Edge case: compiled output happens to have same content as source (e.g. simple file)
    const SHARED_CONTENT = 'export const VERSION = "1.0.0";';
    const tsFile = '/project/src/version.ts';
    const jsFile = '/project/dist/version.js';
    const tsFinding = makeFinding({ file: tsFile, line: 1, type: 'HARDCODED_SECRET' });

    // Only cache the TS file
    setCachedFindings(tsFile, SHARED_CONTENT, [tsFinding]);

    // JS file with identical content should still miss — different path = different key
    const jsMiss = getCachedFindings(jsFile, SHARED_CONTENT);
    expect(jsMiss).toBeNull();

    // TS file should still hit
    const tsHit = getCachedFindings(tsFile, SHARED_CONTENT);
    expect(tsHit).not.toBeNull();
  });
});
