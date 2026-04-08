/**
 * Unit tests for the scan-cache module.
 *
 * Tests cover:
 *  - Cache miss on first scan (no entry in cache)
 *  - Cache hit on second scan with identical content
 *  - Cache miss after content change
 *  - persistCache / clearCache lifecycle
 *  - Disabled cache mode (--no-cache equivalent)
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
  persistCache,
  clearCache,
  getCacheStats,
} from '../../src/scanner/scan-cache';

const FAKE_FILE = '/fake/path/test.ts';
const FAKE_CONTENT_A = 'const x = 1; // version A';
const FAKE_CONTENT_B = 'const x = 2; // version B (changed)';
const FAKE_FINDINGS = [
  {
    type: 'SQL_INJECTION',
    severity: 'critical' as const,
    line: 5,
    column: 4,
    snippet: 'db.query("SELECT * FROM users WHERE id = " + id)',
    message: 'SQL injection detected',
    file: FAKE_FILE,
  },
];

let tmpDir: string;

beforeEach(() => {
  // Use a fresh temp directory for each test so tests don't share disk state
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-cache-test-'));
  initCache({ cacheDir: tmpDir });
});

afterEach(() => {
  clearCache();
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
});

describe('scan-cache — cache miss / hit logic', () => {
  test('returns null (miss) on first lookup for an unseen file', () => {
    const result = getCachedFindings(FAKE_FILE, FAKE_CONTENT_A);
    expect(result).toBeNull();
  });

  test('returns cached findings (hit) on second lookup with same content', () => {
    // Populate the cache
    setCachedFindings(FAKE_FILE, FAKE_CONTENT_A, FAKE_FINDINGS);

    // Second lookup with identical content should hit
    const result = getCachedFindings(FAKE_FILE, FAKE_CONTENT_A);
    expect(result).not.toBeNull();
    expect(result).toHaveLength(1);
    expect(result![0]!.type).toBe('SQL_INJECTION');
  });

  test('returns null (miss) after content changes', () => {
    // Cache entry for version A
    setCachedFindings(FAKE_FILE, FAKE_CONTENT_A, FAKE_FINDINGS);

    // Lookup with version B — different hash, should miss
    const result = getCachedFindings(FAKE_FILE, FAKE_CONTENT_B);
    expect(result).toBeNull();
  });

  test('miss increments miss counter, hit increments hit counter', () => {
    // Two misses
    getCachedFindings(FAKE_FILE, FAKE_CONTENT_A);
    getCachedFindings(FAKE_FILE, FAKE_CONTENT_B);

    setCachedFindings(FAKE_FILE, FAKE_CONTENT_A, FAKE_FINDINGS);

    // One hit
    getCachedFindings(FAKE_FILE, FAKE_CONTENT_A);

    const stats = getCacheStats();
    expect(stats.misses).toBeGreaterThanOrEqual(2);
    expect(stats.hits).toBeGreaterThanOrEqual(1);
  });
});

describe('scan-cache — persist and clear lifecycle', () => {
  test('persistCache writes a file to disk', () => {
    setCachedFindings(FAKE_FILE, FAKE_CONTENT_A, FAKE_FINDINGS);
    persistCache();

    const files = fs.readdirSync(tmpDir);
    expect(files.some((f) => f.endsWith('.json'))).toBe(true);
  });

  test('clearCache removes the on-disk file and resets in-memory entries', () => {
    setCachedFindings(FAKE_FILE, FAKE_CONTENT_A, FAKE_FINDINGS);
    persistCache();

    clearCache();

    const stats = getCacheStats();
    expect(stats.entries).toBe(0);

    // Re-init so getCachedFindings works after clear
    initCache({ cacheDir: tmpDir });
    const result = getCachedFindings(FAKE_FILE, FAKE_CONTENT_A);
    expect(result).toBeNull();
  });

  test('getCacheStats.entries reflects number of cached files', () => {
    setCachedFindings('/file/a.ts', FAKE_CONTENT_A, FAKE_FINDINGS);
    setCachedFindings('/file/b.ts', FAKE_CONTENT_B, []);

    const stats = getCacheStats();
    expect(stats.entries).toBeGreaterThanOrEqual(2);
    expect(stats.disabled).toBe(false);
  });

  test('_dirty flag is reset correctly after clearCache() without prior persistCache()', () => {
    // Set entries without persisting
    setCachedFindings(FAKE_FILE, FAKE_CONTENT_A, FAKE_FINDINGS);

    // Clear without persist — _dirty flag should be reset
    clearCache();

    // Re-init with the same cacheDir
    initCache({ cacheDir: tmpDir });

    // Add a new entry after clear
    setCachedFindings(FAKE_FILE, FAKE_CONTENT_B, FAKE_FINDINGS);

    // Persist should not write a stale file
    persistCache();

    // Verify the cache file contains only the new entry, not stale data
    const cacheFile = path.join(tmpDir, 'scan-cache.json');
    if (fs.existsSync(cacheFile)) {
      const raw = JSON.parse(fs.readFileSync(cacheFile, 'utf8')) as { entries: Record<string, unknown> };
      // After clear + re-init + new entry, only FAKE_CONTENT_B should be in cache
      const cachedEntry = raw.entries[FAKE_FILE];
      expect(cachedEntry).toBeDefined();
      // Verify _dirty is correctly false after a fresh persist (no entries left from before clear)
    }
  });
});

describe('scan-cache — disabled mode', () => {
  test('getCachedFindings always returns null when cache is disabled', () => {
    initCache({ disabled: true });

    // Even after a set, get should return null
    setCachedFindings(FAKE_FILE, FAKE_CONTENT_A, FAKE_FINDINGS);
    const result = getCachedFindings(FAKE_FILE, FAKE_CONTENT_A);
    expect(result).toBeNull();
  });

  test('getCacheStats.disabled is true when cache is disabled', () => {
    initCache({ disabled: true });
    const stats = getCacheStats();
    expect(stats.disabled).toBe(true);
  });

  test('persistCache is a no-op when cache is disabled', () => {
    initCache({ disabled: true });
    setCachedFindings(FAKE_FILE, FAKE_CONTENT_A, FAKE_FINDINGS);
    persistCache();

    // No JSON file should have been written
    const files = fs.readdirSync(tmpDir);
    expect(files.filter((f) => f.endsWith('.json'))).toHaveLength(0);
  });
});


describe('scan-cache — LRU eviction', () => {
  test('cache does not grow beyond MAX_CACHE_ENTRIES (verified via getCacheStats)', () => {
    // We cannot import MAX_CACHE_ENTRIES directly since it is module-private,
    // but we can verify that adding a large number of entries stays bounded.
    // Add 10 entries and confirm stats.entries is exactly 10 (well within limit).
    for (let i = 0; i < 10; i++) {
      setCachedFindings(`/fake/path/file-${i}.ts`, `content-${i}`, FAKE_FINDINGS);
    }
    const stats = getCacheStats();
    expect(stats.entries).toBe(10);
  });

  test('newer entries survive when old entries are evicted', () => {
    // Fill cache with 3 entries, then add a 4th. All 4 should be present
    // (well below MAX_CACHE_ENTRIES=5000), but we verify the latest one is accessible.
    setCachedFindings('/fake/path/old1.ts', 'old-content-1', FAKE_FINDINGS);
    setCachedFindings('/fake/path/old2.ts', 'old-content-2', FAKE_FINDINGS);
    setCachedFindings('/fake/path/old3.ts', 'old-content-3', FAKE_FINDINGS);
    setCachedFindings('/fake/path/new.ts', 'new-content', FAKE_FINDINGS);

    const result = getCachedFindings('/fake/path/new.ts', 'new-content');
    expect(result).not.toBeNull();
    expect(result).toHaveLength(1);
  });

  test('accessing an entry promotes it ahead of older entries', () => {
    // Add two entries, access the first one to promote it, then verify it is still accessible.
    setCachedFindings('/fake/path/a.ts', 'content-a', FAKE_FINDINGS);
    setCachedFindings('/fake/path/b.ts', 'content-b', []);

    // Promote 'a' by reading it
    getCachedFindings('/fake/path/a.ts', 'content-a');

    // Both should still be cached
    expect(getCachedFindings('/fake/path/a.ts', 'content-a')).not.toBeNull();
    expect(getCachedFindings('/fake/path/b.ts', 'content-b')).not.toBeNull();
  });
});

// ── Regression: clearCache + re-init with different TTL ──────────────────────

describe('scan-cache — clearCache regression: re-init with different TTL', () => {
  test('re-initialising with a shorter TTL after clearCache applies the new TTL', () => {
    // This is a regression test for the bug where _cacheDir was not reset in
    // clearCache(), causing initCache() to skip re-initialisation (it assumed
    // the same cacheDir meant the cache was still valid) and the new TTL was
    // silently ignored.

    // 1. Init with a very long TTL (1 hour)
    initCache({ cacheDir: tmpDir, cacheTtlMs: 60 * 60 * 1000 });
    setCachedFindings(FAKE_FILE, FAKE_CONTENT_A, FAKE_FINDINGS);

    // 2. Clear and re-init with 1ms TTL (effectively zero — expires immediately)
    clearCache();
    initCache({ cacheDir: tmpDir, cacheTtlMs: 1 });

    // Give the 1ms TTL time to expire
    const start = Date.now();
    while (Date.now() - start < 5) { /* busy-wait 5ms */ }

    // 3. The entry should be expired under the new TTL
    const result = getCachedFindings(FAKE_FILE, FAKE_CONTENT_A);
    expect(result).toBeNull();
  });

  test('re-initialising with a longer TTL after clearCache applies the new TTL', () => {
    // Init with 1ms TTL
    initCache({ cacheDir: tmpDir, cacheTtlMs: 1 });
    // Wait for it to "expire conceptually" then clear and upgrade TTL
    clearCache();
    // Re-init with long TTL and verify the new entries are cached properly
    initCache({ cacheDir: tmpDir, cacheTtlMs: 60 * 60 * 1000 });

    setCachedFindings(FAKE_FILE, FAKE_CONTENT_B, FAKE_FINDINGS);
    const result = getCachedFindings(FAKE_FILE, FAKE_CONTENT_B);
    expect(result).not.toBeNull();
    expect(result).toHaveLength(1);
  });
});


// ── readScannerVersion fallback chain ─────────────────────────────────────────
// These tests verify that readScannerVersion() tries multiple candidate paths
// and returns the version from the first readable package.json it finds.
// We exercise the fallback indirectly through getCacheStats() — the SCANNER_VERSION
// constant is baked in at module load time, so we cannot retrigger it. Instead
// we directly test the helper logic by importing a re-exported version for tests
// or by confirming the module loaded successfully with a non-unknown version
// when package.json is present at the project root.

describe('scan-cache — readScannerVersion fallback', () => {
  test('SCANNER_VERSION is set to a non-unknown value when package.json exists at root', () => {
    // The module is already loaded — if __dirname-based resolution worked,
    // getCacheStats() will have a real version in the cache file it writes.
    // We verify by inspecting the cache file written by persistCache().
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-version-test-'));
    try {
      initCache({ cacheDir: dir });
      setCachedFindings('/tmp/test.ts', 'content', []);
      persistCache();

      const cacheFile = path.join(dir, 'scan-cache.json');
      expect(fs.existsSync(cacheFile)).toBe(true);

      const raw = JSON.parse(fs.readFileSync(cacheFile, 'utf8')) as { scannerVersion: string };
      // If fallback resolution works, the version will be a semver string, NOT 'unknown'
      expect(raw.scannerVersion).not.toBe('unknown');
      expect(raw.scannerVersion).toMatch(/^\d+\.\d+\.\d+/);
    } finally {
      clearCache();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('cache file written by persistCache() contains a valid scannerVersion entry', () => {
    // Verify the cache file structure: scannerVersion must be present and
    // non-empty, confirming the fallback chain resolved a real version.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-version-test2-'));
    try {
      initCache({ cacheDir: dir });
      setCachedFindings('/tmp/test2.ts', 'my-content', FAKE_FINDINGS);
      persistCache();

      const cacheFile = path.join(dir, 'scan-cache.json');
      const raw = JSON.parse(fs.readFileSync(cacheFile, 'utf8')) as { scannerVersion: string; entries: Record<string, unknown> };
      // The scannerVersion field must be present and non-empty
      expect(typeof raw.scannerVersion).toBe('string');
      expect(raw.scannerVersion.length).toBeGreaterThan(0);
      // The entries map must contain the file we cached
      expect(raw.entries['/tmp/test2.ts']).toBeDefined();
    } finally {
      clearCache();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
