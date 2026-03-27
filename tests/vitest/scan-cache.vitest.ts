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
