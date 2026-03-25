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
