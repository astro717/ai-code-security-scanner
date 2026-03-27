/**
 * Scan result cache for the AI Code Security Scanner.
 *
 * Results are keyed by a SHA-256 hash of the file contents. When a file has
 * not changed since the last scan, the cached findings are returned immediately
 * without re-running any detectors. This significantly reduces wall-clock time
 * and API call usage for large repos or incremental CI runs.
 *
 * Cache storage
 * ─────────────
 * By default the cache is persisted to disk at:
 *   ~/.cache/ai-sec-scan/scan-cache.json
 *
 * The location can be overridden with the AI_SEC_SCAN_CACHE_DIR environment
 * variable or the --cache-dir CLI option (passed through CacheOptions).
 *
 * Cache invalidation
 * ──────────────────
 * A cache entry is considered valid when:
 *   1. The file path matches an existing entry.
 *   2. The SHA-256 digest of the current file content matches the stored hash.
 *   3. The scanner version matches the version used when the entry was created.
 *
 * Any content change — even a single character — produces a different digest
 * and forces a full re-scan for that file. A scanner upgrade also invalidates
 * the entire cache so that new detection patterns are applied.
 *
 * Thread / process safety
 * ───────────────────────
 * The cache is read once at startup and written once on process exit (or
 * explicitly via persistCache()). Multiple concurrent processes may race on
 * the same cache file; the last writer wins. This is acceptable for the
 * typical CLI use-case where a single scan process runs at a time.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as os from 'os';
import type { Finding } from './reporter';

// ── Constants ─────────────────────────────────────────────────────────────────

/**
 * Read the scanner version from package.json at module load time.
 * This version is embedded in the cache file so that upgrading the scanner
 * automatically invalidates all cached entries (new patterns would otherwise
 * be missed). Falls back to 'unknown' if package.json cannot be read.
 */
function readScannerVersion(): string {
  try {
    const pkgPath = path.join(__dirname, '..', '..', 'package.json');
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    return pkg.version ?? 'unknown';
  } catch {
    return 'unknown';
  }
}

const SCANNER_VERSION = readScannerVersion();

const CACHE_FILENAME = 'scan-cache.json';

/** Maximum number of entries stored in the in-memory cache. Oldest-accessed entry is evicted when exceeded. */
const MAX_CACHE_ENTRIES = 5000;

// ── Types ────────────────────────────────────────────────────────────────────

export interface CacheEntry {
  /** SHA-256 hex digest of the file content at scan time. */
  hash: string;
  /** ISO-8601 timestamp of when the entry was cached. */
  scannedAt: string;
  /** The findings that were produced for this file. */
  findings: Finding[];
}

export interface CacheOptions {
  /** Override the default cache directory (~/.cache/ai-sec-scan). */
  cacheDir?: string;
  /** Disable the cache entirely (useful for --no-cache flag). */
  disabled?: boolean;
}

interface CacheFile {
  /** Scanner version that produced the cache entries. */
  scannerVersion: string;
  entries: Record<string, CacheEntry>;
}

// ── Module-level state ────────────────────────────────────────────────────────

let _cacheDir: string | null = null;
let _cachePath: string | null = null;
// Map preserves insertion order — we use it as an LRU queue: oldest key first.
let _entries: Map<string, CacheEntry> = new Map();
let _dirty = false;
let _disabled = false;
let _hits = 0;
let _misses = 0;

// ── Helpers ───────────────────────────────────────────────────────────────────

function defaultCacheDir(): string {
  // Honour XDG_CACHE_HOME if set, otherwise fall back to ~/.cache
  const xdg = process.env['XDG_CACHE_HOME'];
  const base = xdg ? xdg : path.join(os.homedir(), '.cache');
  return path.join(base, 'ai-sec-scan');
}

function hashContent(content: string): string {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Initialise the cache. Must be called once before any get/set operations.
 * Safe to call multiple times — subsequent calls are no-ops if options match.
 */
export function initCache(options: CacheOptions = {}): void {
  _disabled = options.disabled ?? false;
  if (_disabled) return;

  const dir =
    options.cacheDir ??
    process.env['AI_SEC_SCAN_CACHE_DIR'] ??
    defaultCacheDir();

  _cacheDir = dir;
  _cachePath = path.join(dir, CACHE_FILENAME);

  // Load existing cache from disk (failures are non-fatal)
  try {
    if (fs.existsSync(_cachePath)) {
      const raw = fs.readFileSync(_cachePath, 'utf8');
      const parsed = JSON.parse(raw) as Partial<CacheFile>;

      // Validate scanner version — if it differs, discard the entire cache.
      // This ensures that new detection patterns added in a scanner upgrade
      // are applied to all files, not just those whose content changed.
      if (
        parsed.scannerVersion === SCANNER_VERSION &&
        typeof parsed.entries === 'object'
      ) {
        _entries = new Map(Object.entries(parsed.entries ?? {}));
      } else {
        // Version mismatch — start fresh
        _entries = new Map();
        _dirty = true; // Will overwrite the stale file on next persist
      }
    }
  } catch {
    // Corrupt or unreadable cache — start fresh
    _entries = new Map();
  }
}

/**
 * Look up cached findings for a file.
 *
 * @param filePath  Absolute path to the source file.
 * @param content   Current file content (used to validate the hash).
 * @returns  The cached findings array if the entry is valid, or null on a
 *           cache miss (file changed, entry absent, or cache disabled).
 */
export function getCachedFindings(
  filePath: string,
  content: string,
): Finding[] | null {
  if (_disabled) { _misses++; return null; }
  const entry = _entries.get(filePath);
  if (!entry) { _misses++; return null; }
  const currentHash = hashContent(content);
  if (entry.hash !== currentHash) { _misses++; return null; }
  // Promote to most-recently-used: delete and re-insert so it moves to the end.
  _entries.delete(filePath);
  _entries.set(filePath, entry);
  _hits++;
  return entry.findings;
}

/**
 * Store findings for a file in the in-memory cache.
 * Call persistCache() to flush to disk.
 *
 * @param filePath  Absolute path to the source file.
 * @param content   Current file content (hashed for cache key validation).
 * @param findings  The findings produced by the scan.
 */
export function setCachedFindings(
  filePath: string,
  content: string,
  findings: Finding[],
): void {
  if (_disabled) return;
  // If this key already exists, remove it first so it is re-inserted at the end.
  if (_entries.has(filePath)) _entries.delete(filePath);
  _entries.set(filePath, {
    hash: hashContent(content),
    scannedAt: new Date().toISOString(),
    findings,
  });
  // Evict the least-recently-used (first / oldest) entry if we exceed the limit.
  if (_entries.size > MAX_CACHE_ENTRIES) {
    const lruKey = _entries.keys().next().value;
    if (lruKey !== undefined) _entries.delete(lruKey);
  }
  _dirty = true;
}

/**
 * Flush the in-memory cache to disk.
 * A no-op when the cache is disabled or nothing has changed since the last persist.
 */
export function persistCache(): void {
  if (_disabled || !_dirty || !_cachePath || !_cacheDir) return;

  try {
    fs.mkdirSync(_cacheDir, { recursive: true });
    const data: CacheFile = {
      scannerVersion: SCANNER_VERSION,
      entries: Object.fromEntries(_entries),
    };
    fs.writeFileSync(_cachePath, JSON.stringify(data, null, 2), 'utf8');
    _dirty = false;
  } catch {
    // Cache write failure is non-fatal — the scan result is still correct.
  }
}

/**
 * Return basic cache statistics for diagnostic output.
 */
export function getCacheStats(): {
  entries: number;
  cachePath: string | null;
  disabled: boolean;
  hits: number;
  misses: number;
} {
  return {
    entries: _entries.size,
    cachePath: _cachePath,
    disabled: _disabled,
    hits: _hits,
    misses: _misses,
  };
}

/**
 * Clear all in-memory entries and delete the on-disk cache file.
 * Primarily useful in tests and for a future --clear-cache flag.
 */
export function clearCache(): void {
  _entries = new Map();
  _dirty = false;
  if (_cachePath && fs.existsSync(_cachePath)) {
    try {
      fs.unlinkSync(_cachePath);
    } catch {
      /* ignore */
    }
  }
}
