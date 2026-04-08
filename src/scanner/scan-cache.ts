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
  // Try multiple candidate paths in order so the function works both from
  // the TypeScript source tree (__dirname = src/scanner/) and from a
  // compiled dist/ bundle (__dirname = dist/scanner/) inside Docker.
  const candidates = [
    path.join(__dirname, '..', '..', 'package.json'),   // src/scanner/ → root
    path.join(__dirname, '..', 'package.json'),          // dist/scanner/ → dist/ (sometimes)
    path.join(process.cwd(), 'package.json'),            // CWD fallback (Docker WORKDIR)
  ];

  for (const pkgPath of candidates) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as { version?: string };
      if (pkg.version) return pkg.version;
    } catch {
      // Path not readable — try next candidate
    }
  }

  return 'unknown';
}

const SCANNER_VERSION = readScannerVersion();

const CACHE_FILENAME = 'scan-cache.json';

/** Default maximum number of entries stored in the in-memory cache. Oldest-accessed entry is evicted when exceeded. */
const DEFAULT_MAX_CACHE_ENTRIES = 5000;

/** Default cache TTL: 7 days in milliseconds. */
const DEFAULT_CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

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
  /** Cache entry TTL in milliseconds. Entries older than this are evicted. Default: 7 days. */
  cacheTtlMs?: number;
  /** Maximum number of in-memory cache entries. Oldest entries are evicted when exceeded. Default: 5000. */
  maxEntries?: number;
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
let _cacheTtlMs: number = DEFAULT_CACHE_TTL_MS;
let _maxEntries: number = DEFAULT_MAX_CACHE_ENTRIES;

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
  const newDisabled = options.disabled ?? false;

  if (!newDisabled) {
    const dir =
      options.cacheDir ??
      process.env['AI_SEC_SCAN_CACHE_DIR'] ??
      defaultCacheDir();

    // Re-init guard: if already initialised with the same cacheDir, skip the
    // disk reload and counter reset entirely. This prevents tests that call
    // initCache() in beforeEach from accidentally discarding in-flight entries
    // and resetting hit/miss counters on the second call.
    if (_cacheDir === dir && !newDisabled && _disabled === false) {
      return;
    }

    _disabled = false;
    _cacheDir = dir;
    _cachePath = path.join(dir, CACHE_FILENAME);
    _cacheTtlMs = options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;

    // Read maxEntries from options or env var (SCAN_CACHE_MAX_ENTRIES)
    const envMaxEntries = process.env['SCAN_CACHE_MAX_ENTRIES'];
    _maxEntries = options.maxEntries ?? (envMaxEntries ? parseInt(envMaxEntries, 10) : DEFAULT_MAX_CACHE_ENTRIES);
    if (isNaN(_maxEntries) || _maxEntries < 1) {
      _maxEntries = DEFAULT_MAX_CACHE_ENTRIES;
    }
  } else {
    _disabled = true;
    return;
  }

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
  // Evict stale entries by age (TTL check).
  // Use >= so entries at exactly the TTL boundary are treated as expired.
  if (Date.now() - new Date(entry.scannedAt).getTime() >= _cacheTtlMs) {
    _entries.delete(filePath);
    _misses++;
    return null;
  }
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
  if (_entries.size > _maxEntries) {
    const lruKey = _entries.keys().next().value;
    if (lruKey !== undefined) _entries.delete(lruKey);
  }
  _dirty = true;
}

/**
 * Flush the in-memory cache to disk.
 * A no-op when the cache is disabled or nothing has changed since the last persist.
 *
 * Uses atomic write (write to temp file, then rename) to prevent corruption
 * in concurrent process scenarios. This is safe even when multiple processes
 * try to write simultaneously — the last rename wins, and intermediate files
 * are cleaned up.
 */
export function persistCache(): void {
  if (_disabled || !_dirty || !_cachePath || !_cacheDir) return;

  try {
    fs.mkdirSync(_cacheDir, { recursive: true });
    const data: CacheFile = {
      scannerVersion: SCANNER_VERSION,
      entries: Object.fromEntries(_entries),
    };
    const json = JSON.stringify(data, null, 2);

    // Write to a temporary file first, then atomically rename to the target path.
    // This prevents concurrent writers from creating a partially-written/corrupt cache.
    const tmpPath = _cachePath + '.tmp';
    fs.writeFileSync(tmpPath, json, 'utf8');
    fs.renameSync(tmpPath, _cachePath);

    _dirty = false;
  } catch {
    // Cache write failure is non-fatal — the scan result is still correct.
  }
}

export interface CacheAgeDistribution {
  /** Entries cached within the last hour. */
  lastHour: number;
  /** Entries cached between 1 hour and 1 day ago. */
  lastDay: number;
  /** Entries cached between 1 day and 7 days ago. */
  lastWeek: number;
  /** Entries older than 7 days. */
  older: number;
}

export interface CacheStatsResult {
  entries: number;
  cachePath: string | null;
  disabled: boolean;
  hits: number;
  misses: number;
  cacheTtlMs: number;
  /** Hit rate as a percentage string e.g. "72.4". Empty string when no lookups. */
  hitRatePct: string;
  /** Distribution of cache entry ages across four buckets. */
  ageDistribution: CacheAgeDistribution;
}

/**
 * Return cache statistics for diagnostic output, including hit rate percentage
 * and a distribution of entry ages across four time buckets.
 */
export function getCacheStats(): CacheStatsResult {
  const totalLookups = _hits + _misses;
  const hitRatePct = totalLookups > 0
    ? ((_hits / totalLookups) * 100).toFixed(1)
    : '—';

  const now = Date.now();
  const ONE_HOUR = 60 * 60 * 1000;
  const ONE_DAY = 24 * ONE_HOUR;
  const ONE_WEEK = 7 * ONE_DAY;

  const ageDistribution: CacheAgeDistribution = {
    lastHour: 0,
    lastDay: 0,
    lastWeek: 0,
    older: 0,
  };

  for (const entry of _entries.values()) {
    const ageMs = now - new Date(entry.scannedAt).getTime();
    if (ageMs < ONE_HOUR) {
      ageDistribution.lastHour++;
    } else if (ageMs < ONE_DAY) {
      ageDistribution.lastDay++;
    } else if (ageMs < ONE_WEEK) {
      ageDistribution.lastWeek++;
    } else {
      ageDistribution.older++;
    }
  }

  return {
    entries: _entries.size,
    cachePath: _cachePath,
    disabled: _disabled,
    hits: _hits,
    misses: _misses,
    cacheTtlMs: _cacheTtlMs,
    hitRatePct,
    ageDistribution,
  };
}

/**
 * Clear all in-memory entries and delete the on-disk cache file.
 * Primarily useful in tests and for a future --clear-cache flag.
 */
export function clearCache(): void {
  _entries = new Map();
  _dirty = false;
  _hits = 0;
  _misses = 0;
  const pathToDelete = _cachePath;
  // Reset _cacheDir and _cachePath so the re-init guard in initCache() does not
  // short-circuit when tests call clearCache() + initCache() with the same
  // directory but different options (e.g. a different cacheTtlMs).
  _cacheDir = null;
  _cachePath = null;
  if (pathToDelete && fs.existsSync(pathToDelete)) {
    try {
      fs.unlinkSync(pathToDelete);
    } catch {
      /* ignore */
    }
  }
}
