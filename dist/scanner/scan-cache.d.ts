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
import type { Finding } from './reporter';
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
/**
 * Initialise the cache. Must be called once before any get/set operations.
 * Safe to call multiple times — subsequent calls are no-ops if options match.
 */
export declare function initCache(options?: CacheOptions): void;
/**
 * Look up cached findings for a file.
 *
 * @param filePath  Absolute path to the source file.
 * @param content   Current file content (used to validate the hash).
 * @returns  The cached findings array if the entry is valid, or null on a
 *           cache miss (file changed, entry absent, or cache disabled).
 */
export declare function getCachedFindings(filePath: string, content: string): Finding[] | null;
/**
 * Store findings for a file in the in-memory cache.
 * Call persistCache() to flush to disk.
 *
 * @param filePath  Absolute path to the source file.
 * @param content   Current file content (hashed for cache key validation).
 * @param findings  The findings produced by the scan.
 */
export declare function setCachedFindings(filePath: string, content: string, findings: Finding[]): void;
/**
 * Flush the in-memory cache to disk.
 * A no-op when the cache is disabled or nothing has changed since the last persist.
 */
export declare function persistCache(): void;
/**
 * Return basic cache statistics for diagnostic output.
 */
export declare function getCacheStats(): {
    entries: number;
    cachePath: string | null;
    disabled: boolean;
    hits: number;
    misses: number;
};
/**
 * Clear all in-memory entries and delete the on-disk cache file.
 * Primarily useful in tests and for a future --clear-cache flag.
 */
export declare function clearCache(): void;
//# sourceMappingURL=scan-cache.d.ts.map