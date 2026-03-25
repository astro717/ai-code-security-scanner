/**
 * Scan result cache — avoids re-scanning files whose content has not changed.
 *
 * Cache entries are keyed by the SHA-256 hash of the file content. When a file
 * is scanned, its findings are stored alongside the hash. On subsequent scans,
 * if the content hash matches a cached entry, the stored findings are returned
 * immediately — skipping the expensive parse + detect pipeline.
 *
 * The cache is in-memory only and lives for the duration of the process. This
 * is intentionally simple: it benefits directory scans (where hundreds of files
 * are scanned in one invocation) and watch mode (where unchanged files are
 * re-encountered on every cycle). A persistent disk cache can be added later.
 */

import * as crypto from 'crypto';
import type { Finding } from './reporter';

interface CacheEntry {
  hash: string;
  findings: Finding[];
}

const cache = new Map<string, CacheEntry>();

let hits = 0;
let misses = 0;

/**
 * Computes a SHA-256 content hash suitable for cache keying.
 */
export function contentHash(content: string): string {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

/**
 * Looks up cached findings for a file. Returns the findings array if the file
 * content matches the cached hash, or `undefined` on a cache miss.
 */
export function getCachedFindings(filePath: string, currentHash: string): Finding[] | undefined {
  const entry = cache.get(filePath);
  if (entry && entry.hash === currentHash) {
    hits++;
    return entry.findings;
  }
  misses++;
  return undefined;
}

/**
 * Stores scan findings in the cache, keyed by file path and content hash.
 */
export function setCachedFindings(filePath: string, hash: string, findings: Finding[]): void {
  cache.set(filePath, { hash, findings });
}

/**
 * Returns cache statistics for logging/debugging.
 */
export function getCacheStats(): { hits: number; misses: number; size: number } {
  return { hits, misses, size: cache.size };
}

/**
 * Clears the cache entirely. Useful for testing.
 */
export function clearCache(): void {
  cache.clear();
  hits = 0;
  misses = 0;
}
