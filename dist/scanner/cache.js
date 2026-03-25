"use strict";
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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.contentHash = contentHash;
exports.getCachedFindings = getCachedFindings;
exports.setCachedFindings = setCachedFindings;
exports.getCacheStats = getCacheStats;
exports.clearCache = clearCache;
const crypto = __importStar(require("crypto"));
const cache = new Map();
let hits = 0;
let misses = 0;
/**
 * Computes a SHA-256 content hash suitable for cache keying.
 */
function contentHash(content) {
    return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}
/**
 * Looks up cached findings for a file. Returns the findings array if the file
 * content matches the cached hash, or `undefined` on a cache miss.
 */
function getCachedFindings(filePath, currentHash) {
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
function setCachedFindings(filePath, hash, findings) {
    cache.set(filePath, { hash, findings });
}
/**
 * Returns cache statistics for logging/debugging.
 */
function getCacheStats() {
    return { hits, misses, size: cache.size };
}
/**
 * Clears the cache entirely. Useful for testing.
 */
function clearCache() {
    cache.clear();
    hits = 0;
    misses = 0;
}
//# sourceMappingURL=cache.js.map