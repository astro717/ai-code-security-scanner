"use strict";
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
exports.initCache = initCache;
exports.getCachedFindings = getCachedFindings;
exports.setCachedFindings = setCachedFindings;
exports.persistCache = persistCache;
exports.getCacheStats = getCacheStats;
exports.clearCache = clearCache;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const crypto = __importStar(require("crypto"));
const os = __importStar(require("os"));
// ── Constants ─────────────────────────────────────────────────────────────────
/**
 * Read the scanner version from package.json at module load time.
 * This version is embedded in the cache file so that upgrading the scanner
 * automatically invalidates all cached entries (new patterns would otherwise
 * be missed). Falls back to 'unknown' if package.json cannot be read.
 */
function readScannerVersion() {
    try {
        const pkgPath = path.join(__dirname, '..', '..', 'package.json');
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
        return pkg.version ?? 'unknown';
    }
    catch {
        return 'unknown';
    }
}
const SCANNER_VERSION = readScannerVersion();
const CACHE_FILENAME = 'scan-cache.json';
// ── Module-level state ────────────────────────────────────────────────────────
let _cacheDir = null;
let _cachePath = null;
let _entries = {};
let _dirty = false;
let _disabled = false;
let _hits = 0;
let _misses = 0;
// ── Helpers ───────────────────────────────────────────────────────────────────
function defaultCacheDir() {
    // Honour XDG_CACHE_HOME if set, otherwise fall back to ~/.cache
    const xdg = process.env['XDG_CACHE_HOME'];
    const base = xdg ? xdg : path.join(os.homedir(), '.cache');
    return path.join(base, 'ai-sec-scan');
}
function hashContent(content) {
    return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}
// ── Public API ────────────────────────────────────────────────────────────────
/**
 * Initialise the cache. Must be called once before any get/set operations.
 * Safe to call multiple times — subsequent calls are no-ops if options match.
 */
function initCache(options = {}) {
    _disabled = options.disabled ?? false;
    if (_disabled)
        return;
    const dir = options.cacheDir ??
        process.env['AI_SEC_SCAN_CACHE_DIR'] ??
        defaultCacheDir();
    _cacheDir = dir;
    _cachePath = path.join(dir, CACHE_FILENAME);
    // Load existing cache from disk (failures are non-fatal)
    try {
        if (fs.existsSync(_cachePath)) {
            const raw = fs.readFileSync(_cachePath, 'utf8');
            const parsed = JSON.parse(raw);
            // Validate scanner version — if it differs, discard the entire cache.
            // This ensures that new detection patterns added in a scanner upgrade
            // are applied to all files, not just those whose content changed.
            if (parsed.scannerVersion === SCANNER_VERSION &&
                typeof parsed.entries === 'object') {
                _entries = parsed.entries ?? {};
            }
            else {
                // Version mismatch — start fresh
                _entries = {};
                _dirty = true; // Will overwrite the stale file on next persist
            }
        }
    }
    catch {
        // Corrupt or unreadable cache — start fresh
        _entries = {};
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
function getCachedFindings(filePath, content) {
    if (_disabled) {
        _misses++;
        return null;
    }
    const entry = _entries[filePath];
    if (!entry) {
        _misses++;
        return null;
    }
    const currentHash = hashContent(content);
    if (entry.hash !== currentHash) {
        _misses++;
        return null;
    }
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
function setCachedFindings(filePath, content, findings) {
    if (_disabled)
        return;
    _entries[filePath] = {
        hash: hashContent(content),
        scannedAt: new Date().toISOString(),
        findings,
    };
    _dirty = true;
}
/**
 * Flush the in-memory cache to disk.
 * A no-op when the cache is disabled or nothing has changed since the last persist.
 */
function persistCache() {
    if (_disabled || !_dirty || !_cachePath || !_cacheDir)
        return;
    try {
        fs.mkdirSync(_cacheDir, { recursive: true });
        const data = {
            scannerVersion: SCANNER_VERSION,
            entries: _entries,
        };
        fs.writeFileSync(_cachePath, JSON.stringify(data, null, 2), 'utf8');
        _dirty = false;
    }
    catch {
        // Cache write failure is non-fatal — the scan result is still correct.
    }
}
/**
 * Return basic cache statistics for diagnostic output.
 */
function getCacheStats() {
    return {
        entries: Object.keys(_entries).length,
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
function clearCache() {
    _entries = {};
    _dirty = false;
    if (_cachePath && fs.existsSync(_cachePath)) {
        try {
            fs.unlinkSync(_cachePath);
        }
        catch {
            /* ignore */
        }
    }
}
//# sourceMappingURL=scan-cache.js.map