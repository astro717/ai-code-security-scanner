"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.server = exports.INTERNAL_API_TOKEN = exports.app = void 0;
exports.resetRateLimiters = resetRateLimiters;
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const crypto_1 = __importDefault(require("crypto"));
const fs_1 = __importDefault(require("fs"));
const http_1 = __importDefault(require("http"));
const https_1 = __importDefault(require("https"));
const path_1 = __importDefault(require("path"));
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const minimatch_1 = require("minimatch");
const parser_1 = require("./scanner/parser");
const secrets_1 = require("./scanner/detectors/secrets");
const sql_1 = require("./scanner/detectors/sql");
const shell_1 = require("./scanner/detectors/shell");
const eval_1 = require("./scanner/detectors/eval");
const xss_1 = require("./scanner/detectors/xss");
const pathTraversal_1 = require("./scanner/detectors/pathTraversal");
const prototypePollution_1 = require("./scanner/detectors/prototypePollution");
const insecureRandom_1 = require("./scanner/detectors/insecureRandom");
const openRedirect_1 = require("./scanner/detectors/openRedirect");
const ssrf_1 = require("./scanner/detectors/ssrf");
const jwt_1 = require("./scanner/detectors/jwt");
const commandInjection_1 = require("./scanner/detectors/commandInjection");
const cors_2 = require("./scanner/detectors/cors");
const redos_1 = require("./scanner/detectors/redos");
const weakCrypto_1 = require("./scanner/detectors/weakCrypto");
const jwtNone_1 = require("./scanner/detectors/jwtNone");
const csrf_1 = require("./scanner/detectors/csrf");
const reporter_1 = require("./scanner/reporter");
const owasp_1 = require("./scanner/owasp");
const sarif_1 = require("./scanner/sarif");
const deps_1 = require("./scanner/detectors/deps");
const python_parser_1 = require("./scanner/python-parser");
const go_parser_1 = require("./scanner/go-parser");
const java_parser_1 = require("./scanner/java-parser");
const csharp_parser_1 = require("./scanner/csharp-parser");
const c_parser_1 = require("./scanner/c-parser");
const ruby_parser_1 = require("./scanner/ruby-parser");
const kotlin_parser_1 = require("./scanner/kotlin-parser");
const swift_parser_1 = require("./scanner/swift-parser");
const rust_parser_1 = require("./scanner/rust-parser");
const php_parser_1 = require("./scanner/php-parser");
const scan_cache_1 = require("./scanner/scan-cache");
const fixer_js_1 = require("./scanner/fixer.js");
function validateRequestBody(body, schema, endpointName) {
    if (typeof body !== 'object' || body === null || Array.isArray(body)) {
        return { valid: false, errors: [`${endpointName} request body must be a JSON object`] };
    }
    const record = body;
    const errors = [];
    for (const [key, rule] of Object.entries(schema)) {
        const val = record[key];
        // Check required fields for presence
        if (rule.required && (val === undefined || val === null)) {
            errors.push(`Missing required field: ${key} (${rule.type})`);
            continue;
        }
        // Skip type check if the field is absent and optional
        if (val === undefined || val === null)
            continue;
        // Type validation for all present fields (required and optional)
        if (rule.type === 'string' && typeof val !== 'string') {
            errors.push(`${key} must be a string`);
        }
        else if (rule.type === 'boolean' && typeof val !== 'boolean') {
            errors.push(`${key} must be a boolean`);
        }
        else if (rule.type === 'array') {
            if (!Array.isArray(val)) {
                errors.push(`${key} must be an array`);
            }
            // Note: mixed-type arrays are tolerated — non-string items are filtered downstream
        }
        else if (rule.type === 'object' && (typeof val !== 'object' || Array.isArray(val))) {
            errors.push(`${key} must be an object`);
        }
    }
    return errors.length > 0 ? { valid: false, errors } : { valid: true };
}
const SCAN_BODY_SCHEMA = {
    code: { type: 'string', required: true },
    filename: { type: 'string', required: true },
    packageJson: { type: 'string' },
    aiExplain: { type: 'boolean' },
    ignoreTypes: { type: 'array', items: 'string' },
    webhookUrl: { type: 'string' },
    webhookSecret: { type: 'string' },
};
const SCAN_REPO_BODY_SCHEMA = {
    repoUrl: { type: 'string', required: true },
    branch: { type: 'string' },
    sinceCommit: { type: 'string' },
    changedFilesOnly: { type: 'boolean' },
    ignorePatterns: { type: 'array', items: 'string' },
    ignoreTypes: { type: 'array', items: 'string' },
    webhookUrl: { type: 'string' },
    webhookSecret: { type: 'string' },
};
// LLM calls can be slow — 30 s gives ample time for a response while bounding
// the maximum time a single /scan?aiExplain=true request can block the server.
const AI_REQUEST_TIMEOUT_MS = 30000;
/** @deprecated use AI_REQUEST_TIMEOUT_MS */
const ANTHROPIC_REQUEST_TIMEOUT_MS = AI_REQUEST_TIMEOUT_MS;
/**
 * Makes a request to the Anthropic Messages API.
 * @param body      - JSON request body
 * @param apiKey    - Anthropic API key to use; falls back to ANTHROPIC_API_KEY env var
 */
async function anthropicRequest(body, apiKey) {
    const effectiveKey = apiKey ?? process.env.ANTHROPIC_API_KEY ?? '';
    return new Promise((resolve, reject) => {
        const payload = JSON.stringify(body);
        const req = https_1.default.request({
            hostname: 'api.anthropic.com',
            path: '/v1/messages',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'anthropic-version': '2023-06-01',
                'x-api-key': effectiveKey,
                'Content-Length': Buffer.byteLength(payload),
            },
        }, (res) => {
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
                try {
                    resolve(JSON.parse(data));
                }
                catch {
                    reject(new Error('Invalid JSON from Anthropic'));
                }
            });
        });
        req.setTimeout(AI_REQUEST_TIMEOUT_MS, () => {
            req.destroy(new Error(`Anthropic API request timed out after ${AI_REQUEST_TIMEOUT_MS}ms`));
        });
        req.on('error', reject);
        req.write(payload);
        req.end();
    });
}
/**
 * Makes a request to an OpenAI-compatible Chat Completions endpoint.
 *
 * @param prompt     - User message prompt text
 * @param apiKey     - OpenAI API key; falls back to OPENAI_API_KEY env var
 * @param model      - Model name; falls back to AI_EXPLAIN_MODEL env var or 'gpt-4o-mini'
 * @param endpoint   - Full URL of the chat completions endpoint; falls back to
 *                     AI_EXPLAIN_ENDPOINT env var or https://api.openai.com/v1/chat/completions
 */
async function openaiRequest(prompt, apiKey, model, endpoint) {
    const effectiveKey = apiKey ?? process.env.OPENAI_API_KEY ?? '';
    const effectiveModel = model ?? process.env.AI_EXPLAIN_MODEL ?? 'gpt-4o-mini';
    const effectiveEndpoint = endpoint ?? process.env.AI_EXPLAIN_ENDPOINT ?? 'https://api.openai.com/v1/chat/completions';
    const parsed = new URL(effectiveEndpoint);
    const isHttps = parsed.protocol === 'https:';
    const transport = isHttps ? https_1.default : http_1.default;
    const body = {
        model: effectiveModel,
        max_tokens: 512,
        messages: [{ role: 'user', content: prompt }],
    };
    return new Promise((resolve, reject) => {
        const payload = JSON.stringify(body);
        const req = transport.request({
            hostname: parsed.hostname,
            port: parsed.port || (isHttps ? 443 : 80),
            path: parsed.pathname + parsed.search,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${effectiveKey}`,
                'Content-Length': Buffer.byteLength(payload),
            },
        }, (res) => {
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
                try {
                    resolve(JSON.parse(data));
                }
                catch {
                    reject(new Error('Invalid JSON from OpenAI-compatible endpoint'));
                }
            });
        });
        req.setTimeout(AI_REQUEST_TIMEOUT_MS, () => {
            req.destroy(new Error(`OpenAI API request timed out after ${AI_REQUEST_TIMEOUT_MS}ms`));
        });
        req.on('error', reject);
        req.write(payload);
        req.end();
    });
}
/**
 * Resolves the active AI provider. Priority:
 *   1. per-request provider parameter (from X-AI-Provider header)
 *   2. AI_EXPLAIN_PROVIDER environment variable
 *   3. 'anthropic' default
 */
function resolveAiProvider(requestProvider) {
    const raw = (requestProvider ?? process.env.AI_EXPLAIN_PROVIDER ?? 'anthropic').toLowerCase();
    return raw === 'openai' ? 'openai' : 'anthropic';
}
const EXPLAIN_PROMPT_TEMPLATE = (finding) => `You are a security expert. Analyze this vulnerability finding and respond with ONLY a JSON object (no markdown, no extra text):

Vulnerability type: ${finding.type}
Severity: ${finding.severity}
Code snippet: ${finding.snippet ?? '(not available)'}
Message: ${finding.message}

Respond with exactly this JSON structure:
{"explanation": "2-sentence explanation of why this is dangerous and what could be exploited", "fixSuggestion": "the corrected code snippet, just the code, no explanation"}`;
async function explainFinding(finding, apiKey, provider, openaiEndpoint) {
    const activeProvider = provider ?? resolveAiProvider();
    if (activeProvider === 'openai') {
        const effectiveModel = process.env.AI_EXPLAIN_MODEL ?? 'gpt-4o-mini';
        const response = await openaiRequest(EXPLAIN_PROMPT_TEMPLATE(finding), apiKey, effectiveModel, openaiEndpoint);
        const text = response.choices?.[0]?.message?.content ?? '';
        try {
            const parsed = JSON.parse(text);
            return {
                explanation: parsed.explanation ?? '',
                fixSuggestion: parsed.fixSuggestion ?? '',
            };
        }
        catch {
            return { explanation: text.slice(0, 200), fixSuggestion: '' };
        }
    }
    // Default: Anthropic
    const effectiveModel = process.env.AI_EXPLAIN_MODEL ?? 'claude-haiku-4-5-20251001';
    const response = await anthropicRequest({
        model: effectiveModel,
        max_tokens: 512,
        messages: [
            {
                role: 'user',
                content: EXPLAIN_PROMPT_TEMPLATE(finding),
            },
        ],
    }, apiKey);
    const text = response.content?.[0]?.text ?? '';
    try {
        const parsed = JSON.parse(text);
        return {
            explanation: parsed.explanation ?? '',
            fixSuggestion: parsed.fixSuggestion ?? '',
        };
    }
    catch {
        return { explanation: text.slice(0, 200), fixSuggestion: '' };
    }
}
/**
 * Enriches up to 5 findings with AI-generated explanations.
 *
 * @param findings       - Findings to enrich
 * @param apiKey         - Optional per-request API key; falls back to ANTHROPIC_API_KEY or OPENAI_API_KEY
 * @param provider       - LLM provider to use ('anthropic' | 'openai'); resolved from env when absent
 * @param openaiEndpoint - Optional custom OpenAI-compatible endpoint URL
 */
async function enrichWithAI(findings, apiKey, provider, openaiEndpoint) {
    const activeProvider = provider ?? resolveAiProvider();
    // Resolve effective key depending on provider
    const effectiveKey = apiKey ?? (activeProvider === 'openai'
        ? process.env.OPENAI_API_KEY
        : process.env.ANTHROPIC_API_KEY);
    if (!effectiveKey) {
        const envVar = activeProvider === 'openai' ? 'OPENAI_API_KEY' : 'ANTHROPIC_API_KEY';
        console.warn(`[ai-explain] ${envVar} not set — skipping AI enrichment`);
        return findings;
    }
    // Process up to 5 findings (highest severity first)
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    const toEnrich = [...findings]
        .sort((a, b) => (severityOrder[a.severity] ?? 3) - (severityOrder[b.severity] ?? 3))
        .slice(0, 5);
    const enriched = new Map();
    await Promise.all(toEnrich.map(async (f) => {
        try {
            const ai = await explainFinding(f, effectiveKey, activeProvider, openaiEndpoint);
            enriched.set(f, { ...f, ...ai });
        }
        catch (err) {
            console.error(`[ai-explain] failed for ${f.type}:`, err);
            enriched.set(f, f);
        }
    }));
    return findings.map((f) => enriched.get(f) ?? f);
}
// ── Structured logging ───────────────────────────────────────────────────────
/**
 * Emits a single structured JSON log line to stdout.
 * Using JSON ensures log aggregators (Datadog, CloudWatch, etc.) can parse
 * all fields without regex extraction.
 */
function logScan(fields) {
    console.log(JSON.stringify({ ...fields, ts: new Date().toISOString() }));
}
// ── Webhook delivery ──────────────────────────────────────────────────────────
const WEBHOOK_TIMEOUT_MS = 10000;
const WEBHOOK_MAX_RETRIES = 3;
const WEBHOOK_BACKOFF_BASE_MS = 1000;
/**
 * Send a single webhook HTTP request. Resolves with the status code on success,
 * rejects on network error or timeout.
 */
function sendWebhookRequest(webhookUrl, body, headers) {
    return new Promise((resolve, reject) => {
        const parsed = new URL(webhookUrl);
        const transport = parsed.protocol === 'https:' ? https_1.default : http_1.default;
        const req = transport.request({
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
            path: parsed.pathname + parsed.search,
            method: 'POST',
            headers,
        }, (res) => {
            res.resume();
            resolve(res.statusCode ?? 0);
        });
        req.setTimeout(WEBHOOK_TIMEOUT_MS, () => {
            req.destroy(new Error(`Webhook timed out after ${WEBHOOK_TIMEOUT_MS}ms`));
        });
        req.on('error', reject);
        req.write(body);
        req.end();
    });
}
function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}
/**
 * Fire-and-forget POST of scan results to a webhook URL.
 * Retries up to 3 times with exponential backoff (1s, 2s, 4s) on non-2xx
 * responses or network errors.
 * If `webhookSecret` is provided, an HMAC-SHA256 signature is sent in
 * the `X-Scanner-Signature` header so the receiver can verify authenticity.
 */
function deliverWebhook(webhookUrl, payload, webhookSecret) {
    const body = JSON.stringify(payload);
    const headers = {
        'Content-Type': 'application/json',
        'Content-Length': String(Buffer.byteLength(body)),
        'User-Agent': 'ai-code-security-scanner/0.1',
    };
    if (webhookSecret) {
        const signature = crypto_1.default
            .createHmac('sha256', webhookSecret)
            .update(body)
            .digest('hex');
        headers['X-Scanner-Signature'] = `sha256=${signature}`;
    }
    // Fire-and-forget: launch async retry loop without awaiting
    (async () => {
        for (let attempt = 0; attempt <= WEBHOOK_MAX_RETRIES; attempt++) {
            try {
                const statusCode = await sendWebhookRequest(webhookUrl, body, headers);
                console.log(`[webhook] POST ${webhookUrl} → ${statusCode} (attempt ${attempt + 1})`);
                if (statusCode >= 200 && statusCode < 300) {
                    return; // Success — done
                }
                // Non-2xx: fall through to retry
                if (attempt < WEBHOOK_MAX_RETRIES) {
                    const delayMs = WEBHOOK_BACKOFF_BASE_MS * Math.pow(2, attempt);
                    console.log(`[webhook] non-2xx (${statusCode}), retrying in ${delayMs}ms…`);
                    await sleep(delayMs);
                }
                else {
                    console.error(`[webhook] POST ${webhookUrl} failed after ${WEBHOOK_MAX_RETRIES + 1} attempts (last status: ${statusCode})`);
                }
            }
            catch (err) {
                const message = err instanceof Error ? err.message : String(err);
                if (attempt < WEBHOOK_MAX_RETRIES) {
                    const delayMs = WEBHOOK_BACKOFF_BASE_MS * Math.pow(2, attempt);
                    console.log(`[webhook] error: ${message}, retrying in ${delayMs}ms…`);
                    await sleep(delayMs);
                }
                else {
                    console.error(`[webhook] POST ${webhookUrl} failed after ${WEBHOOK_MAX_RETRIES + 1} attempts: ${message}`);
                }
            }
        }
    })();
}
exports.app = (0, express_1.default)();
const PORT = process.env.PORT ?? 3001;
// Initialize scan result cache for /watch SSE endpoint caching
(0, scan_cache_1.initCache)({ disabled: process.env.SCAN_CACHE_DISABLED === 'true' });
// Periodically flush scan cache to disk every 5 minutes for resilience
// against unclean shutdowns. The interval is cleared on graceful shutdown.
const CACHE_FLUSH_INTERVAL_MS = 5 * 60 * 1000;
const cacheFlushTimer = setInterval(() => {
    (0, scan_cache_1.persistCache)();
}, CACHE_FLUSH_INTERVAL_MS);
// Prevent the timer from keeping the process alive when tests shut down
if (cacheFlushTimer.unref)
    cacheFlushTimer.unref();
exports.app.use((0, cors_1.default)({
    origin: process.env.CORS_ALLOWED_ORIGINS?.split(',') ?? ['http://localhost:5173', 'http://localhost:3001'],
    credentials: true,
}));
// Limit request body to 500 KB. Express will automatically respond with 413
// for bodies larger than this limit — but we also enforce it explicitly inside
// route handlers so the error message is consistent and human-readable.
const PAYLOAD_LIMIT = '500kb';
const PAYLOAD_LIMIT_BYTES = 500 * 1024;
exports.app.use(express_1.default.json({ limit: PAYLOAD_LIMIT }));
// Middleware to set X-RateLimit-* headers on all responses.
// If express-rate-limit has already set these headers, they are preserved.
// Otherwise, set default values to indicate rate limiting is active.
exports.app.use((req, res, next) => {
    // Only set defaults if not already set by rate limiting middleware
    if (!res.getHeader('X-RateLimit-Limit')) {
        res.setHeader('X-RateLimit-Limit', '100');
    }
    if (!res.getHeader('X-RateLimit-Remaining')) {
        res.setHeader('X-RateLimit-Remaining', '100');
    }
    if (!res.getHeader('X-RateLimit-Reset')) {
        const resetTime = Math.floor(Date.now() / 1000) + 3600; // Reset in 1 hour
        res.setHeader('X-RateLimit-Reset', resetTime.toString());
    }
    next();
});
// Convert express.json() 413 PayloadTooLargeError into our standard JSON error shape
// so callers always get { error: '...' } instead of Express's default HTML/text response.
exports.app.use((err, req, res, next) => {
    if (err && (err.type === 'entity.too.large' || err.status === 413)) {
        res.status(413).json({ error: `Payload too large. Maximum allowed size is ${PAYLOAD_LIMIT}.` });
        return;
    }
    next(err);
});
// ── API key auth ──────────────────────────────────────────────────────────────
// Protect all non-health endpoints with a Bearer token check.
// Set SERVER_API_KEY in the environment to enable; if unset, the server starts
// but logs a warning and all requests are allowed (dev-friendly default).
const SERVER_API_KEY = process.env.SERVER_API_KEY;
if (!SERVER_API_KEY) {
    console.warn('[auth] WARNING: SERVER_API_KEY is not set. ' +
        'All endpoints are publicly accessible — set this variable in production.');
}
else if (SERVER_API_KEY.length < 32) {
    console.warn('[auth] WARNING: SERVER_API_KEY is shorter than 32 characters. ' +
        'Use a long random value to prevent token guessing.');
}
exports.app.use((req, res, next) => {
    // /health is always open so uptime monitors and Docker HEALTHCHECK work
    if (req.path === '/health')
        return next();
    if (!SERVER_API_KEY) {
        // No key configured → open access (dev mode)
        return next();
    }
    const authHeader = req.headers['authorization'] ?? '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    if (token !== SERVER_API_KEY) {
        res.status(401).json({ error: 'Unauthorized — valid Bearer token required.' });
        return;
    }
    next();
});
// ── Trusted internal token ────────────────────────────────────────────────────
//
// Set INTERNAL_API_TOKEN in the environment to enable the rate-limit bypass.
// Callers (CI pipelines, internal dashboards) present the token in the
// X-Internal-Token request header to be exempted from per-IP rate limits.
// The value must be at least 32 characters to prevent accidental weak tokens.
// If the env var is not set the bypass is disabled entirely.
exports.INTERNAL_API_TOKEN = process.env.INTERNAL_API_TOKEN;
if (exports.INTERNAL_API_TOKEN && exports.INTERNAL_API_TOKEN.length < 32) {
    console.warn('[auth] WARNING: INTERNAL_API_TOKEN is shorter than 32 characters. ' +
        'Use a long random value to prevent token guessing.');
}
// ── Rate limiting ─────────────────────────────────────────────────────────────
//
// In test mode (NODE_ENV=test) both limiters use a very high cap so that
// multiple test files loading the server in the same process (sharing module
// cache and therefore limiter state) never exhaust the per-IP budget before
// all assertions run.  Production limits are unaffected.
const IS_TEST = process.env.NODE_ENV === 'test';
// Requests that present a valid X-Internal-Token header skip both limiters so
// internal tools (CI, dashboards) can make burst requests without hitting the
// per-IP cap. All other callers are subject to the standard limits below.
function skipIfInternalToken(req) {
    if (!exports.INTERNAL_API_TOKEN)
        return false;
    const presented = req.headers['x-internal-token'];
    return typeof presented === 'string' && presented === exports.INTERNAL_API_TOKEN;
}
const scanLimiter = (0, express_rate_limit_1.default)({
    windowMs: 60 * 1000, // 1 minute
    max: IS_TEST ? 10000 : 20,
    standardHeaders: true,
    legacyHeaders: true,
    skip: skipIfInternalToken,
    message: { error: 'Too many scan requests from this IP. Limit: 20 requests per minute.' },
});
const scanRepoLimiter = (0, express_rate_limit_1.default)({
    windowMs: 60 * 1000, // 1 minute
    max: IS_TEST ? 10000 : 5,
    standardHeaders: true,
    legacyHeaders: true,
    skip: skipIfInternalToken,
    message: { error: 'Too many scan-repo requests from this IP. Limit: 5 requests per minute (GitHub API calls).' },
});
/**
 * Resets the in-memory hit counters for both rate limiters.
 * Exported for test use only — do not call in production code.
 * Vitest loads the server module once per process (module cache is shared
 * across test files), so calling this in beforeAll() guarantees a clean
 * slate for each test suite regardless of execution order.
 */
async function resetRateLimiters() {
    if (process.env.NODE_ENV !== 'test') {
        throw new Error('resetRateLimiters() is only available in test mode (NODE_ENV=test). ' +
            'Calling this in production would disable rate limiting for all clients.');
    }
    await Promise.all([
        scanLimiter.resetKey('127.0.0.1'),
        scanRepoLimiter.resetKey('127.0.0.1'),
    ]);
}
// ── Scan timeout ─────────────────────────────────────────────────────────────
// Wraps an async operation in a Promise.race with a timeout. Returns the
// operation result or throws a timeout error. Prevents DoS via slow/malformed
// inputs that could cause catastrophic backtracking in regex-based parsers.
const SCAN_TIMEOUT_MS = parseInt(process.env.SCAN_TIMEOUT_MS ?? '30000', 10);
function withScanTimeout(operation, timeoutMs = SCAN_TIMEOUT_MS) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            reject(new Error(`Scan timed out after ${timeoutMs}ms`));
        }, timeoutMs);
        operation
            .then((result) => { clearTimeout(timer); resolve(result); })
            .catch((err) => { clearTimeout(timer); reject(err); });
    });
}
// ── Badge endpoint ────────────────────────────────────────────────────────────
// GET /badge/:orgId?count=<n>&label=<label>
// Returns a shields.io-compatible SVG badge showing critical finding count.
// The count parameter is provided by the caller (e.g. CI pipeline after scanning).
// Example: GET /badge/my-org?count=3 → SVG badge "security | 3 critical"
exports.app.get('/badge/:orgId', (req, res) => {
    const orgId = req.params['orgId'] ?? 'unknown';
    const count = parseInt(String(req.query['count'] ?? '0'), 10);
    const label = String(req.query['label'] ?? 'security');
    const color = count === 0 ? '4c1' : count < 5 ? 'orange' : 'red';
    const labelText = label.replace(/[<>&"]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' }[c] ?? c));
    const valueText = count === 0 ? 'passing' : `${count} critical`;
    // Shields.io-compatible flat badge SVG
    const labelWidth = Math.max(labelText.length * 6 + 20, 60);
    const valueWidth = Math.max(valueText.length * 6 + 20, 60);
    const totalWidth = labelWidth + valueWidth;
    const lx = labelWidth / 2 + 1;
    const vx = labelWidth + valueWidth / 2 - 1;
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20" role="img" aria-label="${labelText}: ${valueText}">
  <title>${labelText}: ${valueText}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="${totalWidth}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelWidth}" height="20" fill="#555"/>
    <rect x="${labelWidth}" width="${valueWidth}" height="20" fill="#${color}"/>
    <rect width="${totalWidth}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="110">
    <text x="${lx * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${(labelWidth - 10) * 10}">${labelText}</text>
    <text x="${lx * 10}" y="140" transform="scale(.1)" textLength="${(labelWidth - 10) * 10}">${labelText}</text>
    <text x="${vx * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${(valueWidth - 10) * 10}">${valueText}</text>
    <text x="${vx * 10}" y="140" transform="scale(.1)" textLength="${(valueWidth - 10) * 10}">${valueText}</text>
  </g>
</svg>`;
    res.setHeader('Content-Type', 'image/svg+xml');
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('X-Org-Id', orgId);
    res.send(svg);
});
exports.app.get('/health', (_req, res) => {
    res.json({ status: 'ok', version: '0.1.0' });
});
exports.app.get('/types', (_req, res) => {
    res.json({ types: [...reporter_1.KNOWN_TYPES], owasp: owasp_1.FINDING_TO_OWASP });
});
exports.app.post('/scan', scanLimiter, async (req, res) => {
    // ── Request timeout guard ──────────────────────────────────────────────────
    // Prevent DoS via inputs that trigger catastrophic backtracking in regex-based
    // parsers. If the handler hasn't responded within SCAN_TIMEOUT_MS, send 408.
    let responded = false;
    const timeoutHandle = setTimeout(() => {
        if (!responded && !res.headersSent) {
            responded = true;
            res.status(408).json({
                error: `Scan timed out after ${SCAN_TIMEOUT_MS}ms. The input may contain patterns that cause excessive processing time.`,
            });
        }
    }, SCAN_TIMEOUT_MS);
    const originalJson = res.json.bind(res);
    res.json = ((body) => {
        responded = true;
        clearTimeout(timeoutHandle);
        return originalJson(body);
    });
    // Content-Type validation: only accept application/json
    const contentType = req.headers['content-type'] ?? '';
    if (!contentType.includes('application/json')) {
        res.status(415).json({ error: 'Unsupported Media Type: Content-Type must be application/json' });
        return;
    }
    // ?sarif=true returns a SARIF 2.1.0 document instead of the default JSON shape.
    const sarifMode = req.query['sarif'] === 'true';
    // Explicit payload size guard (belt-and-suspenders on top of express.json limit)
    const rawLength = parseInt(req.headers['content-length'] ?? '0', 10);
    if (rawLength > PAYLOAD_LIMIT_BYTES) {
        res.status(413).json({
            error: `Payload too large. Maximum allowed size is ${PAYLOAD_LIMIT} (${PAYLOAD_LIMIT_BYTES} bytes). Received ${rawLength} bytes.`,
        });
        return;
    }
    // ── Per-request AI provider and key resolution ────────────────────────────
    //
    // X-AI-Provider header: "anthropic" (default) | "openai"
    // X-Anthropic-Key header: Anthropic API key (validated format)
    // X-OpenAI-Key header: OpenAI API key (or any sk-... token for compatible endpoints)
    // X-AI-Endpoint header: optional custom OpenAI-compatible base URL
    const requestAiProvider = resolveAiProvider((() => { const h = req.headers['x-ai-provider']; return typeof h === 'string' ? h : undefined; })());
    const requestOpenAiKey = (() => {
        const h = req.headers['x-openai-key'];
        return typeof h === 'string' && h.length > 0 ? h : undefined;
    })();
    const requestOpenAiEndpoint = (() => {
        const h = req.headers['x-ai-endpoint'];
        return typeof h === 'string' && h.length > 0 ? h : undefined;
    })();
    // Per-request Anthropic key: the caller may supply their own key via the
    // X-Anthropic-Key header. This lets individual callers use ?aiExplain=true
    // without the server having a shared ANTHROPIC_API_KEY. Falls back to the
    // server-level env var when the header is absent.
    const requestAnthropicKey = (() => {
        const h = req.headers['x-anthropic-key'];
        if (typeof h !== 'string' || h.length === 0)
            return undefined;
        // Basic format validation: Anthropic keys start with "sk-ant-" and are
        // at least 20 characters. Reject obviously malformed keys early so the
        // caller gets a clear 400 instead of an opaque 401 from the upstream API.
        if (!/^sk-ant-.{13,}$/.test(h)) {
            res.status(400).json({
                error: 'Invalid X-Anthropic-Key header. Anthropic API keys start with "sk-ant-" and ' +
                    'are at least 20 characters long. Check your key and try again.',
            });
            return null; // sentinel: response already sent
        }
        return h;
    })();
    // If requestAnthropicKey is null, the response was already sent (invalid key).
    if (requestAnthropicKey === null)
        return;
    // Resolve the per-request API key: prefer provider-specific header, fall back to Anthropic key
    const resolvedApiKey = requestAiProvider === 'openai'
        ? (requestOpenAiKey ?? requestAnthropicKey)
        : (requestAnthropicKey ?? requestOpenAiKey);
    // Schema validation — reject malformed requests early with detailed errors.
    const scanValidation = validateRequestBody(req.body, SCAN_BODY_SCHEMA, '/scan');
    if (!scanValidation.valid) {
        res.status(400).json({ error: scanValidation.errors.join('; ') });
        return;
    }
    const { code, filename: rawFilename, packageJson, aiExplain, ignoreTypes, webhookUrl, webhookSecret, minConfidence: bodyMinConfidence } = req.body;
    // minConfidence: filter out findings below this threshold (0.0–1.0).
    // Accepted from body field or query parameter; body takes precedence.
    const rawMinConf = bodyMinConfidence ?? (req.query['minConfidence'] ? parseFloat(req.query['minConfidence']) : undefined);
    if (rawMinConf !== undefined && (typeof rawMinConf !== 'number' || isNaN(rawMinConf) || rawMinConf < 0 || rawMinConf > 1)) {
        res.status(400).json({ error: 'minConfidence must be a number between 0.0 and 1.0' });
        return;
    }
    const minConfidence = rawMinConf;
    if (!code || typeof code !== 'string') {
        res.status(400).json({ error: 'Missing required field: code (string)' });
        return;
    }
    // Sanitize filename: strip path components and reject null bytes / traversal sequences
    // before the value is used for display, parsing, or logging.
    let filename;
    if (rawFilename !== undefined) {
        if (typeof rawFilename !== 'string') {
            res.status(400).json({ error: 'Invalid field: filename must be a string' });
            return;
        }
        if (rawFilename.includes('\0')) {
            res.status(400).json({ error: 'Invalid filename: null bytes are not allowed' });
            return;
        }
        if (rawFilename.includes('..') || rawFilename.startsWith('/') || rawFilename.startsWith('\\')) {
            res.status(400).json({ error: 'Invalid filename: path traversal sequences are not allowed' });
            return;
        }
        // Strip any remaining path components — only keep the base name
        filename = path_1.default.basename(rawFilename);
    }
    // Validate ignoreTypes — reject unknown type strings so callers learn about
    // typos early instead of silently getting unfiltered results.
    if (Array.isArray(ignoreTypes) && ignoreTypes.length > 0) {
        const stringTypes = ignoreTypes.filter((t) => typeof t === 'string').map((t) => t.trim().toUpperCase());
        const unknown = stringTypes.filter((t) => !reporter_1.KNOWN_TYPES.has(t));
        if (unknown.length > 0) {
            res.status(400).json({
                error: `Unknown ignoreTypes: ${unknown.join(', ')}. Valid types: ${[...reporter_1.KNOWN_TYPES].sort().join(', ')}`,
            });
            return;
        }
    }
    // Validate webhookUrl: must be a valid https URL if provided
    if (webhookUrl !== undefined) {
        if (typeof webhookUrl !== 'string') {
            res.status(400).json({ error: 'Invalid field: webhookUrl must be a string' });
            return;
        }
        let parsedWebhookUrl;
        try {
            parsedWebhookUrl = new URL(webhookUrl);
        }
        catch {
            res.status(400).json({ error: 'Invalid webhookUrl: must be a valid URL' });
            return;
        }
        if (parsedWebhookUrl.protocol !== 'https:') {
            res.status(400).json({ error: 'Invalid webhookUrl: only https:// URLs are accepted' });
            return;
        }
    }
    const effectiveFilename = filename ?? 'input.tsx';
    const ext = path_1.default.extname(effectiveFilename).toLowerCase();
    let findings;
    if (ext === '.java') {
        // Java files use the dedicated regex-based Java scanner
        const javaResult = (0, java_parser_1.parseJavaCode)(code, effectiveFilename);
        findings = (0, java_parser_1.scanJava)(javaResult).map((f) => ({ ...f, file: filename ?? 'input' }));
    }
    else if (ext === '.py') {
        // Python files use the dedicated regex-based Python scanner
        const pyResult = (0, python_parser_1.parsePythonCode)(code, effectiveFilename);
        findings = (0, python_parser_1.scanPython)(pyResult).map((f) => ({ ...f, file: filename ?? 'input' }));
    }
    else if (ext === '.go') {
        // Go files use the dedicated regex-based Go scanner
        const goResult = (0, go_parser_1.parseGoCode)(code, effectiveFilename);
        findings = (0, go_parser_1.scanGo)(goResult).map((f) => ({ ...f, file: filename ?? 'input' }));
    }
    else if (ext === '.cs') {
        // C# files use the dedicated regex-based C# scanner
        const csResult = (0, csharp_parser_1.parseCSharpCode)(code, effectiveFilename);
        findings = (0, csharp_parser_1.scanCSharp)(csResult).map((f) => ({ ...f, file: filename ?? 'input' }));
    }
    else if (['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp'].includes(ext)) {
        // C/C++ files use the dedicated regex-based C scanner
        const cResult = (0, c_parser_1.parseCCode)(code, effectiveFilename);
        findings = (0, c_parser_1.scanC)(cResult).map((f) => ({ ...f, file: filename ?? 'input' }));
    }
    else if (ext === '.rb') {
        // Ruby files use the dedicated regex-based Ruby scanner
        const rbResult = (0, ruby_parser_1.parseRubyCode)(code, effectiveFilename);
        findings = (0, ruby_parser_1.scanRuby)(rbResult).map((f) => ({ ...f, file: filename ?? 'input' }));
    }
    else if (ext === '.kt' || ext === '.kts') {
        // Kotlin/Android files use the dedicated regex-based Kotlin scanner
        const ktResult = (0, kotlin_parser_1.parseKotlinCode)(code, effectiveFilename);
        findings = (0, kotlin_parser_1.scanKotlin)(ktResult).map((f) => ({ ...f, file: filename ?? 'input' }));
    }
    else if (ext === '.swift') {
        // Swift files use the dedicated regex-based Swift scanner
        const swiftResult = (0, swift_parser_1.parseSwiftCode)(code, effectiveFilename);
        findings = (0, swift_parser_1.scanSwift)(swiftResult).map((f) => ({ ...f, file: filename ?? 'input' }));
    }
    else if (ext === '.rs') {
        // Rust files use the dedicated regex-based Rust scanner
        const rustResult = (0, rust_parser_1.parseRustCode)(code, effectiveFilename);
        findings = (0, rust_parser_1.scanRust)(rustResult).map((f) => ({ ...f, file: filename ?? 'input' }));
    }
    else if (ext === '.php') {
        // PHP files use the dedicated regex-based PHP scanner
        const phpResult = (0, php_parser_1.parsePHPCode)(code, effectiveFilename);
        findings = (0, php_parser_1.scanPHP)(phpResult).map((f) => ({ ...f, file: filename ?? 'input' }));
    }
    else {
        // JS/TS files use the AST-based parser and detector suite
        let parsed;
        try {
            parsed = (0, parser_1.parseCode)(code, effectiveFilename);
        }
        catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            res.status(400).json({ error: `Parse error: ${msg}` });
            return;
        }
        findings = [
            ...(0, secrets_1.detectSecrets)(parsed),
            ...(0, sql_1.detectSQLInjection)(parsed),
            ...(0, shell_1.detectShellInjection)(parsed),
            ...(0, eval_1.detectEval)(parsed),
            ...(0, xss_1.detectXSS)(parsed),
            ...(0, pathTraversal_1.detectPathTraversal)(parsed),
            ...(0, prototypePollution_1.detectPrototypePollution)(parsed),
            ...(0, insecureRandom_1.detectInsecureRandom)(parsed),
            ...(0, openRedirect_1.detectOpenRedirect)(parsed),
            ...(0, ssrf_1.detectSSRF)(parsed),
            ...(0, jwt_1.detectJWTSecrets)(parsed),
            ...(0, jwtNone_1.detectJWTNoneAlgorithm)(parsed),
            ...(0, commandInjection_1.detectCommandInjection)(parsed),
            ...(0, cors_2.detectCORSMisconfiguration)(parsed),
            ...(0, redos_1.detectReDoS)(parsed),
            ...(0, weakCrypto_1.detectWeakCrypto)(parsed),
            ...(0, csrf_1.detectCSRF)(parsed),
        ].map((f) => ({ ...f, file: filename ?? 'input' }));
    }
    // Scan package.json for unsafe deps if provided
    if (packageJson && typeof packageJson === 'string') {
        const depsFindings = (0, deps_1.detectUnsafeDepsFromJson)(packageJson);
        findings.push(...depsFindings);
    }
    // Deduplicate by (type, file, line, column) before reporting.
    findings = (0, reporter_1.deduplicateFindings)(findings);
    // Optional ignoreTypes suppression — mirrors the CLI --ignore-type flag.
    // Only accepts an array of strings; malformed values are silently ignored so
    // the endpoint degrades gracefully for clients that send unexpected shapes.
    if (Array.isArray(ignoreTypes) && ignoreTypes.length > 0) {
        const typesToIgnore = new Set(ignoreTypes.filter((t) => typeof t === 'string').map((t) => t.trim().toUpperCase()));
        if (typesToIgnore.size > 0) {
            findings = findings.filter((f) => !typesToIgnore.has(f.type));
        }
    }
    // Optional minConfidence filter — drop findings with a confidence score below the
    // caller-specified threshold.  Findings that do not carry a confidence field are
    // always kept (conservative: absence of a score means the detector didn't rate
    // itself, not that it is low-confidence).
    const rawMinConfidence = req.query['minConfidence'];
    if (rawMinConfidence !== undefined) {
        const threshold = parseFloat(String(rawMinConfidence));
        if (!Number.isNaN(threshold) && threshold >= 0 && threshold <= 1) {
            findings = findings.filter((f) => f.confidence === undefined ||
                f.confidence >= threshold);
        }
    }
    // Optional minConfidence threshold — remove findings below the confidence threshold.
    // Findings without a confidence value are kept (they pass the filter).
    if (minConfidence !== undefined) {
        findings = findings.filter((f) => (f.confidence ?? 1) >= minConfidence);
    }
    // AI explain enrichment — supports Anthropic (default) and OpenAI backends.
    // Provider resolved from X-AI-Provider header → AI_EXPLAIN_PROVIDER env var → 'anthropic'.
    // API key resolved from X-Anthropic-Key / X-OpenAI-Key headers → env vars.
    if (aiExplain && findings.length > 0) {
        findings = await enrichWithAI(findings, resolvedApiKey, requestAiProvider, requestOpenAiEndpoint);
    }
    const scanSummary = findings.reduce((acc, f) => {
        acc[f.severity] = (acc[f.severity] ?? 0) + 1;
        return acc;
    }, {});
    logScan({
        event: 'scan',
        file: filename ?? 'input',
        findings_total: findings.length,
        findings_by_severity: scanSummary,
        ai_enriched: !!aiExplain,
    });
    if (sarifMode) {
        res.setHeader('Content-Type', 'application/sarif+json');
        res.json((0, sarif_1.buildSARIF)(findings));
        return;
    }
    const responsePayload = { findings, summary: (0, reporter_1.summarize)(findings) };
    res.json(responsePayload);
    // Fire-and-forget webhook delivery after responding to the client
    if (webhookUrl && typeof webhookUrl === 'string') {
        deliverWebhook(webhookUrl, { event: 'scan_complete', file: filename ?? 'input', ...responsePayload }, webhookSecret);
    }
});
// Helper: fetch JSON from GitHub Contents API
const GITHUB_REQUEST_TIMEOUT_MS = 30000;
function githubGet(url) {
    return new Promise((resolve, reject) => {
        const opts = new URL(url);
        const reqOpts = {
            hostname: opts.hostname,
            path: opts.pathname + opts.search,
            headers: {
                'User-Agent': 'ai-code-security-scanner/0.1',
                'Accept': 'application/vnd.github.v3+json',
                ...(process.env.GITHUB_TOKEN ? { 'Authorization': `token ${process.env.GITHUB_TOKEN}` } : {}),
            },
        };
        const req = https_1.default.get(reqOpts, (res) => {
            let body = '';
            res.on('data', (chunk) => body += chunk);
            res.on('end', () => {
                try {
                    resolve(JSON.parse(body));
                }
                catch {
                    reject(new Error('Invalid JSON from GitHub'));
                }
            });
        });
        req.setTimeout(GITHUB_REQUEST_TIMEOUT_MS, () => {
            req.destroy(new Error(`GitHub API request timed out after ${GITHUB_REQUEST_TIMEOUT_MS}ms`));
        });
        req.on('error', reject);
    });
}
function githubGetText(url) {
    return new Promise((resolve, reject) => {
        const opts = new URL(url);
        const req = https_1.default.get({
            hostname: opts.hostname,
            path: opts.pathname + opts.search,
            headers: {
                'User-Agent': 'ai-code-security-scanner/0.1',
                'Accept': 'application/vnd.github.v3.raw',
                ...(process.env.GITHUB_TOKEN ? { 'Authorization': `token ${process.env.GITHUB_TOKEN}` } : {}),
            },
        }, (res) => {
            let body = '';
            res.on('data', (chunk) => body += chunk);
            res.on('end', () => resolve(body));
        });
        req.setTimeout(GITHUB_REQUEST_TIMEOUT_MS, () => {
            req.destroy(new Error(`GitHub API request timed out after ${GITHUB_REQUEST_TIMEOUT_MS}ms`));
        });
        req.on('error', reject);
    });
}
function isIgnoredByPatterns(filePath, ignorePatterns) {
    if (ignorePatterns.length === 0)
        return false;
    const normalised = filePath.replace(/\\/g, '/');
    return ignorePatterns.some((pattern) => (0, minimatch_1.minimatch)(normalised, pattern, { matchBase: true, dot: true }));
}
async function collectFiles(apiBase, dirPath, branch, collected, max, ignorePatterns = []) {
    if (collected.length >= max)
        return;
    const url = `${apiBase}/contents/${dirPath}?ref=${encodeURIComponent(branch)}`;
    const items = await githubGet(url);
    if (!Array.isArray(items))
        return;
    for (const item of items) {
        if (collected.length >= max)
            break;
        if (isIgnoredByPatterns(item.path, ignorePatterns))
            continue;
        if (item.type === 'file') {
            const ext = item.name.split('.').pop() ?? '';
            if (['ts', 'tsx', 'js', 'jsx', 'py', 'go', 'java', 'cs', 'c', 'cpp', 'cc', 'cxx', 'h', 'hpp', 'rb', 'php', 'kt', 'kts', 'swift', 'rs'].includes(ext) && item.size <= 200 * 1024) {
                collected.push(item);
            }
        }
        else if (item.type === 'dir') {
            await collectFiles(apiBase, item.path, branch, collected, max, ignorePatterns);
        }
    }
}
exports.app.post('/scan-repo', scanRepoLimiter, async (req, res) => {
    // ?sarif=true or body.sarif === true returns a SARIF 2.1.0 document instead of the default JSON shape.
    // This enables GitHub Code Scanning integration for repository scans.
    const body = req.body;
    const sarifMode = req.query['sarif'] === 'true' || body['sarif'] === true;
    // Schema validation — reject malformed requests early with detailed errors.
    const repoValidation = validateRequestBody(req.body, SCAN_REPO_BODY_SCHEMA, '/scan-repo');
    if (!repoValidation.valid) {
        res.status(400).json({ error: repoValidation.errors.join('; ') });
        return;
    }
    const { repoUrl, branch = 'main', sinceCommit, changedFilesOnly, ignorePatterns = [], ignoreTypes, webhookUrl, webhookSecret } = req.body;
    if (!repoUrl || typeof repoUrl !== 'string') {
        res.status(400).json({ error: 'Missing required field: repoUrl (string)' });
        return;
    }
    // SSRF protection: validate repoUrl against allowlisted hostnames
    let parsedUrl;
    try {
        parsedUrl = new URL(repoUrl.trim());
    }
    catch {
        res.status(400).json({ error: 'repoUrl must be a valid URL (e.g. https://github.com/owner/repo)' });
        return;
    }
    if (parsedUrl.protocol !== 'https:') {
        res.status(400).json({ error: 'repoUrl must use the https:// scheme' });
        return;
    }
    const ALLOWED_HOSTS = new Set(['github.com', 'gitlab.com', 'bitbucket.org']);
    if (!ALLOWED_HOSTS.has(parsedUrl.hostname)) {
        res.status(400).json({ error: 'Only github.com, gitlab.com, and bitbucket.org repositories are supported' });
        return;
    }
    // Block private IP ranges to prevent SSRF via DNS rebinding
    const PRIVATE_IP_RE = /^(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|::1$|localhost)/i;
    if (PRIVATE_IP_RE.test(parsedUrl.hostname)) {
        res.status(400).json({ error: 'repoUrl resolves to a private or loopback address — not allowed' });
        return;
    }
    // Parse GitHub URL: https://github.com/owner/repo
    const match = repoUrl.trim().replace(/\.git$/, '').match(/(?:github\.com|gitlab\.com|bitbucket\.org)\/([^/]+)\/([^/]+)/);
    if (!match) {
        res.status(400).json({ error: 'repoUrl must be a valid repository URL (https://github.com/owner/repo)' });
        return;
    }
    const [, owner, repo] = match;
    // Only GitHub is supported for the API calls — other hosts fall back to GitHub-compatible API
    const apiBase = `https://api.github.com/repos/${owner}/${repo}`;
    try {
        const repoScanStart = Date.now();
        // Base patterns from the request body (explicit caller-provided list).
        const bodyPatterns = Array.isArray(ignorePatterns) ? ignorePatterns.filter((p) => typeof p === 'string') : [];
        // Attempt to fetch .aiscanner from the repo root via the GitHub Contents API.
        // This mirrors the CLI behaviour where .aiscanner patterns are loaded from the
        // local filesystem. We fail silently so a missing file never blocks the scan.
        let dotAiScannerPatterns = [];
        try {
            const aiScannerUrl = `${apiBase}/contents/.aiscanner?ref=${encodeURIComponent(branch)}`;
            const rawContent = await githubGetText(aiScannerUrl);
            dotAiScannerPatterns = rawContent
                .split(/\r?\n/)
                .map((l) => l.trim())
                .filter((l) => l.length > 0 && !l.startsWith('#'));
            if (dotAiScannerPatterns.length > 0) {
                console.log(`[scan-repo] Loaded ${dotAiScannerPatterns.length} pattern(s) from ${owner}/${repo}/.aiscanner`);
            }
        }
        catch {
            // .aiscanner file not present or unreadable — ignore
        }
        const patterns = [...bodyPatterns, ...dotAiScannerPatterns];
        // ── Incremental mode: filter to changed files only ────────────────────────
        // When sinceCommit is provided, use the GitHub Compare API to get only files
        // changed between sinceCommit and the target branch. This dramatically reduces
        // scan time for large repos in CI pipelines.
        let changedFilePaths = null;
        if (sinceCommit && typeof sinceCommit === 'string' && sinceCommit.length >= 7) {
            try {
                const compareUrl = `${apiBase}/compare/${encodeURIComponent(sinceCommit)}...${encodeURIComponent(branch)}`;
                const compareData = await githubGet(compareUrl);
                if (compareData.files && Array.isArray(compareData.files)) {
                    changedFilePaths = new Set(compareData.files
                        .filter((f) => f.status !== 'removed')
                        .map((f) => f.filename));
                    console.log(`[scan-repo] Incremental mode: ${changedFilePaths.size} file(s) changed since ${sinceCommit.slice(0, 8)}`);
                }
            }
            catch (err) {
                const msg = err instanceof Error ? err.message : String(err);
                console.warn(`[scan-repo] Compare API failed (${msg}) — falling back to full scan`);
            }
        }
        const collected = [];
        await collectFiles(apiBase, '', branch, collected, 50, patterns);
        // Filter to changed files if incremental mode is active
        const filesToScan = changedFilePaths
            ? collected.filter((item) => changedFilePaths.has(item.path))
            : collected;
        if (filesToScan.length === 0) {
            res.json({
                findings: [],
                summary: (0, reporter_1.summarize)([]),
                filesScanned: 0,
                ...(changedFilePaths ? { incrementalMode: true, totalFiles: collected.length, changedFiles: changedFilePaths.size } : {}),
            });
            return;
        }
        const allFindings = [];
        await Promise.all(filesToScan.map(async (item) => {
            try {
                const code = await githubGetText(`${apiBase}/contents/${item.path}?ref=${encodeURIComponent(branch)}`);
                const ext = path_1.default.extname(item.name).toLowerCase();
                let findings;
                if (ext === '.py') {
                    const parsed = (0, python_parser_1.parsePythonCode)(code, item.path);
                    findings = (0, python_parser_1.scanPython)(parsed);
                }
                else if (ext === '.go') {
                    const parsed = (0, go_parser_1.parseGoCode)(code, item.path);
                    findings = (0, go_parser_1.scanGo)(parsed);
                }
                else if (ext === '.java') {
                    const parsed = (0, java_parser_1.parseJavaCode)(code, item.path);
                    findings = (0, java_parser_1.scanJava)(parsed);
                }
                else if (ext === '.cs') {
                    const parsed = (0, csharp_parser_1.parseCSharpCode)(code, item.path);
                    findings = (0, csharp_parser_1.scanCSharp)(parsed);
                }
                else if (['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp'].includes(ext)) {
                    const parsed = (0, c_parser_1.parseCCode)(code, item.path);
                    findings = (0, c_parser_1.scanC)(parsed);
                }
                else if (ext === '.rb') {
                    const parsed = (0, ruby_parser_1.parseRubyCode)(code, item.path);
                    findings = (0, ruby_parser_1.scanRuby)(parsed);
                }
                else if (ext === '.kt' || ext === '.kts') {
                    const parsed = (0, kotlin_parser_1.parseKotlinCode)(code, item.path);
                    findings = (0, kotlin_parser_1.scanKotlin)(parsed);
                }
                else if (ext === '.swift') {
                    const parsed = (0, swift_parser_1.parseSwiftCode)(code, item.path);
                    findings = (0, swift_parser_1.scanSwift)(parsed);
                }
                else if (ext === '.rs') {
                    const parsed = (0, rust_parser_1.parseRustCode)(code, item.path);
                    findings = (0, rust_parser_1.scanRust)(parsed);
                }
                else if (ext === '.php') {
                    const parsed = (0, php_parser_1.parsePHPCode)(code, item.path);
                    findings = (0, php_parser_1.scanPHP)(parsed);
                }
                else {
                    // JS/TS — use AST-based detectors
                    const parsed = (0, parser_1.parseCode)(code, item.path);
                    findings = [
                        ...(0, secrets_1.detectSecrets)(parsed),
                        ...(0, sql_1.detectSQLInjection)(parsed),
                        ...(0, shell_1.detectShellInjection)(parsed),
                        ...(0, eval_1.detectEval)(parsed),
                        ...(0, xss_1.detectXSS)(parsed),
                        ...(0, pathTraversal_1.detectPathTraversal)(parsed),
                        ...(0, prototypePollution_1.detectPrototypePollution)(parsed),
                        ...(0, insecureRandom_1.detectInsecureRandom)(parsed),
                        ...(0, openRedirect_1.detectOpenRedirect)(parsed),
                        ...(0, ssrf_1.detectSSRF)(parsed),
                        ...(0, jwt_1.detectJWTSecrets)(parsed),
                        ...(0, jwtNone_1.detectJWTNoneAlgorithm)(parsed),
                        ...(0, commandInjection_1.detectCommandInjection)(parsed),
                        ...(0, cors_2.detectCORSMisconfiguration)(parsed),
                        ...(0, redos_1.detectReDoS)(parsed),
                        ...(0, weakCrypto_1.detectWeakCrypto)(parsed),
                        ...(0, csrf_1.detectCSRF)(parsed),
                    ].map((f) => ({ ...f, file: item.path }));
                }
                allFindings.push(...findings);
            }
            catch {
                // Skip files that fail to parse
            }
        }));
        // Deduplicate by (type, file, line, column) across all scanned files — same
        // logic as the /scan endpoint — so parallel file scans don't produce duplicate
        // findings for the same location when detectors overlap.
        let dedupedFindings = (0, reporter_1.deduplicateFindings)(allFindings);
        // Optional ignoreTypes suppression — mirrors the CLI --ignore-type flag and
        // the /scan endpoint behaviour. Only accepts an array of strings.
        if (Array.isArray(ignoreTypes) && ignoreTypes.length > 0) {
            const typesToIgnore = new Set(ignoreTypes.filter((t) => typeof t === 'string').map((t) => t.trim().toUpperCase()));
            if (typesToIgnore.size > 0) {
                dedupedFindings = dedupedFindings.filter((f) => !typesToIgnore.has(f.type));
            }
        }
        const repoScanDurationMs = Date.now() - repoScanStart;
        const repoScanSummary = dedupedFindings.reduce((acc, f) => {
            acc[f.severity] = (acc[f.severity] ?? 0) + 1;
            return acc;
        }, {});
        logScan({
            event: 'scan_repo',
            repo: `${owner}/${repo}`,
            branch,
            files_scanned: collected.length,
            findings_total: dedupedFindings.length,
            findings_by_severity: repoScanSummary,
            duration_ms: repoScanDurationMs,
            sarif: sarifMode,
        });
        if (sarifMode) {
            res.setHeader('Content-Type', 'application/sarif+json');
            res.json((0, sarif_1.buildSARIF)(dedupedFindings));
            return;
        }
        const responsePayload = {
            findings: dedupedFindings,
            summary: (0, reporter_1.summarize)(dedupedFindings),
            filesScanned: filesToScan.length,
            ...(changedFilePaths ? { incrementalMode: true, totalFiles: collected.length, changedFiles: changedFilePaths.size } : {}),
        };
        res.json(responsePayload);
        // Fire-and-forget webhook delivery after responding to the client
        if (webhookUrl && typeof webhookUrl === 'string') {
            deliverWebhook(webhookUrl, { event: 'scan_repo_complete', repo: `${owner}/${repo}`, branch, ...responsePayload }, webhookSecret);
        }
    }
    catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`[scan-repo] error: ${msg}`);
        res.status(500).json({ error: `Failed to scan repository: ${msg}` });
    }
});
// ── POST /fix — dry-run fix preview ──────────────────────────────────────────
//
// Accepts: { code: string, filename: string, findings?: Finding[] }
// If findings are not provided, runs a scan first.
// Returns: { fixes: FixResult[], diff: string, applied: number }
exports.app.post('/fix', scanLimiter, async (req, res) => {
    // Content-Type validation: only accept application/json
    const fixContentType = req.headers['content-type'] ?? '';
    if (!fixContentType.includes('application/json')) {
        res.status(415).json({ error: 'Unsupported Media Type: Content-Type must be application/json' });
        return;
    }
    const body = req.body;
    const code = body['code'];
    const filename = body['filename'];
    if (typeof code !== 'string' || !code.trim()) {
        res.status(400).json({ error: '"code" must be a non-empty string' });
        return;
    }
    if (typeof filename !== 'string' || !filename.trim()) {
        res.status(400).json({ error: '"filename" must be a non-empty string' });
        return;
    }
    // Payload size guard: prevent DoS via large code strings
    if (typeof code === 'string' && code.length > 500000) {
        res.status(413).json({ error: 'Payload too large' });
        return;
    }
    // Write code to a temp file so applyFixes can read it
    const os = await import('os');
    const tmpDir = fs_1.default.mkdtempSync(path_1.default.join(os.tmpdir(), 'ai-sec-fix-'));
    try {
        const tmpFile = path_1.default.join(tmpDir, path_1.default.basename(filename));
        fs_1.default.writeFileSync(tmpFile, code, 'utf-8');
        // Get findings — either from body or by scanning
        let findings;
        if (Array.isArray(body['findings']) && body['findings'].length > 0) {
            // Use provided findings but remap file paths to tmpFile
            findings = body['findings'].map((f) => ({ ...f, file: tmpFile }));
        }
        else {
            // Run a fresh scan on the temp file
            const scanBody = { code, filename };
            // Inline scan logic (same as /scan but synchronous-ish)
            const tempReq = { body: scanBody };
            // Simplified: just run the same scan function used in /scan
            const scanFindings = await (async () => {
                const ext = path_1.default.extname(filename).toLowerCase();
                if (ext === '.py') {
                    const { parsePythonCode: p, scanPython: s } = await import('./scanner/python-parser.js');
                    return s(p(code, tmpFile));
                }
                else if (ext === '.java') {
                    const { parseJavaCode: p, scanJava: s } = await import('./scanner/java-parser.js');
                    return s(p(code, tmpFile));
                }
                else if (ext === '.cs') {
                    const { parseCSharpCode: p, scanCSharp: s } = await import('./scanner/csharp-parser.js');
                    return s(p(code, tmpFile));
                }
                else if (ext === '.go') {
                    const { parseGoCode: p, scanGo: s } = await import('./scanner/go-parser.js');
                    return s(p(code, tmpFile));
                }
                else if (ext === '.rb') {
                    const { parseRubyCode: p, scanRuby: s } = await import('./scanner/ruby-parser.js');
                    return s(p(code, tmpFile));
                }
                else if (ext === '.kt' || ext === '.kts') {
                    const { parseKotlinCode: p, scanKotlin: s } = await import('./scanner/kotlin-parser.js');
                    return s(p(code, tmpFile));
                }
                else if (ext === '.swift') {
                    const { parseSwiftCode: p, scanSwift: s } = await import('./scanner/swift-parser.js');
                    return s(p(code, tmpFile));
                }
                else if (ext === '.rs') {
                    const { parseRustCode: p, scanRust: s } = await import('./scanner/rust-parser.js');
                    return s(p(code, tmpFile));
                }
                return [];
            })();
            findings = scanFindings;
        }
        // Apply fixes in dry-run mode
        const fixResults = (0, fixer_js_1.applyFixes)(findings, /* dryRun */ true);
        const applied = fixResults.filter((r) => r.applied).length;
        // Build diff
        const diffLines = [];
        const codeLines = code.split('\n');
        for (const r of fixResults) {
            if (!r.applied || r.originalLine === undefined || r.fixedLine === undefined)
                continue;
            const lineIdx = r.finding.line - 1;
            const ctxStart = Math.max(0, lineIdx - 2);
            const ctxEnd = Math.min(codeLines.length - 1, lineIdx + 2);
            diffLines.push(`@@ -${ctxStart + 1},${ctxEnd - ctxStart + 1} +${ctxStart + 1},${ctxEnd - ctxStart + 1} @@ [${r.finding.type}]`);
            for (let i = ctxStart; i <= ctxEnd; i++) {
                if (i === lineIdx) {
                    diffLines.push(`-${r.originalLine}`);
                    diffLines.push(`+${r.fixedLine}`);
                }
                else {
                    diffLines.push(` ${codeLines[i] ?? ''}`);
                }
            }
        }
        res.json({
            fixes: fixResults.map((r) => ({
                type: r.finding.type,
                severity: r.finding.severity,
                line: r.finding.line,
                applied: r.applied,
                description: r.description,
                originalLine: r.originalLine,
                fixedLine: r.fixedLine,
            })),
            diff: diffLines.join('\n'),
            applied,
            total: fixResults.length,
        });
    }
    catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        res.status(500).json({ error: `Fix preview failed: ${msg}` });
    }
    finally {
        // Guaranteed cleanup of temp directory on all code paths
        try {
            fs_1.default.rmSync(tmpDir, { recursive: true, force: true });
        }
        catch {
            /* ignore cleanup errors */
        }
    }
});
// ── SSE /watch endpoint — streams scan results as files change ───────────────
exports.app.get('/watch', (req, res) => {
    const targetPath = req.query['path'] ?? process.cwd();
    const resolvedPath = path_1.default.resolve(targetPath);
    if (!fs_1.default.existsSync(resolvedPath) || !fs_1.default.statSync(resolvedPath).isDirectory()) {
        res.status(400).json({ error: `path must be an existing directory: ${resolvedPath}` });
        return;
    }
    // SSE headers
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();
    // Send initial connected event
    res.write(`event: connected\ndata: ${JSON.stringify({ path: resolvedPath, ts: new Date().toISOString() })}\n\n`);
    const JS_TS_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs']);
    const ALL_EXTENSIONS = new Set([...JS_TS_EXTENSIONS, '.py', '.go', '.java', '.cs', '.c', '.cpp', '.cc', '.h', '.rb', '.kt', '.kts', '.swift', '.rs', '.php']);
    let debounceTimer = null;
    const pendingFiles = new Set();
    function scanFile(filePath) {
        try {
            const code = fs_1.default.readFileSync(filePath, 'utf-8');
            // Check cache first — return cached findings if file content hasn't changed
            const cached = (0, scan_cache_1.getCachedFindings)(filePath, code);
            if (cached !== null)
                return cached;
            const ext = path_1.default.extname(filePath).toLowerCase();
            let findings;
            if (ext === '.py') {
                const parsed = (0, python_parser_1.parsePythonCode)(code, filePath);
                findings = (0, python_parser_1.scanPython)(parsed);
            }
            else if (ext === '.go') {
                const parsed = (0, go_parser_1.parseGoCode)(code, filePath);
                findings = (0, go_parser_1.scanGo)(parsed);
            }
            else if (ext === '.java') {
                const parsed = (0, java_parser_1.parseJavaCode)(code, filePath);
                findings = (0, java_parser_1.scanJava)(parsed);
            }
            else if (ext === '.cs') {
                const parsed = (0, csharp_parser_1.parseCSharpCode)(code, filePath);
                findings = (0, csharp_parser_1.scanCSharp)(parsed);
            }
            else if (['.c', '.cpp', '.cc', '.h'].includes(ext)) {
                const parsed = (0, c_parser_1.parseCCode)(code, filePath);
                findings = (0, c_parser_1.scanC)(parsed);
            }
            else if (ext === '.rb') {
                const parsed = (0, ruby_parser_1.parseRubyCode)(code, filePath);
                findings = (0, ruby_parser_1.scanRuby)(parsed);
            }
            else if (ext === '.kt' || ext === '.kts') {
                const parsed = (0, kotlin_parser_1.parseKotlinCode)(code, filePath);
                findings = (0, kotlin_parser_1.scanKotlin)(parsed);
            }
            else if (ext === '.swift') {
                const parsed = (0, swift_parser_1.parseSwiftCode)(code, filePath);
                findings = (0, swift_parser_1.scanSwift)(parsed);
            }
            else if (ext === '.rs') {
                const parsed = (0, rust_parser_1.parseRustCode)(code, filePath);
                findings = (0, rust_parser_1.scanRust)(parsed);
            }
            else if (ext === '.php') {
                const parsed = (0, php_parser_1.parsePHPCode)(code, filePath);
                findings = (0, php_parser_1.scanPHP)(parsed);
            }
            else if (JS_TS_EXTENSIONS.has(ext)) {
                const parsed = (0, parser_1.parseCode)(code, filePath);
                findings = [
                    ...(0, secrets_1.detectSecrets)(parsed),
                    ...(0, sql_1.detectSQLInjection)(parsed),
                    ...(0, shell_1.detectShellInjection)(parsed),
                    ...(0, eval_1.detectEval)(parsed),
                    ...(0, xss_1.detectXSS)(parsed),
                    ...(0, pathTraversal_1.detectPathTraversal)(parsed),
                    ...(0, prototypePollution_1.detectPrototypePollution)(parsed),
                    ...(0, insecureRandom_1.detectInsecureRandom)(parsed),
                    ...(0, openRedirect_1.detectOpenRedirect)(parsed),
                    ...(0, ssrf_1.detectSSRF)(parsed),
                    ...(0, jwt_1.detectJWTSecrets)(parsed),
                    ...(0, jwtNone_1.detectJWTNoneAlgorithm)(parsed),
                    ...(0, commandInjection_1.detectCommandInjection)(parsed),
                    ...(0, cors_2.detectCORSMisconfiguration)(parsed),
                    ...(0, redos_1.detectReDoS)(parsed),
                    ...(0, weakCrypto_1.detectWeakCrypto)(parsed),
                    ...(0, csrf_1.detectCSRF)(parsed),
                ].map((f) => ({ ...f, file: filePath }));
            }
            else {
                findings = [];
            }
            // Cache the scan results for this file content
            (0, scan_cache_1.setCachedFindings)(filePath, code, findings);
            return findings;
        }
        catch {
            return [];
        }
    }
    function processPendingFiles() {
        const files = [...pendingFiles];
        pendingFiles.clear();
        const allFindings = [];
        for (const file of files) {
            if (fs_1.default.existsSync(file)) {
                allFindings.push(...scanFile(file));
            }
        }
        const deduped = (0, reporter_1.deduplicateFindings)(allFindings);
        const payload = {
            files,
            findings: deduped,
            summary: (0, reporter_1.summarize)(deduped),
            ts: new Date().toISOString(),
        };
        res.write(`event: scan\ndata: ${JSON.stringify(payload)}\n\n`);
    }
    let watcher;
    try {
        watcher = fs_1.default.watch(resolvedPath, { recursive: true }, (_event, filename) => {
            if (!filename)
                return;
            const full = path_1.default.isAbsolute(filename) ? filename : path_1.default.join(resolvedPath, filename);
            const ext = path_1.default.extname(full).toLowerCase();
            if (!ALL_EXTENSIONS.has(ext))
                return;
            if (full.includes('node_modules') || full.includes('.git'))
                return;
            pendingFiles.add(full);
            if (debounceTimer)
                clearTimeout(debounceTimer);
            debounceTimer = setTimeout(processPendingFiles, 300);
        });
    }
    catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        res.write(`event: error\ndata: ${JSON.stringify({ error: msg })}\n\n`);
        res.end();
        return;
    }
    req.on('close', () => {
        if (debounceTimer)
            clearTimeout(debounceTimer);
        watcher.close();
    });
});
// In test mode, do not auto-start: let supertest or the test create its own server.
exports.server = process.env.NODE_ENV === 'test'
    ? null
    : exports.app.listen(PORT, () => {
        console.log(`AI Security Scanner server running on http://localhost:${PORT}`);
    });
// Graceful shutdown: drain connections before process exit so tests close
// cleanly and production process managers can do zero-downtime restarts.
function gracefulShutdown(signal) {
    console.log(`[server] ${signal} received — closing HTTP server...`);
    clearInterval(cacheFlushTimer);
    (0, scan_cache_1.persistCache)();
    if (exports.server) {
        exports.server.close(() => {
            console.log('[server] HTTP server closed. Exiting.');
            process.exit(0);
        });
    }
    else {
        console.log('[server] No active HTTP server (test mode). Exiting.');
        process.exit(0);
    }
}
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
//# sourceMappingURL=server.js.map