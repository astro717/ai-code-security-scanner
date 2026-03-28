import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import fs from 'fs';
import http from 'http';
import https from 'https';
import path from 'path';
import rateLimit from 'express-rate-limit';
import { minimatch } from 'minimatch';
import { parseCode } from './scanner/parser';
import { detectSecrets } from './scanner/detectors/secrets';
import { detectSQLInjection } from './scanner/detectors/sql';
import { detectShellInjection } from './scanner/detectors/shell';
import { detectEval } from './scanner/detectors/eval';
import { detectXSS } from './scanner/detectors/xss';
import { detectPathTraversal } from './scanner/detectors/pathTraversal';
import { detectPrototypePollution } from './scanner/detectors/prototypePollution';
import { detectInsecureRandom } from './scanner/detectors/insecureRandom';
import { detectOpenRedirect } from './scanner/detectors/openRedirect';
import { detectSSRF } from './scanner/detectors/ssrf';
import { detectJWTSecrets } from './scanner/detectors/jwt';
import { detectCommandInjection } from './scanner/detectors/commandInjection';
import { detectCORSMisconfiguration } from './scanner/detectors/cors';
import { detectReDoS } from './scanner/detectors/redos';
import { detectWeakCrypto } from './scanner/detectors/weakCrypto';
import { detectJWTNoneAlgorithm } from './scanner/detectors/jwtNone';
import { summarize, Finding, deduplicateFindings, KNOWN_TYPES } from './scanner/reporter';
import { FINDING_TO_OWASP } from './scanner/owasp';
import { buildSARIF } from './scanner/sarif';
import { detectUnsafeDepsFromJson } from './scanner/detectors/deps';
import { parsePythonCode, scanPython } from './scanner/python-parser';
import { parseGoCode, scanGo } from './scanner/go-parser';
import { parseJavaCode, scanJava } from './scanner/java-parser';
import { parseCSharpCode, scanCSharp } from './scanner/csharp-parser';
import { parseCCode, scanC } from './scanner/c-parser';
import { parseRubyCode, scanRuby } from './scanner/ruby-parser';
import { parseKotlinCode, scanKotlin } from './scanner/kotlin-parser';

// ── Request body schema validation ───────────────────────────────────────────

interface FieldSchema {
  type: 'string' | 'boolean' | 'array' | 'object';
  required?: boolean;
  items?: 'string';
}

function validateRequestBody(
  body: unknown,
  schema: Record<string, FieldSchema>,
  endpointName: string,
): { valid: true } | { valid: false; errors: string[] } {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    return { valid: false, errors: [`${endpointName} request body must be a JSON object`] };
  }

  const record = body as Record<string, unknown>;
  const errors: string[] = [];

  for (const [key, rule] of Object.entries(schema)) {
    const val = record[key];

    // Check required fields for presence
    if (rule.required && (val === undefined || val === null)) {
      errors.push(`Missing required field: ${key} (${rule.type})`);
      continue;
    }

    // Skip type check if the field is absent and optional
    if (val === undefined || val === null) continue;

    // Type validation for all present fields (required and optional)
    if (rule.type === 'string' && typeof val !== 'string') {
      errors.push(`${key} must be a string`);
    } else if (rule.type === 'boolean' && typeof val !== 'boolean') {
      errors.push(`${key} must be a boolean`);
    } else if (rule.type === 'array') {
      if (!Array.isArray(val)) {
        errors.push(`${key} must be an array`);
      }
      // Note: mixed-type arrays are tolerated — non-string items are filtered downstream
    } else if (rule.type === 'object' && (typeof val !== 'object' || Array.isArray(val))) {
      errors.push(`${key} must be an object`);
    }
  }

  return errors.length > 0 ? { valid: false, errors } : { valid: true };
}

const SCAN_BODY_SCHEMA: Record<string, FieldSchema> = {
  code:          { type: 'string', required: true },
  filename:      { type: 'string' },
  packageJson:   { type: 'string' },
  aiExplain:     { type: 'boolean' },
  ignoreTypes:   { type: 'array', items: 'string' },
  webhookUrl:    { type: 'string' },
  webhookSecret: { type: 'string' },
};

const SCAN_REPO_BODY_SCHEMA: Record<string, FieldSchema> = {
  repoUrl:        { type: 'string', required: true },
  branch:         { type: 'string' },
  ignorePatterns: { type: 'array', items: 'string' },
  ignoreTypes:    { type: 'array', items: 'string' },
  webhookUrl:     { type: 'string' },
  webhookSecret:  { type: 'string' },
};

// ── AI explain — multi-provider LLM backend ───────────────────────────────────
//
// Supports two remote LLM backends:
//   • Anthropic (default) — set ANTHROPIC_API_KEY; optionally override model via
//     AI_EXPLAIN_MODEL (default: claude-haiku-4-5-20251001)
//   • OpenAI — set OPENAI_API_KEY; optionally override model via AI_EXPLAIN_MODEL
//     (default: gpt-4o-mini) and endpoint via AI_EXPLAIN_ENDPOINT
//     (default: https://api.openai.com/v1/chat/completions)
//
// Provider selection: if AI_EXPLAIN_PROVIDER=openai (or the per-request
// X-AI-Provider header is "openai"), the OpenAI path is used. Otherwise
// Anthropic is the default. The per-request auth key header (X-Anthropic-Key
// for Anthropic, X-OpenAI-Key for OpenAI) always takes precedence over the
// corresponding environment variable.

interface FindingWithAI extends Finding {
  explanation?: string;
  fixSuggestion?: string;
}

// LLM calls can be slow — 30 s gives ample time for a response while bounding
// the maximum time a single /scan?aiExplain=true request can block the server.
const AI_REQUEST_TIMEOUT_MS = 30_000;

/** @deprecated use AI_REQUEST_TIMEOUT_MS */
const ANTHROPIC_REQUEST_TIMEOUT_MS = AI_REQUEST_TIMEOUT_MS;

/**
 * Makes a request to the Anthropic Messages API.
 * @param body      - JSON request body
 * @param apiKey    - Anthropic API key to use; falls back to ANTHROPIC_API_KEY env var
 */
async function anthropicRequest(body: object, apiKey?: string): Promise<unknown> {
  const effectiveKey = apiKey ?? process.env.ANTHROPIC_API_KEY ?? '';
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = https.request({
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
        try { resolve(JSON.parse(data)); }
        catch { reject(new Error('Invalid JSON from Anthropic')); }
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
async function openaiRequest(
  prompt: string,
  apiKey?: string,
  model?: string,
  endpoint?: string,
): Promise<unknown> {
  const effectiveKey = apiKey ?? process.env.OPENAI_API_KEY ?? '';
  const effectiveModel = model ?? process.env.AI_EXPLAIN_MODEL ?? 'gpt-4o-mini';
  const effectiveEndpoint = endpoint ?? process.env.AI_EXPLAIN_ENDPOINT ?? 'https://api.openai.com/v1/chat/completions';

  const parsed = new URL(effectiveEndpoint);
  const isHttps = parsed.protocol === 'https:';
  const transport = isHttps ? https : http;

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
        try { resolve(JSON.parse(data)); }
        catch { reject(new Error('Invalid JSON from OpenAI-compatible endpoint')); }
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

type AiProvider = 'anthropic' | 'openai';

/**
 * Resolves the active AI provider. Priority:
 *   1. per-request provider parameter (from X-AI-Provider header)
 *   2. AI_EXPLAIN_PROVIDER environment variable
 *   3. 'anthropic' default
 */
function resolveAiProvider(requestProvider?: string): AiProvider {
  const raw = (requestProvider ?? process.env.AI_EXPLAIN_PROVIDER ?? 'anthropic').toLowerCase();
  return raw === 'openai' ? 'openai' : 'anthropic';
}

const EXPLAIN_PROMPT_TEMPLATE = (finding: Finding): string =>
  `You are a security expert. Analyze this vulnerability finding and respond with ONLY a JSON object (no markdown, no extra text):

Vulnerability type: ${finding.type}
Severity: ${finding.severity}
Code snippet: ${finding.snippet ?? '(not available)'}
Message: ${finding.message}

Respond with exactly this JSON structure:
{"explanation": "2-sentence explanation of why this is dangerous and what could be exploited", "fixSuggestion": "the corrected code snippet, just the code, no explanation"}`;

async function explainFinding(
  finding: Finding,
  apiKey?: string,
  provider?: AiProvider,
  openaiEndpoint?: string,
): Promise<{ explanation: string; fixSuggestion: string }> {
  const activeProvider = provider ?? resolveAiProvider();

  if (activeProvider === 'openai') {
    const effectiveModel = process.env.AI_EXPLAIN_MODEL ?? 'gpt-4o-mini';
    const response = await openaiRequest(
      EXPLAIN_PROMPT_TEMPLATE(finding),
      apiKey,
      effectiveModel,
      openaiEndpoint,
    ) as { choices?: Array<{ message?: { content?: string } }> };

    const text = response.choices?.[0]?.message?.content ?? '';
    try {
      const parsed = JSON.parse(text) as { explanation?: string; fixSuggestion?: string };
      return {
        explanation: parsed.explanation ?? '',
        fixSuggestion: parsed.fixSuggestion ?? '',
      };
    } catch {
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
  }, apiKey) as { content?: Array<{ text?: string }> };

  const text = response.content?.[0]?.text ?? '';
  try {
    const parsed = JSON.parse(text) as { explanation?: string; fixSuggestion?: string };
    return {
      explanation: parsed.explanation ?? '',
      fixSuggestion: parsed.fixSuggestion ?? '',
    };
  } catch {
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
async function enrichWithAI(
  findings: Finding[],
  apiKey?: string,
  provider?: AiProvider,
  openaiEndpoint?: string,
): Promise<FindingWithAI[]> {
  const activeProvider = provider ?? resolveAiProvider();

  // Resolve effective key depending on provider
  const effectiveKey = apiKey ?? (
    activeProvider === 'openai'
      ? process.env.OPENAI_API_KEY
      : process.env.ANTHROPIC_API_KEY
  );

  if (!effectiveKey) {
    const envVar = activeProvider === 'openai' ? 'OPENAI_API_KEY' : 'ANTHROPIC_API_KEY';
    console.warn(`[ai-explain] ${envVar} not set — skipping AI enrichment`);
    return findings;
  }

  // Process up to 5 findings (highest severity first)
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  const toEnrich = [...findings]
    .sort((a, b) => (severityOrder[a.severity] ?? 3) - (severityOrder[b.severity] ?? 3))
    .slice(0, 5);

  const enriched = new Map<Finding, FindingWithAI>();
  await Promise.all(
    toEnrich.map(async (f) => {
      try {
        const ai = await explainFinding(f, effectiveKey, activeProvider, openaiEndpoint);
        enriched.set(f, { ...f, ...ai });
      } catch (err) {
        console.error(`[ai-explain] failed for ${f.type}:`, err);
        enriched.set(f, f);
      }
    }),
  );

  return findings.map((f) => enriched.get(f) ?? f);
}

// ── Structured logging ───────────────────────────────────────────────────────

/**
 * Emits a single structured JSON log line to stdout.
 * Using JSON ensures log aggregators (Datadog, CloudWatch, etc.) can parse
 * all fields without regex extraction.
 */
function logScan(fields: Record<string, unknown>): void {
  console.log(JSON.stringify({ ...fields, ts: new Date().toISOString() }));
}

// ── Webhook delivery ──────────────────────────────────────────────────────────

const WEBHOOK_TIMEOUT_MS = 10_000;
const WEBHOOK_MAX_RETRIES = 3;
const WEBHOOK_BACKOFF_BASE_MS = 1_000;

/**
 * Send a single webhook HTTP request. Resolves with the status code on success,
 * rejects on network error or timeout.
 */
function sendWebhookRequest(
  webhookUrl: string,
  body: string,
  headers: Record<string, string>,
): Promise<number> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(webhookUrl);
    const transport = parsed.protocol === 'https:' ? https : http;

    const req = transport.request(
      {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: 'POST',
        headers,
      },
      (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      },
    );
    req.setTimeout(WEBHOOK_TIMEOUT_MS, () => {
      req.destroy(new Error(`Webhook timed out after ${WEBHOOK_TIMEOUT_MS}ms`));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Fire-and-forget POST of scan results to a webhook URL.
 * Retries up to 3 times with exponential backoff (1s, 2s, 4s) on non-2xx
 * responses or network errors.
 * If `webhookSecret` is provided, an HMAC-SHA256 signature is sent in
 * the `X-Scanner-Signature` header so the receiver can verify authenticity.
 */
function deliverWebhook(
  webhookUrl: string,
  payload: unknown,
  webhookSecret?: string,
): void {
  const body = JSON.stringify(payload);

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'Content-Length': String(Buffer.byteLength(body)),
    'User-Agent': 'ai-code-security-scanner/0.1',
  };

  if (webhookSecret) {
    const signature = crypto
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
        } else {
          console.error(`[webhook] POST ${webhookUrl} failed after ${WEBHOOK_MAX_RETRIES + 1} attempts (last status: ${statusCode})`);
        }
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        if (attempt < WEBHOOK_MAX_RETRIES) {
          const delayMs = WEBHOOK_BACKOFF_BASE_MS * Math.pow(2, attempt);
          console.log(`[webhook] error: ${message}, retrying in ${delayMs}ms…`);
          await sleep(delayMs);
        } else {
          console.error(`[webhook] POST ${webhookUrl} failed after ${WEBHOOK_MAX_RETRIES + 1} attempts: ${message}`);
        }
      }
    }
  })();
}

const app = express();
const PORT = process.env.PORT ?? 3001;

app.use(cors());

// Limit request body to 500 KB. Express will automatically respond with 413
// for bodies larger than this limit — but we also enforce it explicitly inside
// route handlers so the error message is consistent and human-readable.
const PAYLOAD_LIMIT = '500kb';
const PAYLOAD_LIMIT_BYTES = 500 * 1024;

app.use(express.json({ limit: PAYLOAD_LIMIT }));

// ── API key auth ──────────────────────────────────────────────────────────────
// Protect all non-health endpoints with a Bearer token check.
// Set SERVER_API_KEY in the environment to enable; if unset, the server starts
// but logs a warning and all requests are allowed (dev-friendly default).

const SERVER_API_KEY = process.env.SERVER_API_KEY;

if (!SERVER_API_KEY) {
  console.warn(
    '[auth] WARNING: SERVER_API_KEY is not set. ' +
    'All endpoints are publicly accessible — set this variable in production.',
  );
} else if (SERVER_API_KEY.length < 32) {
  console.warn(
    '[auth] WARNING: SERVER_API_KEY is shorter than 32 characters. ' +
    'Use a long random value to prevent token guessing.',
  );
}

app.use((req, res, next) => {
  // /health is always open so uptime monitors and Docker HEALTHCHECK work
  if (req.path === '/health') return next();

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

const INTERNAL_API_TOKEN = process.env.INTERNAL_API_TOKEN;

if (INTERNAL_API_TOKEN && INTERNAL_API_TOKEN.length < 32) {
  console.warn(
    '[auth] WARNING: INTERNAL_API_TOKEN is shorter than 32 characters. ' +
    'Use a long random value to prevent token guessing.',
  );
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

function skipIfInternalToken(req: import('express').Request): boolean {
  if (!INTERNAL_API_TOKEN) return false;
  const presented = req.headers['x-internal-token'];
  return typeof presented === 'string' && presented === INTERNAL_API_TOKEN;
}

const scanLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: IS_TEST ? 10_000 : 20,
  standardHeaders: true,
  legacyHeaders: true,
  skip: skipIfInternalToken,
  message: { error: 'Too many scan requests from this IP. Limit: 20 requests per minute.' },
});

const scanRepoLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: IS_TEST ? 10_000 : 5,
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
export async function resetRateLimiters(): Promise<void> {
  if (process.env.NODE_ENV !== 'test') {
    throw new Error(
      'resetRateLimiters() is only available in test mode (NODE_ENV=test). ' +
      'Calling this in production would disable rate limiting for all clients.',
    );
  }
  await Promise.all([
    scanLimiter.resetKey('127.0.0.1'),
    scanRepoLimiter.resetKey('127.0.0.1'),
  ]);
}

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', version: '0.1.0' });
});

app.get('/types', (_req, res) => {
  res.json({ types: [...KNOWN_TYPES], owasp: FINDING_TO_OWASP });
});

app.post('/scan', scanLimiter, async (req, res): Promise<void> => {
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

  const requestAiProvider = resolveAiProvider(
    (() => { const h = req.headers['x-ai-provider']; return typeof h === 'string' ? h : undefined; })(),
  );

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
    if (typeof h !== 'string' || h.length === 0) return undefined;
    // Basic format validation: Anthropic keys start with "sk-ant-" and are
    // at least 20 characters. Reject obviously malformed keys early so the
    // caller gets a clear 400 instead of an opaque 401 from the upstream API.
    if (!/^sk-ant-.{13,}$/.test(h)) {
      res.status(400).json({
        error:
          'Invalid X-Anthropic-Key header. Anthropic API keys start with "sk-ant-" and ' +
          'are at least 20 characters long. Check your key and try again.',
      });
      return null; // sentinel: response already sent
    }
    return h;
  })();

  // If requestAnthropicKey is null, the response was already sent (invalid key).
  if (requestAnthropicKey === null) return;

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

  const { code, filename: rawFilename, packageJson, aiExplain, ignoreTypes, webhookUrl, webhookSecret } = req.body as {
    code?: string;
    filename?: string;
    packageJson?: string;
    aiExplain?: boolean;
    ignoreTypes?: string[];
    webhookUrl?: string;
    webhookSecret?: string;
  };

  if (!code || typeof code !== 'string') {
    res.status(400).json({ error: 'Missing required field: code (string)' });
    return;
  }

  // Sanitize filename: strip path components and reject null bytes / traversal sequences
  // before the value is used for display, parsing, or logging.
  let filename: string | undefined;
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
    filename = path.basename(rawFilename);
  }

  // Validate ignoreTypes — reject unknown type strings so callers learn about
  // typos early instead of silently getting unfiltered results.
  if (Array.isArray(ignoreTypes) && ignoreTypes.length > 0) {
    const stringTypes = ignoreTypes.filter((t) => typeof t === 'string').map((t) => t.trim().toUpperCase());
    const unknown = stringTypes.filter((t) => !KNOWN_TYPES.has(t));
    if (unknown.length > 0) {
      res.status(400).json({
        error: `Unknown ignoreTypes: ${unknown.join(', ')}. Valid types: ${[...KNOWN_TYPES].sort().join(', ')}`,
      });
      return;
    }
  }

  const effectiveFilename = filename ?? 'input.tsx';
  const ext = path.extname(effectiveFilename).toLowerCase();

  let findings: FindingWithAI[];

  if (ext === '.java') {
    // Java files use the dedicated regex-based Java scanner
    const javaResult = parseJavaCode(code, effectiveFilename);
    findings = scanJava(javaResult).map((f) => ({ ...f, file: filename ?? 'input' }));
  } else if (ext === '.py') {
    // Python files use the dedicated regex-based Python scanner
    const pyResult = parsePythonCode(code, effectiveFilename);
    findings = scanPython(pyResult).map((f) => ({ ...f, file: filename ?? 'input' }));
  } else if (ext === '.go') {
    // Go files use the dedicated regex-based Go scanner
    const goResult = parseGoCode(code, effectiveFilename);
    findings = scanGo(goResult).map((f) => ({ ...f, file: filename ?? 'input' }));
  } else if (ext === '.cs') {
    // C# files use the dedicated regex-based C# scanner
    const csResult = parseCSharpCode(code, effectiveFilename);
    findings = scanCSharp(csResult).map((f) => ({ ...f, file: filename ?? 'input' }));
  } else if (['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp'].includes(ext)) {
    // C/C++ files use the dedicated regex-based C scanner
    const cResult = parseCCode(code, effectiveFilename);
    findings = scanC(cResult).map((f) => ({ ...f, file: filename ?? 'input' }));
  } else if (ext === '.rb') {
    // Ruby files use the dedicated regex-based Ruby scanner
    const rbResult = parseRubyCode(code, effectiveFilename);
    findings = scanRuby(rbResult).map((f) => ({ ...f, file: filename ?? 'input' }));
  } else {
    // JS/TS files use the AST-based parser and detector suite
    let parsed;
    try {
      parsed = parseCode(code, effectiveFilename);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(400).json({ error: `Parse error: ${msg}` });
      return;
    }

    findings = [
      ...detectSecrets(parsed),
      ...detectSQLInjection(parsed),
      ...detectShellInjection(parsed),
      ...detectEval(parsed),
      ...detectXSS(parsed),
      ...detectPathTraversal(parsed),
      ...detectPrototypePollution(parsed),
      ...detectInsecureRandom(parsed),
      ...detectOpenRedirect(parsed),
      ...detectSSRF(parsed),
      ...detectJWTSecrets(parsed),
      ...detectJWTNoneAlgorithm(parsed),
      ...detectCommandInjection(parsed),
      ...detectCORSMisconfiguration(parsed),
      ...detectReDoS(parsed),
      ...detectWeakCrypto(parsed),
    ].map((f) => ({ ...f, file: filename ?? 'input' }));
  }

  // Scan package.json for unsafe deps if provided
  if (packageJson && typeof packageJson === 'string') {
    const depsFindings = detectUnsafeDepsFromJson(packageJson);
    findings.push(...depsFindings);
  }

  // Deduplicate by (type, file, line, column) before reporting.
  findings = deduplicateFindings(findings) as FindingWithAI[];

  // Optional ignoreTypes suppression — mirrors the CLI --ignore-type flag.
  // Only accepts an array of strings; malformed values are silently ignored so
  // the endpoint degrades gracefully for clients that send unexpected shapes.
  if (Array.isArray(ignoreTypes) && ignoreTypes.length > 0) {
    const typesToIgnore = new Set(
      ignoreTypes.filter((t) => typeof t === 'string').map((t) => t.trim().toUpperCase()),
    );
    if (typesToIgnore.size > 0) {
      findings = findings.filter((f) => !typesToIgnore.has(f.type));
    }
  }

  // AI explain enrichment — supports Anthropic (default) and OpenAI backends.
  // Provider resolved from X-AI-Provider header → AI_EXPLAIN_PROVIDER env var → 'anthropic'.
  // API key resolved from X-Anthropic-Key / X-OpenAI-Key headers → env vars.
  if (aiExplain && findings.length > 0) {
    findings = await enrichWithAI(
      findings,
      resolvedApiKey,
      requestAiProvider,
      requestOpenAiEndpoint,
    );
  }

  const scanSummary = findings.reduce<Record<string, number>>((acc, f) => {
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
    res.json(buildSARIF(findings));
    return;
  }

  const responsePayload = { findings, summary: summarize(findings) };
  res.json(responsePayload);

  // Fire-and-forget webhook delivery after responding to the client
  if (webhookUrl && typeof webhookUrl === 'string') {
    deliverWebhook(
      webhookUrl,
      { event: 'scan_complete', file: filename ?? 'input', ...responsePayload },
      webhookSecret,
    );
  }
});

// Helper: fetch JSON from GitHub Contents API
const GITHUB_REQUEST_TIMEOUT_MS = 15000;

function githubGet(url: string): Promise<unknown> {
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
    const req = https.get(reqOpts, (res) => {
      let body = '';
      res.on('data', (chunk) => body += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(body)); }
        catch { reject(new Error('Invalid JSON from GitHub')); }
      });
    });
    req.setTimeout(GITHUB_REQUEST_TIMEOUT_MS, () => {
      req.destroy(new Error(`GitHub API request timed out after ${GITHUB_REQUEST_TIMEOUT_MS}ms`));
    });
    req.on('error', reject);
  });
}

function githubGetText(url: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const opts = new URL(url);
    const req = https.get({
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

interface GHItem { type: string; name: string; path: string; size: number; download_url: string | null; url: string }

function isIgnoredByPatterns(filePath: string, ignorePatterns: string[]): boolean {
  if (ignorePatterns.length === 0) return false;
  const normalised = filePath.replace(/\\/g, '/');
  return ignorePatterns.some((pattern) =>
    minimatch(normalised, pattern, { matchBase: true, dot: true }),
  );
}

async function collectFiles(
  apiBase: string,
  dirPath: string,
  branch: string,
  collected: GHItem[],
  max: number,
  ignorePatterns: string[] = [],
): Promise<void> {
  if (collected.length >= max) return;
  const url = `${apiBase}/contents/${dirPath}?ref=${encodeURIComponent(branch)}`;
  const items = await githubGet(url) as GHItem[];
  if (!Array.isArray(items)) return;
  for (const item of items) {
    if (collected.length >= max) break;
    if (isIgnoredByPatterns(item.path, ignorePatterns)) continue;
    if (item.type === 'file') {
      const ext = item.name.split('.').pop() ?? '';
      if (['ts', 'tsx', 'js', 'jsx', 'py', 'go', 'java', 'cs', 'c', 'cpp', 'cc', 'cxx', 'h', 'hpp', 'rb'].includes(ext) && item.size <= 200 * 1024) {
        collected.push(item);
      }
    } else if (item.type === 'dir') {
      await collectFiles(apiBase, item.path, branch, collected, max, ignorePatterns);
    }
  }
}

app.post('/scan-repo', scanRepoLimiter, async (req, res) => {
  // ?sarif=true or body.sarif === true returns a SARIF 2.1.0 document instead of the default JSON shape.
  // This enables GitHub Code Scanning integration for repository scans.
  const body = req.body as Record<string, unknown>;
  const sarifMode = req.query['sarif'] === 'true' || body['sarif'] === true;

  // Schema validation — reject malformed requests early with detailed errors.
  const repoValidation = validateRequestBody(req.body, SCAN_REPO_BODY_SCHEMA, '/scan-repo');
  if (!repoValidation.valid) {
    res.status(400).json({ error: repoValidation.errors.join('; ') });
    return;
  }

  const { repoUrl, branch = 'main', ignorePatterns = [], ignoreTypes, webhookUrl, webhookSecret } = req.body as {
    repoUrl?: string;
    branch?: string;
    ignorePatterns?: string[];
    ignoreTypes?: string[];
    webhookUrl?: string;
    webhookSecret?: string;
  };

  if (!repoUrl || typeof repoUrl !== 'string') {
    res.status(400).json({ error: 'Missing required field: repoUrl (string)' });
    return;
  }

  // Parse GitHub URL: https://github.com/owner/repo
  const match = repoUrl.trim().replace(/\.git$/, '').match(/github\.com\/([^/]+)\/([^/]+)/);
  if (!match) {
    res.status(400).json({ error: 'repoUrl must be a valid GitHub repository URL (https://github.com/owner/repo)' });
    return;
  }

  const [, owner, repo] = match;
  const apiBase = `https://api.github.com/repos/${owner}/${repo}`;

  try {
    const repoScanStart = Date.now();

    // Base patterns from the request body (explicit caller-provided list).
    const bodyPatterns = Array.isArray(ignorePatterns) ? ignorePatterns.filter((p) => typeof p === 'string') : [];

    // Attempt to fetch .aiscanner from the repo root via the GitHub Contents API.
    // This mirrors the CLI behaviour where .aiscanner patterns are loaded from the
    // local filesystem. We fail silently so a missing file never blocks the scan.
    let dotAiScannerPatterns: string[] = [];
    try {
      const aiScannerUrl = `${apiBase}/contents/.aiscanner?ref=${encodeURIComponent(branch)}`;
      const rawContent = await githubGetText(aiScannerUrl);
      dotAiScannerPatterns = rawContent
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l.length > 0 && !l.startsWith('#'));
      if (dotAiScannerPatterns.length > 0) {
        console.log(
          `[scan-repo] Loaded ${dotAiScannerPatterns.length} pattern(s) from ${owner}/${repo}/.aiscanner`,
        );
      }
    } catch {
      // .aiscanner file not present or unreadable — ignore
    }

    const patterns = [...bodyPatterns, ...dotAiScannerPatterns];
    const collected: GHItem[] = [];
    await collectFiles(apiBase, '', branch, collected, 50, patterns);

    if (collected.length === 0) {
      res.json({ findings: [], summary: summarize([]), filesScanned: 0 });
      return;
    }

    const allFindings: Finding[] = [];

    await Promise.all(
      collected.map(async (item) => {
        try {
          const code = await githubGetText(`${apiBase}/contents/${item.path}?ref=${encodeURIComponent(branch)}`);
          const ext = path.extname(item.name).toLowerCase();
          let findings: Finding[];

          if (ext === '.py') {
            const parsed = parsePythonCode(code, item.path);
            findings = scanPython(parsed);
          } else if (ext === '.go') {
            const parsed = parseGoCode(code, item.path);
            findings = scanGo(parsed);
          } else if (ext === '.java') {
            const parsed = parseJavaCode(code, item.path);
            findings = scanJava(parsed);
          } else if (ext === '.cs') {
            const parsed = parseCSharpCode(code, item.path);
            findings = scanCSharp(parsed);
          } else if (['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp'].includes(ext)) {
            const parsed = parseCCode(code, item.path);
            findings = scanC(parsed);
          } else if (ext === '.rb') {
            const parsed = parseRubyCode(code, item.path);
            findings = scanRuby(parsed);
          } else if (ext === '.kt' || ext === '.kts') {
            const parsed = parseKotlinCode(code, item.path);
            findings = scanKotlin(parsed);
          } else {
            // JS/TS — use AST-based detectors
            const parsed = parseCode(code, item.path);
            findings = [
              ...detectSecrets(parsed),
              ...detectSQLInjection(parsed),
              ...detectShellInjection(parsed),
              ...detectEval(parsed),
              ...detectXSS(parsed),
              ...detectPathTraversal(parsed),
              ...detectPrototypePollution(parsed),
              ...detectInsecureRandom(parsed),
              ...detectOpenRedirect(parsed),
              ...detectSSRF(parsed),
              ...detectJWTSecrets(parsed),
              ...detectJWTNoneAlgorithm(parsed),
              ...detectCommandInjection(parsed),
              ...detectCORSMisconfiguration(parsed),
              ...detectReDoS(parsed),
              ...detectWeakCrypto(parsed),
            ].map((f) => ({ ...f, file: item.path }));
          }
          allFindings.push(...findings);
        } catch {
          // Skip files that fail to parse
        }
      }),
    );

    // Deduplicate by (type, file, line, column) across all scanned files — same
    // logic as the /scan endpoint — so parallel file scans don't produce duplicate
    // findings for the same location when detectors overlap.
    let dedupedFindings = deduplicateFindings(allFindings);

    // Optional ignoreTypes suppression — mirrors the CLI --ignore-type flag and
    // the /scan endpoint behaviour. Only accepts an array of strings.
    if (Array.isArray(ignoreTypes) && ignoreTypes.length > 0) {
      const typesToIgnore = new Set(
        ignoreTypes.filter((t) => typeof t === 'string').map((t) => t.trim().toUpperCase()),
      );
      if (typesToIgnore.size > 0) {
        dedupedFindings = dedupedFindings.filter((f) => !typesToIgnore.has(f.type));
      }
    }

    const repoScanDurationMs = Date.now() - repoScanStart;
    const repoScanSummary = dedupedFindings.reduce<Record<string, number>>((acc, f) => {
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
      res.json(buildSARIF(dedupedFindings));
      return;
    }

    const responsePayload = { findings: dedupedFindings, summary: summarize(dedupedFindings), filesScanned: collected.length };
    res.json(responsePayload);

    // Fire-and-forget webhook delivery after responding to the client
    if (webhookUrl && typeof webhookUrl === 'string') {
      deliverWebhook(
        webhookUrl,
        { event: 'scan_repo_complete', repo: `${owner}/${repo}`, branch, ...responsePayload },
        webhookSecret,
      );
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[scan-repo] error: ${msg}`);
    res.status(500).json({ error: `Failed to scan repository: ${msg}` });
  }
});

// ── SSE /watch endpoint — streams scan results as files change ───────────────

app.get('/watch', (req, res) => {
  const targetPath = (req.query['path'] as string | undefined) ?? process.cwd();
  const resolvedPath = path.resolve(targetPath);

  if (!fs.existsSync(resolvedPath) || !fs.statSync(resolvedPath).isDirectory()) {
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
  const ALL_EXTENSIONS = new Set([...JS_TS_EXTENSIONS, '.py', '.go', '.java', '.cs', '.c', '.cpp', '.cc', '.h', '.rb', '.kt', '.kts']);

  let debounceTimer: ReturnType<typeof setTimeout> | null = null;
  const pendingFiles = new Set<string>();

  function scanFile(filePath: string): Finding[] {
    try {
      const code = fs.readFileSync(filePath, 'utf-8');
      const ext = path.extname(filePath).toLowerCase();

      if (ext === '.py') {
        const parsed = parsePythonCode(code, filePath);
        return scanPython(parsed);
      } else if (ext === '.go') {
        const parsed = parseGoCode(code, filePath);
        return scanGo(parsed);
      } else if (ext === '.java') {
        const parsed = parseJavaCode(code, filePath);
        return scanJava(parsed);
      } else if (ext === '.cs') {
        const parsed = parseCSharpCode(code, filePath);
        return scanCSharp(parsed);
      } else if (['.c', '.cpp', '.cc', '.h'].includes(ext)) {
        const parsed = parseCCode(code, filePath);
        return scanC(parsed);
      } else if (ext === '.rb') {
        const parsed = parseRubyCode(code, filePath);
        return scanRuby(parsed);
      } else if (ext === '.kt' || ext === '.kts') {
        const parsed = parseKotlinCode(code, filePath);
        return scanKotlin(parsed);
      } else if (JS_TS_EXTENSIONS.has(ext)) {
        const parsed = parseCode(code, filePath);
        return [
          ...detectSecrets(parsed),
          ...detectSQLInjection(parsed),
          ...detectShellInjection(parsed),
          ...detectEval(parsed),
          ...detectXSS(parsed),
          ...detectPathTraversal(parsed),
          ...detectPrototypePollution(parsed),
          ...detectInsecureRandom(parsed),
          ...detectOpenRedirect(parsed),
          ...detectSSRF(parsed),
          ...detectJWTSecrets(parsed),
          ...detectJWTNoneAlgorithm(parsed),
          ...detectCommandInjection(parsed),
          ...detectCORSMisconfiguration(parsed),
          ...detectReDoS(parsed),
          ...detectWeakCrypto(parsed),
        ].map((f) => ({ ...f, file: filePath }));
      }
      return [];
    } catch {
      return [];
    }
  }

  function processPendingFiles() {
    const files = [...pendingFiles];
    pendingFiles.clear();

    const allFindings: Finding[] = [];
    for (const file of files) {
      if (fs.existsSync(file)) {
        allFindings.push(...scanFile(file));
      }
    }

    const deduped = deduplicateFindings(allFindings);
    const payload = {
      files,
      findings: deduped,
      summary: summarize(deduped),
      ts: new Date().toISOString(),
    };
    res.write(`event: scan\ndata: ${JSON.stringify(payload)}\n\n`);
  }

  let watcher: fs.FSWatcher;
  try {
    watcher = fs.watch(resolvedPath, { recursive: true }, (_event, filename) => {
      if (!filename) return;
      const full = path.isAbsolute(filename) ? filename : path.join(resolvedPath, filename);
      const ext = path.extname(full).toLowerCase();
      if (!ALL_EXTENSIONS.has(ext)) return;
      if (full.includes('node_modules') || full.includes('.git')) return;

      pendingFiles.add(full);

      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(processPendingFiles, 300);
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    res.write(`event: error\ndata: ${JSON.stringify({ error: msg })}\n\n`);
    res.end();
    return;
  }

  req.on('close', () => {
    if (debounceTimer) clearTimeout(debounceTimer);
    watcher.close();
  });
});

export const server = app.listen(PORT, () => {
  console.log(`AI Security Scanner server running on http://localhost:${PORT}`);
});

// Graceful shutdown: drain connections before process exit so tests close
// cleanly and production process managers can do zero-downtime restarts.
function gracefulShutdown(signal: string): void {
  console.log(`[server] ${signal} received — closing HTTP server...`);
  server.close(() => {
    console.log('[server] HTTP server closed. Exiting.');
    process.exit(0);
  });
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
