import express from 'express';
import cors from 'cors';
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
import { summarize, Finding, deduplicateFindings } from './scanner/reporter';
import { detectUnsafeDepsFromJson } from './scanner/detectors/deps';

// ── Anthropic AI explain ──────────────────────────────────────────────────────

interface FindingWithAI extends Finding {
  explanation?: string;
  fixSuggestion?: string;
}

// LLM calls can be slow — 30 s gives ample time for a response while bounding
// the maximum time a single /scan?aiExplain=true request can block the server.
const ANTHROPIC_REQUEST_TIMEOUT_MS = 30_000;

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
    req.setTimeout(ANTHROPIC_REQUEST_TIMEOUT_MS, () => {
      req.destroy(new Error(`Anthropic API request timed out after ${ANTHROPIC_REQUEST_TIMEOUT_MS}ms`));
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

async function explainFinding(finding: Finding, apiKey?: string): Promise<{ explanation: string; fixSuggestion: string }> {
  const response = await anthropicRequest({
    model: 'claude-haiku-4-5-20251001',
    max_tokens: 512,
    messages: [
      {
        role: 'user',
        content: `You are a security expert. Analyze this vulnerability finding and respond with ONLY a JSON object (no markdown, no extra text):

Vulnerability type: ${finding.type}
Severity: ${finding.severity}
Code snippet: ${finding.snippet}
Message: ${finding.message}

Respond with exactly this JSON structure:
{"explanation": "2-sentence explanation of why this is dangerous and what could be exploited", "fixSuggestion": "the corrected code snippet, just the code, no explanation"}`,
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
 * @param findings  - Findings to enrich
 * @param apiKey    - Optional per-request Anthropic key; falls back to env var
 */
async function enrichWithAI(findings: Finding[], apiKey?: string): Promise<FindingWithAI[]> {
  const effectiveKey = apiKey ?? process.env.ANTHROPIC_API_KEY;
  if (!effectiveKey) {
    console.warn('[ai-explain] ANTHROPIC_API_KEY not set — skipping AI enrichment');
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
        const ai = await explainFinding(f, effectiveKey);
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

// ── Rate limiting ─────────────────────────────────────────────────────────────
//
// In test mode (NODE_ENV=test) both limiters use a very high cap so that
// multiple test files loading the server in the same process (sharing module
// cache and therefore limiter state) never exhaust the per-IP budget before
// all assertions run.  Production limits are unaffected.

const IS_TEST = process.env.NODE_ENV === 'test';

const scanLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: IS_TEST ? 10_000 : 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many scan requests from this IP. Limit: 20 requests per minute.' },
});

const scanRepoLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: IS_TEST ? 10_000 : 5,
  standardHeaders: true,
  legacyHeaders: false,
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
  await Promise.all([
    scanLimiter.resetKey('127.0.0.1'),
    scanRepoLimiter.resetKey('127.0.0.1'),
  ]);
}

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', version: '0.1.0' });
});

app.post('/scan', scanLimiter, async (req, res) => {
  // Explicit payload size guard (belt-and-suspenders on top of express.json limit)
  const rawLength = parseInt(req.headers['content-length'] ?? '0', 10);
  if (rawLength > PAYLOAD_LIMIT_BYTES) {
    res.status(413).json({
      error: `Payload too large. Maximum allowed size is ${PAYLOAD_LIMIT} (${PAYLOAD_LIMIT_BYTES} bytes). Received ${rawLength} bytes.`,
    });
    return;
  }

  // Per-request Anthropic key: the caller may supply their own key via the
  // X-Anthropic-Key header. This lets individual callers use ?aiExplain=true
  // without the server having a shared ANTHROPIC_API_KEY. Falls back to the
  // server-level env var when the header is absent.
  const requestAnthropicKey = (() => {
    const h = req.headers['x-anthropic-key'];
    return typeof h === 'string' && h.length > 0 ? h : undefined;
  })();

  const { code, filename: rawFilename, packageJson, aiExplain, ignoreTypes } = req.body as {
    code?: string;
    filename?: string;
    packageJson?: string;
    aiExplain?: boolean;
    ignoreTypes?: string[];
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

  let parsed;
  try {
    parsed = parseCode(code, filename ?? 'input.tsx');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    res.status(400).json({ error: `Parse error: ${msg}` });
    return;
  }

  let findings: FindingWithAI[] = [
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

  // AI explain enrichment — uses per-request key (X-Anthropic-Key header) when
  // present, otherwise falls back to the server-level ANTHROPIC_API_KEY env var.
  if (aiExplain && findings.length > 0) {
    findings = await enrichWithAI(findings, requestAnthropicKey);
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

  res.json({ findings, summary: summarize(findings) });
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
      if (['ts', 'tsx', 'js', 'jsx'].includes(ext) && item.size <= 200 * 1024) {
        collected.push(item);
      }
    } else if (item.type === 'dir') {
      await collectFiles(apiBase, item.path, branch, collected, max, ignorePatterns);
    }
  }
}

app.post('/scan-repo', scanRepoLimiter, async (req, res) => {
  const { repoUrl, branch = 'main', ignorePatterns = [] } = req.body as {
    repoUrl?: string;
    branch?: string;
    ignorePatterns?: string[];
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
          const parsed = parseCode(code, item.path);
          const findings: Finding[] = [
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
          allFindings.push(...findings);
        } catch {
          // Skip files that fail to parse
        }
      }),
    );

    // Deduplicate by (type, file, line, column) across all scanned files — same
    // logic as the /scan endpoint — so parallel file scans don't produce duplicate
    // findings for the same location when detectors overlap.
    const dedupedFindings = deduplicateFindings(allFindings);

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
    });
    res.json({ findings: dedupedFindings, summary: summarize(dedupedFindings), filesScanned: collected.length });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[scan-repo] error: ${msg}`);
    res.status(500).json({ error: `Failed to scan repository: ${msg}` });
  }
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
