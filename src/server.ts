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
import { summarize, Finding } from './scanner/reporter';
import { detectUnsafeDepsFromJson } from './scanner/detectors/deps';

// ── Anthropic AI explain ──────────────────────────────────────────────────────

interface FindingWithAI extends Finding {
  explanation?: string;
  fixSuggestion?: string;
}

async function anthropicRequest(body: object): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = https.request({
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'anthropic-version': '2023-06-01',
        'x-api-key': process.env.ANTHROPIC_API_KEY ?? '',
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
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

async function explainFinding(finding: Finding): Promise<{ explanation: string; fixSuggestion: string }> {
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
  }) as { content?: Array<{ text?: string }> };

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

async function enrichWithAI(findings: Finding[]): Promise<FindingWithAI[]> {
  if (!process.env.ANTHROPIC_API_KEY) {
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
        const ai = await explainFinding(f);
        enriched.set(f, { ...f, ...ai });
      } catch (err) {
        console.error(`[ai-explain] failed for ${f.type}:`, err);
        enriched.set(f, f);
      }
    }),
  );

  return findings.map((f) => enriched.get(f) ?? f);
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

const scanLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many scan requests from this IP. Limit: 20 requests per minute.' },
});

const scanRepoLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many scan-repo requests from this IP. Limit: 5 requests per minute (GitHub API calls).' },
});

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

  const { code, filename: rawFilename, packageJson, aiExplain } = req.body as {
    code?: string;
    filename?: string;
    packageJson?: string;
    aiExplain?: boolean;
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

  // Deduplicate findings across detectors keyed on (file, line, type).
  // When multiple detectors flag the same location with the same type, keep
  // only the first occurrence so severity counts in the summary are accurate.
  const seen = new Set<string>();
  findings = findings.filter((f) => {
    const key = `${f.file}:${f.line}:${f.type}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // AI explain enrichment
  if (aiExplain && findings.length > 0) {
    findings = await enrichWithAI(findings);
  }

  console.log(`[scan] ${filename ?? 'input'} → ${findings.length} findings${aiExplain ? ' (AI enriched)' : ''}`);

  res.json({ findings, summary: summarize(findings) });
});

// Helper: fetch JSON from GitHub Contents API
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
    https.get(reqOpts, (res) => {
      let body = '';
      res.on('data', (chunk) => body += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(body)); }
        catch { reject(new Error('Invalid JSON from GitHub')); }
      });
    }).on('error', reject);
  });
}

function githubGetText(url: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const opts = new URL(url);
    https.get({
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
    }).on('error', reject);
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
    const patterns = Array.isArray(ignorePatterns) ? ignorePatterns.filter((p) => typeof p === 'string') : [];
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
            ...detectReDoS(parsed),
            ...detectWeakCrypto(parsed),
          ].map((f) => ({ ...f, file: item.path }));
          allFindings.push(...findings);
        } catch {
          // Skip files that fail to parse
        }
      }),
    );

    console.log(`[scan-repo] ${owner}/${repo}@${branch} — ${collected.length} files → ${allFindings.length} findings`);
    res.json({ findings: allFindings, summary: summarize(allFindings), filesScanned: collected.length });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[scan-repo] error: ${msg}`);
    res.status(500).json({ error: `Failed to scan repository: ${msg}` });
  }
});

app.listen(PORT, () => {
  console.log(`AI Security Scanner server running on http://localhost:${PORT}`);
});
