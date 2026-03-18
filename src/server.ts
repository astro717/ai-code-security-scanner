import express from 'express';
import cors from 'cors';
import https from 'https';
import rateLimit from 'express-rate-limit';
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
import { summarize, Finding } from './scanner/reporter';

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

// Known vulnerable packages with minimum safe versions
const KNOWN_VULNERABLE: Record<string, { below: string; severity: 'critical' | 'high' | 'medium'; cve: string }> = {
  'lodash': { below: '4.17.21', severity: 'critical', cve: 'CVE-2021-23337 / prototype pollution' },
  'lodash.merge': { below: '4.6.2', severity: 'critical', cve: 'CVE-2020-8203 / prototype pollution' },
  'minimist': { below: '1.2.6', severity: 'critical', cve: 'CVE-2021-44906 / prototype pollution' },
  'node-fetch': { below: '3.0.0', severity: 'high', cve: 'CVE-2022-0235 / exposure of sensitive info' },
  'axios': { below: '1.6.0', severity: 'high', cve: 'CVE-2023-45857 / CSRF via forged request' },
  'jsonwebtoken': { below: '9.0.0', severity: 'high', cve: 'CVE-2022-23529 / arbitrary file write' },
  'express': { below: '4.19.0', severity: 'medium', cve: 'CVE-2024-29041 / open redirect' },
  'semver': { below: '7.5.2', severity: 'high', cve: 'CVE-2022-25883 / ReDoS' },
};

function parseVersion(v: string): number[] {
  return v.replace(/^[\^~>=<v]/, '').split('.').map((n) => parseInt(n, 10) || 0);
}

function isBelow(current: string, threshold: string): boolean {
  const c = parseVersion(current);
  const t = parseVersion(threshold);
  for (let i = 0; i < 3; i++) {
    if ((c[i] ?? 0) < (t[i] ?? 0)) return true;
    if ((c[i] ?? 0) > (t[i] ?? 0)) return false;
  }
  return false;
}

function detectUnsafeDepsFromJson(packageJsonStr: string): Finding[] {
  const findings: Finding[] = [];
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(packageJsonStr);
  } catch {
    return findings;
  }

  const allDeps = {
    ...((pkg.dependencies as Record<string, string>) ?? {}),
    ...((pkg.devDependencies as Record<string, string>) ?? {}),
  };

  for (const [name, version] of Object.entries(allDeps)) {
    // Unpinned versions
    if (version === 'latest' || version === '*' || version === 'x') {
      findings.push({
        type: 'UNSAFE_DEPENDENCY',
        severity: 'medium',
        line: 1,
        column: 0,
        snippet: `"${name}": "${version}"`,
        message: `Dependency "${name}" pinned to "${version}" — unpinned versions can introduce breaking changes or malicious updates.`,
        file: 'package.json',
      });
    }
    // Known vulnerable versions
    const vuln = KNOWN_VULNERABLE[name];
    if (vuln && isBelow(version, vuln.below)) {
      findings.push({
        type: 'VULNERABLE_DEPENDENCY',
        severity: vuln.severity,
        line: 1,
        column: 0,
        snippet: `"${name}": "${version}"`,
        message: `"${name}@${version}" is vulnerable (${vuln.cve}). Upgrade to >=${vuln.below}.`,
        file: 'package.json',
      });
    }
  }

  return findings;
}

app.use(cors());

// Limit request body to 500 KB. Express will automatically respond with 413
// for bodies larger than this limit — but we also enforce it explicitly inside
// route handlers so the error message is consistent and human-readable.
const PAYLOAD_LIMIT = '500kb';
const PAYLOAD_LIMIT_BYTES = 500 * 1024;

app.use(express.json({ limit: PAYLOAD_LIMIT }));

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

  const { code, filename, packageJson, aiExplain } = req.body as {
    code?: string;
    filename?: string;
    packageJson?: string;
    aiExplain?: boolean;
  };

  if (!code || typeof code !== 'string') {
    res.status(400).json({ error: 'Missing required field: code (string)' });
    return;
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
    ...detectCommandInjection(parsed),
  ].map((f) => ({ ...f, file: filename ?? 'input' }));

  // Scan package.json for unsafe deps if provided
  if (packageJson && typeof packageJson === 'string') {
    const depsFindings = detectUnsafeDepsFromJson(packageJson);
    findings.push(...depsFindings);
  }

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

async function collectFiles(
  apiBase: string,
  dirPath: string,
  branch: string,
  collected: GHItem[],
  max: number,
): Promise<void> {
  if (collected.length >= max) return;
  const url = `${apiBase}/contents/${dirPath}?ref=${encodeURIComponent(branch)}`;
  const items = await githubGet(url) as GHItem[];
  if (!Array.isArray(items)) return;
  for (const item of items) {
    if (collected.length >= max) break;
    if (item.type === 'file') {
      const ext = item.name.split('.').pop() ?? '';
      if (['ts', 'tsx', 'js', 'jsx'].includes(ext) && item.size <= 200 * 1024) {
        collected.push(item);
      }
    } else if (item.type === 'dir') {
      await collectFiles(apiBase, item.path, branch, collected, max);
    }
  }
}

app.post('/scan-repo', scanRepoLimiter, async (req, res) => {
  const { repoUrl, branch = 'main' } = req.body as { repoUrl?: string; branch?: string };

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
    const collected: GHItem[] = [];
    await collectFiles(apiBase, '', branch, collected, 50);

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
            ...detectCommandInjection(parsed),
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
