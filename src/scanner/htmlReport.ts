import { Finding } from './reporter';
import type { FixResult } from './fixer';
import { getOwaspCategory, OWASP_CATEGORIES, FINDING_TO_OWASP } from './owasp';

// ── HTML output format ─────────────────────────────────────────────────────────

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3,
};

const SEVERITY_COLOR: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
};

const SEVERITY_BG: Record<string, string> = {
  critical: '#fef2f2',
  high:     '#fff7ed',
  medium:   '#fefce8',
  low:      '#f0fdf4',
};

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

/** Groups findings by file path, then by severity within each file. */
function groupByFile(findings: Finding[]): Map<string, Finding[]> {
  const map = new Map<string, Finding[]>();
  for (const f of findings) {
    const key = f.file ?? 'unknown';
    if (!map.has(key)) map.set(key, []);
    map.get(key)!.push(f);
  }
  // Sort each file's findings by severity
  for (const arr of map.values()) {
    arr.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 3) - (SEVERITY_ORDER[b.severity] ?? 3));
  }
  // Sort files: file with highest-severity finding first
  return new Map(
    [...map.entries()].sort(([, a], [, b]) => {
      const aMin = Math.min(...a.map((f) => SEVERITY_ORDER[f.severity] ?? 3));
      const bMin = Math.min(...b.map((f) => SEVERITY_ORDER[f.severity] ?? 3));
      return aMin - bMin;
    }),
  );
}

// ── Remediation snippets per finding type ─────────────────────────────────────

const REMEDIATION_SNIPPETS: Record<string, string> = {
  SQL_INJECTION:
    `// Use parameterised queries instead:\nconst result = await db.query(\n  "SELECT * FROM users WHERE id = $1",\n  [userId]\n);`,
  COMMAND_INJECTION:
    `// Use execFile with explicit args (no shell):\nimport { execFile } from 'child_process';\nexecFile('ls', ['-la', dir], callback);`,
  SHELL_INJECTION:
    `// Avoid shell=true; pass args as array:\nsubprocess.run(['cmd', arg1, arg2])`,
  EVAL_INJECTION:
    `// Replace eval() with a safe parser:\nconst data = JSON.parse(input);\n// Or use a sandboxed interpreter`,
  XSS:
    `// Escape output before rendering:\nconst safe = escapeHtml(userInput);\nelement.textContent = safe;  // not innerHTML`,
  SECRET_HARDCODED:
    `// Load from environment variable:\nconst apiKey = process.env.API_KEY;\n// Or use a secrets manager (Vault, AWS SSM)`,
  PATH_TRAVERSAL:
    `// Resolve and validate the path:\nconst resolved = path.resolve(baseDir, userInput);\nif (!resolved.startsWith(baseDir)) throw new Error('Invalid path');`,
  SSRF:
    `// Validate URL against allowlist:\nconst url = new URL(input);\nif (!ALLOWED_HOSTS.includes(url.hostname)) throw new Error('Blocked');`,
  OPEN_REDIRECT:
    `// Validate redirect is relative or allowlisted:\nif (!url.startsWith('/') || url.startsWith('//')) throw new Error('Invalid redirect');`,
  PROTOTYPE_POLLUTION:
    `// Use Object.create(null) or validate keys:\nconst safe = Object.create(null);\nif (key === '__proto__' || key === 'constructor') throw new Error('Blocked');`,
  WEAK_CRYPTO:
    `// Use SHA-256 or stronger:\nimport { createHash } from 'crypto';\nconst hash = createHash('sha256').update(data).digest('hex');`,
  INSECURE_RANDOM:
    `// Use crypto.randomBytes for security:\nimport { randomBytes } from 'crypto';\nconst token = randomBytes(32).toString('hex');`,
  JWT_HARDCODED_SECRET:
    `// Load JWT secret from env:\nconst secret = process.env.JWT_SECRET;\njwt.sign(payload, secret, { algorithm: 'HS256' });`,
  JWT_NONE_ALGORITHM:
    `// Always specify allowed algorithms:\njwt.verify(token, secret, { algorithms: ['HS256'] });`,
  JWT_DECODE_NO_VERIFY:
    `// Use jwt.verify() instead of jwt.decode():\nconst payload = jwt.verify(token, secret);`,
  UNSAFE_DESERIALIZATION:
    `// Use safe serialization (JSON):\nconst data = JSON.parse(input);\n// Never use pickle.loads() or BinaryFormatter on untrusted data`,
  BUFFER_OVERFLOW:
    `// Use bounded functions:\nfgets(buf, sizeof(buf), stdin);\nsnprintf(buf, sizeof(buf), "%s", input);`,
  FORMAT_STRING:
    `// Always use a literal format string:\nprintf("%s", user_input);\n// Never: printf(user_input);`,
  MASS_ASSIGNMENT:
    `# Explicitly list permitted attributes:\nparams.require(:user).permit(:name, :email)`,
  CORS_MISCONFIGURATION:
    `// Restrict origins explicitly:\napp.use(cors({ origin: 'https://yourdomain.com', credentials: true }));`,
  REDOS:
    `// Avoid user-controlled regex, or use safe-regex:\nimport safe from 'safe-regex';\nif (!safe(pattern)) throw new Error('Unsafe regex');`,
  COMMAND_INJECTION_C:
    `// Use execve() with explicit args:\nexecve("/usr/bin/ls", args, envp);`,
};

/** Renders a single finding row. */
function renderFinding(f: Finding, anchorId?: string): string {
  const color = SEVERITY_COLOR[f.severity] ?? '#6b7280';
  const bg = SEVERITY_BG[f.severity] ?? '#f9fafb';
  const remediation = REMEDIATION_SNIPPETS[f.type];
  const remediationBlock = remediation
    ? `<details style="margin-top:8px;">
        <summary style="font-size:12px;color:${color};cursor:pointer;font-weight:600;">Show safe alternative</summary>
        <pre style="margin:6px 0 0;padding:8px 12px;background:#1f2937;color:#e5e7eb;border-radius:4px;font-size:12px;line-height:1.5;overflow-x:auto;">${escapeHtml(remediation)}</pre>
      </details>`
    : '';

  const owasp = getOwaspCategory(f.type);
  const owaspBadge = owasp
    ? `<a href="${escapeHtml(owasp.url)}" target="_blank" rel="noopener noreferrer"
         title="${escapeHtml(owasp.name)}"
         style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;color:#1d4ed8;background:#dbeafe;padding:2px 7px;border-radius:3px;text-decoration:none;white-space:nowrap;">${escapeHtml(owasp.id)}</a>`
    : '';

  const anchor = anchorId ? ` id="${anchorId}"` : '';
  return `
    <div class="finding"${anchor} style="border-left: 4px solid ${color}; background: ${bg}; border-radius: 6px; padding: 12px 16px; margin-bottom: 10px;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;flex-wrap:wrap;">
        <span style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.06em;color:${color};background:${color}22;padding:2px 8px;border-radius:3px;">${escapeHtml(f.severity)}</span>
        <code style="font-size:12px;color:#374151;background:#f3f4f6;padding:1px 6px;border-radius:3px;">${escapeHtml(f.type)}</code>
        ${owaspBadge}
        <span style="font-size:12px;color:#6b7280;">line ${f.line}, col ${f.column}</span>
      </div>
      <p style="margin:0;font-size:14px;color:#1f2937;">${escapeHtml(f.message)}</p>
      ${remediationBlock}
    </div>`;
}

/** Renders a file card with all its findings. */
function renderFileCard(filePath: string, findings: Finding[], scanRoot: string): string {
  let relPath = filePath;
  try {
    const rel = filePath.startsWith(scanRoot)
      ? filePath.slice(scanRoot.length).replace(/^\//, '')
      : filePath;
    relPath = rel || filePath;
  } catch { /* keep absolute */ }

  const worstSeverity = findings.reduce(
    (acc, f) => (SEVERITY_ORDER[f.severity] ?? 3) < (SEVERITY_ORDER[acc] ?? 3) ? f.severity : acc,
    'low',
  );
  const color = SEVERITY_COLOR[worstSeverity] ?? '#6b7280';

  return `
  <div class="file-card" style="border:1px solid #e5e7eb;border-top:3px solid ${color};border-radius:8px;padding:16px 20px;margin-bottom:20px;">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;">
      <code style="font-size:13px;font-weight:600;color:#111827;">${escapeHtml(relPath)}</code>
      <span style="font-size:12px;color:#6b7280;">${findings.length} finding${findings.length !== 1 ? 's' : ''}</span>
    </div>
    ${findings.map((f, i) => renderFinding(f, `finding-${escapeHtml((f.file ?? 'unknown').replace(/[^a-zA-Z0-9]/g, '-'))}-${i}`)).join('')}
  </div>`;
}

/** Renders the summary bar at the top of the report. */
function renderSummaryBar(findings: Finding[]): string {
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    if (f.severity in counts) counts[f.severity]++;
  }
  const pills = (['critical', 'high', 'medium', 'low'] as const).map((sev) => {
    if (counts[sev] === 0) return '';
    const color = SEVERITY_COLOR[sev];
    return `<div style="display:flex;align-items:center;gap:8px;background:${SEVERITY_BG[sev]};border:1px solid ${color}33;border-radius:6px;padding:10px 18px;">
      <span style="font-size:22px;font-weight:800;color:${color};">${counts[sev]}</span>
      <span style="font-size:12px;text-transform:uppercase;letter-spacing:0.06em;color:${color};font-weight:600;">${sev}</span>
    </div>`;
  });
  return `<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:28px;">${pills.join('')}</div>`;
}

/** Renders the OWASP Top 10 breakdown table. */
function renderOwaspBreakdown(findings: Finding[]): string {
  if (findings.length === 0) return '';

  // Count findings per OWASP category
  const counts = new Map<string, number>();
  for (const f of findings) {
    const owaspId = FINDING_TO_OWASP[f.type];
    if (owaspId) {
      counts.set(owaspId, (counts.get(owaspId) ?? 0) + 1);
    }
  }

  if (counts.size === 0) return '';

  // Sort by count descending
  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);

  const rows = sorted.map(([id, count]) => {
    const cat = OWASP_CATEGORIES[id];
    if (!cat) return '';
    const pct = Math.round((count / findings.length) * 100);
    // Find the first finding belonging to this OWASP category for in-page scroll
    const firstMatch = findings.find((f) => FINDING_TO_OWASP[f.type] === id);
    const firstAnchorId = firstMatch
      ? `finding-${(firstMatch.file ?? 'unknown').replace(/[^a-zA-Z0-9]/g, '-')}-0`
      : '';
    const rowOnClick = firstAnchorId
      ? `onclick="var el=document.getElementById('${firstAnchorId}');if(el){el.scrollIntoView({behavior:'smooth',block:'start'});}" style="cursor:pointer;"`
      : '';
    const cellLink = firstAnchorId
      ? `<a href="#${firstAnchorId}" style="color:#1d4ed8;text-decoration:none;">${escapeHtml(id)}</a>
         <a href="${escapeHtml(cat.url)}" target="_blank" rel="noopener noreferrer" title="OWASP docs" style="margin-left:6px;font-size:10px;color:#93c5fd;text-decoration:none;">↗</a>`
      : `<a href="${escapeHtml(cat.url)}" target="_blank" rel="noopener noreferrer" style="color:#1d4ed8;text-decoration:none;">${escapeHtml(id)}</a>`;
    return `<tr ${rowOnClick}>
      <td style="padding:8px 12px;font-weight:600;color:#1d4ed8;white-space:nowrap;">
        ${cellLink}
      </td>
      <td style="padding:8px 12px;color:#374151;">${escapeHtml(cat.name)}</td>
      <td style="padding:8px 12px;text-align:right;font-weight:600;">${count}</td>
      <td style="padding:8px 12px;width:120px;">
        <div style="background:#e5e7eb;border-radius:3px;height:8px;overflow:hidden;">
          <div style="background:#3b82f6;height:100%;width:${pct}%;border-radius:3px;"></div>
        </div>
      </td>
    </tr>`;
  }).join('');

  return `
  <div style="margin-bottom:28px;">
    <div class="section-title">OWASP Top 10 2021 Breakdown</div>
    <table style="width:100%;border-collapse:collapse;background:#fff;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;">
      <thead>
        <tr style="background:#f9fafb;border-bottom:1px solid #e5e7eb;">
          <th style="padding:8px 12px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:0.06em;color:#6b7280;">Category</th>
          <th style="padding:8px 12px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:0.06em;color:#6b7280;">Name</th>
          <th style="padding:8px 12px;text-align:right;font-size:11px;text-transform:uppercase;letter-spacing:0.06em;color:#6b7280;">Count</th>
          <th style="padding:8px 12px;font-size:11px;text-transform:uppercase;letter-spacing:0.06em;color:#6b7280;">Distribution</th>
        </tr>
      </thead>
      <tbody>
        ${rows}
      </tbody>
    </table>
  </div>`;
}

/**
 * Produces a self-contained single-file HTML report for the given findings.
 *
 * @param findings - The filtered list of findings to render.
 * @param scanRoot - Absolute path of the scan target (used to shorten file paths).
 * @param generatedAt - ISO timestamp to display in the report header.
 */
export function buildHTMLReport(
  findings: Finding[],
  scanRoot: string,
  generatedAt: string = new Date().toISOString(),
  fixResults?: FixResult[],
): string {
  const grouped = groupByFile(findings);
  const fileCards = [...grouped.entries()]
    .map(([filePath, f]) => renderFileCard(filePath, f, scanRoot))
    .join('');

  // ── Fix diff section ────────────────────────────────────────────────────────
  let fixDiffSection = '';
  if (fixResults && fixResults.length > 0) {
    const applied = fixResults.filter((r) => r.applied && r.originalLine !== undefined && r.fixedLine !== undefined);
    if (applied.length > 0) {
      const byFile = new Map<string, typeof applied>();
      for (const r of applied) {
        if (!byFile.has(r.file)) byFile.set(r.file, []);
        byFile.get(r.file)!.push(r);
      }

      const fileBlocks = [...byFile.entries()].map(([filePath, results]) => {
        const relPath = filePath.startsWith(scanRoot) ? filePath.slice(scanRoot.length).replace(/^\//, '') : filePath;
        const diffLines = results.map((r) => {
          const lineHeader = '<div style="font-size:11px;color:#6b7280;font-family:monospace;margin-bottom:4px;">Line ' + r.finding.line + ' [' + escapeHtml(r.finding.type) + ']</div>';
          const minusLine = '<div style="padding:4px 12px;color:#f87171;background:#450a0a;">&minus; ' + escapeHtml(r.originalLine!) + '</div>';
          const plusLine = '<div style="padding:4px 12px;color:#86efac;background:#052e16;">+ ' + escapeHtml(r.fixedLine!) + '</div>';
          return '<div style="margin-bottom:10px;">' + lineHeader + '<div style="background:#1f2937;border-radius:4px;overflow:hidden;font-family:monospace;font-size:12px;line-height:1.6;">' + minusLine + plusLine + '</div></div>';
        }).join('');
        return '<div style="margin-bottom:18px;"><div style="font-size:13px;font-weight:600;color:#374151;font-family:monospace;background:#f3f4f6;padding:6px 12px;border-radius:4px 4px 0 0;border:1px solid #e5e7eb;border-bottom:none;">' + escapeHtml(relPath) + '</div><div style="border:1px solid #e5e7eb;border-radius:0 0 4px 4px;padding:12px;">' + diffLines + '</div></div>';
      }).join('');

      fixDiffSection = '<section style="margin-top:32px;"><div class="section-title">Auto-fix Diffs</div><p style="font-size:13px;color:#6b7280;margin-bottom:16px;">' + applied.length + ' fix(es) &#8212; before/after per changed line.</p>' + fileBlocks + '</section>';
    }
  }

  const emptyState = findings.length === 0
    ? `<div style="text-align:center;padding:60px 20px;color:#6b7280;">
        <p style="font-size:18px;margin-bottom:8px;">No findings</p>
        <p style="font-size:14px;">The scanned path produced no security findings at the selected severity level.</p>
      </div>`
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI Code Security Scanner — Report</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 32px 24px; background: #f9fafb; color: #1f2937; max-width: 900px; margin: 0 auto; }
    h1 { font-size: 24px; font-weight: 800; color: #111827; margin-bottom: 4px; }
    .meta { font-size: 13px; color: #6b7280; margin-bottom: 28px; }
    code { font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace; }
    .section-title { font-size: 14px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.07em; color: #374151; margin-bottom: 14px; padding-bottom: 8px; border-bottom: 1px solid #e5e7eb; }
  </style>
</head>
<body>
  <h1>Security Scan Report</h1>
  <div class="meta">
    Generated: ${escapeHtml(generatedAt)} &nbsp;·&nbsp;
    Target: <code>${escapeHtml(scanRoot)}</code> &nbsp;·&nbsp;
    Total findings: <strong>${findings.length}</strong>
  </div>

  ${renderSummaryBar(findings)}

  ${renderOwaspBreakdown(findings)}

  ${findings.length > 0 ? '<div class="section-title">Findings by file</div>' : ''}
  ${fileCards}
  ${emptyState}

  ${fixDiffSection}

  <div style="margin-top:40px;padding-top:20px;border-top:1px solid #e5e7eb;font-size:12px;color:#9ca3af;text-align:center;">
    Generated by <strong>ai-code-security-scanner</strong> &nbsp;·&nbsp;
    OWASP Top 10 2021 badges link to the relevant category documentation.
  </div>
</body>
</html>`;
}
