"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildHTMLReport = buildHTMLReport;
// ── HTML output format ─────────────────────────────────────────────────────────
const SEVERITY_ORDER = {
    critical: 0, high: 1, medium: 2, low: 3,
};
const SEVERITY_COLOR = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#22c55e',
};
const SEVERITY_BG = {
    critical: '#fef2f2',
    high: '#fff7ed',
    medium: '#fefce8',
    low: '#f0fdf4',
};
function escapeHtml(text) {
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}
/** Groups findings by file path, then by severity within each file. */
function groupByFile(findings) {
    const map = new Map();
    for (const f of findings) {
        const key = f.file ?? 'unknown';
        if (!map.has(key))
            map.set(key, []);
        map.get(key).push(f);
    }
    // Sort each file's findings by severity
    for (const arr of map.values()) {
        arr.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 3) - (SEVERITY_ORDER[b.severity] ?? 3));
    }
    // Sort files: file with highest-severity finding first
    return new Map([...map.entries()].sort(([, a], [, b]) => {
        const aMin = Math.min(...a.map((f) => SEVERITY_ORDER[f.severity] ?? 3));
        const bMin = Math.min(...b.map((f) => SEVERITY_ORDER[f.severity] ?? 3));
        return aMin - bMin;
    }));
}
/** Renders a single finding row. */
function renderFinding(f) {
    const color = SEVERITY_COLOR[f.severity] ?? '#6b7280';
    const bg = SEVERITY_BG[f.severity] ?? '#f9fafb';
    return `
    <div class="finding" style="border-left: 4px solid ${color}; background: ${bg}; border-radius: 6px; padding: 12px 16px; margin-bottom: 10px;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
        <span style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.06em;color:${color};background:${color}22;padding:2px 8px;border-radius:3px;">${escapeHtml(f.severity)}</span>
        <code style="font-size:12px;color:#374151;background:#f3f4f6;padding:1px 6px;border-radius:3px;">${escapeHtml(f.type)}</code>
        <span style="font-size:12px;color:#6b7280;">line ${f.line}, col ${f.column}</span>
      </div>
      <p style="margin:0;font-size:14px;color:#1f2937;">${escapeHtml(f.message)}</p>
    </div>`;
}
/** Renders a file card with all its findings. */
function renderFileCard(filePath, findings, scanRoot) {
    let relPath = filePath;
    try {
        const rel = filePath.startsWith(scanRoot)
            ? filePath.slice(scanRoot.length).replace(/^\//, '')
            : filePath;
        relPath = rel || filePath;
    }
    catch { /* keep absolute */ }
    const worstSeverity = findings.reduce((acc, f) => (SEVERITY_ORDER[f.severity] ?? 3) < (SEVERITY_ORDER[acc] ?? 3) ? f.severity : acc, 'low');
    const color = SEVERITY_COLOR[worstSeverity] ?? '#6b7280';
    return `
  <div class="file-card" style="border:1px solid #e5e7eb;border-top:3px solid ${color};border-radius:8px;padding:16px 20px;margin-bottom:20px;">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;">
      <code style="font-size:13px;font-weight:600;color:#111827;">${escapeHtml(relPath)}</code>
      <span style="font-size:12px;color:#6b7280;">${findings.length} finding${findings.length !== 1 ? 's' : ''}</span>
    </div>
    ${findings.map(renderFinding).join('')}
  </div>`;
}
/** Renders the summary bar at the top of the report. */
function renderSummaryBar(findings) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) {
        if (f.severity in counts)
            counts[f.severity]++;
    }
    const pills = ['critical', 'high', 'medium', 'low'].map((sev) => {
        if (counts[sev] === 0)
            return '';
        const color = SEVERITY_COLOR[sev];
        return `<div style="display:flex;align-items:center;gap:8px;background:${SEVERITY_BG[sev]};border:1px solid ${color}33;border-radius:6px;padding:10px 18px;">
      <span style="font-size:22px;font-weight:800;color:${color};">${counts[sev]}</span>
      <span style="font-size:12px;text-transform:uppercase;letter-spacing:0.06em;color:${color};font-weight:600;">${sev}</span>
    </div>`;
    });
    return `<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:28px;">${pills.join('')}</div>`;
}
/**
 * Produces a self-contained single-file HTML report for the given findings.
 *
 * @param findings - The filtered list of findings to render.
 * @param scanRoot - Absolute path of the scan target (used to shorten file paths).
 * @param generatedAt - ISO timestamp to display in the report header.
 */
function buildHTMLReport(findings, scanRoot, generatedAt = new Date().toISOString()) {
    const grouped = groupByFile(findings);
    const fileCards = [...grouped.entries()]
        .map(([filePath, f]) => renderFileCard(filePath, f, scanRoot))
        .join('');
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

  ${findings.length > 0 ? '<div class="section-title">Findings by file</div>' : ''}
  ${fileCards}
  ${emptyState}

  <div style="margin-top:40px;padding-top:20px;border-top:1px solid #e5e7eb;font-size:12px;color:#9ca3af;text-align:center;">
    Generated by <strong>ai-code-security-scanner</strong>
  </div>
</body>
</html>`;
}
//# sourceMappingURL=htmlReport.js.map