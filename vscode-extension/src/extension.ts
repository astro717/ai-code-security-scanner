import * as vscode from 'vscode';
import * as https from 'https';
import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import { URL } from 'url';
import { Worker, isMainThread, parentPort, workerData } from 'worker_threads';

// ── .aiscanner ignore support ─────────────────────────────────────────────────

/**
 * Loads ignore patterns from the nearest `.aiscanner` file in the workspace
 * root or any ancestor directory.  Each non-comment, non-empty line is a glob
 * pattern.  Returns an empty array when no file is found.
 */
function loadAiScannerIgnore(workspaceRoot: string): string[] {
  let dir = workspaceRoot;
  while (true) {
    const candidate = path.join(dir, '.aiscanner');
    if (fs.existsSync(candidate)) {
      try {
        const lines = fs.readFileSync(candidate, 'utf8')
          .split(/\r?\n/)
          .map((l) => l.trim())
          .filter((l) => l.length > 0 && !l.startsWith('#'));
        return lines;
      } catch {
        return [];
      }
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return [];
}

/**
 * Returns true if `filePath` matches `pattern` using a minimatch-compatible
 * subset (supports `**` wildcards, `*`, and `?`).
 */
function matchesGlob(filePath: string, pattern: string): boolean {
  // Normalise to forward slashes for consistent matching
  const normalised = filePath.split(path.sep).join('/');
  // Convert glob to a RegExp
  const regexStr = pattern
    .split('/')
    .map((seg) =>
      seg === '**'
        ? '.*'
        : seg.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]'),
    )
    .join('(/|$|.*/)');
  try {
    return new RegExp(`(^|/)${regexStr}(/|$)`).test(normalised);
  } catch {
    return false;
  }
}

function isIgnoredByAiScanner(filePath: string, patterns: string[]): boolean {
  return patterns.some((p) => matchesGlob(filePath, p));
}

interface Finding {
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  line: number;
  column: number;
  snippet: string;
  message: string;
  file?: string;
}

interface ScanResponse {
  findings: Finding[];
  summary: Record<string, number>;
}

interface ScanRepoResponse {
  findings: Finding[];
  summary: Record<string, number>;
  filesScanned: number;
}

// ── HTTP helper ───────────────────────────────────────────────────────────────

function postJSON(serverUrl: string, body: object, apiKey?: string): Promise<ScanResponse> {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const parsed = new URL(serverUrl + '/scan');
    const lib = parsed.protocol === 'https:' ? https : http;

    const headers: Record<string, string | number> = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
    };
    if (apiKey) {
      headers['Authorization'] = `Bearer ${apiKey}`;
    }

    const req = lib.request(
      {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname,
        method: 'POST',
        headers,
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          try {
            resolve(JSON.parse(data) as ScanResponse);
          } catch {
            reject(new Error('Invalid JSON response from scanner server'));
          }
        });
      },
    );
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

// ── Diagnostics ───────────────────────────────────────────────────────────────

const DIAGNOSTIC_SOURCE = 'AI Security Scanner';

// Known C/C++-specific finding types returned by c-parser.ts.
// Severity mapping and diagnostic rendering below are intentionally type-agnostic
// (driven by f.severity), so these types are handled automatically without special cases.
const C_FINDING_TYPES = new Set([
  'COMMAND_INJECTION_C',
  'BUFFER_OVERFLOW',
  'FORMAT_STRING',
  'WEAK_CRYPTO',
]);

// Known C#-specific finding types.
const CSHARP_FINDING_TYPES = new Set([
  'COMMAND_INJECTION_CS',
]);

// Export for use in tests
export { C_FINDING_TYPES, CSHARP_FINDING_TYPES };

function findingsToDiagnostics(findings: Finding[]): vscode.Diagnostic[] {
  return findings.map((f) => {
    const line = Math.max(0, f.line - 1); // VS Code is 0-indexed
    const col = Math.max(0, f.column);
    const range = new vscode.Range(line, col, line, col + (f.snippet?.length ?? 80));

    const severity =
      f.severity === 'critical' || f.severity === 'high'
        ? vscode.DiagnosticSeverity.Error
        : f.severity === 'medium'
          ? vscode.DiagnosticSeverity.Warning
          : vscode.DiagnosticSeverity.Information;

    const diag = new vscode.Diagnostic(
      range,
      `[${f.severity.toUpperCase()}] ${f.type}: ${f.message}`,
      severity,
    );
    diag.source = DIAGNOSTIC_SOURCE;
    diag.code = f.type;
    return diag;
  });
}

// ── Scanner ───────────────────────────────────────────────────────────────────

async function scanDocument(
  document: vscode.TextDocument,
  collection: vscode.DiagnosticCollection,
): Promise<void> {
  const config = vscode.workspace.getConfiguration('aiSecScan');
  const serverUrl: string = config.get('serverUrl') ?? 'http://localhost:3001';
  const apiKey: string = config.get('apiKey') ?? '';

  const code = document.getText();
  const filename = document.fileName;

  let response: ScanResponse;
  try {
    response = await postJSON(serverUrl, { code, filename }, apiKey || undefined);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    // Show a subtle warning but don't spam the user
    vscode.window.setStatusBarMessage(
      `$(warning) AI Security Scanner: server unreachable — ${msg}`,
      5000,
    );
    return;
  }

  const diagnostics = findingsToDiagnostics(response.findings);
  collection.set(document.uri, diagnostics);

  if (diagnostics.length > 0) {
    vscode.window.setStatusBarMessage(
      `$(shield) AI Security: ${response.findings.length} finding(s) in ${vscode.workspace.asRelativePath(document.uri)}`,
      6000,
    );
  } else {
    vscode.window.setStatusBarMessage(
      `$(shield) AI Security: clean — ${vscode.workspace.asRelativePath(document.uri)}`,
      3000,
    );
  }
}

async function scanWorkspace(
  collection: vscode.DiagnosticCollection,
): Promise<void> {
  const supportedGlob = '**/*.{ts,tsx,js,jsx,mjs,cjs,py,go,java,cs,c,cpp,h,hpp,rb,php,swift,rs}';
  const files = await vscode.workspace.findFiles(supportedGlob, '**/node_modules/**');

  // Load .aiscanner ignore patterns from the workspace root
  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  const ignorePatterns = workspaceRoot ? loadAiScannerIgnore(workspaceRoot) : [];
  const filteredFiles = ignorePatterns.length > 0
    ? files.filter((uri: vscode.Uri) => !isIgnoredByAiScanner(uri.fsPath, ignorePatterns))
    : files;

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'AI Security Scanner',
      cancellable: true,
    },
    async (progress, token) => {
      progress.report({ message: `Scanning ${filteredFiles.length} files...`, increment: 0 });
      const step = 100 / Math.max(filteredFiles.length, 1);

      for (const fileUri of filteredFiles) {
        if (token.isCancellationRequested) break;
        progress.report({ message: vscode.workspace.asRelativePath(fileUri), increment: step });
        try {
          const doc = await vscode.workspace.openTextDocument(fileUri);
          await scanDocument(doc, collection);
        } catch {
          // Skip files that can't be opened
        }
      }
      progress.report({ message: 'Done.', increment: 100 });
    },
  );
}

// ── /scan-repo HTTP helper ────────────────────────────────────────────────────

function postScanRepo(serverUrl: string, body: object, apiKey?: string): Promise<ScanRepoResponse> {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const parsed = new URL(serverUrl + '/scan-repo');
    const lib = parsed.protocol === 'https:' ? https : http;

    const headers: Record<string, string | number> = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
    };
    if (apiKey) {
      headers['Authorization'] = `Bearer ${apiKey}`;
    }

    const req = lib.request(
      {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname,
        method: 'POST',
        headers,
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          try {
            resolve(JSON.parse(data) as ScanRepoResponse);
          } catch {
            reject(new Error('Invalid JSON response from scanner server'));
          }
        });
      },
    );
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

// ── Status bar ────────────────────────────────────────────────────────────────

type StatusBarState = 'idle' | 'scanning' | 'issues' | 'clean' | 'offline';

function createStatusBarItem(): vscode.StatusBarItem {
  const item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  item.command = 'aiSecScan.scanFile';
  item.tooltip = 'AI Security Scanner — click to scan active file';
  item.text = '$(shield) AI Sec';
  item.show();
  return item;
}

function updateStatusBar(
  item: vscode.StatusBarItem,
  state: StatusBarState,
  detail?: string,
): void {
  switch (state) {
    case 'idle':
      item.text = '$(shield) AI Sec';
      item.color = undefined;
      item.backgroundColor = undefined;
      break;
    case 'scanning':
      item.text = '$(loading~spin) AI Sec: scanning…';
      item.color = undefined;
      item.backgroundColor = undefined;
      break;
    case 'issues':
      item.text = `$(warning) AI Sec: ${detail ?? 'issues found'}`;
      item.color = new vscode.ThemeColor('statusBarItem.warningForeground');
      item.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
      break;
    case 'clean':
      item.text = '$(pass) AI Sec: clean';
      item.color = undefined;
      item.backgroundColor = undefined;
      break;
    case 'offline':
      item.text = '$(plug) AI Sec: offline';
      item.color = new vscode.ThemeColor('statusBarItem.errorForeground');
      item.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
      break;
  }
}

// ── AI Explain helper ───────────────────────────────────────────────────────

async function fetchAIExplanation(
  serverUrl: string,
  code: string,
  filename: string,
  apiKey?: string,
): Promise<Finding[]> {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({ code, filename, aiExplain: true });
    const parsed = new URL(serverUrl + '/scan');
    const lib = parsed.protocol === 'https:' ? https : http;

    const headers: Record<string, string | number> = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
    };
    if (apiKey) {
      headers['Authorization'] = `Bearer ${apiKey}`;
    }

    const req = lib.request(
      {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname,
        method: 'POST',
        headers,
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          try {
            const body = JSON.parse(data) as { findings: Finding[] };
            resolve(body.findings ?? []);
          } catch {
            reject(new Error('Invalid JSON from scanner'));
          }
        });
      },
    );
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

// ── CodeLens provider ───────────────────────────────────────────────────────

class SecurityCodeLensProvider implements vscode.CodeLensProvider {
  private _onDidChange = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this._onDidChange.event;

  constructor(private diagnosticCollection: vscode.DiagnosticCollection) {}

  refresh(): void {
    this._onDidChange.fire();
  }

  provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
    const diagnostics = this.diagnosticCollection.get(document.uri);
    if (!diagnostics || diagnostics.length === 0) return [];

    const lenses: vscode.CodeLens[] = [];
    const seenLines = new Set<number>();

    for (const diag of diagnostics) {
      if (diag.source !== DIAGNOSTIC_SOURCE) continue;

      const line = diag.range.start.line;
      if (seenLines.has(line)) continue;
      seenLines.add(line);

      const lens = new vscode.CodeLens(diag.range, {
        title: '$(lightbulb) Show AI fix',
        command: 'aiSecScan.showAIFix',
        arguments: [document.uri, line, String(diag.code ?? ''), diag.message],
      });
      lenses.push(lens);
    }

    return lenses;
  }
}

function showFixInWebview(
  context: vscode.ExtensionContext,
  finding: Finding & { explanation?: string; fixSuggestion?: string },
): void {
  const panel = vscode.window.createWebviewPanel(
    'aiSecFix',
    `AI Fix: ${finding.type}`,
    vscode.ViewColumn.Beside,
    { enableScripts: false },
  );

  const severityColors: Record<string, string> = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#6b7280',
  };

  const color = severityColors[finding.severity] ?? '#6b7280';

  panel.webview.html = `<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 1.5rem; color: #e6edf3; background: #0d1117; line-height: 1.6; }
    h2 { color: ${color}; font-size: 1.1rem; margin: 0 0 0.25rem; }
    .severity { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; background: ${color}22; color: ${color}; border: 1px solid ${color}44; }
    .snippet { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 0.75rem; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; white-space: pre-wrap; margin: 0.75rem 0; overflow-x: auto; }
    .section { margin: 1.25rem 0; }
    .section-title { color: #7d8590; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 0.35rem; }
    p { margin: 0.25rem 0; }
    .message { color: #7d8590; font-size: 0.9rem; }
  </style>
</head>
<body>
  <h2>${escapeHtml(finding.type)}</h2>
  <span class="severity">${finding.severity.toUpperCase()}</span>
  <p class="message">${escapeHtml(finding.message)}</p>

  ${finding.snippet ? `<div class="section"><div class="section-title">Code</div><div class="snippet">${escapeHtml(finding.snippet)}</div></div>` : ''}

  ${finding.explanation ? `<div class="section"><div class="section-title">Explanation</div><p>${escapeHtml(finding.explanation)}</p></div>` : ''}

  ${finding.fixSuggestion ? `<div class="section"><div class="section-title">Suggested Fix</div><div class="snippet">${escapeHtml(finding.fixSuggestion)}</div></div>` : '<div class="section"><p style="color:#7d8590;">No AI fix available. Set ANTHROPIC_API_KEY on the scanner server to enable AI explanations.</p></div>'}
</body>
</html>`;
}

function escapeHtml(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── Worker-thread scan-on-save ────────────────────────────────────────────────
//
// Scanning is offloaded to a Node.js worker thread so the VS Code extension
// host (UI thread) is never blocked. Each save triggers a queued scan; a
// per-file debounce prevents redundant scans when the user saves rapidly.
//
// Worker protocol:
//   Main → Worker: { code: string; filename: string; serverUrl: string; apiKey: string }
//   Worker → Main: { ok: true; findings: Finding[] } | { ok: false; error: string }
//
// The worker runs the HTTP /scan request (network I/O is already async, but
// keeping it off the main thread avoids any JSON-parse or callback overhead
// blocking the extension host's event loop on very large files).

// Debounce timers: file URI string → NodeJS.Timeout
const _saveDebounceTimers = new Map<string, ReturnType<typeof setTimeout>>();

const SAVE_DEBOUNCE_MS = 500; // wait 500 ms after last save before scanning

/**
 * Queues a worker-thread scan for the given document.
 * If a scan is already queued for this file, the previous timer is cancelled
 * and replaced, giving a debounced "only scan after N ms of inactivity" behaviour.
 */
function queueWorkerScan(
  document: vscode.TextDocument,
  collection: vscode.DiagnosticCollection,
  statusBar: vscode.StatusBarItem,
  codeLensProvider: SecurityCodeLensProvider,
): void {
  const uriKey = document.uri.toString();

  // Cancel any pending scan for this file
  const existing = _saveDebounceTimers.get(uriKey);
  if (existing) clearTimeout(existing);

  const timer = setTimeout(() => {
    _saveDebounceTimers.delete(uriKey);
    _runWorkerScan(document, collection, statusBar, codeLensProvider);
  }, SAVE_DEBOUNCE_MS);

  _saveDebounceTimers.set(uriKey, timer);
}

/**
 * Spawns a Node.js worker thread to POST the document code to the scanner
 * server, then updates diagnostics on completion.
 */
function _runWorkerScan(
  document: vscode.TextDocument,
  collection: vscode.DiagnosticCollection,
  statusBar: vscode.StatusBarItem,
  codeLensProvider: SecurityCodeLensProvider,
): void {
  const config = vscode.workspace.getConfiguration('aiSecScan');
  const serverUrl: string = config.get('serverUrl') ?? 'http://localhost:3001';
  const apiKey: string = config.get('apiKey') ?? '';

  updateStatusBar(statusBar, 'scanning');

  const workerScript = `
    const { workerData, parentPort } = require('worker_threads');
    const https = require('https');
    const http = require('http');
    const { URL } = require('url');

    const { code, filename, serverUrl, apiKey } = workerData;
    const payload = JSON.stringify({ code, filename });
    const parsed = new URL(serverUrl + '/scan');
    const lib = parsed.protocol === 'https:' ? https : http;

    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
    };
    if (apiKey) headers['Authorization'] = 'Bearer ' + apiKey;

    const req = lib.request(
      {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname,
        method: 'POST',
        headers,
        timeout: 15000,
      },
      (res) => {
        let data = '';
        res.on('data', (c) => { data += c; });
        res.on('end', () => {
          try {
            const body = JSON.parse(data);
            parentPort.postMessage({ ok: true, findings: body.findings ?? [] });
          } catch (e) {
            parentPort.postMessage({ ok: false, error: 'Invalid JSON: ' + String(e) });
          }
        });
      },
    );
    req.on('error', (e) => parentPort.postMessage({ ok: false, error: e.message }));
    req.on('timeout', () => { req.destroy(); parentPort.postMessage({ ok: false, error: 'Request timed out' }); });
    req.write(payload);
    req.end();
  `;

  let worker: Worker;
  try {
    worker = new Worker(workerScript, {
      eval: true,
      workerData: {
        code: document.getText(),
        filename: document.fileName,
        serverUrl,
        apiKey,
      },
    });
  } catch {
    // worker_threads unavailable — fall back to inline scan
    void scanDocumentWithStatusFallback(document, collection, statusBar, codeLensProvider);
    return;
  }

  worker.once('message', (msg: { ok: boolean; findings?: Finding[]; error?: string }) => {
    if (!msg.ok) {
      updateStatusBar(statusBar, 'offline');
      return;
    }

    const findings = msg.findings ?? [];
    const diagnostics = findingsToDiagnostics(findings);
    collection.set(document.uri, diagnostics);
    codeLensProvider.refresh();

    if (diagnostics.length > 0) {
      updateStatusBar(statusBar, 'issues', `${findings.length} issue${findings.length !== 1 ? 's' : ''}`);
    } else {
      updateStatusBar(statusBar, 'clean');
    }
  });

  worker.once('error', () => {
    updateStatusBar(statusBar, 'offline');
  });
}

/**
 * Fallback for environments where worker_threads is unavailable.
 * Runs the scan inline (same as original implementation).
 */
async function scanDocumentWithStatusFallback(
  document: vscode.TextDocument,
  collection: vscode.DiagnosticCollection,
  statusBar: vscode.StatusBarItem,
  codeLensProvider: SecurityCodeLensProvider,
): Promise<void> {
  const config = vscode.workspace.getConfiguration('aiSecScan');
  const serverUrl: string = config.get('serverUrl') ?? 'http://localhost:3001';
  const apiKey: string = config.get('apiKey') ?? '';

  let response: ScanResponse;
  try {
    response = await postJSON(serverUrl, { code: document.getText(), filename: document.fileName }, apiKey || undefined);
  } catch {
    updateStatusBar(statusBar, 'offline');
    return;
  }

  const diagnostics = findingsToDiagnostics(response.findings);
  collection.set(document.uri, diagnostics);
  codeLensProvider.refresh();

  if (diagnostics.length > 0) {
    updateStatusBar(statusBar, 'issues', `${response.findings.length} issue${response.findings.length !== 1 ? 's' : ''}`);
  } else {
    updateStatusBar(statusBar, 'clean');
  }
}

// ── Extension lifecycle ───────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext): void {
  const collection = vscode.languages.createDiagnosticCollection('ai-security-scanner');
  context.subscriptions.push(collection);

  const statusBar = createStatusBarItem();
  context.subscriptions.push(statusBar);

  // CodeLens: "Show AI fix" above each diagnostic
  const codeLensProvider = new SecurityCodeLensProvider(collection);
  const supportedLanguages = [
    { language: 'typescript' },
    { language: 'typescriptreact' },
    { language: 'javascript' },
    { language: 'javascriptreact' },
    { language: 'python' },
    { language: 'go' },
    { language: 'java' },
    { language: 'csharp' },
    { language: 'c' },
    { language: 'cpp' },
    { language: 'ruby' },
    { language: 'php' },
    { language: 'swift' },
    { language: 'rust' },
  ];
  context.subscriptions.push(
    vscode.languages.registerCodeLensProvider(supportedLanguages, codeLensProvider),
  );

  // Command: show AI fix in webview panel
  context.subscriptions.push(
    vscode.commands.registerCommand(
      'aiSecScan.showAIFix',
      async (uri: vscode.Uri, line: number, type: string, message: string) => {
        const config = vscode.workspace.getConfiguration('aiSecScan');
        const serverUrl: string = config.get('serverUrl') ?? 'http://localhost:3001';
        const apiKey: string = config.get('apiKey') ?? '';

        // Get the document text and request AI explanation
        let aiFindings: Finding[] = [];
        try {
          const doc = await vscode.workspace.openTextDocument(uri);
          aiFindings = await fetchAIExplanation(serverUrl, doc.getText(), doc.fileName, apiKey || undefined);
        } catch {
          // Fall back to showing basic info without AI
        }

        // Find the matching finding by line and type
        const matchingFinding = aiFindings.find(
          (f) => f.line === line + 1 && f.type === type, // line is 0-indexed from VS Code
        ) ?? {
          type,
          severity: 'medium' as const,
          line: line + 1,
          column: 0,
          snippet: '',
          message,
        };

        showFixInWebview(context, matchingFinding as Finding & { explanation?: string; fixSuggestion?: string });
      },
    ),
  );

  // Wrap scanDocument to update status bar
  async function scanDocumentWithStatus(document: vscode.TextDocument): Promise<void> {
    updateStatusBar(statusBar, 'scanning');
    const config = vscode.workspace.getConfiguration('aiSecScan');
    const serverUrl: string = config.get('serverUrl') ?? 'http://localhost:3001';
    const apiKey: string = config.get('apiKey') ?? '';

    let response: ScanResponse;
    try {
      response = await postJSON(serverUrl, { code: document.getText(), filename: document.fileName }, apiKey || undefined);
    } catch {
      updateStatusBar(statusBar, 'offline');
      return;
    }

    const diagnostics = findingsToDiagnostics(response.findings);
    collection.set(document.uri, diagnostics);
    codeLensProvider.refresh();

    if (diagnostics.length > 0) {
      updateStatusBar(statusBar, 'issues', `${response.findings.length} issue${response.findings.length !== 1 ? 's' : ''}`);
    } else {
      updateStatusBar(statusBar, 'clean');
    }
  }

  // Scan active file on save — uses a worker thread to avoid blocking the UI.
  // A per-file 500 ms debounce prevents redundant scans on rapid saves.
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((document) => {
      const config = vscode.workspace.getConfiguration('aiSecScan');
      const autoScan: boolean = config.get('autoScanOnSave') ?? true;
      const supported = [
        'typescript', 'typescriptreact', 'javascript', 'javascriptreact',
        'python', 'go', 'java', 'csharp', 'c', 'cpp', 'ruby', 'kotlin', 'swift', 'php', 'rust',
      ];
      if (autoScan && supported.includes(document.languageId)) {
        queueWorkerScan(document, collection, statusBar, codeLensProvider);
      }
    }),
  );

  // Dispose debounce timers on deactivation
  context.subscriptions.push({
    dispose(): void {
      for (const timer of _saveDebounceTimers.values()) clearTimeout(timer);
      _saveDebounceTimers.clear();
    },
  });

  // Command: scan active file
  context.subscriptions.push(
    vscode.commands.registerCommand('aiSecScan.scanFile', () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage('AI Security Scanner: no active editor.');
        return;
      }
      void scanDocumentWithStatus(editor.document);
    }),
  );

  // Command: scan workspace
  context.subscriptions.push(
    vscode.commands.registerCommand('aiSecScan.scanWorkspace', () => {
      void scanWorkspace(collection);
    }),
  );

  // Command: scan a GitHub repository via /scan-repo
  context.subscriptions.push(
    vscode.commands.registerCommand('aiSecScan.scanRepo', async () => {
      const repoUrl = await vscode.window.showInputBox({
        prompt: 'Enter a GitHub repository URL to scan',
        placeHolder: 'https://github.com/owner/repo',
        validateInput: (value) => {
          if (!value || !value.trim().match(/github\.com\/[^/]+\/[^/]+/)) {
            return 'Please enter a valid GitHub repository URL (https://github.com/owner/repo)';
          }
          return undefined;
        },
      });

      if (!repoUrl) return; // cancelled

      const config = vscode.workspace.getConfiguration('aiSecScan');
      const serverUrl: string = config.get('serverUrl') ?? 'http://localhost:3001';
      const apiKey: string = config.get('apiKey') ?? '';

      updateStatusBar(statusBar, 'scanning');

      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: `AI Security: scanning ${repoUrl}…`,
          cancellable: false,
        },
        async () => {
          let response: ScanRepoResponse;
          try {
            response = await postScanRepo(serverUrl, { repoUrl }, apiKey || undefined);
          } catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            updateStatusBar(statusBar, 'offline');
            vscode.window.showErrorMessage(`AI Security Scanner: failed to scan repository — ${msg}`);
            return;
          }

          // Display results: reuse existing diagnostic rendering, keying on a
          // synthetic URI so results appear in the Problems panel.
          const syntheticUri = vscode.Uri.parse(`ai-sec-scan-repo://${repoUrl.replace(/https?:\/\//, '')}`);
          const diagnostics = findingsToDiagnostics(response.findings.map((f) => ({
            ...f,
            // Remap file paths to the synthetic URI for display purposes
          })));
          collection.set(syntheticUri, diagnostics);

          if (response.findings.length > 0) {
            updateStatusBar(statusBar, 'issues', `${response.findings.length} issue${response.findings.length !== 1 ? 's' : ''}`);
            const detail = response.findings
              .slice(0, 5)
              .map((f) => `${f.file ?? '?'}:${f.line} [${f.severity}] ${f.type}`)
              .join('\n');
            vscode.window.showWarningMessage(
              `AI Security: ${response.findings.length} finding(s) across ${response.filesScanned} file(s) in ${repoUrl}`,
              { detail, modal: false },
            );
          } else {
            updateStatusBar(statusBar, 'clean');
            vscode.window.showInformationMessage(
              `AI Security: no findings in ${response.filesScanned} file(s) scanned from ${repoUrl}`,
            );
          }
        },
      );
    }),
  );

  // Scan the currently active file on activation (if supported)
  const active = vscode.window.activeTextEditor;
  const supportedLangs = [
    'typescript', 'typescriptreact', 'javascript', 'javascriptreact',
    'python', 'go', 'java', 'csharp', 'c', 'cpp', 'ruby', 'php', 'swift', 'rust',
  ];
  if (active && supportedLangs.includes(active.document.languageId)) {
    void scanDocumentWithStatus(active.document);
  }
}

export function deactivate(): void {
  // Nothing to clean up — DiagnosticCollection is disposed via subscriptions
}
