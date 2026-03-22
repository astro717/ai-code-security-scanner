import * as vscode from 'vscode';
import * as https from 'https';
import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import { URL } from 'url';

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

// ── HTTP helper ───────────────────────────────────────────────────────────────

function postJSON(serverUrl: string, body: object): Promise<ScanResponse> {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const parsed = new URL(serverUrl + '/scan');
    const lib = parsed.protocol === 'https:' ? https : http;

    const req = lib.request(
      {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
        },
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

  const code = document.getText();
  const filename = document.fileName;

  let response: ScanResponse;
  try {
    response = await postJSON(serverUrl, { code, filename });
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
  const supportedGlob = '**/*.{ts,tsx,js,jsx,mjs,cjs}';
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

// ── Extension lifecycle ───────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext): void {
  const collection = vscode.languages.createDiagnosticCollection('ai-security-scanner');
  context.subscriptions.push(collection);

  const statusBar = createStatusBarItem();
  context.subscriptions.push(statusBar);

  // Wrap scanDocument to update status bar
  async function scanDocumentWithStatus(document: vscode.TextDocument): Promise<void> {
    updateStatusBar(statusBar, 'scanning');
    const config = vscode.workspace.getConfiguration('aiSecScan');
    const serverUrl: string = config.get('serverUrl') ?? 'http://localhost:3001';

    let response: ScanResponse;
    try {
      response = await postJSON(serverUrl, { code: document.getText(), filename: document.fileName });
    } catch {
      updateStatusBar(statusBar, 'offline');
      return;
    }

    const diagnostics = findingsToDiagnostics(response.findings);
    collection.set(document.uri, diagnostics);

    if (diagnostics.length > 0) {
      updateStatusBar(statusBar, 'issues', `${response.findings.length} issue${response.findings.length !== 1 ? 's' : ''}`);
    } else {
      updateStatusBar(statusBar, 'clean');
    }
  }

  // Scan active file on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((document) => {
      const config = vscode.workspace.getConfiguration('aiSecScan');
      const autoScan: boolean = config.get('autoScanOnSave') ?? true;
      const supported = [
        'typescript', 'typescriptreact', 'javascript', 'javascriptreact',
      ];
      if (autoScan && supported.includes(document.languageId)) {
        void scanDocumentWithStatus(document);
      }
    }),
  );

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

  // Scan the currently active file on activation (if supported)
  const active = vscode.window.activeTextEditor;
  const supportedLangs = ['typescript', 'typescriptreact', 'javascript', 'javascriptreact'];
  if (active && supportedLangs.includes(active.document.languageId)) {
    void scanDocumentWithStatus(active.document);
  }
}

export function deactivate(): void {
  // Nothing to clean up — DiagnosticCollection is disposed via subscriptions
}
