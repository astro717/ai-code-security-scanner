import * as vscode from 'vscode';
import * as https from 'https';
import * as http from 'http';
import { URL } from 'url';

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

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'AI Security Scanner',
      cancellable: true,
    },
    async (progress, token) => {
      progress.report({ message: `Scanning ${files.length} files...`, increment: 0 });
      const step = 100 / Math.max(files.length, 1);

      for (const fileUri of files) {
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

// ── Extension lifecycle ───────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext): void {
  const collection = vscode.languages.createDiagnosticCollection('ai-security-scanner');
  context.subscriptions.push(collection);

  // Scan active file on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((document) => {
      const config = vscode.workspace.getConfiguration('aiSecScan');
      const autoScan: boolean = config.get('autoScanOnSave') ?? true;
      const supported = [
        'typescript', 'typescriptreact', 'javascript', 'javascriptreact',
      ];
      if (autoScan && supported.includes(document.languageId)) {
        void scanDocument(document, collection);
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
      void scanDocument(editor.document, collection);
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
    void scanDocument(active.document, collection);
  }
}

export function deactivate(): void {
  // Nothing to clean up — DiagnosticCollection is disposed via subscriptions
}
