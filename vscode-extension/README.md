# AI Code Security Scanner — VS Code Extension

AST-based security scanner for AI-generated TypeScript and JavaScript code. Get inline vulnerability findings directly in your editor as you write or save files.

## Features

- **Inline diagnostics** — findings appear as squiggly underlines and in the Problems panel, no external tool required
- **Scan on save** — automatically scans the active file every time you save (configurable)
- **Manual scan commands** — run a scan on the active file or the entire workspace on demand
- **17+ vulnerability detectors** covering the most common security issues in AI-generated code:
  - SQL Injection, Shell Injection, Command Injection
  - Cross-Site Scripting (XSS), Path Traversal
  - Hardcoded Secrets (API keys, tokens, passwords)
  - SSRF, Open Redirect, Prototype Pollution
  - Insecure Randomness (`Math.random` in security contexts)
  - JWT vulnerabilities (hardcoded secret, weak secret, none algorithm)
  - ReDoS (dynamic `RegExp` construction from user input)
  - Weak Cryptography (MD5, SHA-1)
  - CORS Misconfiguration
  - Vulnerable and unpinned dependencies (via `package.json`)
- **Severity levels** — Critical, High, Medium, Low — each finding includes a clear explanation of the risk

> **Screenshots placeholder** — screenshots will be added once the extension is published to the VS Code Marketplace.

## Requirements

This extension requires the `ai-code-security-scanner` backend server to be running locally. The server performs the actual AST analysis.

1. Clone the repository: `git clone https://github.com/rouco-industries/ai-code-security-scanner`
2. Install dependencies: `npm install`
3. Start the server: `npm run dev:server`

The server listens on `http://localhost:3001` by default.

## Installation

### From the VS Code Marketplace (once published)

Search for **"AI Code Security Scanner"** in the VS Code Extensions panel and click Install.

### From source

1. Clone the repository (see above)
2. Open the `vscode-extension/` directory in VS Code
3. Run `npm run compile` to build the extension
4. Press `F5` to launch a new Extension Development Host window with the extension loaded

## Usage

Once the backend server is running and the extension is installed:

- **Auto-scan on save:** Save any `.ts`, `.tsx`, `.js`, or `.jsx` file — findings appear automatically in the Problems panel.
- **Scan active file manually:** Open the Command Palette (`Cmd+Shift+P` / `Ctrl+Shift+P`) and run `AI Security: Scan Active File`.
- **Scan entire workspace:** Open the Command Palette and run `AI Security: Scan Workspace`.

## Configuration

All settings are available under **Settings > Extensions > AI Code Security Scanner** or in your `settings.json`:

| Setting | Type | Default | Description |
|---|---|---|---|
| `aiSecScan.serverUrl` | `string` | `http://localhost:3001` | URL of the backend scanner server |
| `aiSecScan.autoScanOnSave` | `boolean` | `true` | Automatically scan the active file when saved |

**Example `settings.json`:**

```json
{
  "aiSecScan.serverUrl": "http://localhost:3001",
  "aiSecScan.autoScanOnSave": false
}
```

## Contributing

Contributions are welcome. To contribute:

1. Fork the repository on GitHub
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Make your changes and add tests in `tests/scanner.test.ts`
4. Run tests: `npx ts-node tests/scanner.test.ts`
5. Commit with a descriptive message and open a pull request

### Adding a new detector

1. Create `src/scanner/detectors/yourDetector.ts` following the existing detector pattern
2. Export a `detectXxx(result: ParseResult): Finding[]` function
3. Import and call it in `src/server.ts` (and `src/cli.ts` if applicable)
4. Add tests in `tests/scanner.test.ts` — at minimum a positive case, a negative case, and one edge case
5. Add the finding type to `web/src/components/ScanResults.tsx` label maps

## License

MIT
