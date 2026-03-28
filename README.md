# AI Code Security Scanner

[![CI](https://github.com/astro717/ai-code-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/astro717/ai-code-security-scanner/actions/workflows/ci.yml)

AST-based security scanner for AI-generated code. Detects 17 categories of vulnerabilities across TypeScript and JavaScript files.

## Quick Start

```bash
npm install
npm run build      # compile TypeScript → dist/
```

## Usage

### CLI

```bash
# Scan a file
npx ai-sec-scan src/app.ts

# Scan a directory
npx ai-sec-scan ./src

# JSON output
npx ai-sec-scan ./src --json

# SARIF 2.1.0 output (for GitHub Security tab / CI artifacts)
npx ai-sec-scan ./src --sarif

# Filter by minimum severity to report
npx ai-sec-scan ./src --severity high

# Set minimum severity that triggers a non-zero exit code
npx ai-sec-scan ./src --min-severity critical

# Exclude paths matching a glob (repeatable)
npx ai-sec-scan . --ignore '**/node_modules/**' --ignore 'dist/**' --ignore '**/*.test.ts'

# Use a config file
npx ai-sec-scan ./src --config .ai-sec-scan.json

# Watch mode — re-scans on file changes, prints a diff of new/resolved findings
npx ai-sec-scan ./src --watch
```

#### CLI flags

| Flag | Description |
|------|-------------|
| `[path]` | File or directory to scan. Defaults to `.` |
| `--json` | Output as JSON |
| `--sarif` | Output as SARIF 2.1.0 |
| `--format <text\|json\|sarif>` | Explicit format selector (overrides `--json` / `--sarif`) |
| `--severity <level>` | Minimum severity to include in output (`critical\|high\|medium\|low`). Default: `low` |
| `--min-severity <level>` | Severity that triggers a non-zero exit code. Default: `high` |
| `--ignore <glob>` | Exclude matching paths (repeatable) |
| `--config <path>` | Path to a `.ai-sec-scan.json` config file |
| `--watch` | Watch for file changes and print a live diff of findings |

#### Config file (`.ai-sec-scan.json`)

Place a `.ai-sec-scan.json` in your project root (or pass `--config`):

```json
{
  "severity": "medium",
  "format": "sarif",
  "fix": true,
  "ignore": ["dist/**", "**/*.test.ts", "**/*.spec.ts"]
}
```

| Key | Type | Description |
|-----|------|-------------|
| `severity` | `string` | Minimum severity to include (`critical` \| `high` \| `medium` \| `low`). Default: `low` |
| `format` | `string` | Default output format (`text` \| `json` \| `sarif` \| `html` \| `junit`). Default: `text` |
| `fix` | `boolean` | Apply auto-fixes for supported finding types (equivalent to `--fix` on every run). Default: `false` |
| `ignore` | `string[]` | Glob patterns to exclude from scanning (merged with `--ignore` flags). |

CLI flags override config file values.

#### Ignore file (`.aiscanner`)

Create a `.aiscanner` file in your project root (gitignore-style). Each non-comment, non-empty line is a glob pattern:

```
# ignore generated files
dist/**
coverage/**
**/*.min.js
```

Patterns from `.aiscanner` are merged with `--ignore` flags (CLI takes precedence).

### API Server

```bash
npm run dev:server   # starts on http://localhost:3001
```

```bash
# Health check
curl http://localhost:3001/health

# Scan code snippet
curl -X POST http://localhost:3001/scan \
  -H "Content-Type: application/json" \
  -d '{"code": "const password = \"hunter2\""}'

# With AI explanations (requires ANTHROPIC_API_KEY)
curl -X POST http://localhost:3001/scan \
  -H "Content-Type: application/json" \
  -d '{"code": "eval(userInput);", "aiExplain": true}'
```

#### API authentication

When `SERVER_API_KEY` is set, every request (except `GET /health`) must include:

```
Authorization: Bearer <your-server-api-key>
```

```bash
export SERVER_API_KEY=my-secret-key

curl -X POST http://localhost:3001/scan \
  -H "Authorization: Bearer $SERVER_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"code": "const pw = \"hunter2\""}'
```

Requests without a valid token receive `401 Unauthorized`.

### Web UI

```bash
cd web && npm install && npm run dev
```

Open http://localhost:5173 — paste code in the editor, click **Scan Code**.

Set `VITE_SCANNER_URL` to point to a remote server (defaults to `http://localhost:3001`):

```bash
VITE_SCANNER_URL=https://my-scanner.example.com npm run dev
```

### VS Code Extension

The extension in `vscode-extension/` scans on every file save and shows inline diagnostics.

**Configuration** (`File → Preferences → Settings → AI Code Security Scanner`):

| Setting | Default | Description |
|---------|---------|-------------|
| `aiSecScan.serverUrl` | `http://localhost:3001` | Scanner server URL |
| `aiSecScan.apiKey` | `""` | Bearer token — required when `SERVER_API_KEY` is set on the server |
| `aiSecScan.autoScanOnSave` | `true` | Scan active file on save |

## Tests

```bash
npx ts-node tests/scanner.test.ts
```

## Detectors

The scanner currently ships 17 detectors:

| # | Finding type | Severity | Description |
|---|-------------|----------|-------------|
| 1 | `SECRET_HARDCODED` | critical | API keys, tokens, and passwords assigned to variables |
| 2 | `SQL_INJECTION` | critical | String concatenation or template literals inside SQL queries |
| 3 | `XSS` | critical | Unsanitised user input in `innerHTML`, `dangerouslySetInnerHTML`, or `document.write` |
| 4 | `SHELL_INJECTION` | high | `exec()` / `execSync()` with template literals or concatenated user input |
| 5 | `EVAL_INJECTION` | high | `eval()` or `new Function()` with dynamic arguments |
| 6 | `PATH_TRAVERSAL` | high | `fs` calls combined with `path.join` using unsanitised user input |
| 7 | `PROTOTYPE_POLLUTION` | high | `Object.assign`, `_.merge`, or bracket notation writes that can pollute `__proto__` |
| 8 | `INSECURE_RANDOM` | medium | `Math.random()` used in security-sensitive contexts (tokens, IDs, passwords) |
| 9 | `OPEN_REDIRECT` | medium | `res.redirect()` with dynamic, unvalidated destination |
| 10 | `SSRF` | high | `fetch()`, `axios`, or `http.get()` with dynamic, user-controlled URLs |
| 11 | `COMMAND_INJECTION` | high | `spawn()` / `spawnSync()` with a dynamic, user-controlled command string |
| 12 | `CORS_MISCONFIGURATION` | high | Wildcard origin with `credentials: true`, or reflected `req.headers.origin` |
| 13 | `JWT_HARDCODED_SECRET` | high | `jwt.sign()` with a hardcoded string secret |
| 14 | `JWT_WEAK_SECRET` | high | `jwt.sign()` with a short (< 32 char) secret |
| 15 | `JWT_NONE_ALGORITHM` | high | `jwt.verify()` without an algorithms whitelist, or with `algorithms: ['none']` |
| 16 | `REDOS` | medium | `new RegExp()` constructed from dynamic (user-controlled) input |
| 17 | `WEAK_CRYPTO` | high | `crypto.createHash()` using MD5, SHA-1, MD4, or other weak algorithms |
| — | `UNSAFE_DEPENDENCY` | medium | `package.json` dependency pinned to `*`, `latest`, or `x`; or missing lockfile |
| — | `VULNERABLE_DEPENDENCY` | critical/high/medium | Known-vulnerable package version (CVE checked against a built-in list) |

## Use in CI

The scanner ships a reusable GitHub Actions workflow. Call it from any workflow:

```yaml
jobs:
  security:
    uses: ./.github/workflows/security-scan.yml
    with:
      path: src/          # directory or file to scan (default: .)
      fail-on: high       # critical | high | any (default: high)
```

After the job completes:
- **SARIF report** is uploaded to GitHub Security tab (Code Scanning) and as a downloadable artifact
- **JSON report** is saved as a downloadable artifact
- Outputs `findings-count` and `critical-count` for downstream steps

### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | File or directory to scan |
| `fail-on` | `high` | Minimum severity that causes the job to fail |

### Environment variables

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | Used for GitHub Contents API when scanning repos (auto-provided by Actions) |
| `ANTHROPIC_API_KEY` | Optional — enables AI explanations and fix suggestions via `aiExplain` flag |
| `SERVER_API_KEY` | **Required in production** — Bearer token that callers must include in `Authorization: Bearer <key>`. If unset, server runs in open-access dev mode. |
| `VITE_SCANNER_URL` | Web UI only — overrides the default scanner server URL (`http://localhost:3001`) |

## Publish to npm

```bash
npm publish          # runs tsc automatically via prepublishOnly
npm publish --tag beta
```

The `.npmignore` excludes `src/`, `web/`, `tests/`, and `*.map` files — only `dist/` is published.

Automated publishing via GitHub Actions is configured in `.github/workflows/publish.yml` — it triggers on GitHub releases and runs `npm publish` automatically.
