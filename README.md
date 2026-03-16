# AI Code Security Scanner

AST-based security scanner for AI-generated code. Detects hardcoded secrets, SQL injection, shell injection, and eval injection.

## Quick Start

```bash
npm install
```

## Usage

### CLI

```bash
# Scan a file
npx ts-node src/cli.ts tests/fixtures/vulnerable.ts

# Scan a directory
npx ts-node src/cli.ts ./src

# JSON output
npx ts-node src/cli.ts tests/fixtures/vulnerable.ts --json

# Filter by minimum severity
npx ts-node src/cli.ts ./src --severity high

# Exclude paths matching a glob (repeatable)
npx ts-node src/cli.ts ./src --ignore '**/node_modules/**'
npx ts-node src/cli.ts . --ignore '**/node_modules/**' --ignore 'dist/**' --ignore '**/*.test.ts'
```

### API Server

```bash
npm run dev:server   # starts on http://localhost:3001
```

```bash
# Health check
curl http://localhost:3001/health

# Scan code
curl -X POST http://localhost:3001/scan \
  -H "Content-Type: application/json" \
  -d '{"code": "const password = \"hunter2\""}'
```

### Web UI

```bash
cd web && npm install && npm run dev
```
Open http://localhost:5173 — paste code in the editor, click **Scan Code**.

## Tests

```bash
# Run test suite
npx ts-node --transpile-only -e "require('./tests/scanner.test.ts')"
```

## Detectors

| Detector | Type | Severity |
|---|---|---|
| Hardcoded secrets | `SECRET_HARDCODED` | critical |
| SQL injection | `SQL_INJECTION` | critical |
| XSS (innerHTML, dangerouslySetInnerHTML, document.write) | `XSS` | critical |
| Shell injection | `SHELL_INJECTION` | high |
| eval / new Function | `EVAL_INJECTION` | high |
| Path traversal (fs + path.join with user input) | `PATH_TRAVERSAL` | high |

## Use in CI

The scanner ships as a reusable GitHub Actions workflow. Call it from any workflow in your repo:

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

## Publish to npm

```bash
npm publish          # runs tsc automatically via prepublishOnly
npm publish --tag beta
```

The `.npmignore` excludes `src/`, `web/`, `tests/`, and `*.map` files — only `dist/` is published.
