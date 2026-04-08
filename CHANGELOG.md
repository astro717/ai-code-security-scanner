# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] — 2026-04-08

### Added

- **MISSING_AUTH detector** for Python (Flask/FastAPI) and Go (`http.HandleFunc`) — stateful multi-decorator analysis
- **Confidence scores** on all 17 JS/TS detectors (`confidence` field [0.0–1.0])
- **Helmet.js** security response headers on API server (`X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`, etc.)
- **`MAX_CACHE_ENTRIES` env var** — configurable scan cache size limit (default: `10000`)
- **Atomic writes** in `scan-cache.ts` — prevents partial cache corruption on process exit
- **Rate-limit headers** (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`) on all API responses
- **867 tests** across 57 test files

### Changed

- `package.json` version bumped to `1.0.0` — first stable public release

## [0.9.0] — 2026-04-01

### Added

- **14 supported languages**: TypeScript, JavaScript, Python, Go, Java, C#, Ruby, PHP, Rust, Swift, Kotlin, C/C++
- **43+ vulnerability types**: SQL injection, XSS, command injection, path traversal, weak crypto, insecure random, SSRF, XXE, LDAP injection, JWT issues, secret hardcoding, mass assignment, buffer overflow, format string, unsafe deserialization, and more
- **7 output formats**: `text`, `json`, `sarif`, `html`, `junit`, `markdown`, `sonarqube`
- **REST API server** (`src/server.ts`) with endpoints: `/scan`, `/fix`, `/scan-repo`, `/badge`, `/webhook`
- **VS Code extension** (`vscode-extension/`) with inline diagnostics and auto-fix code actions
- **GitHub Actions workflow** (`.github/workflows/ci.yml`) for CI/CD integration
- **OWASP Top 10 mapping** for all finding types via `src/scanner/owasp.ts`
- **AI explanations** for findings via `/scan` with `aiExplain: true` flag
- **CSRF detection** for Express.js and similar frameworks
- **Dependency scanning** for known vulnerable npm packages
- **Scan cache** (`src/scanner/scan-cache.ts`) to skip unchanged files between runs
- **Watch mode** (`--watch` flag) that re-scans on file changes and diffs findings
- **Webhook support**: POST findings to a URL on scan completion
- **Badge endpoint** (`/badge`) returning SVG shield for README embedding
- **Auto-fix rules** for JS/TS, Python, Ruby, PHP, C#, Go, Java, Swift, Rust, C/C++
- **SARIF 2.1.0 output** for GitHub Code Scanning integration
- **`--min-severity` flag** for controlling exit code threshold
- **`--config` file** support for `.ai-sec-scan.json` project configuration
- **Rate limiting** on all API endpoints
- **Content-type validation** and stricter input sanitization on `/scan` and `/fix`
- **SSRF protection** on `/scan-repo` with allowlist (github.com, gitlab.com, bitbucket.org) and private IP blocking
- **Binary file detection** and large file (>2 MB) skipping in CLI

### Security

- Test fixtures use intentionally fake, non-functional credentials (prefixed `sk-live...`, `sk_live...`) — these are not real secrets

### Changed

- Nothing — this is the first versioned release

[Unreleased]: https://github.com/astro717/ai-code-security-scanner/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/astro717/ai-code-security-scanner/compare/v0.9.0...v1.0.0
[0.9.0]: https://github.com/astro717/ai-code-security-scanner/releases/tag/v0.9.0
