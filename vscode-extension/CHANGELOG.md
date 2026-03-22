# Changelog

All notable changes to the AI Code Security Scanner VS Code extension will be documented in this file.

## [Unreleased]

## [0.1.0] — 2026-03-18

### Added

- Initial release of the VS Code extension
- Auto-scan on save for TypeScript, TypeScript React, JavaScript, and JavaScript React files
- Manual scan commands: `AI Security: Scan Active File` and `AI Security: Scan Workspace`
- Inline diagnostics via the VS Code language diagnostics API
- `aiSecScan.serverUrl` setting to configure the backend server URL
- `aiSecScan.autoScanOnSave` setting to enable or disable scan-on-save
- Support for all detectors in the `ai-code-security-scanner` core:
  - SQL Injection, Shell Injection, Command Injection, Eval Injection
  - Cross-Site Scripting (XSS), Path Traversal, Prototype Pollution
  - Hardcoded Secrets, Insecure Randomness, Open Redirect, SSRF
  - JWT (hardcoded secret, weak secret, none algorithm, decode-no-verify)
  - ReDoS, Weak Cryptography, CORS Misconfiguration
  - Vulnerable and unpinned dependencies (from `package.json`)
