# Contributing

## Prerequisites

- Node.js 20+
- npm 10+

## Dev setup

```bash
git clone https://github.com/astro717/ai-code-security-scanner.git
cd ai-code-security-scanner
npm install
npm run build
npm run test:vitest
```

## Project structure

```
src/
  cli.ts               — CLI entry point (file discovery, output formatting, --fix, --watch)
  server.ts            — Express REST API server (/scan, /fix, /scan-repo, /badge, /webhook)
  scanner/
    parser.ts          — TypeScript/JavaScript AST parser
    python-parser.ts   — Python regex-based scanner
    go-parser.ts       — Go regex-based scanner
    java-parser.ts     — Java regex-based scanner
    fixer.ts           — Auto-fix engine (line-level transformations)
    reporter.ts        — Finding types and severity definitions
    sarif.ts           — SARIF 2.1.0 builder
    owasp.ts           — OWASP Top 10 mapping table
    scan-cache.ts      — File hash cache to skip unchanged files
    ...
tests/
  fixtures/            — vulnerable.{ts,py,go,...} and clean.{ts,py,go,...} fixture files
  vitest/              — Unit and integration tests (*.vitest.ts)
```

## Adding a new language detector

1. Create `src/scanner/<lang>-parser.ts` following the pattern of `go-parser.ts`:
   - Export `parse<Lang>File(filePath)` and `parse<Lang>Code(code, filename)`
   - Export `scan<Lang>(parsed)` returning `Finding[]`
2. Add the file extension to `SUPPORTED_EXTENSIONS` in `src/cli.ts`
3. Wire the language into `scanFileUncached()` in `src/cli.ts`
4. Create `tests/fixtures/vulnerable.<ext>` with intentional vulnerability examples
5. Create `tests/fixtures/clean.<ext>` with safe equivalents
6. Create `tests/vitest/<lang>-fixtures.vitest.ts` with detector assertions

## Adding a new vulnerability type

1. Add the pattern to the appropriate parser file (e.g. `src/scanner/python-parser.ts`)
2. Add the type → OWASP mapping in `src/scanner/owasp.ts`
3. Optionally add an auto-fix rule in `src/scanner/fixer.ts`
4. Add a test in the parser's vitest file

## Test commands

```bash
npm run test:vitest              # Run all tests
npm run test:vitest:server       # Run only server integration tests
npm run test:coverage            # Run with coverage report
npm run build                    # Compile TypeScript
```

## PR guidelines

- One feature or fix per PR
- All new detectors must include vitest tests with both positive and negative cases
- No breaking changes to CLI flags without a major version bump
- Keep fixture files realistic — intentionally vulnerable, never containing real credentials
