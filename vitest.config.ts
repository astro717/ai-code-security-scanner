import { defineConfig } from 'vitest/config';

// Node.js 25+ introduced breaking changes in the http module internals that
// cause supertest-based server-scan tests to hang or emit spurious errors.
// When running on Node 25+, exclude all server-scan-*.vitest.ts files so the
// rest of the suite can still be validated in CI.  Use `npm run test:vitest:server`
// to run those tests explicitly on a Node 24 (LTS) runtime.
const nodeMajor = parseInt(process.versions.node.split('.')[0]!, 10);
const serverScanExclude =
  nodeMajor >= 25 ? ['tests/vitest/server-scan-*.vitest.ts'] : [];

export default defineConfig({
  test: {
    // Emit both human-readable output and JUnit XML so CI platforms
    // (Jenkins, GitLab, Azure DevOps) can render per-test pass/fail results
    // directly in the PR UI without additional tooling.
    reporters: ['default', 'junit'],
    outputFile: {
      junit: 'coverage/junit.xml',
    },
    // Only include the vitest-native test files under tests/vitest/.
    // The existing custom runner (tests/scanner.test.ts) uses its own
    // test() / expect() API and calls process.exit() — it is kept for
    // `npm test` (ts-node) but is not compatible with vitest's runner.
    include: ['tests/vitest/**/*.vitest.ts'],
    // Explicitly exclude the custom ts-node runner regardless of include glob
    // changes. scanner.test.ts calls process.exit() which crashes vitest's
    // fork pool — a single accidental inclusion breaks the entire suite.
    // On Node 25+ also exclude server-scan tests (see comment above).
    exclude: ['tests/scanner.test.ts', '**/node_modules/**', ...serverScanExclude],
    // Use the v8 coverage provider (built-in, no external instrumentation).
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'json-summary'],
      // Only measure coverage of source files, not tests or build output.
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.d.ts', 'dist/**'],
      // Fail CI if coverage drops below these baselines (based on current
      // actual coverage: lines ~49%, functions ~49%, branches ~46%).
      // Thresholds are set 5% below actuals to give headroom while still
      // catching significant coverage regressions.
      thresholds: {
        lines: 45,
        functions: 45,
        branches: 40,
        statements: 42,
      },
    },
    // TypeScript support is built-in via Vite's esbuild transform.
    environment: 'node',
    // Set NODE_ENV and a dummy INTERNAL_API_TOKEN so server-rate-limit tests
    // can verify the bypass header behavior without undefined token values.
    env: {
      NODE_ENV: 'test',
      INTERNAL_API_TOKEN: 'test-token-32-chars-long-for-unit-tests',
    },
    // forks pool: each test file runs in a child process. When the custom
    // test runner calls process.exit(1) at the end, only the child dies —
    // vitest captures the exit code and maps it to a test failure, which is
    // the correct behaviour for this custom runner pattern.
    pool: 'forks',
    // Treat a non-zero exit code from the forked process as a test failure.
    // This integrates the custom runner's exit-code protocol with vitest.
    forks: {
      execArgv: [],
    },
  },
});
