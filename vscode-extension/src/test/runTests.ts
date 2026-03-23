/**
 * Test runner entry point for the VS Code extension test harness.
 *
 * Run with: node out/test/runTests.js
 * (compile first: npm run compile)
 *
 * @vscode/test-electron downloads a VS Code binary (cached in .vscode-test/),
 * launches it in headless mode, and runs the Mocha suite inside the extension
 * host process — giving the tests access to the real `vscode` API.
 */

import * as path from 'path';
import { runTests } from '@vscode/test-electron';

async function main(): Promise<void> {
  // Extension root is the vscode-extension/ directory
  const extensionDevelopmentPath = path.resolve(__dirname, '..', '..');

  // The compiled test suite entry point
  const extensionTestsPath = path.resolve(__dirname, 'suite', 'index');

  try {
    await runTests({
      extensionDevelopmentPath,
      extensionTestsPath,
      // Suppress VS Code UI during tests (headless mode on CI)
      launchArgs: ['--disable-extensions', '--no-sandbox'],
    });
  } catch (err) {
    console.error('VS Code extension tests failed:', err);
    process.exit(1);
  }
}

main();
