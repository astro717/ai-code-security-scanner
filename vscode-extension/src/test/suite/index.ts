/**
 * Mocha test suite index — loaded by @vscode/test-electron inside the
 * VS Code extension host process.
 */

import * as path from 'path';
import Mocha from 'mocha';
import * as fs from 'fs';

export function run(): Promise<void> {
  const mocha = new Mocha({
    ui: 'bdd',
    color: true,
    timeout: 10000,
  });

  const testsRoot = path.resolve(__dirname);

  return new Promise((resolve, reject) => {
    // Collect all .test.js files in this directory
    const files = fs.readdirSync(testsRoot).filter((f) => f.endsWith('.test.js'));
    for (const file of files) {
      mocha.addFile(path.join(testsRoot, file));
    }

    try {
      mocha.run((failures: number) => {
        if (failures > 0) {
          reject(new Error(`${failures} test(s) failed.`));
        } else {
          resolve();
        }
      });
    } catch (err) {
      reject(err);
    }
  });
}
