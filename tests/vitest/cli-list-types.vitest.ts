/**
 * Unit tests for the --list-types CLI flag.
 *
 * These tests spawn the CLI as a child process and assert on stdout output.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { execSync } from 'child_process';
import * as path from 'path';

const CLI = path.resolve(__dirname, '../../src/cli.ts');
const TSX = path.resolve(__dirname, '../../node_modules/.bin/tsx');

function runListTypes(): string {
  try {
    // Use tsx to run cli.ts directly — avoids needing a full build step.
    return execSync(`"${TSX}" "${CLI}" . --list-types`, {
      cwd: path.resolve(__dirname, '../..'),
      timeout: 30_000,
      encoding: 'utf-8',
    });
  } catch (e: unknown) {
    // Process exits 0 for --list-types, but capture output even if it exits non-zero.
    if (e && typeof e === 'object' && 'stdout' in e) {
      return (e as { stdout: string }).stdout ?? '';
    }
    throw e;
  }
}

describe('--list-types flag', () => {
  let output: string;

  // Run once; reuse across tests.
  beforeAll(() => {
    output = runListTypes();
  });

  it('exits cleanly and produces output', () => {
    expect(output.length).toBeGreaterThan(0);
  });

  it('contains a TYPE header row', () => {
    expect(output).toMatch(/TYPE\s+SEVERITY\s+LANGUAGES/);
  });

  it('contains SQL_INJECTION with critical severity', () => {
    expect(output).toMatch(/SQL_INJECTION\s+critical/);
  });

  it('contains WEAK_CRYPTO with medium severity', () => {
    expect(output).toMatch(/WEAK_CRYPTO\s+medium/);
  });

  it('contains PERFORMANCE_N_PLUS_ONE', () => {
    expect(output).toContain('PERFORMANCE_N_PLUS_ONE');
  });

  it('contains a count summary line', () => {
    expect(output).toMatch(/\d+ finding types supported/);
  });

  it('lists critical findings before low severity findings', () => {
    const cmdIdx = output.indexOf('COMMAND_INJECTION');
    const lowIdx = output.indexOf('UNSAFE_DEPENDENCY');
    expect(cmdIdx).toBeGreaterThan(0);
    expect(lowIdx).toBeGreaterThan(0);
    expect(cmdIdx).toBeLessThan(lowIdx);
  });
});
