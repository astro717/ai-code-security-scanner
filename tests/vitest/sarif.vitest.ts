/**
 * Unit tests for SARIF output generation (sarif.ts).
 *
 * Verifies that buildSARIF() produces a valid SARIF 2.1.0 document with
 * correct schema version, rule metadata, help URIs, and result mappings.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import { buildSARIF, SARIF_RULE_DESCRIPTIONS } from '../../src/scanner/sarif';
import type { Finding } from '../../src/scanner/reporter';

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<Finding> & { type: string; line: number }): Finding {
  return {
    severity: 'high',
    column: 0,
    message: 'test finding',
    file: 'test.c',
    ...overrides,
  };
}

// ── SARIF structure tests ─────────────────────────────────────────────────────

describe('buildSARIF — top-level structure', () => {
  test('returns a SARIF 2.1.0 document with correct schema version', () => {
    const sarif = buildSARIF([]) as Record<string, unknown>;
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif-schema-2.1.0.json');
  });

  test('document contains a runs array with a single run', () => {
    const sarif = buildSARIF([]) as { runs: unknown[] };
    expect(Array.isArray(sarif.runs)).toBe(true);
    expect(sarif.runs.length).toBe(1);
  });

  test('run contains a tool.driver with name and version', () => {
    const sarif = buildSARIF([], 'test-tool') as {
      runs: Array<{ tool: { driver: { name: string; version: string } } }>;
    };
    const driver = sarif.runs[0].tool.driver;
    expect(driver.name).toBe('test-tool');
    expect(typeof driver.version).toBe('string');
  });

  test('empty findings produce an empty results array', () => {
    const sarif = buildSARIF([]) as {
      runs: Array<{ results: unknown[] }>;
    };
    expect(sarif.runs[0].results).toHaveLength(0);
  });
});

// ── COMMAND_INJECTION_C rule metadata ─────────────────────────────────────────

describe('buildSARIF — COMMAND_INJECTION_C rule', () => {
  const finding = makeFinding({
    type: 'COMMAND_INJECTION_C',
    severity: 'critical',
    line: 34,
    column: 4,
    message: 'system() called with dynamically-constructed command.',
    file: 'vulnerable.c',
  });

  test('produces a rule entry with ruleId COMMAND_INJECTION_C', () => {
    const sarif = buildSARIF([finding]) as {
      runs: Array<{ tool: { driver: { rules: Array<{ id: string }> } } }>;
    };
    const rules = sarif.runs[0].tool.driver.rules;
    const rule = rules.find((r) => r.id === 'COMMAND_INJECTION_C');
    expect(rule).toBeDefined();
  });

  test('COMMAND_INJECTION_C rule has correct shortDescription', () => {
    const sarif = buildSARIF([finding]) as {
      runs: Array<{ tool: { driver: { rules: Array<{ id: string; shortDescription: { text: string } }> } } }>;
    };
    const rules = sarif.runs[0].tool.driver.rules;
    const rule = rules.find((r) => r.id === 'COMMAND_INJECTION_C');
    expect(rule!.shortDescription.text).toBe('COMMAND_INJECTION_C');
  });

  test('COMMAND_INJECTION_C rule has a helpUri pointing to the docs', () => {
    const sarif = buildSARIF([finding]) as {
      runs: Array<{ tool: { driver: { rules: Array<{ id: string; helpUri: string }> } } }>;
    };
    const rules = sarif.runs[0].tool.driver.rules;
    const rule = rules.find((r) => r.id === 'COMMAND_INJECTION_C');
    expect(rule!.helpUri).toContain('command-injection-c');
  });

  test('COMMAND_INJECTION_C result has level "error" (critical severity)', () => {
    const sarif = buildSARIF([finding]) as {
      runs: Array<{ results: Array<{ ruleId: string; level: string }> }>;
    };
    const result = sarif.runs[0].results.find((r) => r.ruleId === 'COMMAND_INJECTION_C');
    expect(result).toBeDefined();
    expect(result!.level).toBe('error');
  });

  test('COMMAND_INJECTION_C result includes correct file location', () => {
    const sarif = buildSARIF([finding]) as {
      runs: Array<{
        results: Array<{
          ruleId: string;
          locations: Array<{
            physicalLocation: {
              artifactLocation: { uri: string };
              region: { startLine: number };
            };
          }>;
        }>;
      }>;
    };
    const result = sarif.runs[0].results.find((r) => r.ruleId === 'COMMAND_INJECTION_C');
    expect(result!.locations[0].physicalLocation.artifactLocation.uri).toBe('vulnerable.c');
    expect(result!.locations[0].physicalLocation.region.startLine).toBe(34);
  });
});

// ── SARIF_RULE_DESCRIPTIONS coverage ─────────────────────────────────────────

describe('SARIF_RULE_DESCRIPTIONS', () => {
  test('contains a description for COMMAND_INJECTION_C', () => {
    expect(SARIF_RULE_DESCRIPTIONS['COMMAND_INJECTION_C']).toBeDefined();
    expect(SARIF_RULE_DESCRIPTIONS['COMMAND_INJECTION_C'].length).toBeGreaterThan(10);
  });

  test('contains descriptions for all C-specific finding types', () => {
    const cTypes = ['BUFFER_OVERFLOW', 'FORMAT_STRING', 'COMMAND_INJECTION_C', 'WEAK_CRYPTO'];
    for (const t of cTypes) {
      expect(SARIF_RULE_DESCRIPTIONS[t], `Missing description for ${t}`).toBeDefined();
    }
  });
});

// ── Multi-finding SARIF output ────────────────────────────────────────────────

describe('buildSARIF — multiple findings', () => {
  const findings: Finding[] = [
    makeFinding({ type: 'COMMAND_INJECTION_C', line: 10, severity: 'critical', file: 'main.c' }),
    makeFinding({ type: 'BUFFER_OVERFLOW', line: 20, severity: 'high', file: 'main.c' }),
    makeFinding({ type: 'WEAK_CRYPTO', line: 30, severity: 'high', file: 'crypto.c' }),
  ];

  test('deduplicates rules — one rule entry per unique type', () => {
    const withDupe: Finding[] = [
      ...findings,
      makeFinding({ type: 'COMMAND_INJECTION_C', line: 50, severity: 'critical', file: 'main.c' }),
    ];
    const sarif = buildSARIF(withDupe) as {
      runs: Array<{ tool: { driver: { rules: Array<{ id: string }> } } }>;
    };
    const rules = sarif.runs[0].tool.driver.rules;
    const cmdInjRules = rules.filter((r) => r.id === 'COMMAND_INJECTION_C');
    expect(cmdInjRules.length).toBe(1);
  });

  test('all findings appear as results', () => {
    const sarif = buildSARIF(findings) as {
      runs: Array<{ results: unknown[] }>;
    };
    expect(sarif.runs[0].results).toHaveLength(findings.length);
  });
});
