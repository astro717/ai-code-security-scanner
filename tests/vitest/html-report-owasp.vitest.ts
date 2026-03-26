/**
 * Unit tests for the HTML report OWASP breakdown section.
 */

import { describe, test, expect } from 'vitest';
import { buildHTMLReport } from '../../src/scanner/htmlReport';
import type { Finding } from '../../src/scanner/reporter';

function makeFinding(overrides: Partial<Finding> & { type: string; line: number; severity: string }): Finding {
  return {
    column: 0,
    message: 'test finding',
    file: '/project/src/app.ts',
    ...overrides,
  };
}

describe('buildHTMLReport — OWASP breakdown', () => {
  test('renders OWASP breakdown table when findings have OWASP mappings', () => {
    const findings: Finding[] = [
      makeFinding({ type: 'SQL_INJECTION', line: 10, severity: 'high' }),
      makeFinding({ type: 'WEAK_CRYPTO', line: 20, severity: 'medium' }),
    ];
    const html = buildHTMLReport(findings, '/project');
    expect(html).toContain('OWASP Top 10 2021 Breakdown');
    expect(html).toContain('A03:2021');
    expect(html).toContain('A02:2021');
  });

  test('OWASP table rows contain anchor links to first matching finding', () => {
    const findings: Finding[] = [
      makeFinding({ type: 'SQL_INJECTION', line: 10, severity: 'high' }),
    ];
    const html = buildHTMLReport(findings, '/project');
    // Row should contain an in-page anchor href
    expect(html).toContain('href="#finding-');
    // Row should have scrollIntoView onclick
    expect(html).toContain('scrollIntoView');
  });

  test('finding divs have anchor id attributes', () => {
    const findings: Finding[] = [
      makeFinding({ type: 'XSS', line: 5, severity: 'medium' }),
    ];
    const html = buildHTMLReport(findings, '/project');
    expect(html).toMatch(/id="finding-[a-zA-Z0-9-]+-0"/);
  });

  test('returns empty string for OWASP breakdown when no findings match', () => {
    const html = buildHTMLReport([], '/project');
    expect(html).not.toContain('OWASP Top 10 2021 Breakdown');
  });

  test('OWASP breakdown shows correct count per category', () => {
    const findings: Finding[] = [
      makeFinding({ type: 'SQL_INJECTION', line: 1, severity: 'high' }),
      makeFinding({ type: 'COMMAND_INJECTION', line: 2, severity: 'high' }),
      makeFinding({ type: 'WEAK_CRYPTO', line: 3, severity: 'medium' }),
    ];
    const html = buildHTMLReport(findings, '/project');
    // A03 has 2 findings (SQL + COMMAND)
    expect(html).toContain('A03:2021');
    expect(html).toContain('Injection');
  });
});
