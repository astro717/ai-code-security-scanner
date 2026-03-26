import { describe, it, expect } from 'vitest';
import {
  detectUnsafeDepsFromJson,
  detectUnsafeDeps,
  parseVersion,
  isBelow,
} from '../../src/scanner/detectors/deps';

// ── parseVersion ──────────────────────────────────────────────────────────────

describe('parseVersion', () => {
  it('parses a plain semver string', () => {
    expect(parseVersion('4.17.21')).toEqual([4, 17, 21]);
  });

  it('strips leading caret', () => {
    expect(parseVersion('^1.2.3')).toEqual([1, 2, 3]);
  });

  it('strips leading tilde', () => {
    expect(parseVersion('~2.0.0')).toEqual([2, 0, 0]);
  });
});

// ── isBelow ───────────────────────────────────────────────────────────────────

describe('isBelow', () => {
  it('returns true when current is below threshold', () => {
    expect(isBelow('4.17.20', '4.17.21')).toBe(true);
  });

  it('returns false when current equals threshold', () => {
    expect(isBelow('4.17.21', '4.17.21')).toBe(false);
  });

  it('returns false when current is above threshold', () => {
    expect(isBelow('5.0.0', '4.17.21')).toBe(false);
  });

  it('handles caret prefix', () => {
    expect(isBelow('^1.0.0', '2.0.0')).toBe(true);
  });
});

// ── detectUnsafeDepsFromJson ──────────────────────────────────────────────────

describe('detectUnsafeDepsFromJson', () => {
  it('returns empty array for a safe package.json', () => {
    const pkg = JSON.stringify({
      dependencies: {
        express: '4.19.0',
        lodash: '4.17.21',
      },
    });
    const findings = detectUnsafeDepsFromJson(pkg);
    expect(findings).toEqual([]);
  });

  it('detects UNSAFE_DEPENDENCY for "latest" version', () => {
    const pkg = JSON.stringify({
      dependencies: { lodash: 'latest' },
    });
    const findings = detectUnsafeDepsFromJson(pkg);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.some((f) => f.type === 'UNSAFE_DEPENDENCY')).toBe(true);
    expect(findings.find((f) => f.type === 'UNSAFE_DEPENDENCY')!.severity).toBe('medium');
  });

  it('detects UNSAFE_DEPENDENCY for "*" version', () => {
    const pkg = JSON.stringify({
      dependencies: { lodash: '*' },
    });
    const findings = detectUnsafeDepsFromJson(pkg);
    expect(findings.some((f) => f.type === 'UNSAFE_DEPENDENCY')).toBe(true);
  });

  it('detects VULNERABLE_DEPENDENCY for known CVE package', () => {
    const pkg = JSON.stringify({
      dependencies: { lodash: '4.17.19' },
    });
    const findings = detectUnsafeDepsFromJson(pkg);
    expect(findings.some((f) => f.type === 'VULNERABLE_DEPENDENCY')).toBe(true);
    expect(findings.find((f) => f.type === 'VULNERABLE_DEPENDENCY')!.severity).toBe('critical');
  });

  it('does not flag a pinned safe version', () => {
    const pkg = JSON.stringify({
      dependencies: { lodash: '4.17.21' },
    });
    const findings = detectUnsafeDepsFromJson(pkg);
    expect(findings.length).toBe(0);
  });

  it('scans devDependencies as well', () => {
    const pkg = JSON.stringify({
      devDependencies: { handlebars: '4.7.6' },
    });
    const findings = detectUnsafeDepsFromJson(pkg);
    expect(findings.some((f) => f.type === 'VULNERABLE_DEPENDENCY')).toBe(true);
  });

  it('returns empty array for invalid JSON', () => {
    const findings = detectUnsafeDepsFromJson('not json');
    expect(findings).toEqual([]);
  });

  it('returns empty array for JSON with no deps', () => {
    const findings = detectUnsafeDepsFromJson(JSON.stringify({ name: 'test' }));
    expect(findings).toEqual([]);
  });

  it('detects multiple issues in one package.json', () => {
    const pkg = JSON.stringify({
      dependencies: {
        lodash: '4.17.19',    // vulnerable
        express: 'latest',     // unsafe
        axios: '1.5.0',       // vulnerable
      },
    });
    const findings = detectUnsafeDepsFromJson(pkg);
    expect(findings.length).toBeGreaterThanOrEqual(3);
  });
});

// ── detectUnsafeDeps (directory-based) ────────────────────────────────────────

describe('detectUnsafeDeps', () => {
  it('returns empty array for non-existent directory', () => {
    const findings = detectUnsafeDeps('/tmp/does-not-exist-' + Date.now());
    expect(findings).toEqual([]);
  });
});
