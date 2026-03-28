/**
 * Fixture-based unit tests for the Swift language scanner.
 *
 * Each test uses an inline code snippet or the fixture files in tests/fixtures/
 * to verify the scanner fires the expected finding type (or stays silent).
 */

import { describe, it, expect } from 'vitest';
import * as path from 'path';
import * as fs from 'fs';
import { parseSwiftCode, parseSwiftFile, scanSwift } from '../../src/scanner/swift-parser';

// Helper: scan inline snippet, return array of finding types
function scan(code: string): string[] {
  return scanSwift(parseSwiftCode(code, 'test.swift')).map((f) => f.type);
}

// Helper: scan inline snippet, return all findings (for metadata checks)
function scanFull(code: string) {
  return scanSwift(parseSwiftCode(code, 'test.swift'));
}

const FIXTURES = path.resolve(__dirname, '../fixtures');

// ── SSRF ──────────────────────────────────────────────────────────────────────

describe('SSRF', () => {
  it('fires on URLSession.shared.dataTask with user URL variable', () => {
    const code = `URLSession.shared.dataTask(with: userUrl) { _, _, _ in }.resume()`;
    expect(scan(code)).toContain('SSRF');
  });

  it('fires on URLRequest(url: userInput)', () => {
    const code = `let req = URLRequest(url: userInput)`;
    expect(scan(code)).toContain('SSRF');
  });

  it('does NOT fire on a line that does not call URLSession or URLRequest', () => {
    const code = `let result = computeValue(with: someParam)`;
    expect(scan(code)).not.toContain('SSRF');
  });
});

// ── INSECURE_SHARED_PREFS ─────────────────────────────────────────────────────

describe('INSECURE_SHARED_PREFS', () => {
  it('fires on UserDefaults.standard.set with password key', () => {
    const code = `UserDefaults.standard.set(pwd, forKey: "password")`;
    expect(scan(code)).toContain('INSECURE_SHARED_PREFS');
  });

  it('fires on UserDefaults.standard.setValue with auth_token key', () => {
    const code = `UserDefaults.standard.setValue(tok, forKey: "auth_token")`;
    expect(scan(code)).toContain('INSECURE_SHARED_PREFS');
  });

  it('does NOT fire on UserDefaults with non-sensitive key', () => {
    const code = `UserDefaults.standard.set(true, forKey: "onboardingCompleted")`;
    expect(scan(code)).not.toContain('INSECURE_SHARED_PREFS');
  });
});

// ── UNSAFE_WEBVIEW ────────────────────────────────────────────────────────────

describe('UNSAFE_WEBVIEW', () => {
  it('fires on NSAllowsArbitraryLoads: true', () => {
    const code = `"NSAllowsArbitraryLoads": true`;
    expect(scan(code)).toContain('UNSAFE_WEBVIEW');
  });

  it('fires on allowsArbitraryLoads = true', () => {
    const code = `config.allowsArbitraryLoads = true`;
    expect(scan(code)).toContain('UNSAFE_WEBVIEW');
  });

  it('does NOT fire on allowsArbitraryLoads = false', () => {
    const code = `config.allowsArbitraryLoads = false`;
    expect(scan(code)).not.toContain('UNSAFE_WEBVIEW');
  });
});

// ── SECRET_HARDCODED ──────────────────────────────────────────────────────────

describe('SECRET_HARDCODED', () => {
  it('fires on hardcoded apiKey variable', () => {
    const code = `let apiKey: String = "sk-liveabcdef1234567890secretkey"`;
    expect(scan(code)).toContain('SECRET_HARDCODED');
  });

  it('fires on sk_ prefix API key literal', () => {
    const code = `let token = "sk_live_abcdef1234567890abcdef"`;
    expect(scan(code)).toContain('SECRET_HARDCODED');
  });

  it('does NOT fire on environment variable reference', () => {
    const code = `let apiKey = ProcessInfo.processInfo.environment["API_KEY"]`;
    expect(scan(code)).not.toContain('SECRET_HARDCODED');
  });
});

// ── WEAK_CRYPTO ───────────────────────────────────────────────────────────────

describe('WEAK_CRYPTO', () => {
  it('fires on CC_MD5(', () => {
    const code = `CC_MD5(bytes.baseAddress, CC_LONG(data.count), &digest)`;
    expect(scan(code)).toContain('WEAK_CRYPTO');
  });

  it('fires on CC_SHA1(', () => {
    const code = `CC_SHA1(bytes.baseAddress, CC_LONG(data.count), &digest)`;
    expect(scan(code)).toContain('WEAK_CRYPTO');
  });

  it('fires on kCCAlgorithmDES', () => {
    const code = `CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmDES), ...)`;
    expect(scan(code)).toContain('WEAK_CRYPTO');
  });

  it('fires on Insecure.MD5', () => {
    const code = `let hash = Insecure.MD5.hash(data: data)`;
    expect(scan(code)).toContain('WEAK_CRYPTO');
  });

  it('fires on Insecure.SHA1', () => {
    const code = `let hash = Insecure.SHA1.hash(data: data)`;
    expect(scan(code)).toContain('WEAK_CRYPTO');
  });

  it('does NOT fire on SHA256 usage', () => {
    const code = `let hash = SHA256.hash(data: data)`;
    expect(scan(code)).not.toContain('WEAK_CRYPTO');
  });
});

// ── Fixture file tests ────────────────────────────────────────────────────────

describe('vulnerable.swift fixture', () => {
  const vulnerableFile = path.join(FIXTURES, 'vulnerable.swift');

  it('fixture file exists', () => {
    expect(fs.existsSync(vulnerableFile)).toBe(true);
  });

  it('detects SSRF findings', () => {
    const result = scanSwift(parseSwiftFile(vulnerableFile));
    const types = result.map((f) => f.type);
    expect(types).toContain('SSRF');
  });

  it('detects INSECURE_SHARED_PREFS findings', () => {
    const result = scanSwift(parseSwiftFile(vulnerableFile));
    const types = result.map((f) => f.type);
    expect(types).toContain('INSECURE_SHARED_PREFS');
  });

  it('detects UNSAFE_WEBVIEW findings', () => {
    const result = scanSwift(parseSwiftFile(vulnerableFile));
    const types = result.map((f) => f.type);
    expect(types).toContain('UNSAFE_WEBVIEW');
  });

  it('detects SECRET_HARDCODED findings', () => {
    const result = scanSwift(parseSwiftFile(vulnerableFile));
    const types = result.map((f) => f.type);
    expect(types).toContain('SECRET_HARDCODED');
  });

  it('detects WEAK_CRYPTO findings', () => {
    const result = scanSwift(parseSwiftFile(vulnerableFile));
    const types = result.map((f) => f.type);
    expect(types).toContain('WEAK_CRYPTO');
  });

  it('each finding has correct file path', () => {
    const result = scanSwift(parseSwiftFile(vulnerableFile));
    for (const f of result) {
      expect(f.file).toBe(vulnerableFile);
    }
  });
});

describe('clean.swift fixture', () => {
  const cleanFile = path.join(FIXTURES, 'clean.swift');

  it('fixture file exists', () => {
    expect(fs.existsSync(cleanFile)).toBe(true);
  });

  it('produces no INSECURE_SHARED_PREFS findings', () => {
    const result = scanSwift(parseSwiftFile(cleanFile));
    expect(result.filter((f) => f.type === 'INSECURE_SHARED_PREFS')).toHaveLength(0);
  });

  it('produces no SECRET_HARDCODED findings', () => {
    const result = scanSwift(parseSwiftFile(cleanFile));
    expect(result.filter((f) => f.type === 'SECRET_HARDCODED')).toHaveLength(0);
  });

  it('produces no WEAK_CRYPTO findings', () => {
    const result = scanSwift(parseSwiftFile(cleanFile));
    expect(result.filter((f) => f.type === 'WEAK_CRYPTO')).toHaveLength(0);
  });

  it('produces no UNSAFE_WEBVIEW findings', () => {
    const result = scanSwift(parseSwiftFile(cleanFile));
    expect(result.filter((f) => f.type === 'UNSAFE_WEBVIEW')).toHaveLength(0);
  });
});

// ── Metadata accuracy ─────────────────────────────────────────────────────────

describe('Finding metadata', () => {
  it('sets file path correctly', () => {
    const result = scanSwift(parseSwiftCode('CC_MD5(bytes, len, &digest)', '/project/src/Crypto.swift'));
    expect(result[0]?.file).toBe('/project/src/Crypto.swift');
  });

  it('sets line number correctly', () => {
    const code = `\n\nCC_SHA1(bytes, len, &digest)`;
    const findings = scanFull(code);
    const f = findings.find((f) => f.type === 'WEAK_CRYPTO');
    expect(f?.line).toBe(3);
  });

  it('sets snippet to trimmed line content', () => {
    const code = `  CC_MD5(bytes, len, &digest)`;
    const findings = scanFull(code);
    const f = findings.find((f) => f.type === 'WEAK_CRYPTO');
    expect(f?.snippet).toMatch(/CC_MD5/);
  });

  it('does NOT scan comment lines', () => {
    const code = `// CC_MD5(bytes, len, &digest)`;
    expect(scan(code)).not.toContain('WEAK_CRYPTO');
  });
});
