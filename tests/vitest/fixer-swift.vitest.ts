/**
 * Auto-fix rule tests for the Swift language.
 *
 * Covers: INSECURE_RANDOM, WEAK_CRYPTO, FORCE_UNWRAP, FORCE_TRY, WEBVIEW_LOAD_URL
 */

import { describe, it, expect } from 'vitest';
import { applyFixes } from '../../src/scanner/fixer';
import type { Finding } from '../../src/scanner/reporter';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

function makeFinding(overrides: Partial<Finding>): Finding {
  return {
    type: 'UNKNOWN',
    severity: 'high',
    message: 'test',
    file: '/tmp/test.swift',
    line: 1,
    snippet: '',
    confidence: 0.9,
    ...overrides,
  };
}

function fixLine(type: string, lineContent: string): string | null {
  const tmpFile = path.join(os.tmpdir(), `fixer-swift-${Date.now()}.swift`);
  fs.writeFileSync(tmpFile, lineContent + '\n', 'utf-8');

  const finding = makeFinding({ type, file: tmpFile, line: 1, snippet: lineContent });
  applyFixes([finding], false);

  try {
    const content = fs.readFileSync(tmpFile, 'utf-8').trim();
    return content !== lineContent.trim() ? content : null;
  } finally {
    if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile);
  }
}

describe('fixer — Swift INSECURE_RANDOM', () => {
  it('adds SecRandomCopyBytes note for arc4random usage', () => {
    const result = fixLine('INSECURE_RANDOM', '    let n = arc4random_uniform(100)');
    expect(result).toContain('TODO(INSECURE_RANDOM)');
    expect(result).toContain('SecRandomCopyBytes');
  });

  it('does not annotate lines already using SecRandomCopyBytes', () => {
    const result = fixLine('INSECURE_RANDOM', '    SecRandomCopyBytes(kSecRandomDefault, 16, &buf)');
    expect(result).toBeNull();
  });
});

describe('fixer — Swift WEAK_CRYPTO', () => {
  it('adds CryptoKit SHA256 note for CC_MD5 usage', () => {
    const result = fixLine('WEAK_CRYPTO', '    CC_MD5(bytes.baseAddress, CC_LONG(data.count), &digest)');
    expect(result).toContain('TODO(WEAK_CRYPTO)');
    expect(result).toContain('SHA256');
  });

  it('adds CryptoKit SHA256 note for CC_SHA1 usage', () => {
    const result = fixLine('WEAK_CRYPTO', '    CC_SHA1(bytes.baseAddress, CC_LONG(data.count), &digest)');
    expect(result).toContain('TODO(WEAK_CRYPTO)');
    expect(result).toContain('CryptoKit');
  });

  it('adds note for Insecure.MD5 usage', () => {
    const result = fixLine('WEAK_CRYPTO', '    let hash = Insecure.MD5.hash(data: data)');
    expect(result).toContain('TODO(WEAK_CRYPTO)');
  });

  it('does not annotate lines already using SHA256', () => {
    const result = fixLine('WEAK_CRYPTO', '    let hash = SHA256.hash(data: data)');
    expect(result).toBeNull();
  });
});

describe('fixer — Swift FORCE_UNWRAP', () => {
  it('adds guard let note for implicitly unwrapped optional declaration', () => {
    const result = fixLine('FORCE_UNWRAP', '    var manager: NetworkManager!');
    expect(result).toContain('TODO(FORCE_UNWRAP)');
    expect(result).toContain('guard let');
  });

  it('does not annotate regular optional declarations', () => {
    const result = fixLine('FORCE_UNWRAP', '    var manager: NetworkManager?');
    expect(result).toBeNull();
  });
});

describe('fixer — Swift FORCE_TRY', () => {
  it('adds do/catch note for try! expressions', () => {
    const result = fixLine('FORCE_TRY', '    let data = try! JSONSerialization.jsonObject(with: input)');
    expect(result).toContain('TODO(FORCE_TRY)');
    expect(result).toContain('do {');
  });

  it('does not annotate regular try expressions', () => {
    const result = fixLine('FORCE_TRY', '    let data = try JSONSerialization.jsonObject(with: input)');
    expect(result).toBeNull();
  });
});

describe('fixer — Swift WEBVIEW_LOAD_URL', () => {
  it('adds navigationDelegate note for .load() calls', () => {
    const result = fixLine('WEBVIEW_LOAD_URL', '    webView.load(URLRequest(url: url))');
    expect(result).toContain('TODO(WEBVIEW_LOAD_URL)');
    expect(result).toContain('navigationDelegate');
  });
});
