/**
 * Integration tests for Swift file scanning via POST /scan.
 *
 * Verifies that submitting Swift code with filename ending in .swift is correctly
 * routed through the Swift scanner (swift-parser.ts) and returns Swift-specific
 * findings (SSRF, INSECURE_SHARED_PREFS, UNSAFE_WEBVIEW, SECRET_HARDCODED, WEAK_CRYPTO).
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import request from 'supertest';
import { app } from '../../src/server';

// ── Vulnerable Swift fixture ────────────────────────────────────────────────
// Triggers: SSRF, INSECURE_SHARED_PREFS, UNSAFE_WEBVIEW, SECRET_HARDCODED, WEAK_CRYPTO

const VULNERABLE_SWIFT = `
import Foundation
import WebKit
import CommonCrypto

class VulnerableService {

    // SSRF — URLSession with user-controlled URL
    func fetchData(userUrl: URL) {
        URLSession.shared.dataTask(with: userUrl) { data, _, _ in
            print(data as Any)
        }.resume()
    }

    // INSECURE_SHARED_PREFS — storing password in UserDefaults
    func cachePassword(password: String) {
        UserDefaults.standard.set(password, forKey: "password")
    }

    // UNSAFE_WEBVIEW — allowsArbitraryLoads enabled
    func configWebView() -> WKWebViewConfiguration {
        let config = WKWebViewConfiguration()
        config.allowsArbitraryLoads = true
        return config
    }

    // SECRET_HARDCODED — hardcoded API key
    let apiKey: String = "sk-liveabcdef1234567890secretkey"

    // WEAK_CRYPTO — CC_MD5
    func hashData(data: Data) -> [UInt8] {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        data.withUnsafeBytes { bytes in
            CC_MD5(bytes.baseAddress, CC_LONG(data.count), &digest)
        }
        return digest
    }
}
`;

// Clean Swift code — no findings expected
const CLEAN_SWIFT = `
import Foundation

class SafeService {
    func greet(name: String) -> String {
        return "Hello, \\(name)!"
    }

    func add(a: Int, b: Int) -> Int {
        return a + b
    }
}
`;

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('/scan with Swift files (.swift)', () => {
  test('vulnerable Swift code returns findings with filename ending in .swift', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_SWIFT,
      filename: 'VulnerableService.swift',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ type: string; severity: string; message: string }> };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBeGreaterThan(0);

    const types = new Set(body.findings.map((f) => f.type));

    // The fixture must trigger these Swift-specific finding types
    expect(types.has('SSRF')).toBe(true);
    expect(types.has('INSECURE_SHARED_PREFS')).toBe(true);
    expect(types.has('UNSAFE_WEBVIEW')).toBe(true);
    expect(types.has('SECRET_HARDCODED')).toBe(true);
    expect(types.has('WEAK_CRYPTO')).toBe(true);
  });

  test('clean Swift code returns zero findings', async () => {
    const res = await request(app).post('/scan').send({
      code: CLEAN_SWIFT,
      filename: 'SafeService.swift',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: unknown[] };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBe(0);
  });

  test('findings include correct filename in file field', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_SWIFT,
      filename: 'AppDelegate.swift',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ file: string }> };
    expect(body.findings.length).toBeGreaterThan(0);
    for (const f of body.findings) {
      expect(f.file).toBe('AppDelegate.swift');
    }
  });

  test('response includes summary with correct total count', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_SWIFT,
      filename: 'VulnerableService.swift',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: unknown[]; summary: { total: number } };
    expect(typeof body.summary).toBe('object');
    expect(body.summary.total).toBe(body.findings.length);
    expect(body.summary.total).toBeGreaterThan(0);
  });

  test('all Swift findings have required shape (type, severity, line, message, file)', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_SWIFT,
      filename: 'VulnerableService.swift',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<Record<string, unknown>> };
    for (const f of body.findings) {
      expect(typeof f.type).toBe('string');
      expect(typeof f.severity).toBe('string');
      expect(['critical', 'high', 'medium', 'low']).toContain(f.severity);
      expect(typeof f.line).toBe('number');
      expect(f.line).toBeGreaterThan(0);
      expect(typeof f.message).toBe('string');
      expect(f.message.length).toBeGreaterThan(0);
      expect(f.file).toBe('VulnerableService.swift');
    }
  });
});
