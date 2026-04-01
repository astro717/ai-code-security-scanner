/**
 * Integration tests for Swift file scanning via POST /scan.
 *
 * Verifies that submitting Swift code with a .swift filename is correctly
 * routed through the Swift scanner (swift-parser.ts) and returns Swift-specific
 * findings: SSRF, INSECURE_SHARED_PREFS, UNSAFE_WEBVIEW, SECRET_HARDCODED, WEAK_CRYPTO.
 *
 * Run with: npm run test:vitest
 */

import { describe, test, expect } from 'vitest';
import request from 'supertest';
import { app } from '../../src/server';

// ── Vulnerable Swift fixture ──────────────────────────────────────────────────

const VULNERABLE_SWIFT = `
import Foundation
import WebKit
import CommonCrypto

// SECRET_HARDCODED: hardcoded API token
let apiToken = "sk_live_abcdef1234567890abcdef"

// SSRF: URLSession with user-controlled URL variable
let userURL = URL(string: userInput)!
URLSession.shared.dataTask(with: userURL).resume()

// INSECURE_SHARED_PREFS: sensitive value stored in UserDefaults
UserDefaults.standard.set(password, forKey: "userPassword")

// UNSAFE_WEBVIEW: allowsArbitraryLoads ATS bypass
let webView = WKWebView()
let config = WKWebViewConfiguration()
config.preferences.setValue(true, forKey: "allowsArbitraryLoads")

// WEAK_CRYPTO: MD5 usage via CommonCrypto
CC_MD5(data, CC_LONG(data.count), &digest)
`;

// Clean Swift code — no findings expected
const CLEAN_SWIFT = `
import Foundation

struct SafeService {
    func fetchData(from trustedURL: URL) async throws -> Data {
        let (data, _) = try await URLSession.shared.data(from: trustedURL)
        return data
    }

    func saveToken(_ token: String) {
        // Store in Keychain, not UserDefaults
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecValueData as String: token.data(using: .utf8)!
        ]
        SecItemAdd(query as CFDictionary, nil)
    }
}
`;

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('/scan with Swift files (.swift)', () => {
  test('vulnerable Swift code returns findings with filename ending in .swift', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_SWIFT,
      filename: 'vulnerable.swift',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ type: string; severity: string }> };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings.length).toBeGreaterThan(0);
  });

  test('detects SSRF in Swift URLSession with user-controlled URL', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_SWIFT,
      filename: 'network.swift',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ type: string }> };
    const types = new Set(body.findings.map((f) => f.type));
    expect(types.has('SSRF')).toBe(true);
  });

  test('detects INSECURE_SHARED_PREFS in Swift UserDefaults usage', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_SWIFT,
      filename: 'storage.swift',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ type: string }> };
    const types = new Set(body.findings.map((f) => f.type));
    expect(types.has('INSECURE_SHARED_PREFS')).toBe(true);
  });

  test('detects SECRET_HARDCODED in Swift code', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_SWIFT,
      filename: 'config.swift',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ type: string }> };
    const types = new Set(body.findings.map((f) => f.type));
    expect(types.has('SECRET_HARDCODED')).toBe(true);
  });

  test('detects WEAK_CRYPTO MD5 in Swift code', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_SWIFT,
      filename: 'crypto.swift',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ type: string }> };
    const types = new Set(body.findings.map((f) => f.type));
    expect(types.has('WEAK_CRYPTO')).toBe(true);
  });

  test('clean Swift code returns zero findings', async () => {
    const res = await request(app).post('/scan').send({
      code: CLEAN_SWIFT,
      filename: 'safe-service.swift',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<unknown> };
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings).toHaveLength(0);
  });

  test('findings include required fields (type, severity, message, line)', async () => {
    const res = await request(app).post('/scan').send({
      code: VULNERABLE_SWIFT,
      filename: 'audit.swift',
    });

    expect(res.status).toBe(200);
    const body = res.body as { findings: Array<{ type: string; severity: string; message: string; line: number }> };
    for (const finding of body.findings) {
      expect(typeof finding.type).toBe('string');
      expect(typeof finding.severity).toBe('string');
      expect(typeof finding.message).toBe('string');
      expect(typeof finding.line).toBe('number');
    }
  });
});
