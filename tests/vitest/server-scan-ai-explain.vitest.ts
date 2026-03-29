/**
 * Integration tests for the POST /scan endpoint with aiExplain=true.
 *
 * Stubs https.request so no real Anthropic API calls are made. Verifies:
 *   1. When ANTHROPIC_API_KEY is set and aiExplain=true, findings include
 *      explanation and fixSuggestion fields.
 *   2. When ANTHROPIC_API_KEY is unset and aiExplain=true, findings are
 *      returned without AI fields (graceful degradation).
 *   3. When aiExplain=false, no Anthropic call is made regardless of key.
 */

import { describe, test, expect, vi } from 'vitest';
import request from 'supertest';
import { app } from '../../src/server';
import https from 'https';
import { EventEmitter } from 'events';

function post(
  port: number,
  urlPath: string,
  payload: unknown,
): Promise<{ statusCode: number; body: unknown }> {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(payload);
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: urlPath,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(data),
        },
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk: Buffer) => (raw += chunk.toString()));
        res.on('end', () => {
          try {
            resolve({ statusCode: res.status ?? 0, body: JSON.parse(raw) });
          } catch {
            resolve({ statusCode: res.status ?? 0, body: raw });
          }
        });
      },
    );
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

/** Builds a fake https.request stub that returns a canned Anthropic response. */
function makeAnthropicStub(responseJson: object) {
  return vi.spyOn(https, 'request').mockImplementation((_opts: unknown, callback?: (res: unknown) => void) => {
    // Simulate an IncomingMessage with the JSON payload
    const fakeRes = new EventEmitter() as any;
    fakeRes.statusCode = 200;
    fakeRes.headers = {};
    if (callback) {
      process.nextTick(() => {
        callback(fakeRes);
        fakeRes.emit('data', Buffer.from(JSON.stringify(responseJson)));
        fakeRes.emit('end');
      });
    }
    const fakeReq = new EventEmitter() as any;
    fakeReq.setTimeout = () => fakeReq;
    fakeReq.write = () => {};
    fakeReq.end = () => {};
    fakeReq.destroy = () => {};
    return fakeReq;
  });
}

// ── Vulnerable code that will produce at least one finding ────────────────────

const VULNERABLE_CODE = `
const token = Math.random();
const secret = "hardcoded-api-key-12345678";
`;

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('POST /scan — aiExplain=true with stubbed Anthropic', () => {
  test('returns explanation and fixSuggestion fields when aiExplain=true', async () => {
    const anthropicResponse = {
      content: [
        {
          text: JSON.stringify({
            explanation: 'Math.random() is not cryptographically secure and predictable.',
            fixSuggestion: "const token = require('crypto').randomBytes(32).toString('hex');",
          }),
        },
      ],
    };

    const stub = makeAnthropicStub(anthropicResponse);

    try {
      const { statusCode, body } = await request(app).post('/scan').send({
        code: VULNERABLE_CODE,
        filename: 'test.ts',
        aiExplain: true,
      });

      expect(statusCode).toBe(200);
      const { findings } = body as { findings: Array<Record<string, unknown>> };
      expect(Array.isArray(findings)).toBe(true);
      expect(findings.length).toBeGreaterThan(0);

      // At least one finding should have AI fields
      const withAI = findings.filter((f) => f.explanation !== undefined || f.fixSuggestion !== undefined);
      expect(withAI.length).toBeGreaterThan(0);
      expect(typeof withAI[0]!.explanation).toBe('string');
      expect(typeof withAI[0]!.fixSuggestion).toBe('string');
    } finally {
      stub.mockRestore();
    }
  });

  test('Anthropic stub is called when aiExplain=true', async () => {
    const anthropicResponse = {
      content: [{ text: JSON.stringify({ explanation: 'Test explanation.', fixSuggestion: 'crypto.randomBytes()' }) }],
    };
    const stub = makeAnthropicStub(anthropicResponse);

    try {
      await request(app).post('/scan').send({
        code: VULNERABLE_CODE,
        filename: 'test.ts',
        aiExplain: true,
      });
      expect(stub).toHaveBeenCalled();
    } finally {
      stub.mockRestore();
    }
  });

  test('Anthropic stub is NOT called when aiExplain=false', async () => {
    const stub = vi.spyOn(https, 'request');

    try {
      const { statusCode, body } = await request(app).post('/scan').send({
        code: VULNERABLE_CODE,
        filename: 'test.ts',
        aiExplain: false,
      });
      expect(statusCode).toBe(200);
      // https.request should not have been called for Anthropic
      expect(stub).not.toHaveBeenCalled();
      const { findings } = body as { findings: Array<Record<string, unknown>> };
      expect(Array.isArray(findings)).toBe(true);
    } finally {
      stub.mockRestore();
    }
  });
});

describe('POST /scan — aiExplain=true without ANTHROPIC_API_KEY', () => {
  test('returns findings without AI fields when key is missing', async () => {
    const savedKey = process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;

    try {
      const { statusCode, body } = await request(app).post('/scan').send({
        code: VULNERABLE_CODE,
        filename: 'test.ts',
        aiExplain: true,
      });

      expect(statusCode).toBe(200);
      const { findings } = body as { findings: Array<Record<string, unknown>> };
      expect(Array.isArray(findings)).toBe(true);
      // Without an API key, enrichment is skipped — no AI fields expected
      for (const f of findings) {
        expect(f.explanation).toBeUndefined();
      }
    } finally {
      if (savedKey) process.env.ANTHROPIC_API_KEY = savedKey;
    }
  });
});

// ── Swift finding AI explain test ─────────────────────────────────────────────

const VULNERABLE_SWIFT_CODE = `
import Foundation
class Net {
  func fetch(url: URL) {
    URLSession.shared.dataTask(with: url) { d, _, _ in print(d as Any) }.resume()
  }
  let apiKey: String = "sk-liveabcdef1234567890secretkey"
}
`;

describe('POST /scan — Swift finding with aiExplain=true', () => {
  test('returns AI explanation for Swift SSRF finding', async () => {
    const anthropicResponse = {
      content: [
        {
          text: JSON.stringify({
            explanation: 'URLSession with user-controlled URL can be exploited for SSRF attacks against internal services.',
            fixSuggestion: 'guard let url = URL(string: input), ["https"].contains(url.scheme) else { return }',
          }),
        },
      ],
    };

    const stub = makeAnthropicStub(anthropicResponse);

    try {
      const { statusCode, body } = await request(app).post('/scan').send({
        code: VULNERABLE_SWIFT_CODE,
        filename: 'Network.swift',
        aiExplain: true,
      });

      expect(statusCode).toBe(200);
      const { findings } = body as { findings: Array<Record<string, unknown>> };
      expect(Array.isArray(findings)).toBe(true);
      expect(findings.length).toBeGreaterThan(0);

      // Verify Swift finding types are present
      const types = findings.map((f) => f.type);
      expect(types).toContain('SSRF');

      // At least one finding should have AI fields
      const withAI = findings.filter((f) => f.explanation !== undefined);
      expect(withAI.length).toBeGreaterThan(0);
    } finally {
      stub.mockRestore();
    }
  });
});

// ── Additional Swift finding type AI explain tests ───────────────────────────

const SWIFT_SHARED_PREFS_CODE = `
import Foundation
class AuthManager {
  func saveToken(_ token: String) {
    UserDefaults.standard.set(token, forKey: "authToken")
  }
  func savePassword(_ pwd: String) {
    UserDefaults.standard["userPassword"] = pwd
  }
}
`;

const SWIFT_WEBVIEW_CODE = `
import WebKit
class BrowserVC: UIViewController {
  var webView = WKWebView()
  func loadPage(url: URL) {
    webView.loadRequest(URLRequest(url: url))
    webView.loadHTMLString("<b>hello</b>", baseURL: nil)
  }
}
`;

const SWIFT_N_PLUS_ONE_CODE = `
import CoreData
class PostRepository {
  func allPosts(context: NSManagedObjectContext) {
    let posts = try? context.fetch(NSFetchRequest<NSManagedObject>(entityName: "Post"))
    posts?.forEach { post in
      let req = NSFetchRequest<NSManagedObject>(entityName: "Comment")
      req.predicate = NSPredicate(format: "postId == %@", post.value(forKey: "id") as! CVarArg)
      _ = try? context.fetch(req)
    }
  }
}
`;

describe('POST /scan — Swift INSECURE_SHARED_PREFS finding with aiExplain=true', () => {
  test('returns AI explanation for Swift INSECURE_SHARED_PREFS finding', async () => {
    const anthropicResponse = {
      content: [
        {
          text: JSON.stringify({
            explanation: 'UserDefaults stores data in plaintext plist files. Sensitive values like tokens and passwords must be stored in the iOS Keychain instead.',
            fixSuggestion: 'Use KeychainSwift: keychain.set(token, forKey: "authToken") after importing KeychainSwift',
          }),
        },
      ],
    };

    const stub = makeAnthropicStub(anthropicResponse);

    try {
      const { statusCode, body } = await request(app).post('/scan').send({
        code: SWIFT_SHARED_PREFS_CODE,
        filename: 'AuthManager.swift',
        aiExplain: true,
      });

      expect(statusCode).toBe(200);
      const { findings } = body as { findings: Array<Record<string, unknown>> };
      expect(Array.isArray(findings)).toBe(true);
      expect(findings.length).toBeGreaterThan(0);

      const types = findings.map((f) => f.type);
      expect(types).toContain('INSECURE_SHARED_PREFS');

      // At least the INSECURE_SHARED_PREFS finding should have AI fields
      const withAI = findings.filter((f) => f.explanation !== undefined);
      expect(withAI.length).toBeGreaterThan(0);
    } finally {
      stub.mockRestore();
    }
  });
});

describe('POST /scan — Swift UNSAFE_WEBVIEW finding with aiExplain=true', () => {
  test('returns AI explanation for Swift UNSAFE_WEBVIEW finding', async () => {
    const anthropicResponse = {
      content: [
        {
          text: JSON.stringify({
            explanation: 'Loading arbitrary URLs in WKWebView without validation allows XSS attacks and data exfiltration from your app context.',
            fixSuggestion: 'Implement WKNavigationDelegate.webView(_:decidePolicyFor:decisionHandler:) and allow only specific trusted origins.',
          }),
        },
      ],
    };

    const stub = makeAnthropicStub(anthropicResponse);

    try {
      const { statusCode, body } = await request(app).post('/scan').send({
        code: SWIFT_WEBVIEW_CODE,
        filename: 'BrowserVC.swift',
        aiExplain: true,
      });

      expect(statusCode).toBe(200);
      const { findings } = body as { findings: Array<Record<string, unknown>> };
      expect(Array.isArray(findings)).toBe(true);
      expect(findings.length).toBeGreaterThan(0);

      const types = findings.map((f) => f.type);
      expect(types).toContain('UNSAFE_WEBVIEW');

      const withAI = findings.filter((f) => f.explanation !== undefined);
      expect(withAI.length).toBeGreaterThan(0);
    } finally {
      stub.mockRestore();
    }
  });
});

describe('POST /scan — Swift PERFORMANCE_N_PLUS_ONE finding with aiExplain=true', () => {
  test('returns AI explanation for Swift PERFORMANCE_N_PLUS_ONE finding', async () => {
    const anthropicResponse = {
      content: [
        {
          text: JSON.stringify({
            explanation: 'Issuing a CoreData fetch inside a loop causes N+1 queries: one for the outer list and N for each element. This scales poorly and degrades performance.',
            fixSuggestion: 'Use a single NSFetchRequest with an NSPredicate covering all IDs, or use a relationship fetch with a batch size set on the NSFetchedResultsController.',
          }),
        },
      ],
    };

    const stub = makeAnthropicStub(anthropicResponse);

    try {
      const { statusCode, body } = await request(app).post('/scan').send({
        code: SWIFT_N_PLUS_ONE_CODE,
        filename: 'PostRepository.swift',
        aiExplain: true,
      });

      expect(statusCode).toBe(200);
      const { findings } = body as { findings: Array<Record<string, unknown>> };
      expect(Array.isArray(findings)).toBe(true);
      expect(findings.length).toBeGreaterThan(0);

      const types = findings.map((f) => f.type);
      expect(types).toContain('PERFORMANCE_N_PLUS_ONE');

      const withAI = findings.filter((f) => f.explanation !== undefined);
      expect(withAI.length).toBeGreaterThan(0);
    } finally {
      stub.mockRestore();
    }
  });
});
